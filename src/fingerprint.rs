//! Parsers operate on captured wire bytes. Missing evidence never means a match.
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const MAX_HELLO: usize = 256 * 1024;

pub fn grease(n: u16) -> bool {
    n & 0x0f0f == 0x0a0a && n >> 8 == n & 255
}
fn normalize(n: u16) -> u16 {
    if grease(n) {
        0x0a0a
    } else {
        n
    }
}
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.b.len().saturating_sub(self.p), "truncated field");
        let out = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
    fn v8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn v16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn done(&self) -> Result<()> {
        ensure!(self.p == self.b.len(), "trailing data");
        Ok(())
    }
}
fn words(b: &[u8]) -> Result<Vec<u16>> {
    ensure!(b.len() % 2 == 0, "odd u16 vector");
    Ok(b.chunks_exact(2)
        .map(|c| normalize(u16::from_be_bytes([c[0], c[1]])))
        .collect())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub compression: Vec<u8>,
    pub groups: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub alpn: Vec<String>,
    pub key_share_groups: Vec<u16>,
    pub key_share_lengths: Vec<usize>,
    pub cert_compression: Vec<u16>,
    pub psk_modes: Vec<u8>,
    pub sni_present: bool,
    pub other_extensions: Vec<(u16, String)>,
}
impl TlsHello {
    pub fn ja3_string(&self) -> String {
        fn list(xs: impl Iterator<Item = u16>) -> String {
            xs.filter(|n| !grease(*n))
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join("-")
        }
        format!(
            "{},{},{},{},{}",
            self.legacy_version,
            list(self.ciphers.iter().copied()),
            list(self.extensions.iter().copied()),
            list(self.groups.iter().copied()),
            list(self.point_formats.iter().map(|n| *n as u16))
        )
    }
    pub fn ja3(&self) -> String {
        format!("{:x}", md5::compute(self.ja3_string()))
    }
    /// JA4 for TLS-over-TCP; original field order is also retained in evidence.
    pub fn ja4(&self) -> String {
        let filtered = |xs: &[u16]| {
            xs.iter()
                .copied()
                .filter(|n| !grease(*n))
                .collect::<Vec<_>>()
        };
        let mut c = filtered(&self.ciphers);
        let mut e = filtered(&self.extensions);
        let version = filtered(&self.supported_versions)
            .into_iter()
            .max()
            .unwrap_or(self.legacy_version);
        let version = match version {
            0x304 => "13",
            0x303 => "12",
            0x302 => "11",
            0x301 => "10",
            0x300 => "s3",
            2 => "s2",
            _ => "00",
        };
        let alpn = self
            .alpn
            .first()
            .and_then(|s| hex::decode(s).ok())
            .filter(|s| !s.is_empty())
            .map_or_else(
                || "00".into(),
                |s| {
                    let a = s[0];
                    let z = s[s.len() - 1];
                    if a.is_ascii_alphanumeric() && z.is_ascii_alphanumeric() {
                        format!("{}{}", a as char, z as char)
                    } else {
                        let h = hex::encode(s);
                        format!("{}{}", &h[..1], &h[h.len() - 1..])
                    }
                },
            );
        let prefix = format!(
            "t{version}{}{:02}{:02}{alpn}",
            if self.extensions.contains(&0) {
                'd'
            } else {
                'i'
            },
            c.len().min(99),
            e.len().min(99)
        );
        let list = |xs: &[u16]| {
            xs.iter()
                .map(|n| format!("{n:04x}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let hash = |s: &str| {
            if s.is_empty() {
                "000000000000".to_string()
            } else {
                digest(s.as_bytes())[..12].to_string()
            }
        };
        c.sort_unstable();
        e.retain(|n| *n != 0 && *n != 16);
        e.sort_unstable();
        let sigs = filtered(&self.signature_algorithms);
        let mut exts = list(&e);
        if !e.is_empty() && !sigs.is_empty() {
            exts.push('_');
            exts.push_str(&list(&sigs));
        }
        format!("{prefix}_{}_{}", hash(&list(&c)), hash(&exts))
    }
    pub fn evidence(&self) -> Value {
        json!({"ja3":self.ja3(), "ja3_string":self.ja3_string(),"ja4":self.ja4(), "fields":self})
    }
}

/// Returns None until an entire ClientHello is available; reassembles TLS records.
pub fn client_hello(records: &[u8]) -> Result<Option<TlsHello>> {
    ensure!(
        records.len() <= MAX_HELLO,
        "ClientHello capture limit exceeded"
    );
    let mut off = 0;
    let mut handshake = Vec::new();
    while off + 5 <= records.len() {
        ensure!(records[off] == 22, "expected TLS handshake record");
        let n = u16::from_be_bytes([records[off + 3], records[off + 4]]) as usize;
        ensure!(n <= 18432, "oversized TLS record");
        if off + 5 + n > records.len() {
            return Ok(None);
        }
        handshake.extend_from_slice(&records[off + 5..off + 5 + n]);
        off += 5 + n;
        if handshake.len() >= 4 {
            ensure!(handshake[0] == 1, "expected ClientHello");
            let n = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            ensure!(n + 4 <= MAX_HELLO, "oversized ClientHello");
            if handshake.len() >= n + 4 {
                return parse_hello(&handshake[4..n + 4]).map(Some);
            }
        }
    }
    Ok(None)
}

fn parse_hello(bytes: &[u8]) -> Result<TlsHello> {
    let mut r = Reader::new(bytes);
    let legacy_version = r.u16()?;
    r.take(32)?;
    r.v8()?;
    let ciphers = words(r.v16()?)?;
    ensure!(!ciphers.is_empty(), "empty ciphers");
    let compression = r.v8()?.to_vec();
    let mut hello = TlsHello {
        legacy_version,
        ciphers,
        compression,
        extensions: vec![],
        groups: vec![],
        point_formats: vec![],
        signature_algorithms: vec![],
        supported_versions: vec![],
        alpn: vec![],
        key_share_groups: vec![],
        key_share_lengths: vec![],
        cert_compression: vec![],
        psk_modes: vec![],
        sni_present: false,
        other_extensions: vec![],
    };
    if r.p == r.b.len() {
        return Ok(hello);
    }
    let mut ext = Reader::new(r.v16()?);
    r.done()?;
    let mut seen = std::collections::HashSet::new();
    while ext.p < ext.b.len() {
        let id = ext.u16()?;
        let raw = ext.v16()?;
        ensure!(seen.insert(id), "duplicate TLS extension");
        hello.extensions.push(normalize(id));
        if grease(id) {
            continue;
        }
        let mut v = Reader::new(raw);
        match id {
            0 => {
                let mut names = Reader::new(v.v16()?);
                while names.p < names.b.len() {
                    let kind = names.u8()?;
                    let name = names.v16()?;
                    if kind == 0 {
                        ensure!(!name.is_empty(), "empty SNI");
                        hello.sni_present = true;
                    }
                }
                v.done()?;
            }
            10 => {
                hello.groups = words(v.v16()?)?;
                v.done()?;
            }
            11 => {
                hello.point_formats = v.v8()?.to_vec();
                v.done()?;
            }
            13 => {
                hello.signature_algorithms = words(v.v16()?)?;
                v.done()?;
            }
            16 => {
                let mut protocols = Reader::new(v.v16()?);
                v.done()?;
                while protocols.p < protocols.b.len() {
                    let p = protocols.v8()?;
                    ensure!(!p.is_empty(), "empty ALPN");
                    hello.alpn.push(hex::encode(p));
                }
            }
            27 => {
                hello.cert_compression = words(v.v8()?)?;
                v.done()?;
            }
            43 => {
                hello.supported_versions = words(v.v8()?)?;
                v.done()?;
            }
            45 => {
                hello.psk_modes = v.v8()?.to_vec();
                v.done()?;
            }
            51 => {
                let mut shares = Reader::new(v.v16()?);
                v.done()?;
                while shares.p < shares.b.len() {
                    hello.key_share_groups.push(normalize(shares.u16()?));
                    hello.key_share_lengths.push(shares.v16()?.len());
                }
            }
            // SNI value, padding, session secrets/binders/tickets and ECH ciphertext
            // are explicitly exempt. Extension presence/order is still compared.
            21 | 35 | 41 | 44 | 65037 => {}
            _ => hello.other_extensions.push((id, digest(raw))),
        }
    }
    Ok(hello)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpSyn {
    pub ip_version: u8,
    pub ttl: u8,
    pub df: bool,
    pub window: u16,
    pub flags: u16,
    pub options: Vec<(u8, String)>,
}
pub fn tcp_syn(ip: &[u8]) -> Result<Option<TcpSyn>> {
    ensure!(!ip.is_empty(), "empty IP packet");
    let version = ip[0] >> 4;
    let (offset, total, ttl, df) = match version {
        4 => {
            ensure!(ip.len() >= 20, "short IPv4");
            let off = (ip[0] & 15) as usize * 4;
            let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            ensure!(
                off >= 20 && total >= off && total <= ip.len(),
                "invalid IPv4 size"
            );
            ensure!(
                u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff == 0,
                "fragmented IPv4 is unsupported"
            );
            if ip[9] != 6 {
                return Ok(None);
            }
            (off, total, ip[8], ip[6] & 0x40 != 0)
        }
        6 => {
            ensure!(ip.len() >= 40, "short IPv6");
            ensure!(ip[6] == 6, "IPv6 extension headers/non-TCP unsupported");
            let total = 40 + u16::from_be_bytes([ip[4], ip[5]]) as usize;
            ensure!(total <= ip.len(), "truncated IPv6");
            (40, total, ip[7], false)
        }
        _ => bail!("unsupported IP version"),
    };
    let tcp = &ip[offset..total];
    ensure!(tcp.len() >= 20, "short TCP");
    if tcp[13] & 0x12 != 2 {
        return Ok(None);
    }
    let end = (tcp[12] >> 4) as usize * 4;
    ensure!(end >= 20 && end <= tcp.len(), "invalid TCP header length");
    let mut options = Vec::new();
    let mut p = 20;
    while p < end {
        let kind = tcp[p];
        p += 1;
        if kind == 0 {
            options.push((0, hex::encode(&tcp[p..end])));
            break;
        }
        if kind == 1 {
            options.push((1, String::new()));
            continue;
        }
        ensure!(p < end, "truncated TCP option");
        let n = tcp[p] as usize;
        p += 1;
        ensure!(n >= 2 && p + n - 2 <= end, "invalid TCP option length");
        let b = &tcp[p..p + n - 2];
        p += n - 2;
        let value = if kind == 8 {
            ensure!(n == 10, "invalid timestamp option");
            "present".into()
        } else {
            hex::encode(b)
        };
        options.push((kind, value));
    }
    Ok(Some(TcpSyn {
        ip_version: version,
        ttl,
        df,
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        flags: ((tcp[12] & 15) as u16) << 8 | tcp[13] as u16,
        options,
    }))
}

/// Classic PCAP, Ethernet (including VLAN), RAW IP, Linux SLL/SLL2. No guessed flows.
pub fn pcap_syns(pcap: &[u8]) -> Result<Vec<Value>> {
    ensure!(pcap.len() >= 24, "short pcap");
    let little = match &pcap[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => bail!("need classic pcap; convert pcapng with editcap -F pcap"),
    };
    let u32at = |b: &[u8]| {
        if little {
            u32::from_le_bytes(b.try_into().unwrap())
        } else {
            u32::from_be_bytes(b.try_into().unwrap())
        }
    };
    let link = u32at(&pcap[20..24]);
    let mut p = 24;
    let mut out = vec![];
    while p < pcap.len() {
        ensure!(pcap.len() - p >= 16, "truncated pcap record");
        let n = u32at(&pcap[p + 8..p + 12]) as usize;
        p += 16;
        ensure!(
            n <= 16 * 1024 * 1024 && n <= pcap.len() - p,
            "invalid capture size"
        );
        let packet = &pcap[p..p + n];
        p += n;
        let offset = match link {
            1 => {
                ensure!(packet.len() >= 14, "short Ethernet");
                let mut off = 14;
                let mut proto = u16::from_be_bytes([packet[12], packet[13]]);
                while proto == 0x8100 || proto == 0x88a8 {
                    ensure!(off + 4 <= packet.len(), "short VLAN");
                    proto = u16::from_be_bytes([packet[off + 2], packet[off + 3]]);
                    off += 4;
                }
                if proto != 0x800 && proto != 0x86dd {
                    continue;
                }
                off
            }
            101 => 0,
            113 => {
                ensure!(packet.len() >= 16, "short SLL");
                let proto = u16::from_be_bytes([packet[14], packet[15]]);
                if proto != 0x800 && proto != 0x86dd {
                    continue;
                }
                16
            }
            276 => {
                ensure!(packet.len() >= 20, "short SLL2");
                let proto = u16::from_be_bytes([packet[0], packet[1]]);
                if proto != 0x800 && proto != 0x86dd {
                    continue;
                }
                20
            }
            _ => bail!("unsupported pcap link type {link}"),
        };
        if let Some(syn) = tcp_syn(&packet[offset..])? {
            out.push(serde_json::to_value(syn)?);
        }
    }
    ensure!(!out.is_empty(), "no initial TCP SYN captured");
    Ok(out)
}

#[derive(Debug, Serialize)]
pub struct Difference {
    pub field: String,
    pub baseline: Value,
    pub observed: Value,
}
pub fn differences(a: &Value, b: &Value) -> Vec<Difference> {
    fn walk(p: &str, a: &Value, b: &Value, out: &mut Vec<Difference>) {
        if let (Value::Object(a), Value::Object(b)) = (a, b) {
            let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
            for k in keys {
                walk(
                    &format!("{p}/{k}"),
                    a.get(k).unwrap_or(&Value::Null),
                    b.get(k).unwrap_or(&Value::Null),
                    out,
                );
            }
        } else if a != b {
            out.push(Difference {
                field: p.into(),
                baseline: a.clone(),
                observed: b.clone(),
            });
        }
    }
    let mut out = vec![];
    walk("", a, b, &mut out);
    out
}
/// All requested layers must contain actual nonempty observations on both sides.
pub fn compare(a: &Value, b: &Value, layers: &[String]) -> Result<Value> {
    ensure!(!layers.is_empty(), "no layers requested");
    let mut missing = vec![];
    let mut diff = vec![];
    for layer in layers {
        let valid = |v: &Value| {
            !v.is_null()
                && !v.as_object().is_some_and(|x| x.is_empty())
                && !v.as_array().is_some_and(|x| x.is_empty())
        };
        let x = a.get(layer).filter(|x| valid(x));
        let y = b.get(layer).filter(|y| valid(y));
        match (x, y) {
            (Some(x), Some(y)) => {
                for mut d in differences(x, y) {
                    d.field = format!("/{layer}{}", d.field);
                    diff.push(d);
                }
            }
            _ => missing.push(layer),
        }
    }
    Ok(
        json!({"schema_version":1,"pass":missing.is_empty()&&diff.is_empty(),"missing_layers":missing,"differences":diff,"scope":layers}),
    )
}
pub fn load_json(path: &std::path::Path) -> Result<Value> {
    serde_json::from_slice(&std::fs::read(path)?).context("invalid evidence JSON")
}
