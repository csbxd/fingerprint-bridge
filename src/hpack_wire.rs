//! Preserve HPACK representations while translating only mapped values.
//! Inbound and outbound tables can evict different entries when a value grows.
use crate::{h2::MAX_BLOCK, rewrite::Mapping};
use anyhow::{ensure, Result};
use std::sync::OnceLock;

mod codes {
    include!("huffman_codes.rs");
}
type Header = (Vec<u8>, Vec<u8>);

fn integer(b: &[u8], p: &mut usize, bits: u8) -> Result<usize> {
    ensure!(*p < b.len(), "truncated HPACK integer");
    let mask = (1usize << bits) - 1;
    let mut n = b[*p] as usize & mask;
    *p += 1;
    if n < mask {
        return Ok(n);
    }
    let mut shift = 0;
    loop {
        ensure!(*p < b.len() && shift <= 28, "invalid HPACK integer");
        let c = b[*p];
        *p += 1;
        n = n
            .checked_add(((c & 127) as usize) << shift)
            .ok_or_else(|| anyhow::anyhow!("HPACK overflow"))?;
        if c & 128 == 0 {
            return Ok(n);
        }
        shift += 7;
    }
}
fn skip_string(b: &[u8], p: &mut usize) -> Result<()> {
    let n = integer(b, p, 7)?;
    ensure!(n <= b.len() - *p, "truncated HPACK string");
    *p += n;
    Ok(())
}
fn put_int(out: &mut Vec<u8>, mut n: usize, prefix: u8, bits: u8) {
    let max = (1usize << bits) - 1;
    if n < max {
        out.push(prefix | n as u8);
        return;
    }
    out.push(prefix | max as u8);
    n -= max;
    while n >= 128 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn put_string(out: &mut Vec<u8>, value: &[u8], huffman: bool) {
    if !huffman {
        put_int(out, value.len(), 0, 7);
        out.extend(value);
        return;
    }
    let mut encoded = Vec::new();
    let (mut buffer, mut bits) = (0u64, 0u8);
    for c in value {
        let (code, width) = codes::HUFFMAN_CODE_TABLE[*c as usize];
        buffer = (buffer << width) | u64::from(code);
        bits += width;
        while bits >= 8 {
            bits -= 8;
            encoded.push((buffer >> bits) as u8);
        }
    }
    if bits != 0 {
        encoded.push(((buffer << (8 - bits)) as u8) | (0xff >> bits));
    }
    put_int(out, encoded.len(), 0x80, 7);
    out.extend(encoded);
}

fn static_table() -> &'static [Header] {
    static TABLE: OnceLock<Vec<Header>> = OnceLock::new();
    TABLE.get_or_init(|| {
        (1..=61u8)
            .map(|i| hpack::Decoder::new().decode(&[0x80 | i]).unwrap().remove(0))
            .collect()
    })
}
struct Table {
    entries: Vec<Header>,
    size: usize,
    limit: usize,
}
impl Table {
    fn get(&self, index: usize) -> Option<&Header> {
        match index {
            0 => None,
            1..=61 => static_table().get(index - 1),
            _ => self.entries.get(index - 62),
        }
    }
    fn find(&self, preferred: usize, name: &[u8], value: Option<&[u8]>) -> usize {
        let matches = |h: &Header| h.0 == name && value.is_none_or(|v| h.1 == v);
        if self.get(preferred).is_some_and(matches) {
            return preferred;
        }
        static_table()
            .iter()
            .chain(&self.entries)
            .position(matches)
            .map_or(0, |i| i + 1)
    }
    fn evict(&mut self) {
        while self.size > self.limit {
            let (n, v) = self.entries.pop().unwrap();
            self.size -= n.len() + v.len() + 32;
        }
    }
    fn insert(&mut self, h: Header) {
        self.size += h.0.len() + h.1.len() + 32;
        self.entries.insert(0, h);
        self.evict();
    }
}

/// State is private to one connection and one direction, including responses.
pub struct HeaderRewriter {
    inbound: hpack::Decoder<'static>,
    outbound: Table,
}
impl Default for HeaderRewriter {
    fn default() -> Self {
        Self::new()
    }
}
impl HeaderRewriter {
    pub fn new() -> Self {
        Self {
            inbound: hpack::Decoder::new(),
            outbound: Table {
                entries: vec![],
                size: 0,
                limit: 4096,
            },
        }
    }
    pub fn rewrite(
        &mut self,
        block: &[u8],
        mapping: &Mapping,
        response: bool,
        limit: usize,
    ) -> Result<Vec<u8>> {
        ensure!(block.len() <= MAX_BLOCK, "header block too large");
        let mut out = Vec::new();
        let (mut p, mut total, mut authority) = (0, 0, 0);
        let (mut fields, mut regular, mut method) = (false, false, false);
        while p < block.len() {
            let start = p;
            let c = block[p];
            if c & 0xe0 == 0x20 {
                ensure!(!fields, "HPACK table update after fields");
                let n = integer(block, &mut p, 5)?;
                ensure!(
                    n <= limit.min(65536),
                    "HPACK table exceeds advertised/configured limit"
                );
                self.inbound
                    .decode(&block[start..p])
                    .map_err(|e| anyhow::anyhow!("HPACK decode: {e:?}"))?;
                self.outbound.limit = n;
                self.outbound.evict();
                out.extend_from_slice(&block[start..p]);
                continue;
            }
            fields = true;
            let indexed = c & 0x80 != 0;
            let incremental = !indexed && c & 0x40 != 0;
            let bits = if indexed {
                7
            } else if incremental {
                6
            } else {
                4
            };
            let index = integer(block, &mut p, bits)?;
            let name_start = p;
            if !indexed && index == 0 {
                skip_string(block, &mut p)?;
            }
            let value_start = p;
            if !indexed {
                skip_string(block, &mut p)?;
            }
            let mut headers = self
                .inbound
                .decode(&block[start..p])
                .map_err(|e| anyhow::anyhow!("HPACK decode: {e:?}"))?;
            ensure!(headers.len() == 1, "invalid HPACK field");
            let (name, value) = headers.remove(0);
            ensure!(
                !name.is_empty()
                    && !name
                        .iter()
                        .any(|c| c.is_ascii_uppercase() || *c <= 32 || *c == 127),
                "invalid HTTP/2 name"
            );
            ensure!(
                !value.iter().any(|c| matches!(*c, b'\r' | b'\n' | 0)),
                "invalid HTTP/2 value"
            );
            if name.starts_with(b":") {
                ensure!(!regular, "pseudo-header after regular header");
            } else {
                regular = true;
            }
            if name == b":method" {
                ensure!(value != b"CONNECT", "HTTP/2 CONNECT unsupported");
                method = true;
            }
            if name == b":authority" {
                authority += 1;
            }
            let mapped = mapping.value(&name, &value, response)?;
            total += name.len() + mapped.len().max(value.len()) + 32;
            ensure!(total <= MAX_BLOCK, "decoded headers too large");
            if indexed {
                let target = self.outbound.find(index, &name, Some(&mapped));
                if target == index {
                    out.extend_from_slice(&block[start..p]);
                } else if target != 0 {
                    put_int(&mut out, target, 0x80, 7);
                } else {
                    // A longer rewritten value may have evicted this entry only
                    // at the receiver. Do not add a new, unrequested table entry.
                    let target = self.outbound.find(0, &name, None);
                    put_int(&mut out, target, 0, 4);
                    if target == 0 {
                        put_string(&mut out, &name, false);
                    }
                    put_string(&mut out, &mapped, false);
                }
            } else {
                let target = if index == 0 {
                    0
                } else {
                    self.outbound.find(index, &name, None)
                };
                if target == index {
                    out.extend_from_slice(&block[start..value_start]);
                } else {
                    put_int(
                        &mut out,
                        target,
                        c & if incremental { 0xc0 } else { 0xf0 },
                        bits,
                    );
                    if target == 0 {
                        if index == 0 {
                            out.extend_from_slice(&block[name_start..value_start]);
                        } else {
                            put_string(&mut out, &name, false);
                        }
                    }
                }
                if mapped == value {
                    out.extend_from_slice(&block[value_start..p]);
                } else {
                    put_string(&mut out, &mapped, block[value_start] & 0x80 != 0);
                }
                if incremental {
                    self.outbound.insert((name, mapped));
                }
            }
            ensure!(out.len() <= MAX_BLOCK, "rewritten header block too large");
        }
        if !response && method {
            ensure!(authority == 1, "exactly one :authority required");
        }
        Ok(out)
    }
}

/// Standalone never-indexed encoding for callers constructing fresh headers.
pub fn encode_headers(headers: &[Header]) -> Vec<u8> {
    let mut out = vec![];
    for (n, v) in headers {
        out.push(0x10);
        put_string(&mut out, n, false);
        put_string(&mut out, v, false);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn huffman_rfc7541_c4_and_all_octets() {
        let mut encoded = Vec::new();
        put_string(&mut encoded, b"www.example.com", true);
        assert_eq!(hex::encode(encoded), "8cf1e3c2e5f23a6ba0ab90f4ff");
        let input: Vec<_> = (0..=255).collect();
        let mut encoded = Vec::new();
        put_string(&mut encoded, &input, true);
        let mut p = 0;
        let size = integer(&encoded, &mut p, 7).unwrap();
        assert_eq!(size, encoded.len() - p);
        assert_eq!(
            hpack::huffman::HuffmanDecoder::new()
                .decode(&encoded[p..])
                .unwrap(),
            input
        );
    }
}
