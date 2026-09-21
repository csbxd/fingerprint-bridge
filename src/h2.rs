//! Frame bridge: preserves SETTINGS order, flow-control frames, stream ids and DATA.
//! HPACK blocks are decoded per direction and re-encoded as never-indexed literals.
use crate::rewrite::Mapping;
use anyhow::{bail, ensure, Result};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const MAX_BLOCK: usize = 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}
impl Frame {
    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Self>> {
        let mut h = [0; 9];
        let n = r.read(&mut h[..1]).await?;
        if n == 0 {
            return Ok(None);
        }
        r.read_exact(&mut h[1..]).await?;
        let len = ((h[0] as usize) << 16) | ((h[1] as usize) << 8) | h[2] as usize;
        ensure!(len <= MAX_BLOCK, "frame exceeds configured 1 MiB limit");
        let mut payload = vec![0; len];
        r.read_exact(&mut payload).await?;
        Ok(Some(Self {
            kind: h[3],
            flags: h[4],
            stream: u32::from_be_bytes(h[5..9].try_into()?),
            payload,
        }))
    }
    pub async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        let n = self.payload.len();
        ensure!(n <= 0xffffff, "oversized frame");
        let mut h = vec![
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
            self.kind,
            self.flags,
        ];
        h.extend(self.stream.to_be_bytes());
        w.write_all(&h).await?;
        w.write_all(&self.payload).await?;
        Ok(())
    }
}
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
fn validate_block(b: &[u8], table_limit: usize) -> Result<()> {
    let mut p = 0;
    let mut fields = false;
    while p < b.len() {
        let c = b[p];
        if c & 128 != 0 {
            integer(b, &mut p, 7)?;
            fields = true;
        } else if c & 0xe0 == 0x20 {
            ensure!(!fields, "HPACK table update after fields");
            let n = integer(b, &mut p, 5)?;
            ensure!(
                n <= table_limit.min(65536),
                "HPACK table exceeds advertised/configured limit"
            );
        } else {
            let prefix = if c & 0x40 != 0 { 6 } else { 4 };
            if integer(b, &mut p, prefix)? == 0 {
                skip_string(b, &mut p)?
            }
            skip_string(b, &mut p)?;
            fields = true;
        }
    }
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
/// Avoids cross-user compression state; preserves decoded header order and duplicates.
pub fn encode_headers(headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![];
    for (n, v) in headers {
        out.push(0x10);
        put_int(&mut out, n.len(), 0, 7);
        out.extend(n);
        put_int(&mut out, v.len(), 0, 7);
        out.extend(v);
    }
    out
}
pub fn rewrite_block(
    decoder: &mut hpack::Decoder<'_>,
    block: &[u8],
    mapping: &Mapping,
    response: bool,
    limit: usize,
) -> Result<Vec<u8>> {
    ensure!(block.len() <= MAX_BLOCK, "header block too large");
    validate_block(block, limit)?;
    let mut headers = decoder
        .decode(block)
        .map_err(|e| anyhow::anyhow!("HPACK decode: {e:?}"))?;
    ensure!(
        headers
            .iter()
            .map(|(n, v)| n.len() + v.len() + 32)
            .sum::<usize>()
            <= MAX_BLOCK,
        "decoded headers too large"
    );
    let mut authority = 0;
    let mut regular = false;
    for (n, v) in &mut headers {
        ensure!(
            !n.is_empty()
                && !n
                    .iter()
                    .any(|c| c.is_ascii_uppercase() || *c <= 32 || *c == 127),
            "invalid HTTP/2 name"
        );
        ensure!(
            !v.contains(&b'\r') && !v.contains(&b'\n') && !v.contains(&0),
            "invalid HTTP/2 value"
        );
        if n.starts_with(b":") {
            ensure!(!regular, "pseudo-header after regular header")
        } else {
            regular = true;
        }
        if n == b":method" {
            ensure!(v != b"CONNECT", "HTTP/2 CONNECT unsupported")
        }
        if n == b":authority" {
            authority += 1;
        }
        *v = mapping.value(n, v, response)?;
    }
    // Trailers have no pseudo-headers and are still passed through.
    if !response && headers.iter().any(|(n, _)| n == b":method") {
        ensure!(authority == 1, "exactly one :authority required")
    }
    Ok(encode_headers(&headers))
}
pub fn settings(frame: &Frame) -> Result<Vec<(u16, u32)>> {
    ensure!(frame.kind == 4 && frame.stream == 0, "invalid SETTINGS");
    if frame.flags & 1 != 0 {
        ensure!(frame.payload.is_empty(), "SETTINGS ACK payload");
        return Ok(vec![]);
    }
    ensure!(frame.payload.len() % 6 == 0, "malformed SETTINGS");
    Ok(frame
        .payload
        .chunks_exact(6)
        .map(|b| {
            (
                u16::from_be_bytes([b[0], b[1]]),
                u32::from_be_bytes(b[2..6].try_into().unwrap()),
            )
        })
        .collect())
}
/// Preserve HEADERS priority metadata, padding, END_STREAM; emit legal-size fragments.
pub fn reframe(first: &Frame, encoded: &[u8]) -> Result<Vec<Frame>> {
    let (prefix, padding, _) = header_parts(first)?;
    let mut out = vec![];
    let first_cap = 16384 - prefix.len() - padding.len();
    let n = first_cap.min(encoded.len());
    let mut payload = prefix;
    payload.extend_from_slice(&encoded[..n]);
    payload.extend(padding);
    out.push(Frame {
        kind: 1,
        flags: (first.flags & !4) | if n == encoded.len() { 4 } else { 0 },
        stream: first.stream,
        payload,
    });
    for chunk in encoded[n..].chunks(16384) {
        out.push(Frame {
            kind: 9,
            flags: 0,
            stream: first.stream,
            payload: chunk.to_vec(),
        });
    }
    out.last_mut().unwrap().flags |= 4;
    Ok(out)
}
fn header_parts(frame: &Frame) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    ensure!(
        frame.kind == 1 && frame.stream & 0x7fffffff != 0,
        "invalid HEADERS"
    );
    let b = &frame.payload;
    let pad = if frame.flags & 8 != 0 {
        ensure!(!b.is_empty(), "missing pad length");
        b[0] as usize
    } else {
        0
    };
    let start = usize::from(frame.flags & 8 != 0) + if frame.flags & 32 != 0 { 5 } else { 0 };
    ensure!(start + pad <= b.len(), "bad HEADERS padding/priority");
    Ok((
        b[..start].to_vec(),
        b[b.len() - pad..].to_vec(),
        b[start..b.len() - pad].to_vec(),
    ))
}
async fn direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    mapping: &Mapping,
    response: bool,
    table: Arc<AtomicUsize>,
    other: Arc<AtomicUsize>,
) -> Result<()> {
    let mut decoder = hpack::Decoder::new();
    if !response {
        let mut preface = [0; 24];
        r.read_exact(&mut preface).await?;
        ensure!(preface == PREFACE, "invalid HTTP/2 preface");
        w.write_all(&preface).await?;
    }
    while let Some(frame) = Frame::read(&mut r).await? {
        match frame.kind {
            4 => {
                for (id, value) in settings(&frame)? {
                    if id == 1 {
                        other.store(value as usize, Ordering::Relaxed)
                    }
                }
                frame.write(&mut w).await?;
            }
            1 => {
                let (_, _, mut block) = header_parts(&frame)?;
                let mut flags = frame.flags;
                while flags & 4 == 0 {
                    let next = Frame::read(&mut r)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("truncated CONTINUATION"))?;
                    ensure!(
                        next.kind == 9 && next.stream == frame.stream,
                        "interleaved CONTINUATION"
                    );
                    ensure!(
                        block.len() + next.payload.len() <= MAX_BLOCK,
                        "header block too large"
                    );
                    flags = next.flags;
                    block.extend(next.payload);
                }
                let encoded = rewrite_block(
                    &mut decoder,
                    &block,
                    mapping,
                    response,
                    table.load(Ordering::Relaxed),
                )?;
                for f in reframe(&frame, &encoded)? {
                    f.write(&mut w).await?;
                }
            }
            5 => bail!("HTTP/2 server push unsupported"),
            9 => bail!("unexpected CONTINUATION"),
            _ => frame.write(&mut w).await?,
        }
        w.flush().await?;
    }
    w.shutdown().await?;
    Ok(())
}
pub async fn bridge<C, U>(client: C, upstream: U, mapping: Mapping) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let c = Arc::new(AtomicUsize::new(4096));
    let s = Arc::new(AtomicUsize::new(4096));
    let requests = direction(cr, uw, &mapping, false, c.clone(), s.clone());
    let responses = direction(ur, cw, &mapping, true, s, c);
    tokio::pin!(requests);
    tokio::pin!(responses);
    tokio::select! {r=&mut responses=>r,r=&mut requests=>{r?;responses.await}}
}
