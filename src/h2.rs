//! Frame bridge: preserves SETTINGS order, flow-control frames, stream ids and DATA.
//! HPACK representation, Huffman choices and dynamic state are retained when possible.
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
pub use crate::hpack_wire::{encode_headers, HeaderRewriter};
pub fn rewrite_block(
    rewriter: &mut HeaderRewriter,
    block: &[u8],
    mapping: &Mapping,
    response: bool,
    limit: usize,
) -> Result<Vec<u8>> {
    rewriter.rewrite(block, mapping, response, limit)
}
pub fn settings(frame: &Frame) -> Result<Vec<(u16, u32)>> {
    ensure!(frame.kind == 4 && frame.stream == 0, "invalid SETTINGS");
    if frame.flags & 1 != 0 {
        ensure!(frame.payload.is_empty(), "SETTINGS ACK payload");
        return Ok(vec![]);
    }
    ensure!(frame.payload.len().is_multiple_of(6), "malformed SETTINGS");
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
/// Retain original fragments; only the last fragment absorbs a length change.
/// Additional CONTINUATION frames are needed only if the peer's limit is exceeded.
pub fn reframe(original: &[Frame], encoded: &[u8], max_frame: usize) -> Result<Vec<Frame>> {
    ensure!(
        (16384..=0xffffff).contains(&max_frame),
        "invalid frame limit"
    );
    let first = original
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing HEADERS"))?;
    let (prefix, padding, _) = header_parts(first)?;
    let mut out = vec![];
    let mut pos = 0;
    for (i, frame) in original.iter().enumerate() {
        ensure!(
            frame.payload.len() <= max_frame,
            "header frame exceeds peer limit"
        );
        ensure!(
            i == 0 || (frame.kind == 9 && frame.stream == first.stream),
            "invalid CONTINUATION"
        );
        let overhead = if i == 0 {
            prefix.len() + padding.len()
        } else {
            0
        };
        let cap = if i + 1 == original.len() {
            max_frame - overhead
        } else {
            frame.payload.len() - overhead
        };
        let n = cap.min(encoded.len() - pos);
        let mut payload = if i == 0 { prefix.clone() } else { vec![] };
        payload.extend_from_slice(&encoded[pos..pos + n]);
        if i == 0 {
            payload.extend_from_slice(&padding);
        }
        out.push(Frame {
            kind: frame.kind,
            flags: frame.flags & !4,
            stream: frame.stream,
            payload,
        });
        pos += n;
    }
    for chunk in encoded[pos..].chunks(max_frame) {
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
struct PeerLimits {
    table: AtomicUsize,
    frame: AtomicUsize,
}
impl PeerLimits {
    fn new() -> Self {
        Self {
            table: AtomicUsize::new(4096),
            frame: AtomicUsize::new(16384),
        }
    }
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
    limits: Arc<PeerLimits>,
    other: Arc<PeerLimits>,
) -> Result<()> {
    let mut decoder = HeaderRewriter::new();
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
                        other.table.store(value as usize, Ordering::Relaxed)
                    } else if id == 5 {
                        ensure!(
                            (16384..=0xffffff).contains(&value),
                            "invalid SETTINGS_MAX_FRAME_SIZE"
                        );
                        other.frame.store(value as usize, Ordering::Relaxed)
                    }
                }
                frame.write(&mut w).await?;
            }
            1 => {
                let (_, _, mut block) = header_parts(&frame)?;
                let mut flags = frame.flags;
                let mut original = vec![frame];
                while flags & 4 == 0 {
                    let next = Frame::read(&mut r)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("truncated CONTINUATION"))?;
                    ensure!(
                        next.kind == 9 && next.stream == original[0].stream,
                        "interleaved CONTINUATION"
                    );
                    ensure!(
                        block.len() + next.payload.len() <= MAX_BLOCK,
                        "header block too large"
                    );
                    flags = next.flags;
                    block.extend_from_slice(&next.payload);
                    original.push(next);
                    ensure!(original.len() <= 1024, "too many CONTINUATION frames");
                }
                let encoded = rewrite_block(
                    &mut decoder,
                    &block,
                    mapping,
                    response,
                    limits.table.load(Ordering::Relaxed),
                )?;
                for f in reframe(&original, &encoded, limits.frame.load(Ordering::Relaxed))? {
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
    let c = Arc::new(PeerLimits::new());
    let s = Arc::new(PeerLimits::new());
    let requests = direction(cr, uw, &mapping, false, c.clone(), s.clone());
    let responses = direction(ur, cw, &mapping, true, s, c);
    tokio::pin!(requests);
    tokio::pin!(responses);
    tokio::select! {r=&mut responses=>r,r=&mut requests=>{r?;responses.await}}
}
