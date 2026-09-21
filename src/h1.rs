//! One upstream connection per downstream connection. No header maps or auto headers.
use crate::rewrite::Mapping;
use anyhow::{bail, ensure, Result};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
pub const MAX_HEAD: usize = 64 * 1024;

pub async fn line<R: AsyncBufRead + Unpin>(r: &mut R, limit: usize) -> Result<Vec<u8>> {
    let mut out = vec![];
    loop {
        let b = r.fill_buf().await?;
        if b.is_empty() {
            ensure!(out.is_empty(), "truncated line");
            return Ok(out);
        }
        let n = b
            .iter()
            .position(|b| *b == b'\n')
            .map_or(b.len(), |n| n + 1);
        ensure!(out.len() + n <= limit, "line limit exceeded");
        out.extend_from_slice(&b[..n]);
        r.consume(n);
        if out.ends_with(b"\n") {
            ensure!(out.ends_with(b"\r\n"), "bare LF unsupported");
            return Ok(out);
        }
    }
}
pub async fn head<R: AsyncBufRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut out = vec![];
    loop {
        let l = line(r, MAX_HEAD - out.len()).await?;
        if l.is_empty() {
            ensure!(out.is_empty(), "truncated head");
            return Ok(out);
        }
        let done = l == b"\r\n";
        out.extend(l);
        if done {
            return Ok(out);
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    Empty,
    Length(u64),
    Chunked,
    UntilEof,
}
pub fn framing(head: &[u8], response: bool, no_body: bool) -> Result<Body> {
    let mut length = None;
    let mut te = None;
    for line in head.split(|b| *b == b'\n').skip(1) {
        if let Some(p) = line.iter().position(|b| *b == b':') {
            let name = &line[..p];
            if ![
                b"content-length".as_slice(),
                b"transfer-encoding",
                b"upgrade",
            ]
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
            {
                continue;
            }
            let value = std::str::from_utf8(&line[p + 1..])?.trim();
            if name.eq_ignore_ascii_case(b"content-length") {
                ensure!(
                    length.is_none()
                        && !value.is_empty()
                        && value.bytes().all(|b| b.is_ascii_digit()),
                    "ambiguous Content-Length"
                );
                length = Some(value.parse::<u64>()?);
            }
            if name.eq_ignore_ascii_case(b"transfer-encoding") {
                ensure!(te.is_none(), "duplicate Transfer-Encoding");
                te = Some(value.to_ascii_lowercase());
            }
            if name.eq_ignore_ascii_case(b"upgrade") {
                bail!("HTTP upgrade is unsupported")
            }
        }
    }
    ensure!(length.is_none() || te.is_none(), "CL+TE is rejected");
    if no_body {
        return Ok(Body::Empty);
    }
    if let Some(te) = te {
        ensure!(te == "chunked", "unsupported transfer coding");
        return Ok(Body::Chunked);
    }
    Ok(match length {
        Some(n) => Body::Length(n),
        None if response => Body::UntilEof,
        _ => Body::Empty,
    })
}
async fn exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    n: u64,
) -> Result<()> {
    let mut part = r.take(n);
    let copied = tokio::io::copy(&mut part, w).await?;
    ensure!(copied == n, "truncated body");
    Ok(())
}
pub async fn body<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    kind: Body,
) -> Result<()> {
    match kind {
        Body::Empty => {}
        Body::Length(n) => exact(r, w, n).await?,
        Body::UntilEof => {
            tokio::io::copy(r, w).await?;
        }
        Body::Chunked => loop {
            let l = line(r, 8192).await?;
            ensure!(!l.is_empty(), "truncated chunk");
            let size = l.split(|b| *b == b';' || *b == b'\r').next().unwrap();
            ensure!(
                !size.is_empty() && size.iter().all(|c| c.is_ascii_hexdigit()),
                "invalid chunk size"
            );
            let n = u64::from_str_radix(std::str::from_utf8(size)?, 16)?;
            w.write_all(&l).await?;
            if n == 0 {
                let mut total = 0;
                loop {
                    let l = line(r, MAX_HEAD - total).await?;
                    ensure!(!l.is_empty(), "truncated trailer");
                    total += l.len();
                    w.write_all(&l).await?;
                    if l == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            exact(r, w, n).await?;
            let mut end = [0; 2];
            r.read_exact(&mut end).await?;
            ensure!(end == *b"\r\n", "invalid chunk terminator");
            w.write_all(&end).await?;
        },
    }
    w.flush().await?;
    Ok(())
}

pub async fn bridge<C, U>(client: C, upstream: U, mapping: Mapping) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (cr, mut cw) = tokio::io::split(client);
    let (ur, mut uw) = tokio::io::split(upstream);
    let mut cr = BufReader::new(cr);
    let mut ur = BufReader::new(ur);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(32);
    let requests = async {
        loop {
            let h = head(&mut cr).await?;
            if h.is_empty() {
                break;
            }
            let first = h.split(|c| *c == b'\n').next().unwrap();
            let first = std::str::from_utf8(first)?.trim_end();
            let parts: Vec<_> = first.split(' ').collect();
            ensure!(
                parts.len() == 3 && parts[2] == "HTTP/1.1",
                "only HTTP/1.1 origin-form supported"
            );
            ensure!(
                parts[0] != "CONNECT" && (parts[1].starts_with('/') || parts[1] == "*"),
                "unsupported request target"
            );
            let framing = framing(&h, false, false)?;
            let rewritten = mapping.h1_head(&h, false)?;
            tx.send(parts[0] == "HEAD")
                .await
                .map_err(|_| anyhow::anyhow!("response direction closed"))?;
            uw.write_all(&rewritten).await?;
            uw.flush().await?;
            body(&mut cr, &mut uw, framing).await?;
        }
        drop(tx);
        uw.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let responses = async {
        while let Some(is_head) = rx.recv().await {
            loop {
                let h = head(&mut ur).await?;
                ensure!(!h.is_empty(), "upstream closed before response");
                let first = std::str::from_utf8(h.split(|b| *b == b'\n').next().unwrap())?;
                let status = first
                    .split(' ')
                    .nth(1)
                    .ok_or_else(|| anyhow::anyhow!("invalid status"))?
                    .parse::<u16>()?;
                ensure!(status != 101, "upgrade unsupported");
                let interim = (100..200).contains(&status);
                let kind = framing(
                    &h,
                    true,
                    is_head || interim || status == 204 || status == 304,
                )?;
                cw.write_all(&mapping.h1_head(&h, true)?).await?;
                cw.flush().await?;
                body(&mut ur, &mut cw, kind).await?;
                if kind == Body::UntilEof {
                    cw.shutdown().await?;
                    return Ok::<_, anyhow::Error>(());
                }
                if !interim {
                    break;
                }
            }
        }
        cw.shutdown().await?;
        Ok(())
    };
    // A completed response direction means no further requests can be serviced.
    tokio::pin!(requests);
    tokio::pin!(responses);
    tokio::select! { r=&mut responses=>r, r=&mut requests=>{r?;responses.await} }
}
