use crate::fingerprint::{client_hello, TlsHello, MAX_HELLO};
use anyhow::{ensure, Result};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
};

pub struct Replay<S> {
    pub inner: S,
    prefix: Vec<u8>,
    position: usize,
}
impl<S> Replay<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            position: 0,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position < self.prefix.len() {
            let n = b.remaining().min(self.prefix.len() - self.position);
            b.put_slice(&self.prefix[self.position..self.position + n]);
            self.position += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, b)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[derive(Default, Debug)]
pub struct Capture {
    pub bytes: Vec<u8>,
    done: bool,
}
pub struct Tap<S> {
    pub inner: S,
    pub capture: Arc<Mutex<Capture>>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, b)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, b) {
            Poll::Ready(Ok(n)) => {
                let mut c = self.capture.lock().unwrap();
                if !c.done {
                    let take = n.min(MAX_HELLO - c.bytes.len());
                    c.bytes.extend_from_slice(&b[..take]);
                    c.done =
                        matches!(client_hello(&c.bytes), Ok(Some(_))) || c.bytes.len() == MAX_HELLO;
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
pub async fn read_hello(stream: &mut TcpStream) -> Result<(Vec<u8>, TlsHello)> {
    let mut bytes = vec![];
    loop {
        let mut h = [0; 5];
        stream.read_exact(&mut h).await?;
        ensure!(h[0] == 22, "expected TLS handshake");
        let n = u16::from_be_bytes([h[3], h[4]]) as usize;
        ensure!(
            n <= 18432 && bytes.len() + n + 5 <= MAX_HELLO,
            "ClientHello too large"
        );
        bytes.extend(h);
        let old = bytes.len();
        bytes.resize(old + n, 0);
        stream.read_exact(&mut bytes[old..]).await?;
        if let Some(hello) = client_hello(&bytes)? {
            return Ok((bytes, hello));
        }
    }
}

/// Opt-in diagnostic plaintext capture. Bounded; truncation invalidates evidence.
#[derive(Default, serde::Serialize)]
pub struct HttpCapture {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}
pub async fn write_private_evidence(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let temporary = path.with_extension("partial");
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    drop(file);
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}
impl HttpCapture {
    fn append(&mut self, bytes: &[u8]) {
        let n = bytes.len().min((1024 * 1024) - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..n]);
        self.truncated |= n != bytes.len();
    }
}
pub struct HttpTap<S> {
    pub inner: S,
    pub capture: Arc<Mutex<HttpCapture>>,
    pub on_read: bool,
}
impl<S: AsyncRead + Unpin> AsyncRead for HttpTap<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = b.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, b);
        if self.on_read && matches!(result, Poll::Ready(Ok(()))) {
            self.capture.lock().unwrap().append(&b.filled()[before..]);
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for HttpTap<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, b);
        if !self.on_read {
            if let Poll::Ready(Ok(n)) = result {
                self.capture.lock().unwrap().append(&b[..n]);
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
pub async fn connect(addr: SocketAddr, mss: Option<u32>, ttl: Option<u32>) -> Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    let s = socket2::SockRef::from(&socket);
    #[cfg(target_os = "linux")]
    if let Some(mss) = mss {
        s.set_tcp_mss(mss)?;
    }
    #[cfg(not(target_os = "linux"))]
    ensure!(mss.is_none(), "--tcp-mss currently requires Linux");
    if let Some(ttl) = ttl {
        if addr.is_ipv4() {
            s.set_ttl_v4(ttl)?
        } else {
            s.set_unicast_hops_v6(ttl)?
        }
    }
    let stream = socket.connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}
