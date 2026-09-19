use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

/// Preserve every sniffed byte, including fragmented HTTP/2 prefaces. The caller
/// supplies a total deadline, not a per-byte deadline. This is not h2c Upgrade.
pub async fn detect(mut io: BoxIo) -> io::Result<(bool, BoxIo)> {
    let mut prefix = Vec::with_capacity(H2_PREFACE.len());
    for expected in H2_PREFACE {
        let actual = io.read_u8().await?;
        prefix.push(actual);
        if actual != *expected {
            return Ok((
                false,
                Box::new(PrefixedIo {
                    io,
                    prefix,
                    offset: 0,
                }),
            ));
        }
    }
    Ok((
        true,
        Box::new(PrefixedIo {
            io,
            prefix,
            offset: 0,
        }),
    ))
}

struct PrefixedIo {
    io: BoxIo,
    prefix: Vec<u8>,
    offset: usize,
}

impl AsyncRead for PrefixedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && buf.remaining() > 0 {
            let count = (self.prefix.len() - self.offset).min(buf.remaining());
            buf.put_slice(&self.prefix[self.offset..self.offset + count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
