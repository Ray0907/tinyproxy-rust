use crate::runtime::Metrics;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{lookup_host, TcpSocket, TcpStream};
use tokio::time::{sleep_until, timeout, Instant};

struct ActivityState { started: Instant, last_millis: AtomicU64 }

#[derive(Clone)]
pub struct Activity { state: Arc<ActivityState>, idle: Duration }

impl Activity {
    pub fn new(idle: Duration) -> Self {
        Self { state: Arc::new(ActivityState { started: Instant::now(), last_millis: AtomicU64::new(0) }), idle }
    }
    pub(crate) fn touch(&self) {
        let elapsed = self.state.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.state.last_millis.fetch_max(elapsed, Ordering::Relaxed);
    }
    fn deadline(&self) -> Instant {
        self.state.started + Duration::from_millis(self.state.last_millis.load(Ordering::Relaxed)) + self.idle
    }
    /// Progress in either direction resets idle time, not maximum lifetime.
    pub async fn expired(&self) {
        loop {
            sleep_until(self.deadline()).await;
            if Instant::now() >= self.deadline() { return; }
        }
    }
}

pub struct ActivityIo<T> { inner: T, activity: Activity, metrics: Option<Arc<Metrics>> }
impl<T> ActivityIo<T> {
    pub fn new(inner: T, activity: Activity, metrics: Option<Arc<Metrics>>) -> Self {
        Self { inner, activity, metrics }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let count = buf.filled().len() - before;
            if count > 0 {
                self.activity.touch();
                if let Some(metrics) = &self.metrics { metrics.bytes_in.fetch_add(count as u64, Ordering::Relaxed); }
            }
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityIo<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = &result {
            if *count > 0 {
                self.activity.touch();
                if let Some(metrics) = &self.metrics { metrics.bytes_out.fetch_add(*count as u64, Ordering::Relaxed); }
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
}

pub async fn connect(host: &str, port: u16, bind: Option<IpAddr>, seconds: u64) -> io::Result<TcpStream> {
    timeout(Duration::from_secs(seconds), async {
        let Some(bind) = bind else { return TcpStream::connect((host, port)).await; };
        let addresses = lookup_host((host, port)).await?;
        let mut last_error = io::Error::new(io::ErrorKind::AddrNotAvailable, "No address matches Bind family");
        for address in addresses {
            if address.is_ipv4() != bind.is_ipv4() { continue; }
            let socket = if bind.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
            socket.bind(SocketAddr::new(bind, 0))?;
            match socket.connect(address).await { Ok(stream) => return Ok(stream), Err(error) => last_error = error }
        }
        Err(last_error)
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS/connect deadline exceeded"))?
}
