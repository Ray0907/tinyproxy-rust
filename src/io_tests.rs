use crate::protocol;
use crate::runtime::Metrics;
use crate::transport::{Activity, ActivityIo};
use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Writes {
    data: Vec<u8>,
    scalar: usize,
    vectored: usize,
    flushes: usize,
    shutdowns: usize,
    pending: bool,
    error: bool,
    limit: usize,
}

struct Mock {
    input: VecDeque<u8>,
    writes: Arc<Mutex<Writes>>,
    efficient: bool,
}

impl Mock {
    fn new(input: &[u8], efficient: bool) -> (Self, Arc<Mutex<Writes>>) {
        let writes = Arc::new(Mutex::new(Writes {
            limit: 4,
            ..Writes::default()
        }));
        (
            Self {
                input: input.iter().copied().collect(),
                writes: writes.clone(),
                efficient,
            },
            writes,
        )
    }
}

impl AsyncRead for Mock {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        for _ in 0..buf.remaining().min(self.input.len()).min(3) {
            buf.put_slice(&[self.input.pop_front().unwrap()]);
        }
        Poll::Ready(Ok(()))
    }
}

fn write_slices(
    writes: &mut Writes,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
) -> Poll<io::Result<usize>> {
    if writes.pending {
        cx.waker().wake_by_ref();
        return Poll::Pending;
    }
    if writes.error {
        return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
    }
    let mut count = 0;
    for buf in bufs {
        let n = buf.len().min(writes.limit - count);
        writes.data.extend_from_slice(&buf[..n]);
        count += n;
        if count == writes.limit {
            break;
        }
    }
    Poll::Ready(Ok(count))
}

impl AsyncWrite for Mock {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut writes = self.writes.lock().unwrap();
        writes.scalar += 1;
        write_slices(&mut writes, cx, &[IoSlice::new(buf)])
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if !self.efficient {
            let buf = bufs.iter().find(|b| !b.is_empty());
            return self.poll_write(cx, buf.map(|b| &b[..]).unwrap_or(&[]));
        }
        let mut writes = self.writes.lock().unwrap();
        writes.vectored += 1;
        write_slices(&mut writes, cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.efficient
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.writes.lock().unwrap().flushes += 1;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.writes.lock().unwrap().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}

fn activity() -> Activity {
    Activity::new(Duration::from_secs(60))
}

#[test]
fn vectored_partial_write_counts_only_accepted_bytes_once() {
    let (mock, writes) = Mock::new(&[], true);
    let metrics = Arc::new(Metrics::default());
    let mut io = ActivityIo::new(mock, activity(), Some(metrics.clone()));
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    let bufs = [
        IoSlice::new(b""),
        IoSlice::new(b"ab"),
        IoSlice::new(b"cdef"),
    ];
    assert!(io.is_write_vectored());
    assert!(matches!(
        Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs),
        Poll::Ready(Ok(4))
    ));
    let state = writes.lock().unwrap();
    assert_eq!(state.data, b"abcd");
    assert_eq!(state.vectored, 1);
    assert_eq!(state.scalar, 0);
    assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 4);
}

#[test]
fn pending_error_and_zero_writes_do_not_count_as_traffic() {
    let (mock, writes) = Mock::new(&[], true);
    let metrics = Arc::new(Metrics::default());
    let mut io = ActivityIo::new(mock, activity(), Some(metrics.clone()));
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    let bufs = [IoSlice::new(b"abc")];
    writes.lock().unwrap().pending = true;
    assert!(Pin::new(&mut io)
        .poll_write_vectored(&mut cx, &bufs)
        .is_pending());
    {
        let mut state = writes.lock().unwrap();
        state.pending = false;
        state.error = true;
    }
    assert!(matches!(
        Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs),
        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe
    ));
    {
        let mut state = writes.lock().unwrap();
        state.error = false;
        state.limit = 0;
    }
    assert!(matches!(
        Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs),
        Poll::Ready(Ok(0))
    ));
    assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 0);
    assert!(writes.lock().unwrap().data.is_empty());
}

#[test]
fn non_vectored_capability_and_fallback_are_preserved() {
    let (mock, writes) = Mock::new(&[], false);
    let metrics = Arc::new(Metrics::default());
    let mut io = ActivityIo::new(mock, activity(), Some(metrics.clone()));
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    assert!(!io.is_write_vectored());
    let bufs = [IoSlice::new(b""), IoSlice::new(b"ab"), IoSlice::new(b"cd")];
    assert!(matches!(
        Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs),
        Poll::Ready(Ok(2))
    ));
    assert_eq!(writes.lock().unwrap().data, b"ab");
    assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 2);
}

#[test]
fn empty_vectors_flush_and_shutdown_do_not_add_bytes() {
    let (mock, writes) = Mock::new(&[], true);
    let metrics = Arc::new(Metrics::default());
    let mut io = ActivityIo::new(mock, activity(), Some(metrics.clone()));
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(
        Pin::new(&mut io).poll_write_vectored(&mut cx, &[]),
        Poll::Ready(Ok(0))
    ));
    assert!(matches!(
        Pin::new(&mut io).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        Pin::new(&mut io).poll_shutdown(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 0);
    let state = writes.lock().unwrap();
    assert_eq!((state.flushes, state.shutdowns), (1, 1));
}

#[tokio::test]
async fn detection_and_nested_activity_preserve_vectored_io_and_all_prefix_bytes() {
    for (input, expected_h2) in [
        (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nextra".as_slice(), true),
        (b"GET / HTTP/1.1\r\n".as_slice(), false),
    ] {
        let (mock, writes) = Mock::new(input, true);
        let inner_metrics = Arc::new(Metrics::default());
        let outer_metrics = Arc::new(Metrics::default());
        let inner = ActivityIo::new(mock, activity(), Some(inner_metrics.clone()));
        let (h2, prefixed) = protocol::detect(Box::new(inner)).await.unwrap();
        assert_eq!(h2, expected_h2);
        let mut io = ActivityIo::new(prefixed, activity(), Some(outer_metrics.clone()));
        assert!(io.is_write_vectored());
        let mut received = Vec::new();
        io.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, input);
        assert_eq!(
            inner_metrics.bytes_in.load(Ordering::Relaxed),
            input.len() as u64
        );
        assert_eq!(
            outer_metrics.bytes_in.load(Ordering::Relaxed),
            input.len() as u64
        );
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        let bufs = [IoSlice::new(b"ab"), IoSlice::new(b"cd")];
        assert!(matches!(
            Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(writes.lock().unwrap().vectored, 1);
        assert_eq!(inner_metrics.bytes_out.load(Ordering::Relaxed), 4);
        assert_eq!(outer_metrics.bytes_out.load(Ordering::Relaxed), 4);
    }
}

#[tokio::test]
async fn detection_does_not_invent_vectored_support() {
    let (mock, _) = Mock::new(b"GET / HTTP/1.1\r\n", false);
    let (_, io) = protocol::detect(Box::new(mock)).await.unwrap();
    assert!(!io.is_write_vectored());
}
