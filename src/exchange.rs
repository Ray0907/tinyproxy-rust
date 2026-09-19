use crate::runtime::{ConnectionGuard, Metrics};
use crate::transport::Activity;
use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::error::Error;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type Body = UnsyncBoxBody<Bytes, BoxError>;

/// One HTTP exchange or CONNECT stream. A busy sibling cannot extend this idle
/// deadline. Hold capacity until both response body and upstream task are gone.
pub struct Exchange {
    pub activity: Activity,
    pub cancelled: CancellationToken,
    _permit: OwnedSemaphorePermit,
    _connection: Arc<ConnectionGuard>,
    metrics: Arc<Metrics>,
}

impl Exchange {
    pub fn new(permit: OwnedSemaphorePermit, connection: Arc<ConnectionGuard>, metrics: Arc<Metrics>, cancelled: CancellationToken, idle: Duration) -> Arc<Self> {
        metrics.inflight.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { activity: Activity::new(idle), cancelled, _permit: permit, _connection: connection, metrics })
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        self.cancelled.cancel();
        self.metrics.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Dropping a reset/cancelled service future immediately stops its upstream.
/// Disarm only when ownership has moved to a response body or tunnel task.
pub struct CancelOnDrop(pub Option<Arc<Exchange>>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(state) = &self.0 {
            state.cancelled.cancel();
        }
    }
}

struct TrackedBody {
    inner: Body,
    state: Arc<Exchange>,
    cancel_on_drop: bool,
}

pub fn track<B>(body: B, state: Arc<Exchange>, cancel_on_drop: bool) -> Body
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    TrackedBody { inner: body.map_err(Into::into).boxed_unsync(), state, cancel_on_drop }.boxed_unsync()
}

impl HttpBody for TrackedBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match result {
            Poll::Ready(Some(Ok(mut frame))) => {
                if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                    self.state.activity.touch();
                }
                // Trailers must not reintroduce proxy credentials, routing, or
                // hop-by-hop fields after the initial header sanitization.
                if let Some(trailers) = frame.trailers_mut() {
                    if crate::connection::strip_hop_by_hop(trailers).is_err() {
                        return Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid HTTP trailers").into())));
                    }
                    for name in ["host", "content-length", "authorization", "cookie"] {
                        trailers.remove(name);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }
    fn is_end_stream(&self) -> bool { self.inner.is_end_stream() }
    fn size_hint(&self) -> SizeHint { self.inner.size_hint() }
}

impl Drop for TrackedBody {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.state.cancelled.cancel();
        }
    }
}
