use crate::{acl::AccessControl, auth::Authenticator, config::Config, filter::Filter};
use anyhow::Result;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Default)]
pub struct Metrics {
    pub active: AtomicU64,
    pub opened: AtomicU64,
    pub closed: AtomicU64,
    pub requests: AtomicU64,
    pub rejected: AtomicU64,
    pub auth_failures: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub inflight: AtomicU64,
    pub requests_rejected: AtomicU64,
    pub http2_connections: AtomicU64,
}

impl Metrics {
    pub fn to_html(&self) -> String {
        let mut page = String::from("<!doctype html><html><body><h1>Tinyproxy-Rust</h1><pre>");
        for (name, value) in [
            ("active_connections", &self.active),
            ("connections_opened", &self.opened),
            ("connections_closed", &self.closed),
            ("requests", &self.requests),
            ("rejected_connections", &self.rejected),
            ("authentication_failures", &self.auth_failures),
            ("client_bytes_received", &self.bytes_in),
            ("client_bytes_sent", &self.bytes_out),
            ("inflight_requests", &self.inflight),
            ("requests_rejected_capacity", &self.requests_rejected),
            ("http2_connections_opened", &self.http2_connections),
        ] {
            page.push_str(&format!("{} {}\n", name, value.load(Ordering::Relaxed)));
        }
        page.push_str("</pre></body></html>");
        page
    }
}

pub struct Runtime {
    pub config: Config,
    pub acl: AccessControl,
    pub auth: Authenticator,
    pub filter: Filter,
    pub metrics: Arc<Metrics>,
    pub tasks: TaskTracker,
    pub shutdown: CancellationToken,
    pub force_shutdown: CancellationToken,
    pub requests: Arc<Semaphore>,
    pub tls: Option<TlsAcceptor>,
}

impl Runtime {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            acl: AccessControl::new(&config)?,
            auth: Authenticator::new(&config),
            filter: Filter::new(&config)?,
            tls: crate::tls::acceptor(&config)?,
            requests: Arc::new(Semaphore::new(config.max_inflight_requests)),
            config,
            metrics: Arc::new(Metrics::default()),
            tasks: TaskTracker::new(),
            shutdown: CancellationToken::new(),
            force_shutdown: CancellationToken::new(),
        })
    }
}

/// Hyper's HTTP/2 stream and upgrade drivers must also participate in draining.
#[derive(Clone)]
pub struct Executor {
    pub tasks: TaskTracker,
    pub force_shutdown: CancellationToken,
}
impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    fn execute(&self, future: F) {
        let force = self.force_shutdown.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                _ = future => {},
                _ = force.cancelled() => {},
            }
        });
    }
}

/// Shared by the HTTP connection, its upstream drivers, and any CONNECT tunnel.
/// The final reference releases MaxClients, including after an HTTP upgrade.
pub struct ConnectionGuard {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<Metrics>,
    _started: Instant,
}

impl ConnectionGuard {
    pub fn new(permit: OwnedSemaphorePermit, metrics: Arc<Metrics>) -> Self {
        metrics.opened.fetch_add(1, Ordering::Relaxed);
        metrics.active.fetch_add(1, Ordering::Relaxed);
        Self { _permit: permit, metrics, _started: Instant::now() }
    }
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.active.fetch_sub(1, Ordering::Relaxed);
        self.metrics.closed.fetch_add(1, Ordering::Relaxed);
    }
}
