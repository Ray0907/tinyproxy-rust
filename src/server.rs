use crate::config::Config;
use crate::connection;
use crate::runtime::{ConnectionGuard, Metrics, Runtime};
use anyhow::Result;
use log::{debug, warn};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

pub struct ProxyServer {
    listeners: Vec<TcpListener>,
    runtime: Arc<Runtime>,
}

impl ProxyServer {
    /// Bind only after all policy files and rules have been validated.
    pub async fn bind(config: Config) -> Result<Self> {
        let runtime = Arc::new(Runtime::new(config)?);
        let mut listeners = Vec::new();
        for address in &runtime.config.listen_addresses {
            listeners.push(TcpListener::bind(SocketAddr::new(*address, runtime.config.port)).await?);
        }
        Ok(Self { listeners, runtime })
    }

    pub fn local_addresses(&self) -> Result<Vec<SocketAddr>> {
        self.listeners.iter().map(|listener| listener.local_addr().map_err(Into::into)).collect()
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.runtime.shutdown.clone()
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.runtime.metrics.clone()
    }

    pub async fn run(self) -> Result<()> {
        let runtime = self.runtime;
        let semaphore = Arc::new(Semaphore::new(runtime.config.max_clients));
        let mut acceptors = JoinSet::new();
        for listener in self.listeners {
            let runtime = runtime.clone();
            let semaphore = semaphore.clone();
            acceptors.spawn(async move {
                loop {
                    let accepted = tokio::select! {
                        biased;
                        _ = runtime.shutdown.cancelled() => break,
                        result = listener.accept() => result,
                    };
                    let (stream, address) = match accepted {
                        Ok(pair) => pair,
                        Err(error) => {
                            warn!("Accept failed: {}", error.kind());
                            tokio::select! {
                                _ = runtime.shutdown.cancelled() => break,
                                _ = sleep(Duration::from_millis(100)) => {},
                            }
                            continue;
                        }
                    };
                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        runtime.metrics.rejected.fetch_add(1, Ordering::Relaxed);
                        drop(stream);
                        continue;
                    };
                    let guard = Arc::new(ConnectionGuard::new(permit, runtime.metrics.clone()));
                    let connection_runtime = runtime.clone();
                    runtime.tasks.spawn(async move {
                        if connection::serve(stream, address, connection_runtime, guard).await.is_err() {
                            // Do not log raw requests, URLs, headers, or credentials.
                            debug!("Client connection ended with a protocol or I/O error");
                        }
                    });
                }
            });
        }
        runtime.shutdown.cancelled().await;
        while let Some(result) = acceptors.join_next().await {
            result?;
        }
        runtime.tasks.close();
        if timeout(Duration::from_secs(runtime.config.shutdown_timeout), runtime.tasks.wait()).await.is_err() {
            runtime.force_shutdown.cancel();
            runtime.tasks.wait().await;
        }
        Ok(())
    }
}
