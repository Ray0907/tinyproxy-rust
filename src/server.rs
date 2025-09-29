use crate::config::Config;
use anyhow::Result;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::Duration;

use crate::connection::ConnectionHandler;
use crate::stats::Stats;

#[derive(Clone)]
pub struct ProxyServer {
    config: Arc<Config>,
    stats: Arc<RwLock<Stats>>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<()>>>,
    connection_semaphore: Arc<Semaphore>,
}

impl ProxyServer {
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let stats = Arc::new(RwLock::new(Stats::new()));
        let connection_semaphore = Arc::new(Semaphore::new(config.max_clients));

        Ok(Self {
            config,
            stats,
            shutdown_tx,
            shutdown_rx: Arc::new(tokio::sync::Mutex::new(shutdown_rx)),
            connection_semaphore,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let addresses = self.config.get_listen_addresses();
        let mut listeners = Vec::new();

        // Bind to all specified addresses
        for addr in addresses {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    info!("Listening on {}", addr);
                    listeners.push(listener);
                }
                Err(e) => {
                    error!("Failed to bind to {}: {}", addr, e);
                    return Err(e.into());
                }
            }
        }

        if listeners.is_empty() {
            return Err(anyhow::anyhow!("No listeners could be created"));
        }

        // Start the accept loop for each listener
        let mut tasks = Vec::new();

        for listener in listeners {
            let server = self.clone();
            let task = tokio::spawn(async move {
                server.accept_loop(listener).await;
            });
            tasks.push(task);
        }

        // Wait for shutdown signal
        let mut shutdown_rx = self.shutdown_rx.lock().await;
        shutdown_rx.recv().await;

        info!("Shutdown signal received, waiting for connections to close...");

        // Cancel all accept loops
        for task in tasks {
            task.abort();
        }

        // Wait a bit for existing connections to finish
        tokio::time::sleep(Duration::from_secs(5)).await;

        info!("Server shutdown complete");
        Ok(())
    }

    async fn accept_loop(&self, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New connection from {}", addr);

                    // Check if we can accept more connections
                    let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                "Connection limit reached, rejecting connection from {}",
                                addr
                            );
                            continue;
                        }
                    };

                    // Update connection stats
                    {
                        let mut stats = self.stats.write().await;
                        stats.connections_opened += 1;
                        stats.active_connections += 1;
                    }

                    // Spawn a task to handle the connection
                    let handler = ConnectionHandler::new(
                        stream,
                        addr,
                        self.config.clone(),
                        self.stats.clone(),
                    );

                    let stats_clone = self.stats.clone();
                    tokio::spawn(async move {
                        let start_time = Instant::now();

                        if let Err(e) = handler.handle().await {
                            error!("Connection handler error: {}", e);
                        }

                        // Update stats when connection is closed
                        {
                            let mut stats = stats_clone.write().await;
                            stats.active_connections -= 1;
                            stats.connections_closed += 1;
                            stats.total_connection_time += start_time.elapsed();
                        }

                        // Release the connection permit
                        drop(permit);
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    // Brief pause to avoid busy loop on persistent accept errors
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        info!("Initiating server shutdown...");
        let _ = self.shutdown_tx.send(()).await;
    }

    pub async fn get_stats(&self) -> Stats {
        let stats = self.stats.read().await;
        stats.clone()
    }
}
