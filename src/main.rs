use anyhow::Result;
use clap::{Arg, Command};
use log::{error, info};
use std::process;
use std::sync::Arc;
use tokio::signal;

mod acl;
mod auth;
mod config;
mod connection;
mod error;
mod filter;
mod proxy;
mod server;
mod stats;
mod utils;

use config::Config;
use server::ProxyServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse command line arguments
    let matches = Command::new("tinyproxy-rust")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A fast lightweight HTTP/HTTPS proxy daemon implemented in Rust")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("/etc/tinyproxy/tinyproxy.conf"),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("Run as daemon")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .help("Display version information")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("Enable debug mode")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    if matches.get_flag("version") {
        println!("tinyproxy-rust {}", env!("CARGO_PKG_VERSION"));
        println!("A fast lightweight HTTP/HTTPS proxy daemon implemented in Rust");
        return Ok(());
    }

    // Load configuration
    let config_file = matches.get_one::<String>("config").unwrap();
    let mut config = match Config::from_file(config_file) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration from {}: {}", config_file, e);
            process::exit(1);
        }
    };

    // Override debug mode if specified
    if matches.get_flag("debug") {
        config.debug = true;
    }

    // Set up logging level based on debug mode
    if config.debug {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }

    info!("Starting tinyproxy-rust v{}", env!("CARGO_PKG_VERSION"));
    info!("Configuration loaded from: {}", config_file);

    // If daemon mode is requested, daemonize the process
    if matches.get_flag("daemon") || config.daemon {
        info!("Running in daemon mode");
        daemonize()?;
    }

    // Create and start the proxy server
    let config = Arc::new(config);
    let server = ProxyServer::new(config.clone()).await?;

    // Set up signal handling
    let server_clone = server.clone();
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Received interrupt signal, shutting down gracefully...");
                server_clone.shutdown().await;
            }
            Err(err) => {
                error!("Unable to listen for shutdown signal: {}", err);
            }
        }
    });

    // Start the server
    match server.run().await {
        Ok(()) => {
            info!("Proxy server shut down gracefully");
        }
        Err(e) => {
            error!("Proxy server error: {}", e);
            process::exit(1);
        }
    }

    Ok(())
}

#[cfg(unix)]
fn daemonize() -> Result<()> {
    #[allow(unused_imports)]
    use nix::sys::stat::Mode;
    use nix::unistd::{fork, setsid, ForkResult};
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    // First fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            process::exit(0);
        }
        Ok(ForkResult::Child) => {}
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to fork: {}", e));
        }
    }

    // Create new session
    setsid().map_err(|e| anyhow::anyhow!("Failed to create new session: {}", e))?;

    // Second fork
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            process::exit(0);
        }
        Ok(ForkResult::Child) => {}
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to fork: {}", e));
        }
    }

    // Change working directory to root
    std::env::set_current_dir("/")
        .map_err(|e| anyhow::anyhow!("Failed to change directory to /: {}", e))?;

    // Redirect standard file descriptors to /dev/null
    let null_fd = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| anyhow::anyhow!("Failed to open /dev/null: {}", e))?;

    let null_fd = null_fd.as_raw_fd();

    unsafe {
        libc::dup2(null_fd, libc::STDIN_FILENO);
        libc::dup2(null_fd, libc::STDOUT_FILENO);
        libc::dup2(null_fd, libc::STDERR_FILENO);
    }

    Ok(())
}

#[cfg(not(unix))]
fn daemonize() -> Result<()> {
    warn!("Daemon mode is not supported on this platform");
    Ok(())
}
