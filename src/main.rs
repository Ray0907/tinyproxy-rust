use anyhow::Result;
use clap::{ArgAction, Parser};
use log::info;
use std::path::PathBuf;
use tinyproxy_rust::{config::Config, runtime::Runtime, server::ProxyServer};

#[derive(Parser)]
#[command(version, about, disable_version_flag = true)]
struct Args {
    #[arg(short = 'c', long, default_value = "/etc/tinyproxy/tinyproxy.conf")]
    config: PathBuf,
    #[arg(long, help = "Validate configuration, ACLs and filters without binding a socket")]
    check: bool,
    #[arg(long)]
    debug: bool,
    #[arg(short = 'd', long = "foreground", help = "Run in foreground (the default)")]
    _foreground: bool,
    #[arg(short = 'v', long = "version", action = ArgAction::Version)]
    _version: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::from_file(&args.config)?;
    let level = if args.debug { log::LevelFilter::Debug } else { config.log_level.parse()? };
    env_logger::Builder::from_default_env().filter_level(level).try_init()?;
    if args.check {
        Runtime::new(config)?;
        println!("Configuration and policy validation passed");
        return Ok(());
    }
    let server = ProxyServer::bind(config).await?;
    for address in server.local_addresses()? {
        info!("Listening on {}", address);
    }
    let shutdown = server.shutdown_token();
    let signal_task = tokio::spawn(async move {
        if let Err(error) = shutdown_signal().await {
            log::error!("Signal handler failed: {}", error);
        }
        shutdown.cancel();
    });
    let result = server.run().await;
    signal_task.abort();
    result
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}
