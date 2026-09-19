use anyhow::{ensure, Result};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tinyproxy_rust::{config::Config, server::ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

async fn header(stream: &mut TcpStream) -> Result<String> {
    timeout(Duration::from_secs(4), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await?);
            ensure!(bytes.len() <= 65536, "Header exceeds test limit");
        }
        Ok(String::from_utf8(bytes)?)
    })
    .await?
}

async fn tunnel(proxy: SocketAddr, target: SocketAddr) -> Result<TcpStream> {
    let mut client = TcpStream::connect(proxy).await?;
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    client.write_all(request.as_bytes()).await?;
    ensure!(header(&mut client).await?.starts_with("HTTP/1.1 200"));
    Ok(client)
}

fn configuration(port: u16) -> Config {
    Config {
        port: 0,
        timeout: 1,
        connect_timeout: 2,
        shutdown_timeout: 2,
        connect_ports: vec![port],
        ..Config::default()
    }
}

#[tokio::test]
async fn idle_tunnel_expires_and_releases_all_sockets() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = listener.local_addr()?;
    let proxy = ProxyServer::bind(configuration(destination.port())).await?;
    let address = proxy.local_addresses()?[0];
    let shutdown = proxy.shutdown_token();
    let metrics = proxy.metrics();
    let task = tokio::spawn(proxy.run());
    let mut client = tunnel(address, destination).await?;
    let (mut upstream, _) = listener.accept().await?;
    assert!(timeout(Duration::from_secs(4), client.read_u8())
        .await?
        .is_err());
    assert!(timeout(Duration::from_secs(2), upstream.read_u8())
        .await?
        .is_err());
    shutdown.cancel();
    timeout(Duration::from_secs(4), task).await???;
    assert_eq!(metrics.active.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn active_tunnel_outlives_idle_timeout_in_both_directions() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = listener.local_addr()?;
    let proxy = ProxyServer::bind(configuration(destination.port())).await?;
    let address = proxy.local_addresses()?[0];
    let shutdown = proxy.shutdown_token();
    let task = tokio::spawn(proxy.run());
    let mut client = tunnel(address, destination).await?;
    let (mut upstream, _) = listener.accept().await?;
    for index in 0..8u8 {
        sleep(Duration::from_millis(250)).await;
        if index % 2 == 0 {
            client.write_all(&[index]).await?;
            assert_eq!(
                timeout(Duration::from_secs(2), upstream.read_u8()).await??,
                index
            );
        } else {
            upstream.write_all(&[index]).await?;
            assert_eq!(
                timeout(Duration::from_secs(2), client.read_u8()).await??,
                index
            );
        }
    }
    drop(client);
    drop(upstream);
    shutdown.cancel();
    timeout(Duration::from_secs(4), task).await???;
    Ok(())
}

#[tokio::test]
async fn ipv6_authorities_work_for_http_and_connect() -> Result<()> {
    let listener = TcpListener::bind("[::1]:0").await?;
    let destination = listener.local_addr()?;
    let origin = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request = header(&mut stream).await?;
        assert!(request.starts_with("GET /ipv6 HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("host: {destination}\r\n")));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        drop(stream);
        let (mut stream, _) = listener.accept().await?;
        assert_eq!(stream.read_u8().await?, b'a');
        stream.write_all(b"b").await?;
        Ok::<_, anyhow::Error>(())
    });
    let proxy = ProxyServer::bind(configuration(destination.port())).await?;
    let address = proxy.local_addresses()?[0];
    let shutdown = proxy.shutdown_token();
    let task = tokio::spawn(proxy.run());
    let mut client = TcpStream::connect(address).await?;
    let request = format!("GET http://{destination}/ipv6 HTTP/1.1\r\nHost: {destination}\r\n\r\n");
    client.write_all(request.as_bytes()).await?;
    assert!(header(&mut client).await?.starts_with("HTTP/1.1 200"));
    let mut body = [0; 2];
    timeout(Duration::from_secs(2), client.read_exact(&mut body)).await??;
    assert_eq!(&body, b"ok");
    drop(client);
    let mut client = tunnel(address, destination).await?;
    client.write_all(b"a").await?;
    assert_eq!(
        timeout(Duration::from_secs(2), client.read_u8()).await??,
        b'b'
    );
    timeout(Duration::from_secs(4), origin).await???;
    drop(client);
    shutdown.cancel();
    timeout(Duration::from_secs(4), task).await???;
    Ok(())
}

#[tokio::test]
async fn shutdown_drains_a_tunnel_that_finishes_before_the_deadline() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = listener.local_addr()?;
    let proxy = ProxyServer::bind(configuration(destination.port())).await?;
    let address = proxy.local_addresses()?[0];
    let shutdown = proxy.shutdown_token();
    let metrics = proxy.metrics();
    let task = tokio::spawn(proxy.run());
    let mut client = tunnel(address, destination).await?;
    let (mut upstream, _) = listener.accept().await?;
    shutdown.cancel();
    sleep(Duration::from_millis(50)).await;
    client.write_all(b"a").await?;
    assert_eq!(
        timeout(Duration::from_secs(2), upstream.read_u8()).await??,
        b'a'
    );
    client.shutdown().await?;
    assert!(timeout(Duration::from_secs(2), upstream.read_u8())
        .await?
        .is_err());
    upstream.write_all(b"b").await?;
    upstream.shutdown().await?;
    assert_eq!(
        timeout(Duration::from_secs(2), client.read_u8()).await??,
        b'b'
    );
    timeout(Duration::from_secs(4), task).await???;
    assert_eq!(metrics.active.load(Ordering::Relaxed), 0);
    Ok(())
}
