use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tinyproxy_rust::{
    config::{BasicAuthConfig, Config},
    runtime::Metrics,
    server::ProxyServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

struct Running {
    address: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<Result<()>>,
    metrics: Arc<Metrics>,
}

impl Running {
    async fn start(config: Config) -> Result<Self> {
        let server = ProxyServer::bind(config).await?;
        let address = server.local_addresses()?[0];
        let shutdown = server.shutdown_token();
        let metrics = server.metrics();
        Ok(Self {
            address,
            shutdown,
            task: tokio::spawn(server.run()),
            metrics,
        })
    }

    async fn stop(self) -> Result<()> {
        self.shutdown.cancel();
        timeout(Duration::from_secs(4), self.task).await???;
        Ok(())
    }
}

fn config() -> Config {
    Config {
        port: 0,
        timeout: 3,
        header_timeout: 2,
        connect_timeout: 2,
        shutdown_timeout: 1,
        ..Config::default()
    }
}

async fn read_header(stream: &mut TcpStream) -> Result<String> {
    timeout(Duration::from_secs(4), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let byte = stream.read_u8().await?;
            bytes.push(byte);
            if bytes.len() > 65536 {
                bail!("test header exceeded limit");
            }
        }
        Ok(String::from_utf8(bytes)?)
    })
    .await?
}

async fn read_response(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let header = read_header(stream).await?;
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    timeout(Duration::from_secs(4), stream.read_exact(&mut body)).await??;
    Ok((header, body))
}

async fn origin(response: &'static str) -> Result<(SocketAddr, JoinHandle<Result<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let header = read_header(&mut stream).await?;
        stream.write_all(response.as_bytes()).await?;
        Ok(header)
    });
    Ok((address, task))
}

async fn echo_origin() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .keep_alive(false)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|request: Request<Incoming>| async move {
                    let bytes = request.into_body().collect().await?.to_bytes();
                    Ok::<_, hyper::Error>(Response::new(Full::<Bytes>::new(bytes)))
                }),
            )
            .await?;
        Ok(())
    });
    Ok((address, task))
}

#[tokio::test]
async fn credentials_and_hop_headers_are_not_forwarded_but_origin_auth_is() -> Result<()> {
    let (destination, origin_task) = origin("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: X-Response, close\r\nX-Response: remove\r\nProxy-Authenticate: Basic realm=bad\r\nWWW-Authenticate: Basic realm=site\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nok").await?;
    let mut configuration = config();
    configuration.basic_auth.push(BasicAuthConfig {
        username: "user".into(),
        password: "pass".into(),
    });
    let proxy = Running::start(configuration).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    client.write_all(format!("GET http://{destination}/path?q=1 HTTP/1.1\r\nHost: wrong.invalid\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nAuthorization: Bearer origin-token\r\nConnection: X-Hop\r\nConnection: X-Extra\r\nX-Hop: remove\r\nX-Extra: remove\r\n\r\n").as_bytes()).await?;
    let (response, body) = read_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert_eq!(body, b"ok");
    let forwarded = origin_task.await??.to_ascii_lowercase();
    assert!(forwarded.starts_with("get /path?q=1 http/1.1\r\n"));
    assert!(forwarded.contains(&format!("host: {destination}\r\n")));
    assert!(!forwarded.contains("proxy-authorization"));
    assert!(!forwarded.contains("x-hop:"));
    assert!(!forwarded.contains("x-extra:"));
    assert!(forwarded.contains("authorization: bearer origin-token"));
    let response = response.to_ascii_lowercase();
    assert!(!response.contains("x-response:"));
    assert!(!response.contains("proxy-authenticate:"));
    assert!(response.contains("www-authenticate:"));
    assert_eq!(response.matches("set-cookie:").count(), 2);
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn each_keep_alive_request_is_authenticated() -> Result<()> {
    let (destination, origin_task) =
        origin("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
    let mut configuration = config();
    configuration.basic_auth.push(BasicAuthConfig {
        username: "user".into(),
        password: "pass".into(),
    });
    let proxy = Running::start(configuration).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    let path = format!("GET http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\n");
    client
        .write_all(format!("{path}Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n").as_bytes())
        .await?;
    assert!(read_response(&mut client)
        .await?
        .0
        .starts_with("HTTP/1.1 200"));
    origin_task.await??;
    client.write_all(format!("{path}\r\n").as_bytes()).await?;
    let (header, body) = read_response(&mut client).await?;
    assert!(header.starts_with("HTTP/1.1 407"));
    assert!(header.to_ascii_lowercase().contains("proxy-authenticate:"));
    assert_eq!(body, b"Proxy authentication required\n");
    assert_eq!(proxy.metrics.requests.load(Ordering::Relaxed), 2);
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn each_keep_alive_request_can_route_to_a_different_origin() -> Result<()> {
    let (first, first_task) =
        origin("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\na").await?;
    let (second, second_task) =
        origin("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nb").await?;
    let proxy = Running::start(config()).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    for (destination, expected) in [(first, b'a'), (second, b'b')] {
        client
            .write_all(
                format!("GET http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        assert_eq!(read_response(&mut client).await?.1, vec![expected]);
    }
    first_task.await??;
    second_task.await??;
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn filters_are_loaded_once_and_apply_to_each_request() -> Result<()> {
    let mut file = NamedTempFile::new()?;
    writeln!(file, "localhost")?;
    let (destination, origin_task) =
        origin("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
    let configuration = Config {
        filter_file: Some(file.path().to_string_lossy().into()),
        ..config()
    };
    let proxy = Running::start(configuration).await?;
    drop(file);
    let mut client = TcpStream::connect(proxy.address).await?;
    client
        .write_all(
            format!("GET http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes(),
        )
        .await?;
    assert!(read_response(&mut client)
        .await?
        .0
        .starts_with("HTTP/1.1 200"));
    origin_task.await??;
    client
        .write_all(b"GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    assert!(read_response(&mut client)
        .await?
        .0
        .starts_with("HTTP/1.1 403"));
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn connect_preserves_early_bytes_and_half_close() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = listener.local_addr()?;
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        assert_eq!(received, b"hello");
        stream.write_all(b"reply:hello").await?;
        Ok::<_, anyhow::Error>(())
    });
    let configuration = Config {
        connect_ports: vec![destination.port()],
        ..config()
    };
    let proxy = Running::start(configuration).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    client
        .write_all(
            format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\nhello")
                .as_bytes(),
        )
        .await?;
    assert!(read_header(&mut client).await?.starts_with("HTTP/1.1 200"));
    client.shutdown().await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(4), client.read_to_end(&mut response)).await??;
    assert_eq!(response, b"reply:hello");
    origin_task.await??;
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn connect_keeps_its_connection_permit_until_tunnel_closes() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = listener.local_addr()?;
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        stream.read_to_end(&mut Vec::new()).await?;
        Ok::<_, anyhow::Error>(())
    });
    let configuration = Config {
        connect_ports: vec![destination.port()],
        max_clients: 1,
        ..config()
    };
    let proxy = Running::start(configuration).await?;
    let mut first = TcpStream::connect(proxy.address).await?;
    first
        .write_all(
            format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes(),
        )
        .await?;
    assert!(read_header(&mut first).await?.starts_with("HTTP/1.1 200"));
    assert_eq!(proxy.metrics.active.load(Ordering::Relaxed), 1);
    let mut second = TcpStream::connect(proxy.address).await?;
    let result = timeout(Duration::from_secs(2), second.read_u8()).await?;
    assert!(result.is_err(), "over-limit client should be disconnected");
    assert_eq!(proxy.metrics.active.load(Ordering::Relaxed), 1);
    drop(second);
    drop(first);
    origin_task.await??;
    timeout(Duration::from_secs(2), async {
        while proxy.metrics.active.load(Ordering::Relaxed) != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    proxy.stop().await
}

#[tokio::test]
async fn large_http_uploads_stream_correctly() -> Result<()> {
    let (destination, origin_task) = echo_origin().await?;
    let proxy = Running::start(config()).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    let body = vec![b'x'; 128 * 1024];
    client.write_all(format!("POST http://{destination}/upload HTTP/1.1\r\nHost: {destination}\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).await?;
    client.write_all(&body).await?;
    assert_eq!(read_response(&mut client).await?.1, body);
    origin_task.await??;
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn chunked_requests_are_decoded_and_reframed_correctly() -> Result<()> {
    let (destination, origin_task) = echo_origin().await?;
    let proxy = Running::start(config()).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    client.write_all(format!("POST http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n").as_bytes()).await?;
    assert_eq!(read_response(&mut client).await?.1, b"abcdefg");
    origin_task.await??;
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn expect_continue_does_not_deadlock_uploads() -> Result<()> {
    let (destination, origin_task) = echo_origin().await?;
    let proxy = Running::start(config()).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    client.write_all(format!("POST http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n").as_bytes()).await?;
    assert!(read_header(&mut client).await?.starts_with("HTTP/1.1 100"));
    client.write_all(b"hello").await?;
    assert_eq!(read_response(&mut client).await?.1, b"hello");
    origin_task.await??;
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn conflicting_content_lengths_are_rejected() -> Result<()> {
    let proxy = Running::start(config()).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    client.write_all(b"POST http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx").await?;
    assert!(read_header(&mut client).await?.starts_with("HTTP/1.1 400"));
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn absolute_https_is_not_sent_as_plaintext_to_the_origin() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = listener.local_addr()?;
    let proxy = Running::start(config()).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    client
        .write_all(
            format!("GET https://{destination}/ HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    assert!(read_response(&mut client)
        .await?
        .0
        .starts_with("HTTP/1.1 400"));
    assert!(timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_err());
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn source_acl_is_enforced_before_forwarding() -> Result<()> {
    let configuration = Config {
        acl_rules: vec![(false, "all".into())],
        ..config()
    };
    let proxy = Running::start(configuration).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    assert!(read_response(&mut client)
        .await?
        .0
        .starts_with("HTTP/1.1 403"));
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn connect_port_zero_disables_tunnels() -> Result<()> {
    let configuration = Config {
        connect_ports: Vec::new(),
        ..config()
    };
    let proxy = Running::start(configuration).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    client
        .write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
        .await?;
    assert!(read_response(&mut client)
        .await?
        .0
        .starts_with("HTTP/1.1 403"));
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn shutdown_forces_idle_tunnels_closed_after_grace_period() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = listener.local_addr()?;
    let configuration = Config {
        connect_ports: vec![destination.port()],
        timeout: 10,
        shutdown_timeout: 1,
        ..config()
    };
    let proxy = Running::start(configuration).await?;
    let mut client = TcpStream::connect(proxy.address).await?;
    client
        .write_all(
            format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes(),
        )
        .await?;
    assert!(read_header(&mut client).await?.starts_with("HTTP/1.1 200"));
    let (mut upstream, _) = listener.accept().await?;
    proxy.shutdown.cancel();
    let metrics = proxy.metrics.clone();
    proxy.stop().await?;
    assert_eq!(metrics.active.load(Ordering::Relaxed), 0);
    assert!(client.read_u8().await.is_err());
    assert!(upstream.read_u8().await.is_err());
    Ok(())
}

#[tokio::test]
async fn header_deadline_is_not_reset_by_trickled_bytes() -> Result<()> {
    let configuration = Config {
        header_timeout: 1,
        timeout: 5,
        ..config()
    };
    let proxy = Running::start(configuration).await?;
    let client = TcpStream::connect(proxy.address).await?;
    let (mut reader, mut writer) = client.into_split();
    let writer_task = tokio::spawn(async move {
        for byte in b"GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n" {
            if writer.write_all(&[*byte]).await.is_err() {
                break;
            }
            sleep(Duration::from_millis(150)).await;
        }
    });
    let mut bytes = Vec::new();
    let closed = timeout(Duration::from_secs(3), reader.read_to_end(&mut bytes)).await;
    writer_task.abort();
    closed.context("slow header was not closed by its total deadline")??;
    proxy.stop().await
}
