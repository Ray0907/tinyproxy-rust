use anyhow::{ensure, Result};
use bytes::Bytes;
use h2::client::SendRequest;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, Method, Request, Response, Version};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tinyproxy_rust::{config::Config, runtime::Metrics, server::ProxyServer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tokio_rustls::{rustls, TlsConnector};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(5);

struct Proxy {
    address: SocketAddr,
    shutdown: CancellationToken,
    metrics: Arc<Metrics>,
    task: JoinHandle<Result<()>>,
}
impl Proxy {
    async fn new(config: Config) -> Result<Self> {
        let proxy = ProxyServer::bind(config).await?;
        let address = proxy.local_addresses()?[0];
        let shutdown = proxy.shutdown_token();
        let metrics = proxy.metrics();
        Ok(Self {
            address,
            shutdown,
            metrics,
            task: tokio::spawn(proxy.run()),
        })
    }
    async fn stop(mut self) -> Result<()> {
        self.shutdown.cancel();
        timeout(WAIT, &mut self.task).await???;
        assert_eq!(self.metrics.active.load(Ordering::Relaxed), 0);
        assert_eq!(self.metrics.inflight.load(Ordering::Relaxed), 0);
        Ok(())
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}
fn config() -> Config {
    Config {
        port: 0,
        allow_h2c: true,
        shutdown_timeout: 1,
        ..Config::default()
    }
}

struct Client {
    sender: SendRequest<Bytes>,
    driver: JoinHandle<()>,
}
impl Client {
    async fn new<T>(io: T) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, connection) = h2::client::handshake(io).await?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { sender, driver })
    }
    async fn plain(proxy: &Proxy) -> Result<Self> {
        Self::new(TcpStream::connect(proxy.address).await?).await
    }
    async fn send(
        &self,
        mut request: Request<()>,
        end: bool,
    ) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>)> {
        let mut sender = timeout(WAIT, self.sender.clone().ready()).await??;
        *request.version_mut() = Version::HTTP_2;
        Ok(sender.send_request(request, end)?)
    }
    async fn get(&self, uri: String) -> Result<Response<h2::RecvStream>> {
        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri(uri)
            .body(())?;
        let (response, _) = self.send(request, true).await?;
        Ok(timeout(WAIT, response).await??)
    }
    async fn tunnel(&self, target: SocketAddr) -> Result<(h2::SendStream<Bytes>, h2::RecvStream)> {
        let request = Request::builder()
            .version(Version::HTTP_2)
            .method(Method::CONNECT)
            .uri(target.to_string())
            .body(())?;
        let (response, send) = self.send(request, false).await?;
        let response = timeout(WAIT, response).await??;
        ensure!(
            response.status() == 200,
            "CONNECT failed: {}",
            response.status()
        );
        ensure!(!response.headers().contains_key("content-length"));
        ensure!(!response.headers().contains_key("connection"));
        Ok((send, response.into_body()))
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

async fn collect(mut body: h2::RecvStream) -> Result<Vec<u8>> {
    timeout(WAIT, async {
        let mut result = Vec::new();
        while let Some(data) = body.data().await {
            let data = data?;
            let count = data.len();
            result.extend_from_slice(&data);
            body.flow_control().release_capacity(count)?;
        }
        Ok(result)
    })
    .await?
}
async fn header<T: AsyncRead + Unpin>(io: &mut T) -> Result<String> {
    timeout(WAIT, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(io.read_u8().await?);
            ensure!(bytes.len() < 65536);
        }
        Ok(String::from_utf8(bytes)?)
    })
    .await?
}
async fn inflight(proxy: &Proxy, count: u64) -> Result<()> {
    timeout(WAIT, async {
        while proxy.metrics.inflight.load(Ordering::Relaxed) != count {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

struct Origin {
    address: SocketAddr,
    task: JoinHandle<()>,
    blocked: Arc<Notify>,
    release: Arc<Notify>,
}
impl Origin {
    async fn new(label: &'static str) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let blocked = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let started = blocked.clone();
        let gate = release.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let started = started.clone();
                        let gate = gate.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let started = started.clone();
                                let gate = gate.clone();
                                async move {
                                    let (parts, body) = request.into_parts();
                                    if parts.uri.path() == "/blocked" { started.notify_one(); gate.notified().await; }
                                    let bytes = body.collect().await.unwrap().to_bytes();
                                    let text = if parts.uri.path() == "/echo" { bytes } else if parts.uri.path() == "/headers" {
                                        let value = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("absent");
                                        Bytes::from(format!("{} {}\nhost={}\nproxy-auth={}\nauth={}\ncookie={}\ncookies={}\nvia={}",
                                            parts.method, parts.uri, value("host"), value("proxy-authorization"), value("authorization"),
                                            value("cookie"), parts.headers.get_all("cookie").iter().count(), value("via")))
                                    } else { Bytes::from_static(label.as_bytes()) };
                                    let response = Response::builder().header("set-cookie", "a=1").header("set-cookie", "b=2")
                                        .header("connection", "x-hop").header("x-hop", "remove-me").body(Full::new(text)).unwrap();
                                    Ok::<_, Infallible>(response)
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        Ok(Self {
            address,
            task,
            blocked,
            release,
        })
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Certificate {
    _directory: tempfile::TempDir,
    cert: String,
    key: String,
    der: rustls::pki_types::CertificateDer<'static>,
}
impl Certificate {
    fn new() -> Result<Self> {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let directory = tempfile::tempdir()?;
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, generated.cert.pem())?;
        std::fs::write(&key, generated.key_pair.serialize_pem())?;
        Ok(Self {
            _directory: directory,
            cert: cert.to_string_lossy().into_owned(),
            key: key.to_string_lossy().into_owned(),
            der: generated.cert.der().clone(),
        })
    }
    fn config(&self) -> Config {
        Config {
            port: 0,
            tls_cert: Some(self.cert.clone()),
            tls_key: Some(self.key.clone()),
            shutdown_timeout: 1,
            ..Config::default()
        }
    }
    async fn connect(
        &self,
        proxy: &Proxy,
        alpn: &[&[u8]],
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der.clone())?;
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let connector = TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(proxy.address).await?;
        Ok(timeout(WAIT, connector.connect("localhost".try_into()?, tcp)).await??)
    }
}

#[tokio::test]
async fn tls_alpn_negotiates_real_http2_and_checks_certificate() -> Result<()> {
    let certificate = Certificate::new()?;
    let proxy = Proxy::new(certificate.config()).await?;
    let origin = Origin::new("tls-h2").await?;
    let tls = certificate.connect(&proxy, &[b"h2", b"http/1.1"]).await?;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let client = Client::new(tls).await?;
    let response = client.get(origin.url("/")).await?;
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(collect(response.into_body()).await?, b"tls-h2");
    assert_eq!(proxy.metrics.http2_connections.load(Ordering::Relaxed), 1);
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn tls_supports_http1_alpn_and_no_alpn_fallback() -> Result<()> {
    let certificate = Certificate::new()?;
    let proxy = Proxy::new(certificate.config()).await?;
    let origin = Origin::new("http1").await?;
    for alpn in [vec![b"http/1.1".as_slice()], vec![]] {
        let mut tls = certificate.connect(&proxy, &alpn).await?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            origin.url("/"),
            origin.address
        );
        tls.write_all(request.as_bytes()).await?;
        let head = header(&mut tls).await?;
        assert!(head.starts_with("HTTP/1.1 200"));
        let mut body = [0; 5];
        timeout(WAIT, tls.read_exact(&mut body)).await??;
        assert_eq!(&body, b"http1");
    }
    proxy.stop().await
}

#[tokio::test]
async fn disabling_http2_excludes_it_from_alpn() -> Result<()> {
    let certificate = Certificate::new()?;
    let mut config = certificate.config();
    config.http2 = false;
    let proxy = Proxy::new(config).await?;
    let tls = certificate.connect(&proxy, &[b"h2", b"http/1.1"]).await?;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    drop(tls);
    proxy.stop().await
}

#[tokio::test]
async fn unrelated_ca_cannot_authenticate_the_proxy() -> Result<()> {
    let certificate = Certificate::new()?;
    let unrelated = Certificate::new()?;
    let proxy = Proxy::new(certificate.config()).await?;
    assert!(unrelated.connect(&proxy, &[b"h2"]).await.is_err());
    proxy.stop().await
}

#[tokio::test]
async fn h2c_is_explicit_and_http1_still_works_on_the_same_port() -> Result<()> {
    let proxy = Proxy::new(config()).await?;
    let origin = Origin::new("shared-port").await?;
    let client = Client::plain(&proxy).await?;
    assert_eq!(
        collect(client.get(origin.url("/")).await?.into_body()).await?,
        b"shared-port"
    );
    let mut tcp = TcpStream::connect(proxy.address).await?;
    tcp.write_all(
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            origin.url("/"),
            origin.address
        )
        .as_bytes(),
    )
    .await?;
    assert!(header(&mut tcp).await?.starts_with("HTTP/1.1 200"));
    drop(tcp);
    drop(client);
    proxy.stop().await?;
    let proxy = Proxy::new(Config {
        port: 0,
        ..Config::default()
    })
    .await?;
    let client = Client::plain(&proxy).await?;
    assert!(client.get(origin.url("/")).await.is_err());
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn multiplexing_does_not_serialize_a_fast_request_behind_a_blocked_one() -> Result<()> {
    let origin = Origin::new("ok").await?;
    let proxy = Proxy::new(config()).await?;
    let client = Client::plain(&proxy).await?;
    let blocked = Request::builder().uri(origin.url("/blocked")).body(())?;
    let (slow, _) = client.send(blocked, true).await?;
    timeout(WAIT, origin.blocked.notified()).await?;
    assert_eq!(
        collect(client.get(origin.url("/fast")).await?.into_body()).await?,
        b"ok"
    );
    origin.release.notify_one();
    assert_eq!(
        collect(timeout(WAIT, slow).await??.into_body()).await?,
        b"ok"
    );
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn multiplexed_requests_route_to_distinct_origins() -> Result<()> {
    let a = Origin::new("A").await?;
    let b = Origin::new("B").await?;
    let proxy = Proxy::new(config()).await?;
    let client = Client::plain(&proxy).await?;
    let (ra, rb) = tokio::join!(client.get(a.url("/")), client.get(b.url("/")));
    assert_eq!(collect(ra?.into_body()).await?, b"A");
    assert_eq!(collect(rb?.into_body()).await?, b"B");
    assert_eq!(proxy.metrics.opened.load(Ordering::Relaxed), 1);
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn h2_auth_is_per_stream_and_translation_preserves_http_semantics() -> Result<()> {
    let mut config = config();
    config.basic_auth = Config::parse("BasicAuth user pass")?.basic_auth;
    let proxy = Proxy::new(config).await?;
    let origin = Origin::new("origin").await?;
    let client = Client::plain(&proxy).await?;
    let denied = client.get(origin.url("/")).await?;
    assert_eq!(denied.status(), 407);
    assert!(!denied.headers().contains_key("connection"));
    collect(denied.into_body()).await?;
    let request = Request::builder()
        .uri(origin.url("/headers?q=1"))
        .header("proxy-authorization", "Basic dXNlcjpwYXNz")
        .header("authorization", "Bearer origin-token")
        .header("cookie", "a=1")
        .header("cookie", "b=2")
        .body(())?;
    let (response, _) = client.send(request, true).await?;
    let response = timeout(WAIT, response).await??;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
    assert!(!response.headers().contains_key("connection"));
    assert!(!response.headers().contains_key("x-hop"));
    let body = String::from_utf8(collect(response.into_body()).await?)?;
    assert!(body.contains("GET /headers?q=1"));
    assert!(body.contains("proxy-auth=absent"));
    assert!(body.contains("auth=Bearer origin-token"));
    assert!(body.contains("cookie=a=1; b=2\ncookies=1"));
    assert!(body.contains("via=2 tinyproxy-rust"));
    assert_eq!(client.get(origin.url("/")).await?.status(), 407);
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn host_authority_conflicts_are_not_forwarded() -> Result<()> {
    let origin = Origin::new("origin").await?;
    let proxy = Proxy::new(config()).await?;
    let client = Client::plain(&proxy).await?;
    let request = Request::builder()
        .uri(origin.url("/"))
        .header("host", "different.invalid")
        .body(())?;
    let (response, _) = client.send(request, true).await?;
    // The protocol library may reject earlier than the application layer.
    if let Ok(response) = timeout(WAIT, response).await? {
        assert_eq!(response.status(), 400);
    }
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn large_h2_upload_and_response_cross_flow_control_windows() -> Result<()> {
    let origin = Origin::new("echo").await?;
    let proxy = Proxy::new(config()).await?;
    let client = Client::plain(&proxy).await?;
    let body = Bytes::from(vec![0x5a; 2 * 1024 * 1024]);
    let request = Request::builder()
        .method(Method::POST)
        .uri(origin.url("/echo"))
        .header("content-length", body.len())
        .body(())?;
    let (response, mut send) = client.send(request, false).await?;
    // h2 buffers test input; production uses bounded Hyper streaming bodies.
    send.send_data(body.clone(), true)?;
    let response = timeout(WAIT, response).await??;
    assert_eq!(response.status(), 200);
    assert_eq!(collect(response.into_body()).await?, body);
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn h2_connect_preserves_early_data_half_close_and_sibling_streams() -> Result<()> {
    let a = TcpListener::bind("127.0.0.1:0").await?;
    let b = TcpListener::bind("127.0.0.1:0").await?;
    let aa = a.local_addr()?;
    let bb = b.local_addr()?;
    let mut config = config();
    config.connect_ports = vec![aa.port(), bb.port()];
    let proxy = Proxy::new(config).await?;
    let client = Client::plain(&proxy).await?;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(aa.to_string())
        .body(())?;
    let (response, mut send_a) = client.send(request, false).await?;
    send_a.send_data(Bytes::from_static(b"early"), true)?;
    let response = timeout(WAIT, response).await??;
    assert_eq!(response.status(), 200);
    let (mut up_a, _) = timeout(WAIT, a.accept()).await??;
    let (mut send_b, recv_b) = client.tunnel(bb).await?;
    let (mut up_b, _) = timeout(WAIT, b.accept()).await??;
    let mut received = Vec::new();
    timeout(WAIT, up_a.read_to_end(&mut received)).await??;
    assert_eq!(received, b"early");
    up_a.write_all(b"after-fin").await?;
    up_a.shutdown().await?;
    assert_eq!(collect(response.into_body()).await?, b"after-fin");
    send_b.send_data(Bytes::from_static(b"alive"), true)?;
    received.clear();
    timeout(WAIT, up_b.read_to_end(&mut received)).await??;
    assert_eq!(received, b"alive");
    up_b.write_all(b"sibling-ok").await?;
    up_b.shutdown().await?;
    assert_eq!(collect(recv_b).await?, b"sibling-ok");
    let origin = Origin::new("still-h2").await?;
    assert_eq!(
        collect(client.get(origin.url("/")).await?.into_body()).await?,
        b"still-h2"
    );
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn global_request_budget_includes_connect_and_recovers_after_reset() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let mut config = config();
    config.connect_ports = vec![target.port()];
    config.max_inflight_requests = 1;
    let proxy = Proxy::new(config).await?;
    let origin = Origin::new("recovered").await?;
    let client = Client::plain(&proxy).await?;
    let (mut send, recv) = client.tunnel(target).await?;
    let (mut upstream, _) = timeout(WAIT, listener.accept()).await??;
    assert_eq!(client.get(origin.url("/")).await?.status(), 503);
    assert_eq!(proxy.metrics.inflight.load(Ordering::Relaxed), 1);
    send.send_reset(h2::Reason::CANCEL);
    drop(recv);
    assert!(timeout(WAIT, upstream.read_u8()).await?.is_err());
    inflight(&proxy, 0).await?;
    assert_eq!(
        collect(client.get(origin.url("/")).await?.into_body()).await?,
        b"recovered"
    );
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn reset_before_response_headers_closes_the_upstream_socket() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy = Proxy::new(config()).await?;
    let client = Client::plain(&proxy).await?;
    let request = Request::builder()
        .uri(format!("http://{}/", listener.local_addr()?))
        .body(())?;
    let (response, mut send) = client.send(request, true).await?;
    let (mut upstream, _) = timeout(WAIT, listener.accept()).await??;
    header(&mut upstream).await?;
    send.send_reset(h2::Reason::CANCEL);
    assert!(timeout(WAIT, response).await?.is_err());
    assert!(timeout(WAIT, upstream.read_u8()).await?.is_err());
    inflight(&proxy, 0).await?;
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn busy_sibling_does_not_keep_an_idle_tunnel_alive() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let mut config = config();
    config.connect_ports = vec![target.port()];
    config.timeout = 1;
    let proxy = Proxy::new(config).await?;
    let client = Client::plain(&proxy).await?;
    let (_idle_send, mut idle_recv) = client.tunnel(target).await?;
    let (mut idle_upstream, _) = timeout(WAIT, listener.accept()).await??;
    let (mut active_send, mut active_recv) = client.tunnel(target).await?;
    let (mut active_upstream, _) = timeout(WAIT, listener.accept()).await??;
    for _ in 0..6 {
        sleep(Duration::from_millis(250)).await;
        active_send.send_data(Bytes::from_static(b"a"), false)?;
        assert_eq!(timeout(WAIT, active_upstream.read_u8()).await??, b'a');
        active_upstream.write_all(b"b").await?;
        let data = timeout(WAIT, active_recv.data())
            .await?
            .transpose()?
            .unwrap();
        assert_eq!(data, b"b".as_slice());
        active_recv.flow_control().release_capacity(data.len())?;
    }
    assert!(timeout(WAIT, idle_upstream.read_u8()).await?.is_err());
    let end = timeout(WAIT, idle_recv.data()).await?;
    assert!(
        end.is_none() || end.is_some_and(|data| data.is_err() || data.is_ok_and(|b| b.is_empty()))
    );
    inflight(&proxy, 1).await?;
    active_send.send_reset(h2::Reason::CANCEL);
    drop(active_recv);
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn max_concurrent_streams_is_advertised_and_enforced() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let mut config = config();
    config.max_concurrent_streams = 1;
    config.connect_ports = vec![target.port()];
    let proxy = Proxy::new(config).await?;
    let origin = Origin::new("after-capacity").await?;
    let client = Client::plain(&proxy).await?;
    let (mut send, recv) = client.tunnel(target).await?;
    let (_upstream, _) = timeout(WAIT, listener.accept()).await??;
    assert_eq!(client.sender.current_max_send_streams(), 1);
    // h2 allows a pending request to be created; ready() alone is not
    // proof of an available wire stream. Assert observable dispatch.
    let request = Request::builder().uri(origin.url("/")).body(())?;
    let (mut response, _) = client.send(request, true).await?;
    assert!(timeout(Duration::from_millis(100), &mut response)
        .await
        .is_err());
    assert_eq!(proxy.metrics.requests.load(Ordering::Relaxed), 1);
    send.send_reset(h2::Reason::CANCEL);
    drop(recv);
    assert_eq!(
        collect(timeout(WAIT, response).await??.into_body()).await?,
        b"after-capacity"
    );
    drop(client);
    proxy.stop().await
}

#[tokio::test]
async fn graceful_goaway_drains_existing_connect_stream() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let mut config = config();
    config.connect_ports = vec![target.port()];
    config.shutdown_timeout = 3;
    let proxy = Proxy::new(config).await?;
    let client = Client::plain(&proxy).await?;
    let (mut send, recv) = client.tunnel(target).await?;
    let (mut upstream, _) = timeout(WAIT, listener.accept()).await??;
    proxy.shutdown.cancel();
    sleep(Duration::from_millis(50)).await;
    send.send_data(Bytes::from_static(b"finish"), true)?;
    let mut request = Vec::new();
    timeout(WAIT, upstream.read_to_end(&mut request)).await??;
    assert_eq!(request, b"finish");
    upstream.write_all(b"drained").await?;
    upstream.shutdown().await?;
    assert_eq!(collect(recv).await?, b"drained");
    proxy.stop().await
}

#[tokio::test]
async fn partial_h2_preface_has_a_total_deadline() -> Result<()> {
    let mut config = config();
    config.header_timeout = 1;
    config.timeout = 30;
    let proxy = Proxy::new(config).await?;
    let mut tcp = TcpStream::connect(proxy.address).await?;
    tcp.write_all(b"PRI ").await?;
    sleep(Duration::from_millis(600)).await;
    tcp.write_all(b"*").await?;
    assert!(timeout(Duration::from_secs(2), tcp.read_u8())
        .await?
        .is_err());
    proxy.stop().await
}

#[tokio::test]
async fn tls_handshake_deadline_releases_connection_capacity() -> Result<()> {
    let certificate = Certificate::new()?;
    let mut config = certificate.config();
    config.tls_handshake_timeout = 1;
    let proxy = Proxy::new(config).await?;
    let mut tcp = TcpStream::connect(proxy.address).await?;
    assert!(timeout(Duration::from_secs(3), tcp.read_u8())
        .await?
        .is_err());
    proxy.stop().await
}

#[test]
fn http2_tls_configuration_rejects_inconsistent_or_unbounded_settings() -> Result<()> {
    for text in [
        "MaxConcurrentStreams 0",
        "MaxConcurrentStreams 1025",
        "MaxInflightRequests 0",
        "TLSCert cert.pem",
        "TLSKey key.pem",
        "HTTP2 No\nAllowH2C Yes",
        "TLSHandshakeTimeout 0",
        "TLSCert a\nTLSKey b\nAllowH2C Yes",
    ] {
        assert!(
            Config::parse(text).is_err(),
            "accepted invalid configuration: {text}"
        );
    }
    let config =
        Config::parse("HTTP2 Yes\nAllowH2C Yes\nMaxConcurrentStreams 8\nMaxInflightRequests 32")?;
    assert!(config.http2 && config.allow_h2c);
    assert_eq!(config.max_concurrent_streams, 8);
    assert_eq!(config.max_inflight_requests, 32);
    Ok(())
}

#[tokio::test]
async fn tls_files_are_validated_before_binding() -> Result<()> {
    let certificate = Certificate::new()?;
    let unrelated = Certificate::new()?;
    let mut config = certificate.config();
    config.tls_key = Some(unrelated.key.clone());
    assert!(ProxyServer::bind(config).await.is_err());
    let mut config = certificate.config();
    config.tls_cert = Some("/nonexistent/tinyproxy-test-cert.pem".into());
    assert!(ProxyServer::bind(config).await.is_err());
    Ok(())
}

#[test]
fn tls_paths_resolve_relative_to_configuration() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("proxy.conf");
    std::fs::write(&path, "TLSCert cert.pem\nTLSKey key.pem\n")?;
    let config = Config::from_file(&path)?;
    assert_eq!(
        config.tls_cert.as_deref(),
        directory.path().join("cert.pem").to_str()
    );
    assert_eq!(
        config.tls_key.as_deref(),
        directory.path().join("key.pem").to_str()
    );
    Ok(())
}

#[tokio::test]
async fn h2_reset_after_half_close_releases_idle_upstream() -> Result<()> {
    for reason in [h2::Reason::CANCEL, h2::Reason::NO_ERROR] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = listener.local_addr()?;
        let mut config = config();
        config.connect_ports = vec![target.port()];
        let proxy = Proxy::new(config).await?;
        let client = Client::plain(&proxy).await?;
        let (mut send, recv) = client.tunnel(target).await?;
        let (mut upstream, _) = timeout(WAIT, listener.accept()).await??;
        send.send_data(Bytes::new(), true)?;
        assert!(timeout(WAIT, upstream.read_u8()).await?.is_err());
        // Normal END_STREAM must retain the response direction.
        assert_eq!(proxy.metrics.inflight.load(Ordering::Relaxed), 1);
        send.send_reset(reason);
        drop(recv);
        // Do NOT close the idle upstream: reset itself must free it.
        inflight(&proxy, 0).await?;
        drop(client);
        proxy.stop().await?;
    }
    Ok(())
}
