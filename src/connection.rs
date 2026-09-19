use crate::exchange::{self, Body, BoxError, CancelOnDrop, Exchange};
use crate::protocol::{self, BoxIo};
use crate::runtime::{ConnectionGuard, Executor, Runtime};
use crate::transport::{self, Activity, ActivityIo};
use anyhow::{ensure, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, COOKIE, HOST, PROXY_AUTHENTICATE, VIA,
};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

type HttpResult<T> = std::result::Result<T, (StatusCode, &'static str)>;

struct Context {
    runtime: Arc<Runtime>,
    guard: Arc<ConnectionGuard>,
    activity: Activity,
    cancelled: CancellationToken,
    http1_upgraded: AtomicBool,
}

pub async fn serve(
    mut stream: TcpStream,
    address: SocketAddr,
    runtime: Arc<Runtime>,
    guard: Arc<ConnectionGuard>,
) -> Result<()> {
    // Reject before TLS work; never send plaintext errors on a TLS/H2 listener.
    if !runtime.acl.is_allowed(address.ip()) {
        runtime.metrics.rejected.fetch_add(1, Ordering::Relaxed);
        if runtime.tls.is_none() && !runtime.config.allow_h2c {
            let _ = timeout(
                Duration::from_secs(2),
                stream.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                ),
            )
            .await;
        }
        return Ok(());
    }
    let negotiate = async {
        let (h2, io): (bool, BoxIo) = if let Some(acceptor) = &runtime.tls {
            let tls = timeout(
                Duration::from_secs(runtime.config.tls_handshake_timeout),
                acceptor.accept(stream),
            )
            .await??;
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            if h2 {
                let (detected, io) = timeout(
                    Duration::from_secs(runtime.config.header_timeout),
                    protocol::detect(Box::new(tls)),
                )
                .await??;
                ensure!(detected, "HTTP/2 ALPN requires an HTTP/2 preface");
                (true, io)
            } else {
                // Absent ALPN means HTTP/1. Do not sniff and silently override it.
                (false, Box::new(tls))
            }
        } else if runtime.config.allow_h2c {
            timeout(
                Duration::from_secs(runtime.config.header_timeout),
                protocol::detect(Box::new(stream)),
            )
            .await??
        } else {
            (false, Box::new(stream))
        };
        Ok::<_, anyhow::Error>((h2, io))
    };
    let (h2, stream) = tokio::select! {
        result = negotiate => result?,
        _ = runtime.shutdown.cancelled() => return Ok(()),
        _ = runtime.force_shutdown.cancelled() => return Ok(()),
    };
    if h2 {
        runtime
            .metrics
            .http2_connections
            .fetch_add(1, Ordering::Relaxed);
    }
    let activity = Activity::new(Duration::from_secs(runtime.config.timeout));
    let io = TokioIo::new(ActivityIo::new(
        stream,
        activity.clone(),
        Some(runtime.metrics.clone()),
    ));
    let context = Arc::new(Context {
        runtime: runtime.clone(),
        guard,
        activity,
        cancelled: CancellationToken::new(),
        http1_upgraded: AtomicBool::new(false),
    });
    let service_context = context.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        let context = service_context.clone();
        async move {
            let version = request.version();
            let mut response = match handle(request, context).await {
                Ok(response) => response,
                Err((status, message)) => error_response(status, message, version),
            };
            *response.version_mut() = version;
            Ok::<_, Infallible>(response)
        }
    });
    // Both protocol drivers have the same graceful/forced shutdown contract.
    macro_rules! drive {
        ($connection:expr) => {{
            let connection = $connection;
            tokio::pin!(connection);
            tokio::select! {
                result = &mut connection => result.map_err(anyhow::Error::from),
                _ = context.activity.expired() => Ok(()),
                _ = runtime.force_shutdown.cancelled() => Ok(()),
                _ = runtime.shutdown.cancelled() => {
                    connection.as_mut().graceful_shutdown();
                    tokio::select! {
                        result = &mut connection => result.map_err(anyhow::Error::from),
                        _ = context.activity.expired() => Ok(()),
                        _ = runtime.force_shutdown.cancelled() => Ok(()),
                    }
                }
            }
        }};
    }
    let result = if h2 {
        let executor = Executor {
            tasks: runtime.tasks.clone(),
            force_shutdown: runtime.force_shutdown.clone(),
        };
        let mut builder = hyper::server::conn::http2::Builder::new(executor);
        builder
            .timer(TokioTimer::new())
            .max_concurrent_streams(runtime.config.max_concurrent_streams)
            .max_header_list_size(16 * 1024)
            .header_table_size(4096)
            .max_frame_size(16 * 1024)
            .initial_stream_window_size(65535)
            .initial_connection_window_size(1024 * 1024)
            .max_send_buf_size(64 * 1024)
            .max_pending_accept_reset_streams(20)
            .max_local_error_reset_streams(100)
            .adaptive_window(false);
        // Ordinary CONNECT works without advertising RFC 8441 extended CONNECT.
        drive!(builder.serve_connection(io, service))
    } else {
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_secs(runtime.config.header_timeout))
            .max_buf_size(16 * 1024)
            .half_close(true);
        drive!(builder.serve_connection(io, service).with_upgrades())
    };
    // An H2 CONNECT upgrades ONE stream, never ownership of the connection.
    if h2 || !context.http1_upgraded.load(Ordering::Relaxed) {
        context.cancelled.cancel();
    }
    result
}

async fn handle(request: Request<Incoming>, context: Arc<Context>) -> HttpResult<Response<Body>> {
    let runtime = &context.runtime;
    runtime.metrics.requests.fetch_add(1, Ordering::Relaxed);
    if !runtime.auth.authenticate(request.headers()) {
        runtime
            .metrics
            .auth_failures
            .fetch_add(1, Ordering::Relaxed);
        return Err((
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "Proxy authentication required",
        ));
    }
    if request.extensions().get::<hyper::ext::Protocol>().is_some() {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "Extended CONNECT is not supported",
        ));
    }
    if request.version() == Version::HTTP_2 {
        validate_h2_headers(request.headers()).map_err(|m| (StatusCode::BAD_REQUEST, m))?;
    }
    let target = Target::parse(&request).map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let is_connect = request.method() == Method::CONNECT;
    if !runtime
        .filter
        .is_allowed(&target.host, &target.url, is_connect)
    {
        return Err((StatusCode::FORBIDDEN, "Blocked by filter"));
    }
    if is_connect && !runtime.config.connect_ports.contains(&target.port) {
        return Err((StatusCode::FORBIDDEN, "CONNECT port not allowed"));
    }
    let permit = runtime.requests.clone().try_acquire_owned().map_err(|_| {
        runtime
            .metrics
            .requests_rejected
            .fetch_add(1, Ordering::Relaxed);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Proxy request capacity reached",
        )
    })?;
    let state = Exchange::new(
        permit,
        context.guard.clone(),
        runtime.metrics.clone(),
        context.cancelled.child_token(),
        Duration::from_secs(runtime.config.timeout),
    );
    let mut lease = CancelOnDrop(Some(state.clone()));
    let result = tokio::select! {
        result = forward(request, target, context.clone(), state.clone()) => result,
        _ = state.activity.expired() => Err((StatusCode::GATEWAY_TIMEOUT, "Request idle timeout")),
        _ = state.cancelled.cancelled() => Err((StatusCode::BAD_GATEWAY, "Request cancelled")),
        _ = runtime.force_shutdown.cancelled() => Err((StatusCode::SERVICE_UNAVAILABLE, "Proxy shutting down")),
    };
    if result.is_ok() {
        lease.0 = None;
    }
    result
}

async fn forward(
    mut request: Request<Incoming>,
    target: Target,
    context: Arc<Context>,
    state: Arc<Exchange>,
) -> HttpResult<Response<Body>> {
    let runtime = &context.runtime;
    let version = request.version();
    let is_connect = request.method() == Method::CONNECT;
    if !is_connect && runtime.config.stat_host.as_deref() == Some(target.host.as_str()) {
        if request.method() != Method::GET && request.method() != Method::HEAD {
            return Err((
                StatusCode::METHOD_NOT_ALLOWED,
                "Statistics require GET or HEAD",
            ));
        }
        let mut response = text_response(
            StatusCode::OK,
            runtime.metrics.to_html(),
            "text/html; charset=utf-8",
        );
        if request.method() == Method::HEAD {
            *response.body_mut() = empty_body();
        }
        return Ok(response.map(|body| exchange::track(body, state, true)));
    }
    if is_connect {
        strip_hop_by_hop(request.headers_mut()).map_err(|m| (StatusCode::BAD_REQUEST, m))?;
        let target_stream = dial(&target, runtime).await?;
        let upgrade = hyper::upgrade::on(&mut request);
        if version != Version::HTTP_2 {
            context.http1_upgraded.store(true, Ordering::Relaxed);
        }
        let force = runtime.force_shutdown.clone();
        runtime.tasks.spawn(async move {
            let tunnel = async {
                let upgraded = upgrade.await?;
                let mut client =
                    ActivityIo::new(TokioIo::new(upgraded), state.activity.clone(), None);
                let mut target = ActivityIo::new(target_stream, state.activity.clone(), None);
                if version == Version::HTTP_2 {
                    crate::h2_tunnel::relay(client, target).await?;
                } else {
                    copy_bidirectional(&mut client, &mut target).await?;
                }
                Ok::<_, BoxError>(())
            };
            tokio::select! {
                _ = tunnel => {},
                _ = state.activity.expired() => {},
                _ = state.cancelled.cancelled() => {},
                _ = force.cancelled() => {},
            }
            state.cancelled.cancel();
        });
        // No Content-Length or Transfer-Encoding on successful CONNECT.
        return Ok(Response::new(empty_body()));
    }
    if request.headers().contains_key("upgrade") {
        return Err((StatusCode::NOT_IMPLEMENTED, "HTTP Upgrade is not supported"));
    }
    strip_hop_by_hop(request.headers_mut()).map_err(|m| (StatusCode::BAD_REQUEST, m))?;
    if version == Version::HTTP_2 {
        coalesce_cookies(request.headers_mut()).map_err(|m| (StatusCode::BAD_REQUEST, m))?;
    }
    let target_stream = dial(&target, runtime).await?;
    request.headers_mut().insert(HOST, target.authority);
    add_via(request.headers_mut(), runtime, version);
    *request.uri_mut() = target.path;
    *request.version_mut() = Version::HTTP_11;
    request.extensions_mut().clear();
    let request = request.map(|body| exchange::track(body, state.clone(), false));
    let io = TokioIo::new(ActivityIo::new(target_stream, state.activity.clone(), None));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream handshake failed"))?;
    let driver_state = state.clone();
    let force = runtime.force_shutdown.clone();
    runtime.tasks.spawn(async move {
        tokio::select! {
            _ = connection => {},
            _ = driver_state.activity.expired() => {},
            _ = driver_state.cancelled.cancelled() => {},
            _ = force.cancelled() => {},
        }
    });
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream request failed"))?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return Err((StatusCode::BAD_GATEWAY, "Unexpected upstream upgrade"));
    }
    let upstream_version = response.version();
    strip_hop_by_hop(response.headers_mut()).map_err(|m| (StatusCode::BAD_GATEWAY, m))?;
    add_via(response.headers_mut(), runtime, upstream_version);
    Ok(response.map(|body| exchange::track(body, state, true)))
}

async fn dial(target: &Target, runtime: &Runtime) -> HttpResult<TcpStream> {
    transport::connect(
        &target.host,
        target.port,
        runtime.config.bind_address,
        runtime.config.connect_timeout,
    )
    .await
    .map_err(|error| {
        if error.kind() == std::io::ErrorKind::TimedOut {
            (StatusCode::GATEWAY_TIMEOUT, "Upstream connection timed out")
        } else {
            (StatusCode::BAD_GATEWAY, "Upstream connection failed")
        }
    })
}

struct Target {
    host: String,
    port: u16,
    authority: HeaderValue,
    path: Uri,
    url: String,
}
impl Target {
    fn parse<B>(request: &Request<B>) -> std::result::Result<Self, &'static str> {
        let connect = request.method() == Method::CONNECT;
        let uri = request.uri();
        if connect && (uri.scheme().is_some() || uri.path_and_query().is_some()) {
            return Err("CONNECT requires host:port authority form");
        }
        if uri
            .scheme_str()
            .is_some_and(|scheme| !scheme.eq_ignore_ascii_case("http"))
        {
            return Err("Use CONNECT for HTTPS destinations");
        }
        if request.headers().get_all(HOST).iter().count() > 1 {
            return Err("Multiple Host headers are not allowed");
        }
        let authority = if let Some(authority) = uri.authority() {
            authority.clone()
        } else {
            if connect {
                return Err("CONNECT requires an authority");
            }
            request
                .headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .ok_or("Host header required")?
                .parse::<hyper::http::uri::Authority>()
                .map_err(|_| "Invalid Host header")?
        };
        if authority.as_str().contains('@') || authority.host().is_empty() {
            return Err("Invalid destination authority");
        }
        let raw = authority.as_str();
        let explicit_port = raw
            .rsplit_once(':')
            .filter(|(before, _)| !raw.starts_with('[') || before.ends_with(']'));
        let port = if let Some((_, port)) = explicit_port {
            port.parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or("Invalid destination port")?
        } else if connect {
            return Err("CONNECT requires an explicit port");
        } else {
            80
        };
        // H2 :authority and Host cannot name different destinations.
        if request.version() == Version::HTTP_2 {
            if let Some(host) = request.headers().get(HOST) {
                let host = host
                    .to_str()
                    .map_err(|_| "Invalid Host header")?
                    .parse::<hyper::http::uri::Authority>()
                    .map_err(|_| "Invalid Host header")?;
                if !host.host().eq_ignore_ascii_case(authority.host())
                    || host.port_u16().unwrap_or(80) != port
                {
                    return Err("Host disagrees with :authority");
                }
            }
        }
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err("Empty destination host");
        }
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        if !connect
            && !path.starts_with('/')
            && !(path == "*" && request.method() == Method::OPTIONS)
        {
            return Err("Invalid HTTP request target");
        }
        Ok(Self {
            host,
            port,
            authority: HeaderValue::from_str(raw).map_err(|_| "Invalid authority header")?,
            path: path.parse().map_err(|_| "Invalid request path")?,
            url: format!("http://{}{}", raw, path),
        })
    }
}

fn validate_h2_headers(headers: &HeaderMap) -> std::result::Result<(), &'static str> {
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    ] {
        if headers.contains_key(name) {
            return Err("Connection-specific field in HTTP/2");
        }
    }
    for value in headers.get_all("te") {
        if !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
            return Err("HTTP/2 TE must be trailers");
        }
    }
    Ok(())
}

/// RFC 9113 section 8.2.3 requires split Cookie fields to be joined using '; '.
fn coalesce_cookies(headers: &mut HeaderMap) -> std::result::Result<(), &'static str> {
    if headers.get_all(COOKIE).iter().count() < 2 {
        return Ok(());
    }
    let mut joined = Vec::new();
    for (index, cookie) in headers.get_all(COOKIE).iter().enumerate() {
        if index != 0 {
            joined.extend_from_slice(b"; ");
        }
        joined.extend_from_slice(cookie.as_bytes());
    }
    let value = HeaderValue::from_bytes(&joined).map_err(|_| "Invalid Cookie")?;
    headers.insert(COOKIE, value);
    Ok(())
}

pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) -> std::result::Result<(), &'static str> {
    if headers.contains_key("content-length") && headers.contains_key("transfer-encoding") {
        return Err("Ambiguous message framing");
    }
    let mut nominated = Vec::new();
    for value in headers.get_all(CONNECTION) {
        for token in value
            .to_str()
            .map_err(|_| "Invalid Connection header")?
            .split(',')
        {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let name =
                HeaderName::from_bytes(token.as_bytes()).map_err(|_| "Invalid Connection token")?;
            if name == "content-length" || name == "transfer-encoding" {
                return Err("Connection must not nominate message framing headers");
            }
            nominated.push(name);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    Ok(())
}

fn add_via(headers: &mut HeaderMap, runtime: &Runtime, version: Version) {
    if !runtime.config.disable_via_header {
        let protocol = match version {
            Version::HTTP_2 => "2",
            Version::HTTP_10 => "1.0",
            _ => "1.1",
        };
        let value =
            HeaderValue::from_str(&format!("{} {}", protocol, runtime.config.via_proxy_name))
                .expect("startup-validated ViaProxyName");
        headers.append(VIA, value);
    }
}
fn empty_body() -> Body {
    Full::new(Bytes::new())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}
fn text_response(status: StatusCode, text: String, content_type: &'static str) -> Response<Body> {
    let length = text.len();
    let body = Full::new(Bytes::from(text))
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        "content-length",
        HeaderValue::from_str(&length.to_string()).expect("valid length"),
    );
    response
}
fn error_response(status: StatusCode, message: &'static str, version: Version) -> Response<Body> {
    let mut response = text_response(
        status,
        format!("{}\n", message),
        "text/plain; charset=utf-8",
    );
    if version != Version::HTTP_2 {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Tinyproxy\""),
        );
    }
    response
}
