use crate::runtime::{ConnectionGuard, Runtime};
use crate::transport::{self, Activity, ActivityIo};
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, HOST, PROXY_AUTHENTICATE, VIA,
};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

type BoxError = Box<dyn Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, BoxError>;
type HttpResult<T> = std::result::Result<T, (StatusCode, &'static str)>;

struct Context {
    runtime: Arc<Runtime>,
    guard: Arc<ConnectionGuard>,
    activity: Activity,
    cancelled: CancellationToken,
    upgraded: AtomicBool,
}

pub async fn serve(
    mut stream: TcpStream,
    address: SocketAddr,
    runtime: Arc<Runtime>,
    guard: Arc<ConnectionGuard>,
) -> Result<()> {
    if !runtime.acl.is_allowed(address.ip()) {
        runtime.metrics.rejected.fetch_add(1, Ordering::Relaxed);
        let _ = timeout(
            Duration::from_secs(2),
            stream.write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        )
        .await;
        return Ok(());
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
        upgraded: AtomicBool::new(false),
    });
    let service_context = context.clone();
    let service = service_fn(move |request| {
        let context = service_context.clone();
        async move {
            let response = match handle(request, context).await {
                Ok(response) => response,
                Err((status, message)) => error_response(status, message),
            };
            Ok::<_, Infallible>(response)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(runtime.config.header_timeout))
        .max_buf_size(16 * 1024)
        .half_close(true);
    let connection = builder.serve_connection(io, service).with_upgrades();
    tokio::pin!(connection);
    let result = tokio::select! {
        result = &mut connection => result.map_err(Into::into),
        _ = context.activity.expired() => Ok(()),
        _ = runtime.force_shutdown.cancelled() => Ok(()),
        _ = runtime.shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            tokio::select! {
                result = &mut connection => result.map_err(Into::into),
                _ = context.activity.expired() => Ok(()),
                _ = runtime.force_shutdown.cancelled() => Ok(()),
            }
        }
    };
    if !context.upgraded.load(Ordering::Relaxed) {
        context.cancelled.cancel();
    }
    result
}

async fn handle(
    mut request: Request<Incoming>,
    context: Arc<Context>,
) -> HttpResult<Response<Body>> {
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
    let target = Target::parse(&request).map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let is_connect = request.method() == Method::CONNECT;
    if !runtime
        .filter
        .is_allowed(&target.host, &target.url, is_connect)
    {
        return Err((StatusCode::FORBIDDEN, "Blocked by filter"));
    }
    if !is_connect && runtime.config.stat_host.as_deref() == Some(target.host.as_str()) {
        if request.method() != Method::GET && request.method() != Method::HEAD {
            return Err((
                StatusCode::METHOD_NOT_ALLOWED,
                "Statistics require GET or HEAD",
            ));
        }
        return Ok(text_response(
            StatusCode::OK,
            runtime.metrics.to_html(),
            "text/html; charset=utf-8",
        ));
    }
    if is_connect {
        if !runtime.config.connect_ports.contains(&target.port) {
            return Err((StatusCode::FORBIDDEN, "CONNECT port not allowed"));
        }
        // Validate hop-by-hop syntax before switching protocols.
        strip_hop_by_hop(request.headers_mut())
            .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
        let target_stream = dial(&target, runtime).await?;
        let upgrade = hyper::upgrade::on(&mut request);
        context.upgraded.store(true, Ordering::Relaxed);
        let tunnel_context = context.clone();
        runtime.tasks.spawn(async move {
            let context = tunnel_context;
            let tunnel = async {
                let upgraded = upgrade.await?;
                let mut client = TokioIo::new(upgraded);
                let mut target = ActivityIo::new(target_stream, context.activity.clone(), None);
                // Hyper's upgrade preserves bytes read beyond the CONNECT header.
                // Tokio preserves half-close and finishes the remaining direction.
                copy_bidirectional(&mut client, &mut target).await?;
                Ok::<_, BoxError>(())
            };
            tokio::select! {
                _ = tunnel => {},
                _ = context.activity.expired() => {},
                _ = context.runtime.force_shutdown.cancelled() => {},
            }
            context.cancelled.cancel();
        });
        return Ok(text_response(StatusCode::OK, String::new(), "text/plain"));
    }
    if request.headers().contains_key("upgrade") {
        return Err((StatusCode::NOT_IMPLEMENTED, "HTTP Upgrade is not supported"));
    }
    strip_hop_by_hop(request.headers_mut())
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    request.headers_mut().insert(HOST, target.authority);
    add_via(request.headers_mut(), runtime);
    *request.uri_mut() = target.path;
    *request.version_mut() = Version::HTTP_11;

    let target_stream = dial(&target, runtime).await?;
    let io = TokioIo::new(ActivityIo::new(
        target_stream,
        context.activity.clone(),
        None,
    ));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream handshake failed"))?;
    let driver_context = context.clone();
    runtime.tasks.spawn(async move {
        // Keep the connection permit until this socket has also been released.
        let _guard = driver_context.guard.clone();
        tokio::select! {
            _ = connection => {},
            _ = driver_context.activity.expired() => {},
            _ = driver_context.cancelled.cancelled() => {},
            _ = driver_context.runtime.force_shutdown.cancelled() => {},
        }
    });
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream request failed"))?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return Err((StatusCode::BAD_GATEWAY, "Unexpected upstream upgrade"));
    }
    strip_hop_by_hop(response.headers_mut())
        .map_err(|message| (StatusCode::BAD_GATEWAY, message))?;
    add_via(response.headers_mut(), runtime);
    Ok(response.map(|body| {
        body.map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync()
    }))
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
                .and_then(|value| value.to_str().ok())
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
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err("Empty destination host");
        }
        let path = uri
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or("/");
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

fn strip_hop_by_hop(headers: &mut HeaderMap) -> std::result::Result<(), &'static str> {
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
    // Hyper decodes and re-encodes body framing. Never blindly relay raw bytes
    // after the first HTTP request; only CONNECT uses a byte tunnel.
    Ok(())
}

fn add_via(headers: &mut HeaderMap, runtime: &Runtime) {
    if !runtime.config.disable_via_header {
        let value = HeaderValue::from_str(&format!("1.1 {}", runtime.config.via_proxy_name))
            .expect("startup-validated ViaProxyName");
        headers.append(VIA, value);
    }
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

fn error_response(status: StatusCode, message: &'static str) -> Response<Body> {
    let mut response = text_response(
        status,
        format!("{}\n", message),
        "text/plain; charset=utf-8",
    );
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Tinyproxy\""),
        );
    }
    response
}
