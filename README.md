# Tinyproxy-Rust

[![CI](https://github.com/Ray0907/tinyproxy-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/Ray0907/tinyproxy-rust/actions/workflows/ci.yml)

A small HTTP/1 and HTTP/2 forward proxy and HTTPS CONNECT tunnel, written in Rust.
Hyper handles HTTP framing and streaming; Tokio handles tunnels; Rustls protects
optional TLS listeners. One executable, with no database or external service.

This is **not a complete drop-in replacement** for C Tinyproxy. Unsupported
directives fail at startup rather than being silently accepted. There is no
measured performance-superiority claim; Criterion benchmarks are microbenchmarks,
not proxy-throughput comparisons.

## Build and run

```sh
cargo build --release --locked
./target/release/tinyproxy-rust --check -c config/tinyproxy-rust.conf
./target/release/tinyproxy-rust -c config/tinyproxy-rust.conf
```

In another terminal:

```sh
curl --proxy http://127.0.0.1:8888 http://example.com/
curl --proxy http://127.0.0.1:8888 https://example.com/
```

The binary stays in the foreground; `-d` / `--foreground` explicitly selects that
behavior. `--debug` initializes logging once. `-v` / `--version` prints the package
version. Unreadable or missing configuration is an error. Run as an unprivileged
user under a service manager. SIGINT and, on Unix, SIGTERM stop new accepts,
drain active work, and force-close remaining work after `ShutdownTimeout`.

## Minimal configuration

Tinyproxy-style key/value lines, **not TOML**. Quoted values and comments beginning
with `#` at a token boundary are supported.

```conf
Listen 127.0.0.1
Port 8888
MaxClients 100
MaxInflightRequests 256
Timeout 600
HeaderTimeout 30
ConnectTimeout 30
ShutdownTimeout 5
ConnectPort 443
LogLevel Info
```

The default listener is loopback only. A non-loopback listener requires explicit
ACL rules or BasicAuth. `Allow all` is an explicit public-access choice; do not use
it for an Internet-accessible unauthenticated proxy. `Bind` sets the **outgoing**
source IP and does not change the listening address.

```conf
BasicAuth alice "a password with spaces"
BasicAuth bob another-password
```

Original-style and old Rust `BasicAuth user:password` syntax are accepted.
Multiple users are supported. Empty credentials, duplicate usernames, missing
fields, malformed ACLs and invalid filter files fail startup. Errors include line
numbers without printing credential values. Policies are compiled once and shared.

## Native HTTP/2 and TLS

The proxy can negotiate **HTTP/2 between client and proxy**, including multiple
HTTP requests and independent CONNECT tunnels on one connection. Every stream is
individually authenticated and filtered. H2 multiplexing, HPACK and flow control
are handled by Hyper/h2, not a custom frame parser.

TLS is enabled by configuring both certificate and key. Paths are relative to the
configuration file. The same listening addresses become TLS-only: this is not an
automatic plaintext/TLS port detector. The example assumes a certificate valid for
`localhost`; use your actual proxy hostname and certificate in deployment.

```conf
Listen 127.0.0.1
Port 8888
TLSCert certs/proxy-cert.pem
TLSKey certs/proxy-key.pem
TLSHandshakeTimeout 10
HTTP2 Yes
MaxConcurrentStreams 32
MaxInflightRequests 256
ConnectPort 443
```

Use curl 8.1.0+ with HTTP/2 support (`curl -V`):

```sh
curl -v --proxy-http2 \
  --proxy https://localhost:8888 \
  --proxy-cacert config/certs/proxy-cert.pem \
  https://example.com/
```

The client verifies the proxy certificate; do not substitute `--proxy-insecure`.
`--proxy-http2` negotiates the **proxy hop**, unlike `--http2`, which concerns the
destination. Clients offering only `http/1.1`, or no ALPN, can still use HTTP/1
on the TLS listener. `HTTP2 No` advertises only HTTP/1.1. TLS early data is disabled.

Cleartext HTTP/2 prior knowledge is separately opt-in:

```conf
HTTP2 Yes
AllowH2C Yes
```

It shares the plaintext listener with HTTP/1. This is for trusted local clients or
an independently secured transport; BasicAuth is **not encrypted** on this hop.
`AllowH2C` cannot be combined with TLS settings or `HTTP2 No`. HTTP/1.1
`Upgrade: h2c` is not implemented. The standard curl `--proxy-http2` option applies
to HTTPS proxies, not h2c proxy connections.

### What HTTP/2 support does and does not mean

| Hop / feature | Support |
| --- | --- |
| Client to proxy, HTTP/1.1 | Plaintext by default, or optional TLS |
| Client to proxy, HTTP/2 | TLS + ALPN; opt-in cleartext prior knowledge |
| Ordinary HTTP request forwarding to origin | HTTP/1.1 streaming; H2 client requests are translated |
| CONNECT over HTTP/2 | One TCP tunnel per H2 stream; independent half-close, reset and idle lifetime |
| HTTPS origin HTTP/2 inside CONNECT | Negotiated end-to-end by client and origin; payload is opaque to the proxy |
| Automatic H2 origin connection pools | Not implemented |
| Extended CONNECT / WebSocket RFC 8441, server push, HTTP/3 | Not implemented or advertised |

This is not TLS interception. Absolute `https://` forwarding is rejected: clients
must use CONNECT for HTTPS origins. Ordinary HTTP Upgrade/WebSocket forwarding is
not implemented either. WebSocket traffic already inside CONNECT remains opaque.

### Bounded resources and lifecycle

`MaxClients` limits client TCP connections, including TLS handshakes and upgraded
HTTP/1 tunnels. `MaxConcurrentStreams` is advertised for **each H2 connection**.
`MaxInflightRequests` limits active HTTP exchanges/CONNECT streams **across the
whole process**, including HTTP/1. Excess application requests receive 503 without
an unbounded wait queue. Capacity remains held until response/tunnel and upstream
work are released. These limits are not requests-per-second rate limiting.

Each exchange has an independent progress-based `Timeout`. Traffic on a sibling
stream cannot keep an idle tunnel alive. RST_STREAM cancels that stream's work,
not the entire client connection. Graceful H2 shutdown sends GOAWAY and drains
existing work before forced termination. Hyper's stream/upgrade drivers are tracked.

H2 limits: 16 KiB decoded header-list limit, 4 KiB HPACK table, 16 KiB inbound
frame size, 65,535-byte initial stream receive window, 1 MiB connection receive
window, 64 KiB per-stream send buffer, and explicit pending/local-reset limits.
Adaptive receive-window growth is disabled. These are protocol/application limits,
**not a promised RSS bound**: TCP, TLS and library buffers also consume memory.

`HeaderTimeout` bounds HTTP/1 header reads and initial H2 preface detection.
**There is no separate per-header-block deadline for fragmented H2 HEADERS /
CONTINUATION after the preface**; a byte-active peer may still tie up connection
resources. The reset and size limits are not a complete DoS defense. Do not expose
this trusted-client proxy as an unauthenticated public service.

## Supported configuration

| Directives | Behavior |
| --- | --- |
| `Listen`, `Port` | Repeatable IP listening addresses; loopback by default. Port 0 supports embedded tests. |
| `Bind` | Outbound source IP, with address-family matching. |
| `Allow`, `Deny` | Ordered IP/CIDR, `all`, `*`; first match wins, unmatched denied when rules exist. IPv4-mapped clients normalized. No hostname ACLs. |
| `BasicAuth` | Multiple users, checked on every request/stream. |
| `ConnectPort` | First explicit value replaces defaults `[443, 563]`. Repeat to add ports; a lone 0 disables CONNECT. |
| `Timeout` | Per-connection and per-exchange idle timeout, seconds; not maximum connection age. |
| `HeaderTimeout`, `ConnectTimeout` | Header/preface and combined DNS/TCP-connect deadlines, seconds. |
| `ShutdownTimeout` | Grace period before forced shutdown, seconds. |
| `MaxClients` | Client TCP connection budget. |
| `HTTP2`, `AllowH2C` | Default Yes / No; H2 requires TLS or explicit h2c. |
| `MaxConcurrentStreams` | H2 streams per connection; default 32, range 1..=1024. |
| `MaxInflightRequests` | Global active-exchange budget; default 256. |
| `TLSCert`, `TLSKey` | PEM certificate chain and matching private key, loaded and validated before binding. No automatic certificate issuance/reload. |
| `TLSHandshakeTimeout` | Total TLS handshake deadline, default 10 seconds. |
| `Filter`, `FilterURLs`, `FilterExtended`, `FilterCaseSensitive`, `FilterDefaultDeny` | See below. |
| `ViaProxyName`, `DisableViaHeader` | Append Via with the received hop's HTTP version, unless disabled. |
| `StatHost` | Exact host match for authenticated GET/HEAD statistics, including H2/in-flight counters. |
| `LogLevel` | Error, Warn, Info, Debug, Trace, Off. |

Other directives are rejected, including upstream proxy chaining, reverse /
transparent modes, Anonymous/AddHeader, custom error pages, User/Group, PID/log
files, syslog, and legacy child-process settings. No fork/chroot is performed.

### Filtering and HTTP semantics

```conf
Filter "blocked-domains.txt"
FilterURLs No
FilterExtended No
FilterCaseSensitive No
```

Relative filter paths resolve against the configuration directory. Missing files
or invalid regexes fail startup. Changes require restart; hot reload is pending.
`FilterURLs No` filters hosts. With `FilterExtended No`, `example.com` and
`.example.com` match the domain and subdomains, not `notexample.com` or
`example.com.evil.test`. With `FilterURLs Yes`, literal rules match substrings of
HTTP URLs. `FilterExtended Yes` uses Rust regex, not POSIX BRE/ERE syntax.
`FilterDefaultDeny Yes` turns the list into an allowlist. CONNECT always filters
its authority host, never an imagined HTTPS URL path.

Proxy credentials and hop-by-hop headers are consumed in both directions.
Ordinary origin Authorization and repeated Set-Cookie fields are preserved.
HTTP/2 Cookie fields are joined with `; ` for HTTP/1 forwarding. H2 Host/authority
conflicts are rejected. Sensitive/routing/hop-by-hop fields cannot be smuggled in
forwarded trailers. Bodies stream rather than being buffered in full.

Metrics count client-facing HTTP bytes after TLS decryption, including framing,
not solely body bytes and not TLS handshake/ciphertext overhead. Initial protocol
sniffed bytes are replayed to the counted stream. Logging intentionally excludes
raw URLs, headers and credentials.

## Verification

```sh
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
cargo bench --locked
```

Tests use local sockets, ephemeral ports, and generated test-only certificates;
no public Internet origins. Coverage includes HTTP/1 regressions, H2 multiplexing,
TLS validation/fallback, stream isolation, flow control, cancellation, capacity,
preface/handshake deadlines and graceful draining. Consult current CI results for
which platforms/checks actually passed. A green suite is not a security audit,
comprehensive conformance claim, or throughput comparison.

## Security boundaries and remaining work

For trusted clients, not a sandbox or complete SSRF/DLP boundary. Source ACLs do
not constrain resolved destination IPs. Allowed clients can reach private /
loopback services unless network policy prevents this. DNS rebinding protection,
destination-IP rules, rate limiting, constant-time authentication, transactional
reload, mutual TLS, and origin connection pooling remain pending. Configuring a
proxy environment variable does not force untrusted software to use the proxy.

Future performance work requires controlled benchmarks against pinned C Tinyproxy
versions, including latency, errors, memory and content correctness. HTTP/2 support
alone does not demonstrate higher throughput or lower latency.

## License

GPL-3.0. See [LICENSE](LICENSE). Original project:
[tinyproxy/tinyproxy](https://github.com/tinyproxy/tinyproxy).
