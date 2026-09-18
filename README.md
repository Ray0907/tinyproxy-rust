# Tinyproxy-Rust

[![CI](https://github.com/Ray0907/tinyproxy-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/Ray0907/tinyproxy-rust/actions/workflows/ci.yml)

A small HTTP/1 forward proxy and HTTPS CONNECT tunnel, written in Rust.

The hardening implementation uses Hyper for HTTP message parsing and streaming,
and Tokio for TCP tunnels. It is **not a complete drop-in replacement** for C
Tinyproxy. Unsupported directives fail at startup instead of being silently
accepted. This project has not yet demonstrated a performance advantage over C
Tinyproxy; the included Criterion benchmarks are microbenchmarks, not proxy
throughput comparisons.

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

The binary stays in the foreground. `-d` / `--foreground` explicitly selects the
same behavior. `--debug` initializes the logger once. `-v` / `--version` displays
the package version. An unreadable or missing configuration is an error, not a
request to start an unauthenticated listener with defaults.

Run as an unprivileged user under a service manager. SIGINT and, on Unix,
SIGTERM stop new accepts, drain active work, and force-close remaining sockets
after `ShutdownTimeout`. This implementation does not fork, change users,
write PID files, or implement chroot. Existing configurations containing those
directives must be migrated explicitly.

## Minimal configuration

The syntax is Tinyproxy-style key/value lines, **not TOML**. Quoted values and
comments beginning with `#` at a token boundary are supported.

```conf
Listen 127.0.0.1
Port 8888
MaxClients 100
Timeout 600
HeaderTimeout 30
ConnectTimeout 30
ShutdownTimeout 5
ConnectPort 443
LogLevel Info
```

The default listener is loopback only. Listening on a non-loopback address
requires explicit ACL rules or BasicAuth. `Allow all` is an explicit public
access choice; do not use it on an Internet-accessible unauthenticated proxy.
`Bind` sets the **outgoing** source IP and never changes the listener.

Authentication can contain multiple users:

```conf
BasicAuth alice "a password with spaces"
BasicAuth bob another-password
```

The old Rust `BasicAuth user:password` syntax is also accepted. Missing fields,
empty credentials, duplicate usernames, and malformed lines are rejected.
Configuration errors include line numbers without printing credential values.

**Basic authentication does not encrypt the client-to-proxy hop.** Use it only
on a trusted network or through an independently protected transport. HTTPS
through CONNECT protects the destination TLS session; it does not turn this
proxy's listening socket into a TLS listener.

## Supported configuration and compatibility

| Directives | Behavior |
| --- | --- |
| `Listen`, `Port` | Repeatable listening addresses; loopback by default. Port 0 is useful for embedded tests. |
| `Bind` | Outbound source IP, including address-family matching. |
| `Allow`, `Deny` | IP/CIDR, `all`, or `*`. First matching rule wins; unmatched clients are denied when any rules exist. Hostname ACLs are not supported. IPv4-mapped clients are normalized. |
| `BasicAuth` | Multiple username/password pairs; checked on every HTTP request. |
| `ConnectPort` | First explicit directive replaces defaults `[443, 563]`; repeat to add ports. A lone `ConnectPort 0` disables CONNECT. Mixing 0 and real ports is an error. |
| `Timeout` | Idle timeout in seconds, reset by actual I/O progress in either direction; not a maximum tunnel lifetime. |
| `HeaderTimeout` | Total time to receive a request header, in seconds; trickling bytes does not reset it. |
| `ConnectTimeout` | Combined DNS resolution and TCP connect deadline, in seconds. |
| `ShutdownTimeout` | Grace period before remaining connections are force-closed. |
| `MaxClients` | Connection limit, retained for the full CONNECT tunnel lifetime. |
| `Filter`, `FilterURLs`, `FilterExtended`, `FilterCaseSensitive`, `FilterDefaultDeny` | See filtering below. |
| `ViaProxyName`, `DisableViaHeader` | Append the proxy's Via value, preserving prior Via entries, unless disabled. |
| `StatHost` | Exact destination-host match for an authenticated GET/HEAD HTML statistics page. |
| `LogLevel` | Rust log levels such as Error, Warn, Info, Debug, Trace, and Off. |

All other directives are rejected. In particular, upstream proxy chaining,
reverse/transparent modes, `Anonymous`, `AddHeader`, custom error pages,
`User`/`Group`, `PidFile`, `LogFile`/`Syslog`, and legacy child-process settings
are **not implemented**. Previous helper functions and configuration fields
that did not participate in actual forwarding have been removed rather than
advertised as working features.

### Filtering

```conf
Filter "blocked-domains.txt"
FilterURLs No
FilterExtended No
FilterCaseSensitive No
```

Relative filter paths resolve against the configuration's directory. Policies
are loaded and compiled once before sockets are bound. Missing files and invalid
regular expressions are startup errors; invalid expressions are not converted
to permissive literal rules. Changes require a restart; hot reload is not yet
implemented.

With `FilterURLs No`, filtering still operates, but uses the destination host.
With `FilterExtended No`, lines such as `example.com` or `.example.com` match
the domain and its subdomains, not `notexample.com` or `example.com.evil.test`.
With `FilterURLs Yes`, literal rules are substring matches against the HTTP URL.
`FilterExtended Yes` selects Rust regular expressions; this is **not POSIX BRE/ERE
syntax compatibility**. `FilterDefaultDeny Yes` makes matching rules an allowlist.
By default, matching rules are blocked.

CONNECT is always filtered by its authority host, never by an imagined HTTPS
URL path. The encrypted request contents are not inspected.

## HTTP and connection behavior

HTTP requests are parsed and forwarded individually, including successive
requests to different origins over one client connection. Bodies remain
streaming. Direct-origin requests use origin-form paths with a Host header
derived from the chosen authority. Absolute `https://` forwarding is rejected;
clients must use CONNECT rather than accidentally sending plaintext to a TLS
port. HTTP Upgrade/WebSocket forwarding is not yet supported.

Proxy credentials and hop-by-hop headers are consumed at the proxy boundary;
ordinary origin `Authorization`, multiple `Set-Cookie` fields, and end-to-end
headers are preserved. Hyper owns body framing instead of converting all
headers into a single-value string map. Request headers are bounded by a 16 KiB
connection buffer and a total read deadline.

CONNECT uses Tokio's bidirectional copy, including half-close handling and
bytes buffered beyond the initial CONNECT header. HTTP connections, upstream
drivers, and upgraded tunnels are tracked during shutdown. Counters use atomics;
wire-byte counters refer to the client-facing socket, including HTTP headers,
not solely response payloads.

## Verification

```sh
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
cargo bench --locked
```

Regression tests use local sockets and ephemeral ports, not public Internet
endpoints. They cover configuration failure modes, credentials and hop-by-hop
headers, repeated requests, origin selection, domain filters, chunked and large
uploads, Expect/100-continue, conflicting Content-Length values, early CONNECT
data, half-close, connection limits, slow headers, and shutdown.

A passing test suite is not a comprehensive security audit or evidence that
all HTTP edge cases are covered. Cross-implementation differential tests,
fuzzing, prolonged load tests, and controlled end-to-end performance comparisons
remain follow-up work.

## Security boundaries and remaining work

This is a trusted-client forward proxy, not a sandbox or a complete SSRF/DLP
boundary. Client ACLs constrain who connects; they do not restrict resolved
destination IPs. Allowed clients can reach private/loopback destinations and
allowed CONNECT ports unless separately restricted by the network. DNS rebinding
protection, destination-IP policy, TLS listeners, rate limiting, and constant-time
authentication are not provided by this revision. Setting a proxy environment
variable also does not force an untrusted program to use the proxy.

Next priorities are end-to-end benchmarks against pinned C Tinyproxy versions,
additional protocol/adversarial tests, measured HTTP connection pooling,
transactional policy reload, and simpler deployment packages. No external service
or database is required by the current executable.

## License

GPL-3.0. See [LICENSE](LICENSE). Original project:
[tinyproxy/tinyproxy](https://github.com/tinyproxy/tinyproxy).
