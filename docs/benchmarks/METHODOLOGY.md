# End-to-end benchmark methodology

## What is being tested

The baseline is the exact runtime source at `d500d2510475daafa8269e09caea6d2043c26aa5`, including its Cargo.lock, built with `cargo build --release --locked`. The comparator is the official C Tinyproxy 1.11.3 release tarball, checked against SHA-256 `9bcf46db1a2375ff3e3d27a41982f1efec4706cce8899ff9f33323a8218f7592` and built with `./configure --disable-manpage-support CFLAGS='-O3 -DNDEBUG'` and `make`.

An optional second Rust executable enables TCP_NODELAY on accepted and outgoing TCP sockets. It is labeled `nodelay-*`, never reported as the unmodified baseline, and is not committed to main by the benchmark workflow. Its exact diff and executable digest are retained. Baseline and experiment both run the regression suite and verified-TLS curl interoperability tests before measurement.

The independent Go load generator and origin live under `benchmarks/e2e`. The runner resolves the explicitly selected Go module version and retains go.mod/go.sum, compiler versions, source commits, executable hashes, CPU topology, memory and file-descriptor limits. Go is test tooling only; the proxy runtime remains Rust and requires no external service or database.

## Workloads and accounting

The driver uses loopback-only local HTTP and echo servers. Requests are never sent to Internet origins. GET bodies and POST upload/response bodies are verified byte for byte. Compression is disabled. HTTP errors, protocol errors, size/content mismatches, transport failures and timeouts are counted rather than included as successful throughput.

Each case has a 1-second warmup and a 4-second measured admission window, repeated three times. Case order is shuffled with seed 20260919. Each proxy process starts afresh for each case; the origin persists. Throughput divides successful completions by elapsed measurement time including the final admitted requests draining. Latencies cover complete successful bodies, not just response headers. Failed request counts and examples, including warmup errors, are retained separately. Percentiles and throughput in the summary are medians of per-round values, not pooled percentiles; raw rounds preserve all reported values and round-to-round throughput ranges.

HTTP/1 has separate `fresh` and `reuse` cases. `fresh` disables client connection reuse. `reuse` permits reuse, but an implementation can close a connection, requiring the client to redial. The driver reports actual TCP dial counts including warmup. These two cases must not be conflated when discussing implementation efficiency.

HTTP/2 cases use exactly one client-to-proxy connection for 1 or 32 workers and four connections for 128 workers, with at most 32 concurrent streams per connection. Plain HTTP origins are still reached via HTTP/1.1 by the Rust proxy; this benchmark is not an HTTP/2 origin pooling benchmark. `h2c` is cleartext prior knowledge; `h2tls` verifies a generated localhost certificate and confirms ALPN `h2`. `h1tls` is a TLS proxy-hop control, not ordinary cleartext HTTP/1.

CONNECT throughput sends a 1 MiB payload to a raw TCP echo origin and receives the same bytes back, with concurrent upload/read to avoid artificial flow-control deadlocks. The reported MiB/s counts the payload in one direction; the network carries the same amount back. It does not include tunnel establishment. A TLS-to-proxy H2 tunnel is not cryptographically cost-equivalent to a plaintext C/H1 tunnel.

Idle cases hold 128 or 512 CONNECT tunnels. H2 packs these into 4 or 16 client-to-proxy TCP connections respectively; each tunnel still has its own origin TCP connection. The script records before-load RSS/threads/FDs, occupied values, three seconds of idle CPU, and values one second after closing all client connections. These are individual observations, not a long-running memory-leak test.

## Resource controls and limitations

Proxy, origin and load generator have separate logical-CPU affinities. Rust uses one Tokio worker and Go uses GOMAXPROCS=1. Logical CPUs can be SMT siblings on shared physical cores; affinity is not physical-core isolation and the retained topology must be consulted. Both proxy implementations are subject to the same one-logical-CPU affinity. MaxClients is 1024; Rust MaxInflightRequests is 1024 and MaxConcurrentStreams is 32. Both allow only localhost clients in these tests. Logging is suppressed to the lowest practical level (Off for Rust, Critical for C); normal per-request logging, authentication and filter costs are not included in the throughput tests.

Resource sampling reads /proc every 100 ms over setup/warmup/measurement. Peak RSS is a sampled resident-process maximum, not virtual address space and not kernel socket memory. CPU percentages refer to one logical CPU; short bursts and process exit can cause sampling error. Samples lost to a procfs exit race are skipped; the independent load generator's success/error accounting is not changed. Direct-to-origin workloads and generator/origin CPU measurements provide checks for test-side bottlenecks, but do not eliminate them.

This is a short, closed-loop benchmark on a shared CI VM. It does not establish open-loop p99/p999 service-level objectives, WAN performance, packet-loss behavior, long-duration stability, DoS resistance, full HTTP conformance, or performance on another CPU. Closed-loop latency can hide queueing under a fixed arrival rate. Low-concurrency TLS cases do not include a new TLS handshake for every request. No broad claim that Rust or HTTP/2 is intrinsically faster is justified.

## Incomplete attempts and harness corrections

Early attempts failed because optional C file-path directives were unquoted. The initial LogFile /dev/null choice was also unsuitable: even a correctly quoted /dev/null is not a regular log file accepted by C Tinyproxy's safe opener. The corrected foreground configuration omits both LogFile and PidFile and captures stdout instead. It performs a validated HTTP preflight on every proxy mode before timed rounds.

A subsequent attempt successfully measured both proxies but the monitor stopped on PermissionError while inspecting /proc/<pid>/fd as a load-generator process exited. The sampler now skips OSError exit races; it does not modify or suppress the driver's request-error counts. These are harness setup/monitoring failures, not measured proxy correctness failures or zero-throughput results. Incomplete attempts remain separate artifacts and are not pooled into a completed run's three-round summary. Runner CPU models may differ between attempts, making such pooling particularly inappropriate.

## Running and retaining results

Run `.github/workflows/benchmark-e2e.yml` from the benchmark branch. It has read-only repository permissions, checks out the pinned baseline separately, builds all executables, tests baseline and experiment, executes shuffled measurements, and uploads `benchmark-results` even if a case fails. The report appears in the Actions job summary. Artifacts are retained for 30 days; copy important results before they expire. Generated test private keys stay outside the uploaded result directory.

For local reproduction, use a Linux machine with at least three available logical CPUs, Rust, Go, gcc/make, Python 3.10+, taskset, openssl and HTTP/2-enabled curl 8.1+. Reproduce the build commands from the workflow and then run:

```sh
ulimit -n 32768
python3 benchmarks/e2e/run.py \
  --rust ./rust-baseline \
  --c-proxy ./c-source/src/tinyproxy \
  --driver ./bench-driver \
  --output benchmark-results --rounds 3 --seconds 4
```

To add the labeled TCP_NODELAY experiment, build it separately using the reviewed `nodelay_experiment.py` on a disposable checkout and pass `--rust-nodelay ./rust-nodelay`. Do not overwrite the baseline executable. Consult the workflow for the exact build and validation sequence. The configuration and payload formats are intentionally identical for paired baseline/experimental cases.
