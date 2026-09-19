#!/usr/bin/env python3
"""Bounded local-only proxy benchmarks with retained raw rounds and metadata."""
from __future__ import annotations
import argparse
import collections
import contextlib
import json
import os
from pathlib import Path
import platform
import random
import socket
import statistics
import subprocess
import tempfile
import time


def snapshot(pid: int) -> dict[str, float]:
    try:
        root = Path(f"/proc/{pid}")
        fields = (root / "stat").read_text().rsplit(") ", 1)[1].split()
        status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                  for line in (root / "status").read_text().splitlines() if ":" in line}
        return {"cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                "rss_mib": int(status.get("VmRSS", "0 kB").split()[0]) / 1024,
                "threads": int(status.get("Threads", "0")), "fds": len(list((root / "fd").iterdir()))}
    except (FileNotFoundError, ProcessLookupError):
        return {}


def stop(p: subprocess.Popen) -> None:
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)


def ready(port: int, p: subprocess.Popen) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if p.poll() is not None:
            raise RuntimeError(f"server exited with {p.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError(f"port {port} never became ready")


def checked(command: list[str]) -> str:
    return subprocess.run(command, check=True, text=True, capture_output=True, timeout=15).stdout.strip()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rust", required=True)
    ap.add_argument("--c-proxy", required=True)
    ap.add_argument("--rust-nodelay", help="optional explicitly patched experimental binary")
    ap.add_argument("--driver", required=True)
    ap.add_argument("--output", default="benchmark-results")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--seconds", type=int, default=4)
    args = ap.parse_args()
    if not 1 <= args.rounds <= 5 or not 1 <= args.seconds <= 15:
        raise ValueError("bounded rounds/duration required")
    args.rust, args.c_proxy, args.driver = [str(Path(x).resolve(strict=True)) for x in (args.rust, args.c_proxy, args.driver)]
    if args.rust_nodelay:
        args.rust_nodelay = str(Path(args.rust_nodelay).resolve(strict=True))
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 3:
        raise RuntimeError("benchmark needs >=3 logical CPUs")
    proxy_cpu, origin_cpu, driver_cpu = cpus[:3]
    env = dict(os.environ, TOKIO_WORKER_THREADS="1", GOMAXPROCS="1", RUST_LOG="off")
    for k in list(env):
        if k.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
            del env[k]
    meta = {"date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rust_commit": "d500d2510475daafa8269e09caea6d2043c26aa5",
            "c_release": "1.11.3", "c_tar_sha256": "9bcf46db1a2375ff3e3d27a41982f1efec4706cce8899ff9f33323a8218f7592",
            "kernel": platform.platform(), "cpu_affinity": cpus,
            "proxy_cpu": proxy_cpu, "origin_cpu": origin_cpu, "generator_cpu": driver_cpu,
            "lscpu": checked(["lscpu"]), "topology": checked(["lscpu", "-e=CPU,CORE,SOCKET"]),
            "go": checked(["go", "version"]), "rustc": checked(["rustc", "--version"]),
            "gcc": checked(["gcc", "--version"]).splitlines()[0],
            "curl": checked(["/usr/bin/curl", "--version"]).splitlines()[0],
            "memory": Path("/proc/meminfo").read_text(), "rounds": args.rounds, "measurement_seconds": args.seconds,
            "warmup_seconds": 1, "sampler_interval_seconds": .1,
            "runtime": {"TOKIO_WORKER_THREADS": 1, "GOMAXPROCS": 1},
            "limits": Path("/proc/self/limits").read_text(),
            "methodology": "closed-loop fixed concurrency; every response byte validated; successful full-body latency; no Internet origin or TLS bypass",
            "c_build": "release tarball ./configure --disable-manpage-support CFLAGS=-O3 -DNDEBUG; make",
            "rust_build": "cargo build --release --locked on pinned source, unchanged baseline runtime code",
            "nodelay_experiment": bool(args.rust_nodelay),
            "nodelay_change": "TCP_NODELAY=true on accepted and outgoing sockets; separate binary, same base/dependencies",
            "limits_note": "affinity uses logical CPUs; SMT siblings may share a physical core"}
    (out / "metadata.json").write_text(json.dumps(meta, indent=2))
    print("METADATA " + json.dumps(meta), flush=True)
    with tempfile.TemporaryDirectory(prefix="proxy-benchmark-cert-") as certdir:
        cert, key = Path(certdir) / "cert.pem", Path(certdir) / "key.pem"
        checked(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                 "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"])
        key.chmod(0o600)
        @contextlib.contextmanager
        def service(impl: str, name: str):
            if impl == "direct":
                yield None
                return
            binary = args.c_proxy if impl == "c" else (args.rust_nodelay if "nodelay" in impl else args.rust)
            port = 18889 if impl.endswith("-tls") else 18888
            common = f"Listen 127.0.0.1\nPort {port}\nTimeout 60\nMaxClients 1024\nAllow 127.0.0.1\nConnectPort 18081\n"
            if impl == "c":
                # Default stdout is captured below. Tinyproxy's safe file opener
                # rejects /dev/null as a non-regular log file.
                content = common + "LogLevel Critical\nPidFile /tmp/tinyproxy-benchmark.pid\n"
            else:
                content = common + "LogLevel Off\nShutdownTimeout 1\nMaxInflightRequests 1024\nMaxConcurrentStreams 32\n"
                content += f"TLSCert {cert}\nTLSKey {key}\nHTTP2 Yes\n" if impl.endswith("-tls") else "AllowH2C Yes\n"
            conf = out / f"{name}.conf"
            conf.write_text(content)
            log = (out / f"{name}.proxy.log").open("wb")
            cmd = ["taskset", "-c", str(proxy_cpu), binary, "-c", str(conf)]
            if impl == "c": cmd.append("-d")
            p = subprocess.Popen(cmd, stdout=log, stderr=log, env=env)
            try:
                try:
                    ready(port, p)
                except RuntimeError as error:
                    raise RuntimeError(f"{name}: {error}: " + (out / f"{name}.proxy.log").read_text(errors="replace")) from error
                time.sleep(.2)
                yield p
            finally:
                stop(p)
                log.close()
                conf.write_text(content.replace(str(cert), "TEST_CERT.pem").replace(str(key), "TEST_KEY.pem"))

        origin_log = (out / "origin.log").open("wb")
        origin = subprocess.Popen(["taskset", "-c", str(origin_cpu), args.driver, "-mode=origin"], env=env, stdout=origin_log, stderr=origin_log)
        try:
            ready(18080, origin)
            cases = []
            def case(name, impl, proto="h1", c=32, size=1024, method="GET", fresh=False, kind="http"):
                cases.append(dict(name=name, impl=impl, protocol=proto, c=c, size=size, method=method, fresh=fresh, kind=kind))
            case("direct-h1-fresh-32", "direct", fresh=True)
            case("direct-h1-fresh-128", "direct", c=128, fresh=True)
            case("direct-h1-reuse-32", "direct")
            case("direct-get-1MiB-8", "direct", c=8, size=1<<20, fresh=True)
            for impl in ("c", "rust"):
                for c in (1, 32, 128):
                    case(f"{impl}-h1-fresh-{c}", impl, c=c, fresh=True)
                case(f"{impl}-h1-reuse-32", impl)
                case(f"{impl}-get-1MiB-8", impl, c=8, size=1<<20, fresh=True)
                case(f"{impl}-post-1MiB-8", impl, c=8, size=1<<20, method="POST", fresh=True)
            for proto in ("h2c", "h2tls"):
                for c in (1, 32, 128):
                    case(f"rust-{proto}-{c}", "rust-tls" if proto == "h2tls" else "rust", proto, c)
            case("rust-h1tls-reuse-32", "rust-tls", "h1tls")
            case("rust-h2tls-get-1MiB-8", "rust-tls", "h2tls", 8, 1<<20)
            for impl, proto in (("direct", "h1"), ("c", "h1"), ("rust", "h1"), ("rust-tls", "h2tls")):
                case(f"{impl}-{proto}-tunnel-1MiB-8", impl, proto, 8, 1<<20, kind="tunnel")
            if args.rust_nodelay:
                for proto in ("h2c", "h2tls"):
                    for c in (1, 32):
                        case(f"nodelay-{proto}-{c}", "rust-nodelay-tls" if proto == "h2tls" else "rust-nodelay", proto, c)
                case("nodelay-h1-reuse-32", "rust-nodelay")
                case("nodelay-post-1MiB-8", "rust-nodelay", c=8, size=1<<20, method="POST", fresh=True)
                case("nodelay-h1-tunnel-1MiB-8", "rust-nodelay", c=8, size=1<<20, kind="tunnel")
            (out / "cases.json").write_text(json.dumps(cases, indent=2))
            all_rounds = []
            rng = random.Random(20260919)
            for r in range(1, args.rounds + 1):
                order = cases.copy(); rng.shuffle(order)
                for item in order:
                    name = f"r{r}-{item['name']}"
                    with service(item["impl"], name) as p:
                        port = 18889 if item["impl"].endswith("-tls") else 18888
                        command = ["taskset", "-c", str(driver_cpu), args.driver,
                                   f"-protocol={item['protocol']}", f"-c={item['c']}", f"-size={item['size']}",
                                   f"-method={item['method']}", f"-kind={item['kind']}",
                                   f"-connections={(item['c'] + 31)//32}", f"-ca={cert}",
                                   f"-duration={args.seconds}s", "-warmup=1s", "-fresh="+str(item["fresh"]).lower(),
                                   "-target=127.0.0.1:" + ("18080" if item["kind"] == "http" else "18081")]
                        if p is not None: command.append(f"-proxy=127.0.0.1:{port}")
                        stdout = (out / f"{name}.jsonl").open("w")
                        stderr = (out / f"{name}.load.log").open("w")
                        loader = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=env)
                        pids = {"origin": origin.pid, "generator": loader.pid}
                        if p is not None: pids["proxy"] = p.pid
                        initial = {k: snapshot(v) for k, v in pids.items()}
                        samples = collections.defaultdict(list)
                        start = time.monotonic()
                        try:
                            while loader.poll() is None:
                                if time.monotonic() - start > args.seconds + 40: raise RuntimeError(f"load deadline {name}")
                                for k, v in pids.items():
                                    s = snapshot(v)
                                    if s: samples[k].append(s)
                                time.sleep(.1)
                            elapsed = time.monotonic() - start
                        finally:
                            stop(loader); stdout.close(); stderr.close()
                        if loader.returncode:
                            raise RuntimeError(f"load failed {name}: " + (out / f"{name}.load.log").read_text()[-5000:])
                        result = json.loads((out / f"{name}.jsonl").read_text())
                        result.update(case=item["name"], round=r)
                        for k, values in samples.items():
                            begin = initial[k].get("cpu_seconds", 0)
                            result[f"{k}_cpu_pct"] = (values[-1]["cpu_seconds"] - begin) / elapsed * 100
                            result[f"{k}_peak_rss_mib"] = max(s["rss_mib"] for s in values)
                            result[f"{k}_peak_threads"] = max(s["threads"] for s in values)
                            result[f"{k}_peak_fds"] = max(s["fds"] for s in values)
                        all_rounds.append(result)
                        (out / "rounds.json").write_text(json.dumps(all_rounds, indent=2))
                        print(f"ROUND {r} {item['name']}: {result['rps']:.1f} req/s p99={result['p99_ms']:.3f}ms errors={result['errors']}", flush=True)

            idle = []
            for impl, proto in (("c", "h1"), ("rust", "h1"), ("rust-tls", "h2tls")):
                for c in (128, 512):
                    name = f"idle-{impl}-{proto}-{c}"
                    with service(impl, name) as p:
                        baseline = snapshot(p.pid)
                        port = 18889 if impl.endswith("-tls") else 18888
                        output = (out / f"{name}.jsonl").open("w")
                        errfile = (out / f"{name}.log").open("w")
                        loader = subprocess.Popen(["taskset", "-c", str(driver_cpu), args.driver, "-kind=idle", f"-protocol={proto}",
                                                   f"-proxy=127.0.0.1:{port}", "-target=127.0.0.1:18081", f"-c={c}",
                                                   f"-connections={(c+31)//32}", f"-ca={cert}", "-hold=6s"],
                                                  env=env, stdout=output, stderr=errfile)
                        try:
                            deadline = time.monotonic() + 30
                            while not (out / f"{name}.jsonl").read_text().strip():
                                if loader.poll() is not None or time.monotonic() > deadline:
                                    raise RuntimeError("idle setup: " + (out / f"{name}.log").read_text())
                                time.sleep(.1)
                            detail = json.loads((out / f"{name}.jsonl").read_text())
                            time.sleep(.5)
                            occupied = snapshot(p.pid)
                            t = time.monotonic(); time.sleep(3)
                            after = snapshot(p.pid)
                            detail.update(case=name, baseline=baseline, occupied=occupied,
                                          idle_cpu_pct=(after["cpu_seconds"]-occupied["cpu_seconds"])/(time.monotonic()-t)*100)
                            loader.wait(timeout=15)
                            time.sleep(1)
                            detail["after_close"] = snapshot(p.pid)
                            idle.append(detail)
                            print("IDLE " + json.dumps(detail), flush=True)
                        finally:
                            stop(loader); output.close(); errfile.close()
            (out / "idle.json").write_text(json.dumps(idle, indent=2))
            summary = []
            for item in cases:
                rs = [x for x in all_rounds if x["case"] == item["name"]]
                row = {"case": item["name"], "success_total": sum(x["success"] for x in rs), "errors_total": sum(x["errors"] for x in rs),
                       "warmup_errors_total": sum(x["warmup_errors"] for x in rs)}
                for k in ("rps", "mib_s", "p50_ms", "p99_ms", "proxy_cpu_pct", "proxy_peak_rss_mib", "proxy_peak_threads",
                          "proxy_peak_fds", "generator_cpu_pct", "origin_cpu_pct", "tcp_dials_including_warmup"):
                    row[k] = statistics.median(x.get(k, 0) for x in rs)
                row["rps_min"] = min(x["rps"] for x in rs); row["rps_max"] = max(x["rps"] for x in rs)
                summary.append(row)
            (out / "summary.json").write_text(json.dumps(summary, indent=2))
            print("SUMMARY_JSON " + json.dumps(summary, separators=(",", ":")), flush=True)
            lines = ["# Loopback benchmark — pinned proxy implementations", "", "Rust: `d500d2510475daafa8269e09caea6d2043c26aa5`; C: `1.11.3`.", "",
                     f"{args.rounds} rounds; 1 s warmup + {args.seconds} s measurement. Shuffled order. One logical CPU per process; physical cores may be shared through SMT.", "",
                     "Cases prefixed nodelay use a separate experimental binary with TCP_NODELAY enabled; this is not main.", "",
                     "Closed-loop latency, successful full-body responses only; not an open-loop tail-latency SLA. All response bytes checked. RSS/CPU sampled over warmup and measurement. Shared CI runner, no WAN/TLS-loss modeling.", "",
                     "Values are medians of per-round values. RPS is completed, validated responses / elapsed measurement+drain time. Tunnel MiB/s is one-way payload; echo carries the same payload back.", "",
                     "| Case | req/s | req/s range | MiB/s | p50 ms | p99 ms | errors | proxy RSS MiB | proxy CPU % |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
            for x in summary:
                lines.append(f"| {x['case']} | {x['rps']:.1f} | {x['rps_min']:.1f}–{x['rps_max']:.1f} | {x['mib_s']:.1f} | {x['p50_ms']:.3f} | {x['p99_ms']:.3f} | {x['errors_total']} | {x['proxy_peak_rss_mib']:.2f} | {x['proxy_cpu_pct']:.1f} |")
            lines += ["", "## Held CONNECT tunnels", "", "Idle cases are one observation, not repeated or a leak/soak certification.", "", "| Case | Established | TCP connections | RSS MiB | threads | FDs | idle CPU % | FDs after close |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
            for x in idle:
                s = x["occupied"]
                lines.append(f"| {x['case']} | {x['ready_idle']} | {x['tcp_connections']} | {s['rss_mib']:.2f} | {s['threads']} | {s['fds']} | {x['idle_cpu_pct']:.2f} | {x['after_close']['fds']} |")
            (out / "REPORT.md").write_text("\n".join(lines) + "\n")
            if os.environ.get("GITHUB_STEP_SUMMARY"):
                with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f: f.write("\n".join(lines) + "\n")
            if any(x["errors_total"] or x["warmup_errors_total"] for x in summary) or any(x["errors"] for x in idle):
                raise RuntimeError("benchmark recorded errors; consult report, do not claim clean performance")
        finally:
            stop(origin); origin_log.close()

if __name__ == "__main__":
    main()
