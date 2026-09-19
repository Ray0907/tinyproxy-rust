#!/usr/bin/env python3
"""Bounded loopback baseline/candidate comparison using the pinned Go driver.

Linux only. Run with --baseline, --candidate, --driver and --output paths.
Certificates are verified and temporary keys never enter the output directory.
"""
from __future__ import annotations

import argparse
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


def command(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, check=True,
                          timeout=30, **kwargs).stdout.strip()


def snapshot(pid):
    try:
        root = Path(f'/proc/{pid}')
        status = dict(line.split(':', 1) for line in (root / 'status').read_text().splitlines())
        stat = (root / 'stat').read_text().rsplit(')', 1)[1].split()
        return {'rss_kib': int(status.get('VmRSS', '0 kB').split()[0]),
                'threads': int(status['Threads']), 'fds': len(list((root / 'fd').iterdir())),
                'cpu_s': (int(stat[11]) + int(stat[12])) / os.sysconf('SC_CLK_TCK'),
                'time': time.monotonic()}
    except (OSError, KeyError, ValueError):
        return None


@contextlib.contextmanager
def process(args, log, cpu):
    env = dict(os.environ, TOKIO_WORKER_THREADS='1', GOMAXPROCS='1')
    with log.open('w') as output:
        p = subprocess.Popen(['taskset', '-c', str(cpu), *args], stdout=output,
                             stderr=subprocess.STDOUT, env=env)
        try:
            yield p
        finally:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=4)


def ready(p, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if p.poll() is not None:
            raise RuntimeError(f'process exited: {p.returncode}')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError('listener not ready')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'driver', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--seconds', type=float, default=2)
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 30 or not 1 <= args.rounds <= 10:
        parser.error('seconds must be 1..30 and rounds 1..10')
    binaries = {v: str(Path(getattr(args, v)).resolve(strict=True)) for v in ('baseline', 'candidate')}
    driver = str(Path(args.driver).resolve(strict=True))
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 3:
        raise RuntimeError('at least three available logical CPUs are required')
    metadata = {'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'kernel': platform.platform(), 'topology': command(['lscpu', '-e=CPU,CORE,SOCKET']),
                'cpu': command(['lscpu']), 'proxy_cpu': cpus[0], 'origin_cpu': cpus[1],
                'generator_cpu': cpus[2], 'rounds': args.rounds, 'seconds': args.seconds,
                'warmup_s': 1, 'seed': 20260919, 'affinity_note': 'logical CPUs may share an SMT core',
                'method': 'closed-loop; full successful body latency; byte-verified payloads',
                'cpu_note': 'sampled CPU over setup/warmup/measurement; not isolated request CPU',
                'rss_note': 'sampled process RSS, not kernel socket memory',
                'clock_ticks': os.sysconf('SC_CLK_TCK')}
    (out / 'transport-environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
    # name, protocol, kind, method, payload size, concurrency, fresh
    cases = [
        ('h2c-1', 'h2c', 'http', 'GET', 1024, 1, False),
        ('h2c-32', 'h2c', 'http', 'GET', 1024, 32, False),
        ('h2tls-1', 'h2tls', 'http', 'GET', 1024, 1, False),
        ('h2tls-32', 'h2tls', 'http', 'GET', 1024, 32, False),
        ('h1-fresh-32', 'h1', 'http', 'GET', 1024, 32, True),
        ('h1-reuse-32', 'h1', 'http', 'GET', 1024, 32, False),
        ('h1-get-1MiB', 'h1', 'http', 'GET', 1048576, 8, True),
        ('h1-post-1MiB', 'h1', 'http', 'POST', 1048576, 8, True),
        ('h1-tunnel-1MiB', 'h1', 'tunnel', 'GET', 1048576, 8, False),
        ('h2tls-tunnel-1MiB', 'h2tls', 'tunnel', 'GET', 1048576, 8, False),
    ]
    rounds, idle = [], []
    rng = random.Random(20260919)
    with tempfile.TemporaryDirectory(prefix='transport-bench-') as temp:
        root = Path(temp)
        cert, key = root / 'cert.pem', root / 'key.pem'
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', str(key), '-out', str(cert), '-days', '1',
                 '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'])
        key.chmod(0o600)

        @contextlib.contextmanager
        def proxy(version, proto, name):
            conf = root / (name + '.conf')
            text = ('Listen 127.0.0.1\nPort 18888\nTimeout 60\nMaxClients 1024\n'
                    'Allow 127.0.0.1\nConnectPort 18081\nLogLevel Off\n'
                    'ShutdownTimeout 1\nMaxInflightRequests 1024\nMaxConcurrentStreams 32\n')
            if proto == 'h2tls':
                text += f'TLSCert "{cert}"\nTLSKey "{key}"\nHTTP2 Yes\n'
            else:
                text += 'AllowH2C Yes\n'
            conf.write_text(text)
            (out / (name + '.conf')).write_text(text.replace(str(root), '<temporary-cert-dir>'))
            log = out / (name + '.proxy.log')
            with process([binaries[version], '-c', str(conf)], log, cpus[0]) as p:
                try:
                    ready(p, 18888)
                    time.sleep(0.1)  # Let the readiness-probe socket be released.
                    yield p
                except Exception:
                    print(log.read_text(errors='replace'), flush=True)
                    raise

        with process([driver, '-mode', 'origin'], out / 'origin.log', cpus[1]) as origin:
            ready(origin, 18080)
            for round_id in range(1, args.rounds + 1):
                jobs = [(version, case) for version in binaries for case in cases]
                rng.shuffle(jobs)
                for version, case in jobs:
                    label, proto, kind, method, size, count, fresh = case
                    name = f'r{round_id}-{version}-{label}'
                    with proxy(version, proto, name) as p:
                        cmd = [driver, '-protocol', proto, '-kind', kind, '-proxy', '127.0.0.1:18888',
                               '-target', '127.0.0.1:' + ('18080' if kind == 'http' else '18081'),
                               '-ca', str(cert), '-c', str(count), '-connections', '1',
                               '-size', str(size), '-method', method, '-warmup', '1s',
                               '-duration', f'{args.seconds}s', '-fresh=' + str(fresh).lower()]
                        log = out / (name + '.driver.log')
                        samples = {'proxy': [], 'origin': [], 'generator': []}
                        with process(cmd, log, cpus[2]) as load:
                            deadline = time.monotonic() + args.seconds + 30
                            while load.poll() is None:
                                if time.monotonic() > deadline:
                                    raise TimeoutError(name)
                                for role, proc in [('proxy', p), ('origin', origin), ('generator', load)]:
                                    s = snapshot(proc.pid)
                                    if s:
                                        samples[role].append(s)
                                time.sleep(0.05)
                            if load.returncode != 0:
                                raise RuntimeError(name + ': ' + log.read_text(errors='replace'))
                        result = json.loads(log.read_text())
                        result.update(version=version, workload=label, round=round_id, samples=samples)
                        rounds.append(result)
                        (out / 'transport-rounds.json').write_text(json.dumps(rounds, indent=2) + '\n')
                        print(f'{name}: {result["rps"]:.1f} req/s p99={result["p99_ms"]:.3f} ms errors={result["errors"]}', flush=True)
                        if result['errors'] or result['warmup_errors'] or not result['success']:
                            raise RuntimeError(f'{name}: request validation failed')
            for version in binaries:
                for proto in ('h1', 'h2tls'):
                    name = f'idle-{version}-{proto}'
                    with proxy(version, proto, name) as p:
                        before = snapshot(p.pid)
                        log = out / (name + '.driver.log')
                        cmd = [driver, '-kind', 'idle', '-protocol', proto, '-proxy', '127.0.0.1:18888',
                               '-target', '127.0.0.1:18081', '-ca', str(cert), '-c', '512',
                               '-connections', '16', '-hold', '3s']
                        with process(cmd, log, cpus[2]) as load:
                            deadline = time.monotonic() + 15
                            while not log.read_text().endswith('\n'):
                                if load.poll() is not None or time.monotonic() > deadline:
                                    raise RuntimeError(name + ': no idle setup result')
                                time.sleep(0.02)
                            setup = json.loads(log.read_text())
                            if setup['errors'] or setup['ready_idle'] != 512:
                                raise RuntimeError(f'{name}: {setup}')
                            occupied = snapshot(p.pid)
                            load.wait(timeout=10)
                            if load.returncode != 0:
                                raise RuntimeError(name + ': idle generator failed')
                        time.sleep(1)
                        after = snapshot(p.pid)
                        entry = dict(version=version, protocol=proto, setup=setup,
                                     before=before, occupied=occupied, after=after)
                        idle.append(entry)
                        (out / 'transport-idle.json').write_text(json.dumps(idle, indent=2) + '\n')
                        print('IDLE ' + json.dumps(entry), flush=True)
                        if not before or not after or after['fds'] != before['fds']:
                            raise RuntimeError(name + ': descriptors did not return to baseline')
    summary = []
    for label, *_ in cases:
        for version in binaries:
            group = [r for r in rounds if r['workload'] == label and r['version'] == version]
            summary.append(dict(workload=label, version=version, rounds=len(group),
                                **{k: statistics.median(r[k] for r in group)
                                   for k in ('rps', 'mib_s', 'p50_ms', 'p99_ms')},
                                rps_min=min(r['rps'] for r in group), rps_max=max(r['rps'] for r in group),
                                errors=sum(r['errors'] for r in group)))
    (out / 'transport-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('SUMMARY ' + json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
