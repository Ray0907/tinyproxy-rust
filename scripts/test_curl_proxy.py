#!/usr/bin/env python3
"""Offline curl interoperability test; generates throwaway TLS credentials.

Run after cargo build --release:
    python3 scripts/test_curl_proxy.py --curl /usr/bin/curl
Requires Python 3.10+, openssl, and curl 8.1+ compiled with HTTP2 support.
No certificate verification is disabled and no Internet origin is contacted.
"""
from __future__ import annotations

import argparse
import http.server
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import threading
import time

PAYLOAD = b"tinyproxy-curl-ok"


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        leaked = self.headers.get("Proxy-Authorization") is not None
        body = b"proxy-credentials-leaked" if leaked else PAYLOAD
        self.send_response(500 if leaked else 200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def run(command: list[str], seconds: float = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=seconds, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/release/tinyproxy-rust")
    parser.add_argument("--curl", default="curl")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve(strict=True))
    version = run([args.curl, "--version"]).stdout
    if "HTTP2" not in version:
        raise RuntimeError("curl must be built with HTTP2 support")
    print(version.splitlines()[0], flush=True)

    with tempfile.TemporaryDirectory(prefix="tinyproxy-curl-") as directory:
        root = Path(directory)
        certificate = root / "cert.pem"
        key = root / "key.pem"
        run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ])
        key.chmod(0o600)
        plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        secure = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certificate), str(key))
        context.set_alpn_protocols(["http/1.1"])
        secure.socket = context.wrap_socket(secure.socket, server_side=True)
        servers = [plain, secure]
        for server in servers:
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()

        configuration = root / "proxy.conf"
        configuration.write_text(
            "Listen 127.0.0.1\nPort 0\nTLSCert cert.pem\nTLSKey key.pem\n"
            "HTTP2 Yes\nShutdownTimeout 1\nBasicAuth test-user test-password\n"
            f"ConnectPort {plain.server_port}\nConnectPort {secure.server_port}\n",
            encoding="utf-8",
        )
        log_path = root / "proxy.log"
        process: subprocess.Popen[bytes] | None = None
        try:
            with log_path.open("wb") as logs:
                environment = dict(os.environ, RUST_LOG="info", RUST_LOG_STYLE="never")
                process = subprocess.Popen(
                    [binary, "-c", str(configuration)], stdout=logs, stderr=logs, env=environment,
                )
                deadline = time.monotonic() + 10
                while True:
                    match = re.search(r"Listening on 127\.0\.0\.1:(\d+)", log_path.read_text(errors="replace"))
                    if match:
                        port = int(match.group(1))
                        break
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("proxy did not start: " + log_path.read_text(errors="replace"))
                    time.sleep(0.02)

                common = [
                    args.curl, "--silent", "--show-error", "--fail", "--max-time", "10",
                    "--noproxy", "", "--proxy", f"https://localhost:{port}",
                    "--proxy-cacert", str(certificate), "--cacert", str(certificate),
                    "--proxy-user", "test-user:test-password", "--write-out", "\n%{http_code} %{http_version}",
                ]
                http_url = f"http://localhost:{plain.server_port}/"
                https_url = f"https://localhost:{secure.server_port}/"
                cases = [
                    ("HTTP2 forwarding over verified TLS", ["--proxy-http2", http_url], "2"),
                    ("HTTP2 CONNECT to verified HTTPS origin", ["--proxy-http2", https_url], "1.1"),
                    ("HTTP2 CONNECT to plaintext TCP origin", ["--proxy-http2", "--proxytunnel", http_url], "1.1"),
                    ("HTTP1 HTTPS-proxy fallback", [http_url], "1.1"),
                ]
                for name, arguments, expected_version in cases:
                    result = run(common + arguments)
                    expected = PAYLOAD.decode() + f"\n200 {expected_version}"
                    if result.stdout != expected:
                        raise AssertionError(f"{name}: unexpected result {result.stdout!r}")
                    print(f"PASS: {name}", flush=True)
                process.terminate()
                process.wait(timeout=5)
                if process.returncode != 0:
                    raise RuntimeError(f"proxy shutdown failed: {process.returncode}")
                print("PASS: graceful proxy process shutdown", flush=True)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
