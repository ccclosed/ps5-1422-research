#!/usr/bin/env python3
"""Local HTTPS probe server for the PS5 browser exploit-delivery stand.

Serves the probe pages from ./pages over TLS with a self-signed certificate that
is generated on first start (RSA-2048/SHA-256, because target browsers are old),
logs every request with its User-Agent, and accepts JSON reports from the pages
on POST /beacon so that probe output survives even when the console gives us no
JS console access.

Endpoints
    GET  /<path>          static files from --root (path traversal is rejected)
    GET  /healthz         200 "ok\n" liveness probe
    GET  /stats           200 JSON counters (requests, statuses, beacons, agents)
    GET  /cert.pem        the TLS certificate currently in use (PEM)
    GET  /cert.sha256     SHA-256 fingerprint of that certificate (DER)
    GET  /delay?ms=N      sleeps N ms (0..3000) then replies; blocks one thread
    POST /beacon          stores a JSON report, logs UA, replies {"ok": true}
    GET  /beacon          405 with an Allow header
    *    /favicon.ico     204 (keeps the log readable)

Everything is written below --log-dir (default ./logs):
    requests.jsonl   one JSON object per request
    beacons.jsonl    one JSON object per POST /beacon
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "1.0.0"
DEFAULT_PORT = 8443
MAX_BEACON_BYTES = 64 * 1024
MAX_DELAY_MS = 3000

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".ico": "image/x-icon",
    ".wasm": "application/wasm",
    ".woff2": "font/woff2",
}

STATUS_COLORS = {
    "2": "\033[32m",
    "3": "\033[36m",
    "4": "\033[33m",
    "5": "\033[31m",
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def local_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024.0 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{n} B"


def detect_ipv4_addresses() -> list[str]:
    """Best-effort list of this host's LAN addresses (no traffic is sent)."""
    found: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))  # TEST-NET-1, RFC 5737
            found.append(sock.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.append(info[4][0])
    except OSError:
        pass
    unique: list[str] = []
    for addr in found:
        if addr not in unique and not addr.startswith("127."):
            unique.append(addr)
    return unique


def cert_fingerprint_sha256(cert_pem: str | bytes) -> str:
    """SHA-256 of the DER body, formatted like `openssl x509 -fingerprint`."""
    import hashlib

    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("ascii")
    lines = [
        line
        for line in cert_pem.decode("ascii", "replace").splitlines()
        if "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
    ]
    der = __import__("base64").b64decode("".join(lines))
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


# --------------------------------------------------------------------------- #
# certificate
# --------------------------------------------------------------------------- #
def ensure_certificate(cert_dir: Path, extra_hosts: list[str], force: bool) -> tuple[Path, Path, str]:
    """Create (or reuse) a self-signed certificate. Returns (cert, key, fingerprint)."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"

    if cert_path.exists() and key_path.exists() and not force:
        try:
            pem = cert_path.read_text(encoding="ascii")
            import ssl as _ssl

            info = _ssl._ssl._test_decode_cert(str(cert_path))  # type: ignore[attr-defined]
            expires = datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            if expires - datetime.now(timezone.utc) > timedelta(days=7):
                return cert_path, key_path, cert_fingerprint_sha256(pem)
            print(f"[cert] existing certificate expires {expires:%Y-%m-%d}, regenerating")
        except Exception as exc:  # noqa: BLE001 - any decode problem means regenerate
            print(f"[cert] cannot reuse {cert_path}: {exc}; regenerating")

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        return _generate_certificate_with_openssl(cert_dir, extra_hosts)

    hosts = ["localhost", "ps5jb-probe.local", "127.0.0.1", "::1"] + extra_hosts
    seen: list[str] = []
    for host in hosts:
        if host and host not in seen:
            seen.append(host)

    san: list[x509.GeneralName] = []
    for host in seen:
        try:
            san.append(x509.IPAddress(__import__("ipaddress").ip_address(host)))
        except ValueError:
            san.append(x509.DNSName(host))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "ps5jb-probe"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ps5jb probe stand"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(pem)
    print(f"[cert] generated self-signed certificate for: {', '.join(seen)}")
    return cert_path, key_path, cert_fingerprint_sha256(pem)


def _generate_certificate_with_openssl(cert_dir: Path, extra_hosts: list[str]) -> tuple[Path, Path, str]:
    """Fallback when `cryptography` is unavailable: shell out to openssl(1)."""
    import subprocess

    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    san = ",".join(f"DNS:{h}" if not h.replace(".", "").isdigit() else f"IP:{h}"
                   for h in ["localhost", "ps5jb-probe.local", "127.0.0.1", *extra_hosts])
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "825", "-keyout", str(key_path), "-out", str(cert_path),
        "-subj", "/CN=ps5jb-probe/O=ps5jb probe stand",
        "-addext", f"subjectAltName={san}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    os.chmod(key_path, 0o600)
    return cert_path, key_path, cert_fingerprint_sha256(cert_path.read_bytes())


# --------------------------------------------------------------------------- #
# logging
# --------------------------------------------------------------------------- #
class RequestLog:
    """Thread-safe JSONL request/beacon log plus counters for /stats."""

    def __init__(self, log_dir: Path, echo: bool = True) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.requests_path = log_dir / "requests.jsonl"
        self.beacons_path = log_dir / "beacons.jsonl"
        self.echo = echo
        self.lock = threading.Lock()
        self.started = time.time()
        self.total = 0
        self.by_status: dict[str, int] = {}
        self.beacons = 0
        self.agents: list[str] = []
        self.pages: dict[str, int] = {}

    def _append(self, path: Path, obj: dict) -> None:
        with self.lock:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
                fh.flush()

    def request(self, record: dict) -> None:
        with self.lock:
            self.total += 1
            status = str(record.get("status", 0))
            self.by_status[status] = self.by_status.get(status, 0) + 1
            agent = record.get("ua") or "-"
            if agent not in self.agents:
                self.agents.append(agent)
            path = str(record.get("path", ""))
            self.pages[path] = self.pages.get(path, 0) + 1
        self._append(self.requests_path, record)
        if self.echo:
            color = STATUS_COLORS.get(status[:1], "")
            reset = "\033[0m" if color else ""
            print(
                f"{record['ts_local']}  {record.get('peer', '-')}  "
                f"{record.get('method', '-'):4s} {path}  "
                f"{color}{status}{reset}  {record.get('bytes', 0)}B  "
                f"UA={agent[:110]}",
                file=sys.stderr,
                flush=True,
            )

    def beacon(self, record: dict) -> int:
        with self.lock:
            self.beacons += 1
            seq = self.beacons
        record["seq"] = seq
        self._append(self.beacons_path, record)
        probe = record.get("probe") or "?"
        peer = record.get("peer", "-")
        print(
            f"{record['ts_local']}  BEACON#{seq}  {peer}  probe={probe}  "
            f"UA={(record.get('ua') or '-')[:110]}",
            file=sys.stderr,
            flush=True,
        )
        return seq

    def stats(self) -> dict:
        with self.lock:
            return {
                "total_requests": self.total,
                "by_status": dict(self.by_status),
                "beacons": self.beacons,
                "unique_user_agents": list(self.agents),
                "paths": dict(self.pages),
                "uptime_s": round(time.time() - self.started, 1),
            }


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class ProbeHandler(BaseHTTPRequestHandler):
    server_version = f"ps5jb-probe/{VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # populated by make_server()
    root: Path
    log_store: RequestLog
    cert_path: Path

    # ------------------------------------------------------------------ utils
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - stdlib API
        """Silence the default stderr access log; we emit structured lines."""

    def _peer(self) -> str:
        try:
            host, port = self.client_address[0], self.client_address[1]
        except (IndexError, TypeError):
            return "-"
        return f"{host}:{port}"

    def _header(self, name: str) -> str:
        raw = self.headers.get(name)
        if raw is None:
            return ""
        return raw.encode("latin-1", "replace").decode("utf-8", "replace")

    def _send(
        self,
        status: int,
        body: bytes = b"",
        content_type: str = "text/plain; charset=utf-8",
        extra: dict[str, str] | None = None,
        head_only: bool = False,
    ) -> int:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body and not head_only:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        return len(body)

    def _record(self, status: int, size: int, extra: dict | None = None) -> None:
        record = {
            "ts": utc_now(),
            "ts_local": local_now(),
            "peer": self._peer(),
            "method": self.command,
            "path": self.path,
            "status": status,
            "bytes": size,
            "ua": self._header("User-Agent"),
            "referer": self._header("Referer"),
            "accept": self._header("Accept"),
            "accept_language": self._header("Accept-Language"),
            "host": self._header("Host"),
            "tls": self._tls_summary(),
        }
        if extra:
            record.update(extra)
        self.log_store.request(record)

    def _tls_summary(self) -> str:
        try:
            version = self.connection.version() if hasattr(self.connection, "version") else ""
            cipher = self.connection.cipher() if hasattr(self.connection, "cipher") else None
            if cipher:
                return f"{version} {cipher[0]}"
            return version or ""
        except Exception:  # noqa: BLE001 - logging must never break a request
            return ""

    # -------------------------------------------------------------- routing
    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        self._handle(head_only=False)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib API
        self._handle(head_only=True)

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib API
        size = self._send(
            204,
            b"",
            extra={"Allow": "GET, HEAD, POST, OPTIONS", "Access-Control-Allow-Origin": "*"},
        )
        self._record(204, size)

    def _handle(self, head_only: bool) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        route = urllib.parse.unquote(parsed.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if route == "/healthz":
            size = self._send(200, b"ok\n", "text/plain; charset=utf-8", head_only=head_only)
            self._record(200, size)
            return
        if route == "/stats":
            body = json.dumps(self.log_store.stats(), ensure_ascii=False, indent=2).encode()
            size = self._send(200, body, "application/json; charset=utf-8", head_only=head_only)
            self._record(200, size)
            return
        if route == "/cert.pem":
            body = self.cert_path.read_bytes()
            size = self._send(
                200, body, "application/x-pem-file", head_only=head_only
            )
            self._record(200, size)
            return
        if route == "/cert.sha256":
            body = (cert_fingerprint_sha256(self.cert_path.read_bytes()) + "\n").encode()
            size = self._send(200, body, "text/plain; charset=utf-8", head_only=head_only)
            self._record(200, size)
            return
        if route == "/delay":
            try:
                delay_ms = int(query.get("ms", ["0"])[0])
            except (TypeError, ValueError):
                delay_ms = -1
            if delay_ms < 0 or delay_ms > MAX_DELAY_MS:
                size = self._send(
                    400, f"ms must be 0..{MAX_DELAY_MS}\n".encode(), head_only=head_only
                )
                self._record(400, size)
                return
            time.sleep(delay_ms / 1000.0)
            body = json.dumps({"slept_ms": delay_ms, "ts": utc_now()}).encode()
            size = self._send(200, body, "application/json; charset=utf-8", head_only=head_only)
            self._record(200, size, {"delay_ms": delay_ms})
            return
        if route == "/beacon":
            size = self._send(
                405,
                b"POST JSON here\n",
                extra={"Allow": "POST, OPTIONS"},
                head_only=head_only,
            )
            self._record(405, size)
            return
        if route == "/favicon.ico":
            size = self._send(204, b"", head_only=head_only)
            self._record(204, size)
            return
        if route == "/":
            route = "/index.html"
        self._serve_static(route, head_only)

    def _serve_static(self, route: str, head_only: bool) -> None:
        if "\x00" in route or "\\" in route:
            size = self._send(400, b"bad path\n", head_only=head_only)
            self._record(400, size)
            return
        relative = route.lstrip("/")
        try:
            candidate = (self.root / relative).resolve(strict=False)
        except (OSError, RuntimeError):
            size = self._send(400, b"bad path\n", head_only=head_only)
            self._record(400, size)
            return
        root = self.root.resolve()
        if candidate != root and root not in candidate.parents:
            size = self._send(403, b"forbidden\n", head_only=head_only)
            self._record(403, size, {"reason": "outside_root"})
            return
        if candidate.is_dir():
            candidate = candidate / "index.html"
        if not candidate.is_file():
            size = self._send(404, b"not found\n", head_only=head_only)
            self._record(404, size)
            return
        ctype = MIME_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
        body = candidate.read_bytes()
        size = self._send(200, body, ctype, head_only=head_only)
        self._record(
            200, size, {"file": str(candidate.relative_to(root))} if candidate != root else None
        )

    def do_POST(self) -> None:  # noqa: N802 - stdlib API
        parsed = urllib.parse.urlsplit(self.path)
        route = urllib.parse.unquote(parsed.path)
        if route != "/beacon":
            size = self._send(404, b"not found\n")
            self._record(404, size)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            length = 0
        if length <= 0:
            size = self._send(411, b"Content-Length required\n")
            self._record(411, size)
            return
        if length > MAX_BEACON_BYTES:
            size = self._send(413, b"payload too large\n")
            self._record(413, size, {"declared_length": length})
            return
        raw = self.rfile.read(length)
        text = raw.decode("utf-8", "replace")
        payload: object
        parsed_ok = True
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            parsed_ok = False
            payload = text[:4096]
        record = {
            "ts": utc_now(),
            "ts_local": local_now(),
            "peer": self._peer(),
            "ua": self._header("User-Agent"),
            "referer": self._header("Referer"),
            "content_type": self._header("Content-Type"),
            "parsed": parsed_ok,
            "bytes": len(raw),
            "probe": (payload.get("probe") if isinstance(payload, dict) else None) or "raw",
            "payload": payload,
        }
        seq = self.log_store.beacon(record)
        body = json.dumps({"ok": True, "seq": seq, "ts": utc_now()}).encode()
        size = self._send(200, body, "application/json; charset=utf-8")
        self._record(200, size, {"beacon_seq": seq})


class RedirectHandler(BaseHTTPRequestHandler):
    """Plain-HTTP companion that bounces browsers to the HTTPS port."""

    protocol_version = "HTTP/1.1"
    https_port: int = DEFAULT_PORT

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        pass

    def do_GET(self) -> None:  # noqa: N802
        self._redirect()

    def do_HEAD(self) -> None:  # noqa: N802
        self._redirect()

    def do_POST(self) -> None:  # noqa: N802
        self._redirect()

    def _redirect(self) -> None:
        host = self.headers.get("Host") or "localhost"
        hostname = host.rsplit(":", 1)[0] if ":" in host else host
        location = f"https://{hostname}:{self.https_port}{self.path}"
        body = f"redirecting to {location}\n".encode()
        self.send_response(301)
        self.send_header("Location", location)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        print(
            f"{local_now()}  {self.client_address[0]}  HTTP {self.command} {self.path} -> 301 {location}",
            file=sys.stderr,
            flush=True,
        )


# --------------------------------------------------------------------------- #
# server bootstrap
# --------------------------------------------------------------------------- #
class DualStackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(
    host: str, port: int, root: Path, log_store: RequestLog, cert: Path, key: Path
) -> DualStackServer:
    handler = type("BoundProbeHandler", (ProbeHandler,), {})
    handler.root = root
    handler.log_store = log_store
    handler.cert_path = cert

    server = DualStackServer((host, port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def make_redirect_server(host: str, port: int, https_port: int) -> ThreadingHTTPServer:
    handler = type("BoundRedirectHandler", (RedirectHandler,), {"https_port": https_port})
    return ThreadingHTTPServer((host, port), handler)


def parse_args(argv: list[str]) -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="HTTPS probe stand for the PS5 browser (self-signed, request log).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="HTTPS port (0 = ephemeral)")
    parser.add_argument("--root", type=Path, default=here / "pages", help="directory served")
    parser.add_argument("--log-dir", type=Path, default=here / "logs", help="JSONL logs")
    parser.add_argument("--cert-dir", type=Path, default=here / "certs", help="certificate storage")
    parser.add_argument("--http-redirect-port", type=int, default=0,
                        help="optional plain-HTTP port that 301-redirects to HTTPS (0 = off)")
    parser.add_argument("--force-cert", action="store_true", help="regenerate the certificate")
    parser.add_argument("--quiet", action="store_true", help="do not echo requests to stderr")
    parser.add_argument("--version", action="version", version=f"serve.py {VERSION}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    root: Path = args.root.resolve()
    if not root.is_dir():
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return 2

    addresses = detect_ipv4_addresses()
    cert, key, fingerprint = ensure_certificate(args.cert_dir, addresses, args.force_cert)

    log_store = RequestLog(args.log_dir, echo=not args.quiet)
    try:
        server = make_server(args.host, args.port, root, log_store, cert, key)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            print(f"error: port {args.port} is already in use (try --port 0)", file=sys.stderr)
        else:
            print(f"error: cannot bind {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2

    port = server.server_address[1]
    redirector = None
    if args.http_redirect_port:
        try:
            redirector = make_redirect_server(args.host, args.http_redirect_port, port)
        except OSError as exc:
            print(f"warning: cannot start HTTP redirect on {args.http_redirect_port}: {exc}",
                  file=sys.stderr)
            redirector = None

    print("=" * 78)
    print(f"ps5jb probe stand {VERSION}  root={root}  pid={os.getpid()}")
    print("=" * 78)
    print(f"certificate : {cert}")
    print(f"key         : {key}")
    print(f"SHA-256     : {fingerprint}")
    print(f"TLS         : >=1.2, HTTP/1.1 only, self-signed")
    print("-" * 78)
    print("open on the PS5 browser:")
    print(f"  https://127.0.0.1:{port}/            (same machine)")
    for address in addresses:
        print(f"  https://{address}:{port}/            (LAN)")
    if redirector is not None:
        print(f"  http://<host>:{args.http_redirect_port}/  -> 301 to HTTPS")
    print("-" * 78)
    print(f"requests log: {log_store.requests_path}")
    print(f"beacons  log: {log_store.beacons_path}")
    print(f"self-check  : curl -k https://127.0.0.1:{port}/healthz")
    print("=" * 78, flush=True)

    stop = threading.Event()

    def shutdown(signum: int, _frame) -> None:  # noqa: ANN001
        print(f"\n[serve] signal {signum}, shutting down", file=sys.stderr, flush=True)
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
        if redirector is not None:
            threading.Thread(target=redirector.shutdown, daemon=True).start()

    import signal

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if redirector is not None:
        threading.Thread(target=redirector.serve_forever, daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        if redirector is not None:
            redirector.server_close()
        print(f"[serve] stopped; {log_store.stats()['total_requests']} requests logged",
              file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())