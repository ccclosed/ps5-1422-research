#!/usr/bin/env python3
"""bundle-1422 / bridge_server.py — мост «вход (LUA/YARPE) → примитив p → kernel-часть».

Kernel-цепочка jb1422 (`tools/jb1422/kernel/relapse1422.js`) ждёт объект `p` с методами
`read64/write64/read32/write32/add/ready()/reason()` (плюс `read1/4/8`, `write1/4/8`, `malloc`
в js/primitive.js). У нас память — в процессе игры (Lua 9026 / Ren'Py 9025), поэтому:

    JS (kernel)  --HTTP JSON-->  bridge_server.py  <--line protocol--  агент в игре
                                    (этот файл)                    agent_lua.lua (9026, passive)
                                                                   agent_yarpe.py (9025, dial-in)

Протокол «агент ↔ мост» — текстовые строки (Lua 5.1 парсит их без JSON-библиотеки):
    агент → мост при подключении:  HELLO <entry> <version>
    мост → агент:                  R <addr_hex> <len>      (read)
                                   W <addr_hex> <hexbytes> (write)
                                   A <size>                (alloc)
                                   ?                       (ready?)
                                   .                       (close)
    агент → мост:                  V <hex>   (значение)
                                   OK        (запись/успех)
                                   RDY <0|1> <reason...>
                                   ERR <text>

HTTP (CORS разрешён — JS может жить в браузере на консоли и ходить на ПК):
    GET  /health · /ready · /read?addr&len · /read64?addr · /read32?addr&off
    POST /write {addr,hex} · /write64 {addr,value} · /write32 {addr,off,value}
    GET  /add?addr&off · /alloc?size

Запуск:
    python3 bridge_server.py                          # HTTP :9137, агент :9138
    python3 bridge_server.py --self-test              # mock-агент + полный контракт
    python3 bridge_server.py --lua-host 192.168.0.50  # сам подключиться к Lua-loader на 9026
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

COMMAND_MAGIC = 0xFFFFFFFF


def parse_int(value) -> int:
    if isinstance(value, int):
        return value
    if value is None:
        raise ValueError("missing value")
    text = str(value).strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text, 0)


def hex_addr(value: int) -> str:
    return "0x%x" % value


class AgentNotConnected(RuntimeError):
    pass


# --------------------------------------------------------------------------- line session
class LineSession:
    """Request/response over a socket, one text line per message."""

    def __init__(self, sock: socket.socket, label: str):
        self.sock = sock
        self.label = label
        self.lock = threading.Lock()
        self.rbuf = b""
        self.closed = False
        self.entry = "?"

    def send(self, line: str) -> None:
        self.sock.sendall((line + "\n").encode())

    def recv_line(self) -> str:
        while b"\n" not in self.rbuf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise AgentNotConnected("agent closed the connection")
            self.rbuf += chunk
            if len(self.rbuf) > 1 << 20:
                raise AgentNotConnected("agent reply too large")
        line, self.rbuf = self.rbuf.split(b"\n", 1)
        return line.decode("utf-8", "replace")

    def handshake(self, timeout: float = 10.0) -> None:
        self.sock.settimeout(timeout)
        hello = self.recv_line()
        parts = hello.split()
        if not parts or parts[0] != "HELLO":
            raise AgentNotConnected("bad handshake: %r" % hello)
        self.entry = parts[1] if len(parts) > 1 else "unknown"
        self.sock.settimeout(None)

    def request(self, line: str) -> str:
        with self.lock:
            if self.closed:
                raise AgentNotConnected("agent session closed")
            try:
                self.send(line)
                reply = self.recv_line()
            except OSError as exc:
                self.closed = True
                raise AgentNotConnected(str(exc)) from exc
            if reply.startswith("ERR"):
                raise RuntimeError(reply[3:].strip() or "agent error")
            return reply

    def close(self) -> None:
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- bridge
class Bridge:
    def __init__(self, http_host: str = "127.0.0.1", http_port: int = 9137,
                 agent_host: str = "0.0.0.0", agent_port: int = 9138,
                 verbose: bool = True, http_allow_origin: str = "*"):
        self.http_host, self.http_port = http_host, http_port
        self.agent_host, self.agent_port = agent_host, agent_port
        self.verbose = verbose
        self.allow_origin = http_allow_origin
        self.session: LineSession | None = None
        self.session_event = threading.Event()
        self._stop = threading.Event()
        self._agent_sock: socket.socket | None = None
        self._httpd: ThreadingHTTPServer | None = None
        self.log_lines: list[str] = []

    def log(self, line: str) -> None:
        self.log_lines.append(line)
        if self.verbose:
            print("[bridge] " + line, flush=True)

    # -- lifecycle -------------------------------------------------------
    def start(self) -> "Bridge":
        self._agent_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._agent_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._agent_sock.bind((self.agent_host, self.agent_port))
        self.agent_port = self._agent_sock.getsockname()[1]
        self._agent_sock.listen(4)
        self._agent_sock.settimeout(0.2)
        threading.Thread(target=self._accept_agents, daemon=True).start()

        handler = _make_handler(self)
        ThreadingHTTPServer.allow_reuse_address = True
        self._httpd = ThreadingHTTPServer((self.http_host, self.http_port), handler)
        self.http_port = self._httpd.server_address[1]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        self.log("http http://%s:%d agent port %d" % (self.http_host, self.http_port, self.agent_port))
        return self

    def attach_lua(self, host: str, port: int = 9026, script_path: str = "agent_lua.lua",
                   timeout: float = 15.0) -> LineSession:
        """Connect to the console Lua loader (9026) and start our passive agent there."""
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(struct.pack("<Q", COMMAND_MAGIC) + bytes([1]))      # enable signal handler
        time.sleep(0.2)
        sock.close()                                                     # loader: one frame/connection

        sock = socket.create_connection((host, port), timeout=timeout)
        source = open(script_path, "rb").read()
        sock.sendall(struct.pack("<Q", len(source)) + source)
        session = LineSession(sock, "lua-%s:%d" % (host, port))
        # the loader runs the script, which prints "HELLO lua <v>" as its first line
        session.handshake(timeout)
        self.session = session
        self.session_event.set()
        self.log("lua agent attached at %s:%d" % (host, port))
        return session

    def _accept_agents(self) -> None:
        assert self._agent_sock is not None
        while not self._stop.is_set():
            try:
                conn, peer = self._agent_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            session = LineSession(conn, "dialin-%s" % (peer,))
            try:
                session.handshake()
            except Exception as exc:                     # noqa: BLE001 - untrusted peer
                self.log("handshake failed from %s: %s" % (peer, exc))
                session.close()
                continue
            self.session = session
            self.session_event.set()
            self.log("agent connected from %s entry=%s" % (peer, session.entry))

    def wait_for_agent(self, timeout: float = 10.0) -> bool:
        return self.session_event.wait(timeout)

    def stop(self) -> None:
        self._stop.set()
        if self.session:
            self.session.close()
        if self._agent_sock:
            self._agent_sock.close()
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    # -- primitive ops ---------------------------------------------------
    def _session_or_raise(self) -> LineSession:
        if not self.session or self.session.closed:
            raise AgentNotConnected("agent not connected (agent_lua.lua на 9026 или agent_yarpe.py)")
        return self.session

    def _value(self, line: str) -> bytes:
        reply = self._session_or_raise().request(line)
        if not reply.startswith("V "):
            raise RuntimeError("unexpected agent reply: %r" % reply)
        return bytes.fromhex(reply[2:].strip())

    def ready(self) -> tuple[bool, str]:
        try:
            reply = self._session_or_raise().request("?")
            parts = reply.split(" ", 2)
            if parts[0] != "RDY":
                return False, "unexpected reply: " + reply
            return parts[1] == "1", parts[2] if len(parts) > 2 else ""
        except Exception as exc:                          # noqa: BLE001 - reason is user-facing
            return False, str(exc)

    def read(self, addr: int, length: int) -> bytes:
        return self._value("R %s %d" % (hex_addr(addr), length))

    def write(self, addr: int, data: bytes) -> None:
        reply = self._session_or_raise().request("W %s %s" % (hex_addr(addr), data.hex()))
        if reply.strip() != "OK":
            raise RuntimeError("unexpected agent reply: %r" % reply)

    def alloc(self, size: int) -> int:
        reply = self._session_or_raise().request("A %d" % size)
        if not reply.startswith("V "):
            raise RuntimeError("unexpected agent reply: %r" % reply)
        return parse_int(reply[2:].strip())

    # convenience wrappers used by Python callers / selftest
    def read64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def read32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def write64(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def write32(self, addr: int, value: int) -> None:
        self.write(addr, struct.pack("<I", value & 0xFFFFFFFF))


# --------------------------------------------------------------------------- HTTP API
def _make_handler(bridge: Bridge):
    class Handler(BaseHTTPRequestHandler):
        server_version = "lua-lab-bridge/1.1"

        def log_message(self, fmt, *args):
            bridge.log("http " + (fmt % args))

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", bridge.allow_origin)
            self.send_header("Access-Control-Allow-Headers", "content-type")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.end_headers()
            self.wfile.write(body)

        def _query(self) -> dict:
            return {k: v[-1] for k, v in parse_qs(urlparse(self.path).query).items()}

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(length).decode()) if length else {}

        def do_OPTIONS(self):                            # noqa: N802
            self._json(200, {"ok": True})

        def do_GET(self):                                # noqa: N802
            self._dispatch("GET")

        def do_POST(self):                               # noqa: N802
            self._dispatch("POST")

        def _dispatch(self, method: str) -> None:
            try:
                self._route(method)
            except AgentNotConnected as exc:
                self._json(503, {"ok": False, "ready": False, "error": str(exc)})
            except Exception as exc:                     # noqa: BLE001
                self._json(400, {"ok": False, "error": str(exc)})

        def _route(self, method: str) -> None:
            path = urlparse(self.path).path.rstrip("/") or "/"
            q = self._query()

            if path == "/health":
                ready, reason = bridge.ready()
                return self._json(200, {"ok": True, "agent": bridge.session is not None,
                                        "entry": bridge.session.entry if bridge.session else None,
                                        "ready": ready, "reason": reason})
            if path == "/ready":
                ready, reason = bridge.ready()
                return self._json(200, {"ok": True, "ready": ready, "reason": reason})
            if path == "/read":
                addr, n = parse_int(q.get("addr")), parse_int(q.get("len", "8"))
                return self._json(200, {"ok": True, "hex": bridge.read(addr, n).hex()})
            if path in ("/read64", "/read32"):
                addr = parse_int(q.get("addr")) + parse_int(q.get("off", "0"))
                width = 8 if path == "/read64" else 4
                data = bridge.read(addr, width)
                return self._json(200, {"ok": True, "value": "0x%x" % int.from_bytes(data, "little"),
                                        "hex": data.hex()})
            if path in ("/write", "/write64", "/write32"):
                body = self._body() if method == "POST" else q
                addr = parse_int(body.get("addr")) + parse_int(body.get("off", "0"))
                if path == "/write":
                    bridge.write(addr, bytes.fromhex(body["hex"]))
                elif path == "/write64":
                    bridge.write64(addr, parse_int(body.get("value")))
                else:
                    bridge.write32(addr, parse_int(body.get("value")))
                return self._json(200, {"ok": True})
            if path == "/add":
                addr = parse_int(q.get("addr")) + parse_int(q.get("off", "0"))
                return self._json(200, {"ok": True, "addr": hex_addr(addr)})
            if path == "/alloc":
                return self._json(200, {"ok": True, "addr": hex_addr(bridge.alloc(parse_int(q.get("size", "256"))))})
            return self._json(404, {"ok": False, "error": "unknown path " + path})

    return Handler


# --------------------------------------------------------------------------- selftest
def _selftest() -> int:
    import urllib.error
    import urllib.request
    from mock_agent import MockAgent

    bridge = Bridge(http_host="127.0.0.1", http_port=0, agent_port=0, verbose=False).start()
    agent = MockAgent(bridge.agent_port, verbose=False).start()
    ok = True

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and bool(condition)
        print(("[PASS] " if condition else "[FAIL] ") + name + (" :: " + detail if detail else ""))

    if not bridge.wait_for_agent(5.0):
        print("[FAIL] mock agent did not connect")
        bridge.stop()
        return 1

    base = "http://127.0.0.1:%d" % bridge.http_port

    def get(path: str) -> dict:
        with urllib.request.urlopen(base + path, timeout=5) as resp:
            return json.loads(resp.read().decode())

    def post(path: str, payload: dict) -> dict:
        req = urllib.request.Request(base + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())

    health = get("/health")
    check("bridge /health sees the agent", health["agent"] is True and health["entry"] == "mock", str(health))
    ready = get("/ready")
    check("p.ready()/p.reason()", ready["ready"] is True and "mock" in ready["reason"], str(ready))

    addr = bridge.alloc(0x100)
    check("p.malloc() -> address", addr > 0, hex_addr(addr))
    bridge.write64(addr, 0x1122334455667788)
    check("p.write64 -> p.read64", bridge.read64(addr) == 0x1122334455667788, hex(bridge.read64(addr)))
    bridge.write32(addr + 8, 0xDEADBEEF)
    check("p.write32 -> p.read32", bridge.read32(addr + 8) == 0xDEADBEEF, hex(bridge.read32(addr + 8)))
    bridge.write(addr + 16, b"JB1422")
    check("raw read/write bytes", bridge.read(addr + 16, 6) == b"JB1422")
    check("HTTP /read64", get("/read64?addr=%s" % hex_addr(addr))["value"] == "0x1122334455667788")
    check("HTTP /write64", post("/write64", {"addr": hex_addr(addr), "value": "0xCAFEBABE"})["ok"]
          and get("/read32?addr=%s&off=0" % hex_addr(addr))["value"] == "0xcafebabe")
    check("HTTP /add", get("/add?addr=0x1000&off=0x20")["addr"] == "0x1020")
    check("HTTP /alloc", int(get("/alloc?size=64")["addr"], 16) > 0)
    try:
        get("/read?addr=0x1&len=8")
        check("bad address reported as error", False)
    except urllib.error.HTTPError as exc:
        check("bad address reported as error", exc.code == 400, "HTTP %d" % exc.code)

    agent.stop()
    bridge.stop()
    print("RESULT: PASS" if ok else "RESULT: FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="bundle-1422 bridge: entry (LUA/YARPE) -> p -> kernel stage")
    ap.add_argument("--http-host", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=9137)
    ap.add_argument("--agent-host", default="0.0.0.0")
    ap.add_argument("--agent-port", type=int, default=9138)
    ap.add_argument("--lua-host", help="attach to the Lua loader on this PS5 (TCP 9026) at startup")
    ap.add_argument("--lua-port", type=int, default=9026)
    ap.add_argument("--lua-script", default=None, help="path to agent_lua.lua (default: next to this file)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return _selftest()

    bridge = Bridge(args.http_host, args.http_port, args.agent_host, args.agent_port,
                    verbose=not args.quiet).start()
    print("READY http=http://%s:%d agent=%d" % (args.http_host, bridge.http_port, bridge.agent_port),
          flush=True)

    if args.lua_host:
        script = args.lua_script or str(__file__).rsplit("/", 1)[0] + "/agent_lua.lua"
        try:
            bridge.attach_lua(args.lua_host, args.lua_port, script)
            print("READY lua-agent attached %s:%d" % (args.lua_host, args.lua_port), flush=True)
        except Exception as exc:                         # noqa: BLE001 - report, keep serving
            print("WARN lua attach failed: %s" % exc, flush=True)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        bridge.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())