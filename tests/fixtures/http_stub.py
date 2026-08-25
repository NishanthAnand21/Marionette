"""A stdlib HTTP stub that answers (or deliberately mis-answers) MCP JSON-RPC.

Used by tests/test_adapters.py to exercise praxis.targets.http against a server
whose every behaviour we control: correct replies, non-200 status, malformed
bodies, SSE framing, and responses slower than the client's timeout.

Always binds 127.0.0.1:0 and reports back the assigned port -- never a
hardcoded port, never a host we do not own.
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "read_public", "description": "Read a public record.",
     "inputSchema": {"type": "object"}},
    {"name": "send_email", "description": "Send an email.",
     "inputSchema": {"type": "object"}},
]


def _result_for(method: str, params: dict) -> dict:
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {},
                "serverInfo": {"name": "http-stub", "version": "1.0"}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = (params or {}).get("name")
        if name not in {t["name"] for t in TOOLS}:
            return {"__error__": {"code": -32602, "message": f"unknown tool {name!r}"}}
        return {"content": [{"type": "text", "text": f"{name} ok"}]}
    return {}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    mode = "ok"
    delay = 0.0

    def log_message(self, *args):  # silence the default stderr spam
        return

    def do_POST(self):  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            msg = {}
        req_id = msg.get("id")
        method = msg.get("method", "")
        mode = self.server.mode  # type: ignore[attr-defined]

        if self.server.delay:  # type: ignore[attr-defined]
            time.sleep(self.server.delay)  # type: ignore[attr-defined]

        if req_id is None:  # a notification: 202 with no body is correct
            self._send(202, "application/json", b"")
            return

        if mode == "status500":
            self._send(500, "text/html",
                       b"<html><body>upstream exploded</body></html>")
            return
        if mode == "badjson":
            self._send(200, "application/json", b"{this is not json at all")
            return
        if mode == "wrong_id":
            body = json.dumps({"jsonrpc": "2.0", "id": req_id + 500,
                               "result": {}}).encode()
            self._send(200, "application/json", body)
            return
        if mode == "sse_noisy" and method != "initialize":
            lines = [
                'data: {"jsonrpc":"2.0","method":"notifications/progress",'
                '"params":{"pct":10}}',
                "",
                "data: not-json-at-all",
                "",
                "data: " + json.dumps({"jsonrpc": "2.0", "id": req_id,
                                       "result": _result_for(method,
                                                             msg.get("params") or {})}),
                "",
            ]
            self._send(200, "text/event-stream",
                       ("\n".join(lines) + "\n").encode())
            return

        result = _result_for(method, msg.get("params") or {})
        if "__error__" in result:
            body = json.dumps({"jsonrpc": "2.0", "id": req_id,
                               "error": result["__error__"]}).encode()
        else:
            body = json.dumps({"jsonrpc": "2.0", "id": req_id,
                               "result": result}).encode()
        self._send(200, "application/json", body)

    def _send(self, status: int, ctype: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


@contextlib.contextmanager
def stub_server(mode: str = "ok", delay: float = 0.0):
    """Run the stub on an ephemeral port; yield its base URL."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.mode = mode          # type: ignore[attr-defined]
    srv.delay = delay        # type: ignore[attr-defined]
    srv.daemon_threads = True
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01},
                              daemon=True, name="praxis-http-stub")
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def closed_port_url() -> str:
    """A URL on a port that was bound and then released: connection refused."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/mcp"
