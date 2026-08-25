"""HTTP MCP adapter — JSON-RPC 2.0 over Streamable HTTP / SSE.

Real MCP servers increasingly ship as HTTP endpoints rather than stdio
subprocesses, so ``--target mcp`` alone cannot reach half the ecosystem.  This
adapter speaks the same MCP semantics (see :class:`marionette.targets.mcp.MCPClient`)
over ``urllib.request`` from the stdlib — no ``requests``, no ``httpx``, no new
dependency for a security tool that people have to trust.

Security posture — this is the first adapter that makes *outbound network
requests on the operator's behalf*, so it is deliberately paranoid:

* **Scheme allowlist.** Only ``http://`` and ``https://``.  ``file://``,
  ``ftp://`` and friends are refused before a socket is opened, so a hostile
  targets file cannot turn a "scan my MCP server" into a local file read.
* **No cross-host redirects.** Redirects that stay on the same host+port are
  followed; anything pointing elsewhere is refused.  Otherwise a server under
  test could bounce Marionette — carrying the operator's ``Authorization`` header —
  at an internal address of its choosing.  ``allow_cross_host_redirect=True``
  opts back in explicitly.
* **Bounded reads.** Response bodies are truncated, so a server cannot exhaust
  memory by streaming forever inside one ``timeout`` window.
* **No credential echo.** Headers are never copied into error context; only
  status, method and a truncated body are.

The server is someone else's, so ``reset()`` is honestly a no-op.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from ..errors import (TargetConnectError, TargetProtocolError,
                      TargetTimeoutError)
from .base import register
from .mcp import MCPClient

# Enough of a body to identify an HTML error page or a stack trace, not enough
# to blow up a JSON report.
_BODY_KEEP = 500
# Hard ceiling on a single response read; an SSE stream can otherwise run forever.
_MAX_BODY = 4 * 1024 * 1024

_ALLOWED_SCHEMES = ("http", "https")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect policy: same origin only.

    urllib follows redirects transparently and *replays the request headers*,
    which for us includes any bearer token.  A server that can choose the next
    hop can therefore choose where our credential goes.  Same host+port+scheme
    is allowed (path-level API moves are routine); anything else raises.
    """

    def __init__(self, origin: tuple[str, str, int | None], allow_cross: bool) -> None:
        self.origin = origin
        self.allow_cross = allow_cross

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if not self.allow_cross:
            p = urlparse(newurl)
            if p.scheme not in _ALLOWED_SCHEMES:
                raise urllib.error.HTTPError(
                    newurl, code, f"refused redirect to non-http(s) scheme {p.scheme!r}",
                    headers, fp)
            if (p.scheme, p.hostname or "", p.port) != self.origin:
                raise urllib.error.HTTPError(
                    newurl, code,
                    f"refused cross-host redirect to {p.scheme}://{p.netloc}",
                    headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@register("http")
class HTTPMCPTarget(MCPClient):
    """Drive a remote MCP server over HTTP POST.

    ``url`` is the base endpoint every JSON-RPC request is POSTed to.  It may
    also be passed as ``command`` so the single-target CLI shorthand
    (``--target http --command https://host/mcp``) works without a dedicated
    flag.

    Thread safety mirrors the stdio adapter: one lock serialises id allocation
    and the exchange, so two callers on one instance cannot swap replies.
    """

    def __init__(
        self,
        name: str = "http",
        url: str | None = None,
        command: str | list[str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 20.0,
        collector: Any = None,
        allow_cross_host_redirect: bool = False,
        session_header: str = "Mcp-Session-Id",
    ) -> None:
        super().__init__(name=name, collector=collector)
        if url is None and command is not None:
            url = command if isinstance(command, str) else " ".join(command)
        if not url:
            raise ValueError(
                "HTTPMCPTarget requires a `url` (or `command`) naming the "
                "MCP endpoint, e.g. http://127.0.0.1:8931/mcp")
        self.url = self._validate_url(url)
        self.headers = dict(headers or {})
        self.timeout = float(timeout)
        self.allow_cross_host_redirect = bool(allow_cross_host_redirect)
        self.session_header = session_header
        self.session_id: str | None = None
        self.server_info: dict[str, Any] = {}
        self._next_id = 0
        self._lock = threading.Lock()
        self._opener = self._build_opener()

    def _validate_url(self, url: str) -> str:
        p = urlparse(url)
        if p.scheme not in _ALLOWED_SCHEMES:
            raise TargetConnectError(
                f"target {self.name!r} refuses URL scheme {p.scheme or '(none)'!r}",
                hint="the http adapter only speaks http:// and https://",
                context={"url": url})
        if not p.hostname:
            raise TargetConnectError(
                f"target {self.name!r} has a URL with no host: {url!r}",
                hint="pass a full URL, e.g. http://127.0.0.1:8931/mcp")
        return url

    def _build_opener(self) -> urllib.request.OpenerDirector:
        p = urlparse(self.url)
        origin = (p.scheme, p.hostname or "", p.port)
        return urllib.request.build_opener(
            _NoRedirect(origin, self.allow_cross_host_redirect))

    # -- lifecycle ----------------------------------------------------------
    def connect(self) -> None:
        self._handshake()

    def close(self) -> None:
        # Nothing to tear down: urllib holds no persistent connection for us.
        self.session_id = None

    def reset(self) -> None:
        """No-op by contract — you cannot reset someone else's server.

        Stated loudly rather than faked: cross-technique isolation on a remote
        HTTP target is the operator's problem, and a lie here would show up as
        a mysterious result-ordering bug instead.
        """
        return None

    def health(self) -> tuple[bool, str | None]:
        try:
            self._request("tools/list", {})
        except Exception as exc:  # noqa: BLE001 - health never raises
            return False, str(exc)
        return True, None

    # -- JSON-RPC over HTTP -------------------------------------------------
    def _protocol_error(self, method: str, msg: str, *, status: int | None = None,
                        body: str = "") -> TargetProtocolError:
        ctx: dict[str, Any] = {"method": method, "url": self.url}
        if status is not None:
            ctx["status"] = status
        if body:
            ctx["body"] = body[:_BODY_KEEP]
        return TargetProtocolError(
            f"target {self.name!r} ({self.kind}) {msg}", context=ctx)

    def _post(self, method: str, payload: dict[str, Any]) -> tuple[str, str]:
        """POST one JSON-RPC message; return ``(content_type, body)``."""
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        # Advertise both so a Streamable-HTTP server may answer either way.
        req.add_header("Accept", "application/json, text/event-stream")
        for k, v in self.headers.items():
            req.add_header(k, v)
        if self.session_id:
            req.add_header(self.session_header, self.session_id)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                sid = resp.headers.get(self.session_header)
                if sid:
                    self.session_id = sid
                ctype = (resp.headers.get("Content-Type") or "").lower()
                body = resp.read(_MAX_BODY).decode("utf-8", "replace")
                return ctype, body
        except urllib.error.HTTPError as exc:
            # A non-2xx is the server speaking, so keep its body: it is usually
            # the only explanation of *why* (auth, wrong path, upstream error).
            try:
                body = exc.read(_MAX_BODY).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                body = ""
            raise self._protocol_error(
                method, f"got HTTP {exc.code} from {self.url}",
                status=exc.code, body=body) from exc
        except socket.timeout as exc:
            raise self._timeout(method) from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, socket.timeout) or "timed out" in str(reason):
                raise self._timeout(method) from exc
            raise TargetConnectError(
                f"target {self.name!r} could not reach {self.url}: {reason}",
                hint="check the URL, that the server is running, and any proxy",
                context={"url": self.url, "method": method}) from exc
        except (OSError, ValueError) as exc:
            raise TargetConnectError(
                f"target {self.name!r} could not reach {self.url}: {exc}",
                context={"url": self.url, "method": method}) from exc

    def _timeout(self, method: str) -> TargetTimeoutError:
        return TargetTimeoutError(
            f"{self.kind} target {self.name!r} timed out after "
            f"{self.timeout:.1f}s awaiting {method}",
            context={"method": method, "timeout_s": self.timeout,
                     "url": self.url})

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        # A notification has no id and expects no result; a 202 with an empty
        # body is the correct answer, so anything we get back is discarded.
        self._post(method, {"jsonrpc": "2.0", "method": method, "params": params})

    def _request(self, method: str, params: dict[str, Any]) -> Any:
        with self._lock:
            self._next_id += 1
            req_id = self._next_id
            ctype, body = self._post(method, {
                "jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        msg = self._extract(method, ctype, body, req_id)
        if "error" in msg:
            raise TargetProtocolError(
                f"target {self.name!r} returned an error for {method!r}: "
                f"{msg['error']}",
                context={"method": method, "error": msg["error"], "url": self.url})
        return msg.get("result")

    def _extract(self, method: str, ctype: str, body: str,
                 req_id: int) -> dict[str, Any]:
        """Find our reply in either an ``application/json`` or SSE body."""
        if "text/event-stream" in ctype:
            found = self._scan_sse(body, req_id)
            if found is None:
                raise self._protocol_error(
                    method, f"SSE stream carried no reply to id {req_id}",
                    body=body)
            return found
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            # Content-Type lies constantly; fall back to a scan before giving up.
            found = self._scan_sse(body, req_id)
            if found is not None:
                return found
            raise self._protocol_error(
                method, "returned a body that is not JSON-RPC", body=body) from exc
        # Batched responses are legal; pick ours out.
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict) and item.get("id") == req_id:
                    return item
            raise self._protocol_error(
                method, f"batch reply carried no id {req_id}", body=body)
        if not isinstance(parsed, dict):
            raise self._protocol_error(
                method, "returned JSON that is not a JSON-RPC object", body=body)
        if parsed.get("id") not in (req_id, None):
            raise self._protocol_error(
                method,
                f"replied to id {parsed.get('id')!r}, expected {req_id}", body=body)
        return parsed

    @staticmethod
    def _scan_sse(body: str, req_id: int) -> dict[str, Any] | None:
        """Pull the JSON-RPC message with ``req_id`` out of an SSE body.

        Servers interleave notifications and progress events on the same
        stream, so matching on id — not on "first data: line" — is what makes
        this correct.
        """
        for line in body.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            chunk = line[5:].strip()
            if not chunk:
                continue
            try:
                obj = json.loads(chunk)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict) and obj.get("id") == req_id:
                return obj
            if isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict) and item.get("id") == req_id:
                        return item
        return None
