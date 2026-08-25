"""MCP adapter — speaks JSON-RPC 2.0 to an MCP server over stdio.

Implemented directly against the wire protocol rather than through the MCP
SDK so that Marionette stays dependency-light and can talk to a deliberately
malformed or hostile server without the SDK sanitising it first.  When you are
testing a server that lies, you do not want a well-behaved client in the way.

The MCP *semantics* (handshake params, ``tools/list`` -> :class:`ToolSpec`,
``tools/call`` -> :class:`ToolResult`, event emission) live in
:class:`MCPClient` and are shared with the HTTP adapter in ``http.py``; only
the transport differs between them.  Anything below :class:`MCPClient` is
stdio-specific.

A hostile server also means every blocking operation is an attack surface: a
server that never answers, or that dies mid-handshake, must not be able to
wedge a run.  Both pipes are therefore drained by dedicated threads and every
request is bounded by ``timeout``.
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import shlex
import signal
import subprocess
import threading
import time
from typing import Any

from ..errors import (TargetConnectError, TargetCrashedError,
                      TargetProtocolError, TargetTimeoutError)
from ..schema import TOOL_LIST
from .base import Target, ToolResult, ToolSpec, register

# One JSON-RPC frame may not exceed this. Generous for honest servers (a
# 10k-tool inventory fits), fatal for a server trying to exhaust our memory.
_MAX_FRAME = 8 * 1024 * 1024
_READ_CHUNK = 65536
_OVERSIZE = object()   # queue marker: a frame was dropped for exceeding _MAX_FRAME

PROTOCOL_VERSION = "2024-11-05"

# How much server stderr to keep for crash reports. Enough for a traceback.
_STDERR_KEEP = 2000

# Alias kept so existing `from .mcp import MCPProtocolError` imports still work.
MCPProtocolError = TargetProtocolError


def initialize_params() -> dict[str, Any]:
    """The client half of the MCP handshake. Identical over every transport."""
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "marionette", "version": "0.1.0"},
    }


def tools_from_result(result: Any) -> list[ToolSpec]:
    """Map a ``tools/list`` result onto ToolSpecs, tolerating a lying server.

    Every field is defaulted rather than required: a server that omits
    ``description`` is a finding for the technique to report, not a reason for
    the adapter to blow up before the technique ever runs.
    """
    if not isinstance(result, dict):
        return []
    out: list[ToolSpec] = []
    for t in result.get("tools", []) or []:
        if not isinstance(t, dict):
            continue
        out.append(ToolSpec(
            name=t.get("name", ""),
            description=t.get("description", "") or "",
            input_schema=t.get("inputSchema", {}) or {},
        ))
    return out


# Shutdown budget. A healthy server notices stdin EOF and exits in
# milliseconds, so this window is only ever paid by one that is wedged or
# ignoring us -- keep it short or every teardown of a misbehaving target taxes
# the whole run. Overridable for the rare server with a slow flush.
_EOF_GRACE = float(os.environ.get("MARIONETTE_EOF_GRACE", "0.5"))
_SIGNAL_GRACE = float(os.environ.get("MARIONETTE_SIGNAL_GRACE", "2.0"))


def _process_group_kwargs() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _wait_quietly(proc: Any, timeout: float) -> bool:
    """Wait for exit, returning whether it happened. Never raises."""
    try:
        proc.wait(timeout=timeout)
        return True
    except Exception:  # noqa: BLE001 - a timeout here is an expected outcome
        return proc.poll() is not None


def _split_command(command: str) -> list[str]:
    """Split a command string the way the host platform means it.

    POSIX shlex treats backslash as an escape, so a Windows path like
    ``C:\\Users\\me\\python.exe`` is silently mangled into
    ``C:Usersmepython.exe`` -- the command still "parses" and then fails to
    launch with a confusing error.
    """
    return shlex.split(command, posix=(os.name != "nt"))


class MCPClient(Target):
    """Transport-agnostic MCP client behaviour.

    Subclasses supply ``_request(method, params)`` and ``_notify(...)``; every
    MCP-level concern above the wire is implemented once, here.
    """

    capabilities = frozenset({"list_tools", "call_tool", "snapshot"})

    def _handshake(self) -> None:
        init = self._request("initialize", initialize_params())
        init = init if isinstance(init, dict) else {}
        self.server_info = init.get("serverInfo", {})
        # Record what the server actually agreed to. Servers do not have to
        # accept our version -- they may answer with their own -- and silently
        # continuing in a protocol we never negotiated turns a clean version
        # mismatch into a confusing failure three calls later.
        self.server_protocol = init.get("protocolVersion")
        if self.server_protocol and self.server_protocol != PROTOCOL_VERSION:
            self.protocol_mismatch = (
                f"server negotiated protocol {self.server_protocol!r}, "
                f"client offered {PROTOCOL_VERSION!r}")
            self._emit(type=TOOL_LIST, severity="low",
                       data={"kind": "protocol_mismatch",
                             "client": PROTOCOL_VERSION,
                             "server": self.server_protocol,
                             "tools": [], "count": 0})
        self._notify("notifications/initialized", {})

    def _request(self, method: str, params: dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError

    def _notify(self, method: str, params: dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError

    def list_tools(self) -> list[ToolSpec]:
        tools = tools_from_result(self._request("tools/list", {}) or {})
        self.emit_tool_list(tools)
        return tools

    def call_tool(self, tool: str, args: dict[str, Any]) -> ToolResult:
        self.emit_tool_call(tool, args, principal="operator", provenance="marionette")
        try:
            raw = self._request("tools/call", {"name": tool, "arguments": args}) or {}
        except TargetProtocolError as exc:
            # A server-side error for one tool is data, not a run-ending failure;
            # timeouts and crashes deliberately propagate.
            res = ToolResult(ok=False, error=str(exc))
            self.emit_tool_result(tool, res)
            return res
        if not isinstance(raw, dict):
            raw = {"content": raw}
        content = raw.get("content", raw)
        res = ToolResult(ok=not raw.get("isError", False), content=content)
        self.emit_tool_result(tool, res)
        return res


@register("mcp")
class MCPTarget(MCPClient):
    """Launch an MCP server as a subprocess and drive it over stdio.

    Thread safety: every request/response exchange is serialised by
    ``self._lock``, so concurrent callers on one instance cannot interleave
    and steal each other's replies.  The intended deployment is still one
    target instance per worker thread; the lock is the safety net, not the
    concurrency model.
    """

    def __init__(
        self,
        name: str = "mcp",
        command: str | list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        inherit_env: bool = False,
        timeout: float = 20.0,
        collector: Any = None,
        retries: int = 1,
    ) -> None:
        super().__init__(name=name, collector=collector)
        if command is None:
            raise ValueError("MCPTarget requires a `command` to launch the server")
        self.command = (_split_command(command) if isinstance(command, str)
                        else list(command))
        self.cwd = cwd
        self.env = self._build_env(env, inherit_env)
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self._proc: subprocess.Popen[str] | None = None
        self._outstanding: set[str] = set()
        self.server_protocol: str | None = None
        self.protocol_mismatch: str | None = None
        self._lock = threading.Lock()
        self._out_q: queue.Queue[str | None] = queue.Queue()
        self._stderr_buf: list[str] = []
        self._stderr_lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self.server_info: dict[str, Any] = {}

    # Passed through to a process we are explicitly testing for hostility, so
    # the operator's ambient credentials are NOT part of the deal by default.
    # Compared case-insensitively: os.environ upper-cases its keys on Windows,
    # so a mixed-case entry here would never match and the subprocess would
    # start without SYSTEMROOT -- which breaks socket/SSL init for most Python
    # servers.
    _ENV_ALLOWLIST = frozenset({
        "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP",
        # Windows: a process will not reliably start without these.
        "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT",
        "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
        "PROGRAMFILES(X86)", "PROGRAMDATA", "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
    })

    @classmethod
    def _build_env(cls, env: dict[str, str] | None,
                   inherit_env: bool) -> dict[str, str]:
        """Minimal environment unless the operator opts in.

        Inheriting os.environ hands AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN and
        every other ambient secret to a subprocess whose whole purpose is to
        be suspect. Only what a program needs to start is forwarded; anything
        the server legitimately needs goes in the target's explicit `env:`.
        """
        base = dict(os.environ) if inherit_env else {
            k: v for k, v in os.environ.items()
            if k.upper() in cls._ENV_ALLOWLIST}
        return {**base, **(env or {})}

    # -- lifecycle ----------------------------------------------------------
    def connect(self) -> None:
        last: TargetConnectError | None = None
        for attempt in range(self.retries + 1):
            try:
                self._connect_once()
                return
            except TargetConnectError as exc:
                # Only launch failures are worth retrying — a protocol or
                # timeout failure will reproduce identically.
                last = exc
                self.close()
                if attempt < self.retries:
                    time.sleep(0.25 * (attempt + 1))
            except BaseException:
                # A handshake that times out or speaks garbage leaves the child
                # alive with its pipes and drain threads. Reap it before the
                # error propagates; the caller should not have to know that a
                # failed connect can still own a process.
                self.close()
                raise
        assert last is not None
        raise last

    def _connect_once(self) -> None:
        try:
            self._proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                env=self.env,
                bufsize=-1,
                # Own process group: required for CTRL_BREAK_EVENT to be
                # deliverable to the child on Windows, and it stops a Ctrl-C in
                # the operator's console from racing us to the child on POSIX.
                **_process_group_kwargs(),
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise TargetConnectError(
                f"target {self.name!r} could not launch its MCP server: {exc}",
                context={"command": " ".join(self.command), "cwd": self.cwd},
            ) from exc

        self._out_q = queue.Queue()
        self._stderr_buf = []
        self._threads = [
            self._spawn(self._drain_stdout, "marionette-mcp-stdout"),
            self._spawn(self._drain_stderr, "marionette-mcp-stderr"),
        ]

        self._handshake()

    def _spawn(self, fn: Any, name: str) -> threading.Thread:
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()
        return t

    def _drain_stdout(self) -> None:
        """Read frames with a byte budget.

        A hostile (or merely broken) server can emit one enormous line. Reading
        it with plain line iteration buffers the whole thing before anyone can
        object, so a 50MB reply becomes 250MB of RSS and a timeout does not
        help -- the deadline fires while this thread keeps allocating. Frames
        past `_MAX_FRAME` are discarded and reported as a protocol error.
        """
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            buf: list[bytes] = []
            size = 0
            overflow = False
            while True:
                # read1: hand back whatever has arrived rather than blocking
                # for a full chunk, which would stall every small reply.
                chunk = proc.stdout.read1(_READ_CHUNK)
                if not chunk:
                    break
                start = 0
                while True:
                    nl = chunk.find(b"\n", start)
                    if nl == -1:
                        rest = chunk[start:]
                        if overflow:
                            pass                      # still dropping this frame
                        elif size + len(rest) > _MAX_FRAME:
                            overflow, buf, size = True, [], 0
                        else:
                            buf.append(rest)
                            size += len(rest)
                        break
                    piece = chunk[start:nl]
                    if overflow or size + len(piece) > _MAX_FRAME:
                        self._out_q.put(_OVERSIZE)
                    else:
                        buf.append(piece)
                        # errors="replace": a server emitting invalid UTF-8 is
                        # a protocol problem, not a reason to lose the stream
                        # and misreport it as the server having exited.
                        self._out_q.put(b"".join(buf).decode("utf-8", "replace"))
                    buf, size, overflow = [], 0, False
                    start = nl + 1
        except Exception:  # noqa: BLE001 - pipe torn down under us on close()
            pass
        finally:
            self._out_q.put(None)  # sentinel: EOF, server is gone

    def _drain_stderr(self) -> None:
        # Must always run: an undrained stderr pipe fills and deadlocks the child.
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        try:
            for raw_line in proc.stderr:
                line = raw_line.decode("utf-8", "replace") \
                    if isinstance(raw_line, bytes) else raw_line
                with self._stderr_lock:
                    self._stderr_buf.append(line)
                    # Cheap ring: trim once the tail is comfortably over budget.
                    if sum(map(len, self._stderr_buf)) > _STDERR_KEEP * 4:
                        self._stderr_buf = ["".join(self._stderr_buf)[-_STDERR_KEEP:]]
        except Exception:  # noqa: BLE001
            pass

    def stderr_tail(self) -> str:
        with self._stderr_lock:
            return "".join(self._stderr_buf)[-_STDERR_KEEP:]

    def close(self) -> None:
        """Idempotent, never raises — safe to call from __exit__ and finalizers."""
        proc, self._proc = self._proc, None
        if proc is not None:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception:  # noqa: BLE001
                pass
            # Graceful shutdown, in escalating order. Closing stdin above is
            # the protocol-level "we are done" -- a well-behaved MCP server
            # exits on EOF, so wait for that first. This matters most on
            # Windows, where `terminate()` is TerminateProcess: an immediate
            # hard kill with no chance to flush or clean up. Without this
            # window the "terminate then kill" escalation is meaningless there.
            if not _wait_quietly(proc, _EOF_GRACE):
                if os.name == "nt":
                    # The only graceful signal available to a console child,
                    # and only because we put it in its own process group.
                    try:
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                    except Exception:  # noqa: BLE001
                        pass
                    _wait_quietly(proc, _SIGNAL_GRACE)
                else:
                    try:
                        proc.terminate()
                    except Exception:  # noqa: BLE001
                        pass
                    _wait_quietly(proc, _SIGNAL_GRACE)
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:  # noqa: BLE001
                    pass
                _wait_quietly(proc, _SIGNAL_GRACE)
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream:
                        stream.close()
                except Exception:  # noqa: BLE001
                    pass
        for t in self._threads:
            try:
                t.join(timeout=2)
            except Exception:  # noqa: BLE001
                pass
        self._threads = []

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- health -------------------------------------------------------------
    def health(self) -> tuple[bool, str | None]:
        if self._proc is None:
            return False, "not connected"
        rc = self._proc.poll()
        if rc is not None:
            return False, f"server exited with returncode {rc}"
        try:
            self._request("tools/list", {})
        except Exception as exc:  # noqa: BLE001 - health never raises
            return False, str(exc)
        return True, None

    # -- JSON-RPC -----------------------------------------------------------
    def _crashed(self, method: str) -> TargetCrashedError:
        rc = self._proc.poll() if self._proc else None
        return TargetCrashedError(
            f"target {self.name!r} MCP server exited (returncode={rc}) "
            f"while awaiting {method!r}",
            context={"returncode": rc, "command": " ".join(self.command),
                     "stderr": self.stderr_tail()},
        )

    def _write(self, payload: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise TargetProtocolError(f"target {self.name!r} is not connected",
                                      hint="call connect() before issuing requests")
        try:
            self._proc.stdin.write(
                (json.dumps(payload) + "\n").encode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, ValueError, OSError) as exc:
            raise self._crashed(str(payload.get("method"))) from exc

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def _request(self, method: str, params: dict[str, Any]) -> Any:
        with self._lock:
            # Unguessable request ids. With sequential ids a hostile server can
            # answer a question we have not asked yet -- emit a reply for id N+1
            # during the handshake and the client accepts it as the result of
            # its next call, letting the server forge a tool inventory. A random
            # id per request makes the reply unforgeable, and we additionally
            # refuse any id we did not issue.
            req_id = f"mar-{secrets.token_hex(8)}"
            self._outstanding.add(req_id)
            self._write({"jsonrpc": "2.0", "id": req_id, "method": method,
                         "params": params})
            t0 = time.monotonic()
            # Skip notifications and any out-of-band chatter until our id lands,
            # but never wait longer than `timeout` in total across all of it.
            while True:
                remaining = self.timeout - (time.monotonic() - t0)
                if remaining <= 0:
                    raise self._timeout(method, time.monotonic() - t0)
                try:
                    line = self._out_q.get(timeout=remaining)
                except queue.Empty:
                    raise self._timeout(method, time.monotonic() - t0) from None
                if line is None:  # EOF sentinel — the server is gone
                    raise self._crashed(method)
                if line is _OVERSIZE:
                    raise TargetProtocolError(
                        f"target {self.name!r} sent a frame larger than "
                        f"{_MAX_FRAME // (1024 * 1024)}MB while awaiting "
                        f"{method!r}; refusing to buffer it",
                        hint=("the server is emitting an implausibly large "
                              "response — check it is not returning an entire "
                              "dataset in a tool description"),
                        context={"method": method, "max_frame_bytes": _MAX_FRAME})
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(msg, dict):
                    continue
                msg_id = msg.get("id")
                if msg_id != req_id:
                    # Anything addressed to an id we never issued is either
                    # server confusion or a forgery attempt; either way it is
                    # not an answer to this request.
                    continue
                self._outstanding.discard(req_id)
                if "error" in msg:
                    raise TargetProtocolError(
                        f"target {self.name!r} returned an error for {method!r}: "
                        f"{msg['error']}",
                        context={"method": method, "error": msg["error"]})
                return msg.get("result")

    def _timeout(self, method: str, elapsed: float) -> TargetTimeoutError:
        return TargetTimeoutError(
            f"{self.kind} target {self.name!r} timed out after {elapsed:.1f}s "
            f"awaiting {method}",
            context={"method": method, "elapsed_s": round(elapsed, 2),
                     "timeout_s": self.timeout,
                     "command": " ".join(self.command)})
