"""Adapter conformance + per-adapter behaviour.

The conformance suite is parametrised over ``marionette.targets.registry()``, so a
new adapter inherits every contract test the day it is registered.  If a kind
appears here without a builder the suite fails loudly rather than silently
skipping it -- an untested adapter is exactly the thing this file exists to
prevent.
"""

from __future__ import annotations

import os
import sys

import pytest

from marionette.errors import (TargetConnectError, TargetError, TargetProtocolError,
                           TargetTimeoutError, UnsupportedCapability)
from marionette.schema import TOOL_LIST
from marionette.targets import ToolResult, ToolSpec, registry
from marionette.targets.base import Target
from marionette.targets.callable import CallableTarget, load_object
from marionette.targets.http import HTTPMCPTarget
from marionette.targets.mcp import MCPTarget

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.http_stub import closed_port_url, stub_server  # noqa: E402

HOSTILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "hostile_mcp.py")


def hostile_cmd(mode: str, *extra: str) -> list[str]:
    return [sys.executable, HOSTILE, mode, *extra]


# --------------------------------------------------------------------------
# A conformant callable shim: implements the whole documented protocol.
# --------------------------------------------------------------------------
class ConformantShim:
    capabilities = {"list_tools", "call_tool", "prompt"}

    def __init__(self):
        self.connected = 0
        self.closed = 0
        self.resets = 0

    def connect(self):
        self.connected += 1

    def close(self):
        self.closed += 1

    def reset(self):
        self.resets += 1

    def list_tools(self):
        return [{"name": "read_public", "description": "Read a record.",
                 "input_schema": {"type": "object"}},
                {"name": "send_email", "description": "Send mail."}]

    def call_tool(self, name, args):
        if name not in ("read_public", "send_email"):
            return {"ok": False, "error": f"no such tool: {name}"}
        return {"ok": True, "content": f"{name} ok"}

    def send_prompt(self, text, provenance="user"):
        return f"echo:{text}"


# --------------------------------------------------------------------------
# Builders: one per registered kind. `_BUILDERS` is asserted to be exhaustive.
# --------------------------------------------------------------------------
class _Built:
    """A live adapter plus whatever context manager keeps its server alive."""

    def __init__(self, target, ctx=None):
        self.target = target
        self.ctx = ctx


def _build(kind, name):
    """Build a live adapter of `kind`.

    Adapters needing a server or a shim get an explicit builder; anything
    else is assumed to be an in-process adapter constructible from a name
    alone, so a newly registered adapter is covered automatically instead of
    being skipped.
    """
    if kind == "callable":
        return _Built(CallableTarget(name=name, target=ConformantShim()))
    if kind == "mcp":
        return _Built(MCPTarget(name=name, command=hostile_cmd("ok"),
                                timeout=10.0))
    if kind == "http":
        ctx = stub_server("ok")
        url = ctx.__enter__()
        return _Built(HTTPMCPTarget(name=name, url=url, timeout=10.0), ctx)
    cls = registry()[kind]
    try:
        return _Built(cls(name=name))
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"adapter kind {kind!r} needs a conformance builder: "
            f"{type(exc).__name__}: {exc}") from exc


@pytest.fixture(params=sorted(registry()))
def adapter(request):
    """A connected adapter of every registered kind."""
    built = _build(request.param, f"conf-{request.param}")
    try:
        built.target.connect()
        yield built.target
    finally:
        try:
            built.target.close()
        finally:
            if built.ctx is not None:
                built.ctx.__exit__(None, None, None)


@pytest.mark.parametrize("kind", sorted(registry()))
def test_every_registered_kind_is_buildable_for_conformance(kind):
    """Guards the suite itself: a new adapter cannot slip through untested."""
    built = _build(kind, f"buildable-{kind}")
    try:
        assert isinstance(built.target, Target)
        assert built.target.kind == kind
    finally:
        built.target.close()
        if built.ctx is not None:
            built.ctx.__exit__(None, None, None)


# --- shared contract -------------------------------------------------------
def test_list_tools_returns_specs_and_emits_exactly_one_list_event(adapter):
    before = len(adapter.collector.of_type(TOOL_LIST))
    tools = adapter.list_tools()
    assert isinstance(tools, list)
    assert all(isinstance(t, ToolSpec) for t in tools)
    assert all(isinstance(t.name, str) and t.name for t in tools)
    after = adapter.collector.of_type(TOOL_LIST)
    assert len(after) - before == 1, (
        f"{adapter.kind}: list_tools() emitted {len(after) - before} "
        f"{TOOL_LIST} events, expected exactly 1")
    assert after[-1].data["count"] == len(tools)


def test_call_tool_on_missing_tool_fails_softly(adapter):
    res = adapter.call_tool("marionette_no_such_tool_xyz", {})
    assert isinstance(res, ToolResult)
    assert res.ok is False, f"{adapter.kind} claimed success for a missing tool"


def test_events_carry_the_adapter_name_as_target(adapter):
    adapter.list_tools()
    adapter.call_tool("marionette_no_such_tool_xyz", {})
    assert adapter.collector.events
    for ev in adapter.collector.events:
        assert ev.target == adapter.name, (
            f"{adapter.kind} emitted an event with target={ev.target!r}")


def test_close_is_idempotent_and_exit_always_closes(adapter):
    adapter.close()
    adapter.close()          # must not raise
    with adapter as t:       # __enter__ reconnects, __exit__ must close
        assert t is adapter
    adapter.close()


@pytest.mark.parametrize("kind", sorted(registry()))
def test_reset_safe_before_connect_and_after_close(kind):
    built = _build(kind, f"reset-{kind}")
    t = built.target
    try:
        t.reset()
        t.reset()            # idempotent before connect
        t.connect()
        t.reset()
        t.close()
        t.reset()
        t.reset()            # idempotent after close
    finally:
        t.close()
        if built.ctx is not None:
            built.ctx.__exit__(None, None, None)


# --- capability <-> method coherence ---------------------------------------
# Capabilities that name a verb the engine dispatches, and the method behind it.
CAP_METHODS = {
    "list_tools": "list_tools",
    "call_tool": "call_tool",
    "prompt": "send_prompt",
    "snapshot": "list_tools",
    "memory": "mem_write",
    "delegation": "delegate",
    "delegate": "delegate",
    "grant": "grant",
    "revoke": "revoke",
    "set_description": "set_description",
    "add_tool": "add_tool",
    "remove_tool": "remove_tool",
    "set_system_prompt": "set_system_prompt",
    "load_artifact": "load_artifact",
    "rag_index": "rag_index",
    "rag_query": "rag_query",
    "set_identity": "set_identity",
    "env_set": "env_set",
    "env_read": "env_read",
}
# Behavioural flags, not verbs: nothing calls them, so they need no method.
BEHAVIOURAL_CAPS = {"follows_tool_output"}


def test_every_advertised_capability_has_a_method(adapter):
    for cap in sorted(adapter.capabilities):
        if cap in BEHAVIOURAL_CAPS:
            continue
        assert cap in CAP_METHODS, (
            f"{adapter.kind} advertises unknown capability {cap!r}; either it "
            "is a typo or this test's map needs the new verb")
        meth = CAP_METHODS[cap]
        fn = getattr(adapter, meth, None)
        assert callable(fn), (
            f"{adapter.kind} advertises {cap!r} but has no {meth}()")
        if cap == "memory":
            assert callable(getattr(adapter, "mem_read", None))


@pytest.mark.parametrize("kind,cls", sorted(registry().items()))
def test_every_implemented_verb_is_advertised(kind, cls):
    """The other direction: a method nobody advertises can never be reached."""
    caps = set(getattr(cls, "capabilities", frozenset()))
    covered = {CAP_METHODS[c] for c in caps if c in CAP_METHODS}
    for cap, meth in CAP_METHODS.items():
        impl = getattr(cls, meth, None)
        base = getattr(Target, meth, None)
        if impl is None or impl is base:
            continue          # inherited stub, not an implementation
        assert meth in covered, (
            f"{kind} implements {meth}() but advertises no capability that "
            f"reaches it (has {sorted(caps)})")


# --------------------------------------------------------------------------
# callable adapter
# --------------------------------------------------------------------------
class RaisingShim:
    def list_tools(self):
        return ["only_tool"]

    def call_tool(self, name, args):
        raise RuntimeError("shim exploded")


class NonStringShim:
    def list_tools(self):
        return [{"name": "n"}]

    def call_tool(self, name, args):
        return {"rows": [1, 2, 3]}


class BlockingShim:
    def list_tools(self):
        return []

    def call_tool(self, name, args):
        import time
        time.sleep(30)
        return "never"


class NotAShim:
    pass


def test_callable_happy_path_lifecycle():
    shim = ConformantShim()
    t = CallableTarget(name="c", target=shim)
    with t:
        tools = t.list_tools()
        assert [x.name for x in tools] == ["read_public", "send_email"]
        assert tools[0].input_schema == {"type": "object"}
        res = t.call_tool("read_public", {"key": "k"})
        assert res.ok and res.content == "read_public ok"
        assert t.send_prompt("hi") == "echo:hi"
        t.reset()
        assert t.health() == (True, None)
    assert shim.connected == 1 and shim.closed == 1 and shim.resets == 1


def test_callable_bare_string_tool_list_is_accepted():
    t = CallableTarget(name="c", target=RaisingShim())
    t.connect()
    tools = t.list_tools()
    assert [x.name for x in tools] == ["only_tool"]
    assert tools[0].description == ""


def test_callable_shim_exception_becomes_a_failed_result_not_a_crash():
    t = CallableTarget(name="c", target=RaisingShim())
    t.connect()
    res = t.call_tool("only_tool", {})
    assert res.ok is False
    assert "RuntimeError" in res.error and "shim exploded" in res.error
    # ...and it is still recorded as an observed result event.
    assert any(e.data.get("ok") is False for e in t.collector.events
               if e.type == "agent.tool.result")


def test_callable_non_string_return_is_wrapped_as_content():
    t = CallableTarget(name="c", target=NonStringShim())
    t.connect()
    res = t.call_tool("n", {})
    assert res.ok is True
    assert res.content == {"rows": [1, 2, 3]}


def test_callable_missing_capability_degrades_to_unsupported():
    t = CallableTarget(name="c", target=NonStringShim())
    t.connect()
    assert "prompt" not in t.capabilities
    with pytest.raises(UnsupportedCapability):
        t.send_prompt("hello")


def test_callable_has_no_timeout_enforcement_documented_by_this_test():
    """The callable adapter takes a `timeout` but runs the shim in-process.

    There is no way to interrupt arbitrary user code, so the value is stored
    and never enforced.  This test pins that reality so nobody assumes a
    blocking shim will be cut short.
    """
    t = CallableTarget(name="c", target=BlockingShim(), timeout=0.01)
    assert t.timeout == 0.01
    import inspect
    src = inspect.getsource(CallableTarget.call_tool)
    assert "timeout" not in src


def test_callable_rejects_an_object_that_is_not_a_shim():
    t = CallableTarget(name="c", target=None, path=f"{__name__}:NotAShim")
    with pytest.raises(TargetConnectError):
        t.connect()


def test_callable_requires_a_target_or_path():
    with pytest.raises(ValueError):
        CallableTarget(name="c")


def test_callable_load_object_errors_name_the_path():
    with pytest.raises(TargetConnectError) as exc:
        load_object("marionette_no_such_module_xyz:thing")
    assert "marionette_no_such_module_xyz" in str(exc.value)
    with pytest.raises(TargetConnectError):
        load_object("nodots")
    with pytest.raises(TargetConnectError):
        load_object("")


def test_callable_health_is_false_before_connect():
    t = CallableTarget(name="c", target=None, path=f"{__name__}:ConformantShim")
    assert t.health()[0] is False


# --------------------------------------------------------------------------
# http adapter -- against a local stub only
# --------------------------------------------------------------------------
def test_http_happy_path():
    with stub_server("ok") as url:
        t = HTTPMCPTarget(name="h", url=url, timeout=5.0)
        with t:
            assert t.server_info.get("name") == "http-stub"
            tools = t.list_tools()
            assert [x.name for x in tools] == ["read_public", "send_email"]
            res = t.call_tool("read_public", {})
            assert res.ok is True
            assert t.health() == (True, None)


def test_http_sse_body_with_interleaved_notifications():
    with stub_server("sse_noisy") as url:
        t = HTTPMCPTarget(name="h", url=url, timeout=5.0)
        with t:
            assert [x.name for x in t.list_tools()] == ["read_public",
                                                        "send_email"]


def test_http_non_200_is_a_protocol_error_carrying_the_body():
    with stub_server("status500") as url:
        t = HTTPMCPTarget(name="h", url=url, timeout=5.0)
        with pytest.raises(TargetProtocolError) as exc:
            t.connect()
        assert exc.value.context["status"] == 500
        assert "upstream exploded" in exc.value.context["body"]


def test_http_malformed_json_body_is_a_protocol_error():
    with stub_server("badjson") as url:
        t = HTTPMCPTarget(name="h", url=url, timeout=5.0)
        with pytest.raises(TargetProtocolError) as exc:
            t.connect()
        assert "not JSON-RPC" in exc.value.message


def test_http_reply_to_the_wrong_id_is_rejected():
    with stub_server("wrong_id") as url:
        t = HTTPMCPTarget(name="h", url=url, timeout=5.0)
        with pytest.raises(TargetProtocolError):
            t.connect()


@pytest.mark.slow
def test_http_slow_response_trips_the_configured_timeout():
    with stub_server("ok", delay=3.0) as url:
        t = HTTPMCPTarget(name="h", url=url, timeout=0.4)
        with pytest.raises(TargetTimeoutError) as exc:
            t.connect()
        assert exc.value.context["timeout_s"] == 0.4


def test_http_connection_refused_is_a_connect_error():
    t = HTTPMCPTarget(name="h", url=closed_port_url(), timeout=2.0)
    with pytest.raises(TargetConnectError):
        t.connect()
    # health() never raises, it reports.
    ok, reason = t.health()
    assert ok is False and reason


def test_http_health_is_false_against_a_dead_endpoint():
    t = HTTPMCPTarget(name="h", url=closed_port_url(), timeout=2.0)
    assert t.health()[0] is False


def test_http_refuses_non_http_schemes_and_hostless_urls():
    for bad in ("file:///etc/passwd", "ftp://example.invalid/x", "://nope"):
        with pytest.raises((TargetConnectError, ValueError)):
            HTTPMCPTarget(name="h", url=bad)
    with pytest.raises(ValueError):
        HTTPMCPTarget(name="h")


def test_http_close_is_idempotent_and_clears_session():
    with stub_server("ok") as url:
        t = HTTPMCPTarget(name="h", url=url, timeout=5.0)
        t.connect()
        t.session_id = "abc"
        t.close()
        t.close()
        assert t.session_id is None


# --------------------------------------------------------------------------
# mcp adapter -- hostile servers
# --------------------------------------------------------------------------
def test_mcp_huge_tools_list_is_handled_whole():
    t = MCPTarget(name="m", command=hostile_cmd("huge", "1500"), timeout=20.0)
    with t:
        tools = t.list_tools()
        assert len(tools) == 1500
        assert tools[-1].name == "tool_01499"
        evs = t.collector.of_type(TOOL_LIST)
        assert len(evs) == 1 and evs[0].data["count"] == 1500


def test_mcp_unsolicited_notifications_do_not_steal_the_reply():
    t = MCPTarget(name="m", command=hostile_cmd("noisy"), timeout=10.0)
    with t:
        tools = t.list_tools()
        assert [x.name for x in tools] == ["read_public", "send_email"]
        res = t.call_tool("read_public", {})
        assert res.ok is True
        # A second exchange must not be poisoned by the first round's chatter.
        assert len(t.list_tools()) == 2


def test_mcp_server_that_closes_stdout_but_keeps_running_is_not_a_hang():
    t = MCPTarget(name="m", command=hostile_cmd("close_stdout"), timeout=10.0)
    t.connect()
    try:
        with pytest.raises(TargetError) as exc:
            t.list_tools()
        # EOF on stdout is reported as a crash, not as a 10s timeout.
        assert exc.value.code in ("MAR-E104", "MAR-E102")
    finally:
        t.close()
    assert t._proc is None


def test_mcp_error_response_for_unknown_tool_is_a_failed_result():
    t = MCPTarget(name="m", command=hostile_cmd("ok"), timeout=10.0)
    with t:
        res = t.call_tool("no_such_tool", {})
        assert res.ok is False and "unknown tool" in (res.error or "")


@pytest.mark.slow
def test_mcp_hanging_server_times_out_and_is_reaped():
    t = MCPTarget(name="m", command=hostile_cmd("hang"), timeout=0.5)
    t.connect()
    with pytest.raises(TargetTimeoutError):
        t.list_tools()
    t.close()
    assert t._proc is None


def test_mcp_crashing_server_is_reported_with_stderr():
    t = MCPTarget(name="m", command=hostile_cmd("crash"), timeout=10.0)
    t.connect()
    try:
        with pytest.raises(TargetError) as exc:
            t.list_tools()
        assert exc.value.code == "MAR-E104"
    finally:
        t.close()
