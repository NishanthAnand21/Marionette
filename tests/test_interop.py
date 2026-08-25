"""Interop against the *official* MCP Python SDK.

Every other server in the suite is a stub we wrote, so testing the adapter
against them is circular — our client talks to our own idea of the protocol.
These tests drive a server built by the reference SDK, so the bytes on the
wire are the reference implementation's, not ours.

The SDK is a dev-only extra (deliberately not a Marionette dependency), so the
whole module skips cleanly when it is absent.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("mcp", reason="official MCP SDK not installed (dev-only)")

from marionette.targets.mcp import (PROTOCOL_VERSION, MCPTarget,  # noqa: E402
                                initialize_params)

SERVER = os.path.join(os.path.dirname(__file__), "fixtures", "sdk_server.py")
COMMAND = [sys.executable, SERVER]


def _sdk_importable() -> bool:
    """The fixture must actually start under the installed SDK major version.

    mcp 1.x and 2.x expose different server classes; the fixture handles both,
    but a future rename would leave it unimportable, and a hard failure here
    would be indistinguishable from an adapter bug.
    """
    p = subprocess.run([sys.executable, SERVER, "--marionette-import-check"],
                       capture_output=True, input="", text=True, timeout=60)
    return p.returncode == 0


pytestmark = pytest.mark.skipif(
    not _sdk_importable(),
    reason="installed MCP SDK is incompatible with the fixture server")


@pytest.fixture()
def sdk_target():
    t = MCPTarget(name="sdk", command=COMMAND, timeout=30)
    t.connect()
    try:
        yield t
    finally:
        t.close()


# -- handshake ------------------------------------------------------------
def test_initialize_negotiates_with_the_real_sdk(sdk_target):
    """Our hardcoded protocolVersion is still accepted by the SDK server."""
    assert sdk_target.server_info.get("name") == "marionette-sdk-fixture"


def _raw_initialize(version: str) -> dict:
    """Speak initialize by hand so the server's own reply can be inspected."""
    proc = subprocess.Popen(COMMAND, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    try:
        params = dict(initialize_params(), protocolVersion=version)
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": "1",
                                     "method": "initialize",
                                     "params": params}) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_server_echoes_our_protocol_version(sdk_target):
    """The SDK honours 2024-11-05 rather than forcing its own latest."""
    reply = _raw_initialize(PROTOCOL_VERSION)
    assert "error" not in reply, reply
    assert reply["result"]["protocolVersion"] == PROTOCOL_VERSION


def test_unknown_version_is_silently_downgraded_not_rejected():
    """Documents real server behaviour the adapter currently ignores.

    An unrecognised client version does not produce a JSON-RPC error — the
    server answers with a version of *its* choosing.  Marionette never reads the
    returned ``protocolVersion`` (``mcp.py`` keeps only ``serverInfo``), so a
    server answering in a protocol we did not ask for goes unnoticed.  This
    test pins the behaviour so a future adapter change is a deliberate one.
    """
    reply = _raw_initialize("1999-01-01")
    assert "error" not in reply, reply
    assert reply["result"]["protocolVersion"] != "1999-01-01"


# -- tools/list -----------------------------------------------------------
def test_tools_list_parses_names_descriptions_and_schemas(sdk_target):
    tools = {t.name: t for t in sdk_target.list_tools()}
    assert set(tools) == {"echo", "add", "boom"}

    echo = tools["echo"]
    assert echo.description.startswith("Echo the supplied text")
    assert echo.input_schema["type"] == "object"
    assert echo.input_schema["properties"]["text"]["type"] == "string"
    assert echo.input_schema["required"] == ["text"]

    add = tools["add"]
    assert set(add.input_schema["properties"]) == {"a", "b"}
    # An optional argument must not land in `required`.
    assert "required" not in tools["boom"].input_schema


# -- tools/call -----------------------------------------------------------
def test_call_tool_returns_content_blocks(sdk_target):
    res = sdk_target.call_tool("echo", {"text": "hello"})
    assert res.ok is True
    assert isinstance(res.content, list)
    block = res.content[0]
    assert block["type"] == "text"
    assert block["text"] == "echo: hello"


def test_call_tool_coerces_typed_arguments(sdk_target):
    res = sdk_target.call_tool("add", {"a": 2, "b": 3})
    assert res.ok is True
    assert res.content[0]["text"] == "5"


def test_tool_side_error_is_isError_not_a_transport_failure(sdk_target):
    """A raising tool comes back as isError, so ok=False and the run survives."""
    res = sdk_target.call_tool("boom", {"reason": "on purpose"})
    assert res.ok is False
    assert "boom" in json.dumps(res.content)


def test_unknown_tool_is_data_not_an_exception(sdk_target):
    res = sdk_target.call_tool("no_such_tool", {})
    assert res.ok is False


def test_health_round_trips_against_the_sdk(sdk_target):
    ok, why = sdk_target.health()
    assert ok is True and why is None


# -- CLI end-to-end -------------------------------------------------------
def _cli(*args, cwd):
    return subprocess.run([sys.executable, "-m", "marionette.cli", *args],
                          capture_output=True, text=True, cwd=cwd, timeout=300)


@pytest.fixture()
def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_cli_snapshot_run_and_drift_against_the_sdk(tmp_path, repo_root):
    cmd = f"{sys.executable} {SERVER}"
    snap_a = str(tmp_path / "a.json")
    snap_b = str(tmp_path / "b.json")

    r = _cli("snapshot", "--target", "mcp", "--command", cmd,
             "--out", snap_a, cwd=repo_root)
    assert r.returncode == 0, r.stderr
    captured = json.load(open(snap_a))
    assert set(captured["tools"]) == {"echo", "add", "boom"}

    r = _cli("run", "--target", "mcp", "--command", cmd, "--quiet",
             cwd=repo_root)
    # Techniques may legitimately skip on a benign server; what must not
    # happen is an adapter-level error.
    assert r.returncode in (0, 1), r.stderr
    assert "error" not in r.stdout.lower() or r.returncode == 0

    # Drift: a second snapshot with one tool removed must be reported.
    mutated = dict(captured)
    mutated["tools"] = {k: v for k, v in captured["tools"].items()
                        if k != "boom"}
    with open(snap_b, "w") as fh:
        json.dump(mutated, fh)
    r = _cli("drift", snap_a, snap_b, cwd=repo_root)
    assert "boom" in r.stdout, r.stdout
    assert r.returncode != 0 or "no drift" not in r.stdout
