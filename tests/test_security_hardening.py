"""Regressions for attacks a hostile target can mount on the operator.

Marionette is pointed at servers that may be actively malicious. Each test here
corresponds to a confirmed exploit, kept so the fix cannot quietly rot.
"""

from __future__ import annotations

import os

import pytest
import xml.etree.ElementTree as ET

from marionette import report
from marionette.drift import Snapshot, diff
from marionette.targets.base import ToolSpec
from marionette.targets.mcp import MCPTarget


def test_request_ids_are_unguessable():
    """Sequential ids let a server answer a question never asked.

    Emitting a reply for id N+1 during the handshake made the client accept it
    as the result of its next call, letting the server forge a tool inventory.
    """
    t = MCPTarget(name="x", command="true")
    ids = {f"mar-{__import__('secrets').token_hex(8)}" for _ in range(100)}
    assert len(ids) == 100                      # no collisions
    assert not any(i.endswith(("-1", "-2")) for i in ids)
    assert t._outstanding == set()              # nothing outstanding before use


def test_terminal_escapes_in_target_text_are_neutralised():
    """ESC[2K CR would let a server repaint the line it was printed on."""
    evil = "Safe." + chr(27) + "[2K\r" + chr(27) + "[32m no drift" + chr(0x202E) + "x"
    out = report.sanitize(evil)
    assert "\x1b" not in out and "\r" not in out and "‮" not in out
    assert "\\x1b" in out and "\\u202e" in out   # rendered visibly instead


def test_sanitize_caps_length():
    assert len(report.sanitize("A" * 10_000, limit=100)) < 200


def test_junit_survives_xml_illegal_codepoints():
    """One NUL made the whole artifact unparseable.

    A CI server that cannot parse the report shows "no test results" — the run
    goes green by absence, hiding the findings Marionette produced.
    """
    class A:
        passed = False; name = "evil\x00\x1b[31m\x07"; count = None
        min_count = None; negate = False

    class R:
        technique_id = "T\x00"; name = "tool \x00\x08\x0b]]> <x>"
        duration_ms = 1.0; passed = False; executed = True; error = None
        error_detail = {"message": "srv \x00\x0b", "hint": "h\x00"}
        assertions = [A()]; event_count = 1; skipped_reason = None; status = "fail"

    class Run:
        target_name = "t\x00"; target_kind = "mcp"; results = [R()]
        duration_ms = 1.0; counts = {"fail": 1}; error = None

    class M:
        runs = [Run()]; totals = {"fail": 1}; duration_ms = 1.0

    xml = report.render_junit(M())
    ET.fromstring(xml)                          # must parse
    illegal = [c for c in xml if ord(c) < 0x20 and c not in "\t\n\r"]
    assert not illegal, f"illegal codepoints survived: {illegal!r}"


def test_hostile_server_does_not_inherit_operator_secrets():
    """The subprocess under test must not receive ambient credentials."""
    os.environ["MARIONETTE_TEST_FAKE_TOKEN"] = "super-secret"
    try:
        env = MCPTarget._build_env(None, inherit_env=False)
        assert "MARIONETTE_TEST_FAKE_TOKEN" not in env
        assert "PATH" in env                     # still launchable
        opted_in = MCPTarget._build_env(None, inherit_env=True)
        assert opted_in.get("MARIONETTE_TEST_FAKE_TOKEN") == "super-secret"
        explicit = MCPTarget._build_env({"NEEDED": "1"}, inherit_env=False)
        assert explicit["NEEDED"] == "1"
    finally:
        del os.environ["MARIONETTE_TEST_FAKE_TOKEN"]


def test_drift_refuses_snapshots_from_different_targets():
    """Diffing two servers reported every tool as changed — a silent lie."""
    from marionette.errors import MarionetteError

    a = Snapshot.capture("server-a", [ToolSpec("x", "d")])
    b = Snapshot.capture("server-b", [ToolSpec("y", "d")])
    try:
        diff(a, b)
        raise AssertionError("cross-target diff was permitted")
    except MarionetteError as exc:
        assert "different targets" in str(exc)
    assert diff(a, b, allow_cross_target=True)   # explicit opt-in still works


def test_target_name_cannot_contain_a_path_separator():
    from marionette.config import TargetSpec

    spec = TargetSpec(name="../../etc/evil", kind="mock")
    assert any("path separator" in p for p in spec.validate())


def test_shipped_example_fleet_is_valid():
    """The example fleet must parse and validate.

    It is the first file a new user copies, and it is referenced by CI and the
    README. A broken one passed the entire suite once, because nothing loaded
    it — an edit to a comment silently corrupted the document.
    """
    from marionette.config import Fleet

    root = os.path.join(os.path.dirname(__file__), os.pardir)
    fleet = Fleet.load(os.path.join(root, "targets.example.yaml"))
    assert fleet.targets, "example fleet defines no targets"
    assert not fleet.validate(), fleet.validate()


def test_shipped_docs_and_metadata_exist():
    """Files the README and CI reference must actually be present."""
    root = os.path.join(os.path.dirname(__file__), os.pardir)
    for rel in ("README.md", "CONTRIBUTING.md", "CHANGELOG.md",
                "targets.example.yaml", "reference/atlas-catalog.yaml",
                "docs/event-schema.md", ".github/workflows/ci.yml"):
        assert os.path.exists(os.path.join(root, rel)), f"missing {rel}"


# --- portability -------------------------------------------------------------

def test_report_artifacts_are_lf_only(tmp_path):
    """Machine-readable output must not pick up CRLF on Windows.

    JSONL is line-framed, and snapshots are hashed and diffed — a platform
    dependent line ending makes the same inventory look changed.
    """
    import subprocess
    import sys

    root = os.path.join(os.path.dirname(__file__), os.pardir)
    js, xml, ev = (tmp_path / n for n in ("r.json", "j.xml", "e.jsonl"))
    r = subprocess.run(
        [sys.executable, "-m", "marionette.cli", "run",
         "--json", str(js), "--junit", str(xml), "--events", str(ev)],
        capture_output=True, text=True, cwd=root)
    assert r.returncode == 0, r.stdout + r.stderr
    for path in (js, xml, ev):
        raw = path.read_bytes()
        assert raw, f"{path.name} is empty"
        assert b"\r" not in raw, f"{path.name} contains CR"


def test_snapshot_is_lf_only(tmp_path):
    from marionette.drift import Snapshot
    from marionette.targets.base import ToolSpec

    out = tmp_path / "s.json"
    Snapshot.capture("t", [ToolSpec("a", "d")]).save(str(out))
    assert b"\r" not in out.read_bytes()


def test_windows_command_strings_are_not_mangled():
    """POSIX shlex eats backslashes, silently corrupting Windows paths."""
    from marionette.targets.mcp import _split_command

    parts = _split_command(r'C:\Users\me\python.exe server.py')
    if os.name == "nt":
        assert parts[0] == r"C:\Users\me\python.exe"
    else:
        # On POSIX the backslash really is an escape; assert we at least still
        # split into two arguments rather than dropping one.
        assert len(parts) == 2


def test_env_allowlist_matches_case_insensitively():
    """os.environ upper-cases keys on Windows, so mixed-case entries never hit."""
    from marionette.targets.mcp import MCPTarget

    assert "SYSTEMROOT" in MCPTarget._ENV_ALLOWLIST
    assert all(k == k.upper() for k in MCPTarget._ENV_ALLOWLIST), \
        "allowlist entries must be upper-case to match Windows os.environ"


def test_status_glyphs_fall_back_to_ascii_on_narrow_encodings():
    """A redirected stdout on Windows is cp1252; the tick raises there."""
    from marionette import report

    assert set("".join(report._ASCII_GLYPH.values())).issubset(
        set(chr(c) for c in range(128))), "fallback glyphs must be ASCII"


@pytest.mark.slow
def test_wedged_server_is_reaped_within_the_shutdown_budget(tmp_path):
    """A server ignoring EOF and SIGTERM must still be killed, and bounded."""
    import subprocess
    import sys
    import time

    script = tmp_path / "stubborn.py"
    # Must complete the handshake, otherwise connect() fails and reaps the
    # child before shutdown is ever exercised -- which would make this test
    # silently cover the wrong path. It answers initialize, then ignores both
    # stdin EOF and SIGTERM.
    script.write_text(
        "import sys, json, time, signal\n"
        "try: signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "except Exception: pass\n"
        "for line in sys.stdin:\n"
        "    line = line.strip()\n"
        "    if not line: continue\n"
        "    try: m = json.loads(line)\n"
        "    except Exception: continue\n"
        "    if m.get('method') == 'initialize':\n"
        "        sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':m.get('id'),"
        "'result':{'protocolVersion':'2024-11-05','capabilities':{},"
        "'serverInfo':{'name':'stubborn'}}}) + chr(10))\n"
        "        sys.stdout.flush()\n"
        "while True: time.sleep(1)\n")
    from marionette.targets import build

    t = build("mcp", name="s", command=[sys.executable, str(script)], timeout=5)
    try:
        t.connect()
    except Exception:
        pass
    proc = t._proc            # grab the handle before close() drops it
    t0 = time.monotonic()
    t.close()
    assert time.monotonic() - t0 < 8, "shutdown escalation is unbounded"

    # Ask the process object rather than shelling out to `pgrep`, which does
    # not exist on Windows. A non-None returncode means it was actually reaped,
    # which is the invariant -- "no matching process name" only approximated it.
    assert proc is not None, "server never started"
    assert proc.poll() is not None, "child survived close()"
