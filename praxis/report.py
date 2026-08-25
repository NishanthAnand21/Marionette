"""Rendering layer — MatrixResult in, strings out.

Kept free of I/O on purpose: every renderer is a pure function of the result
object, so the CLI decides where bytes land (stdout, --json, --junit) and the
tests can assert on output without touching the filesystem.

Three audiences, three renderers: humans (text), other tools (json), and CI
(junit — the format Jenkins/GitLab/GitHub all already parse).
"""

from __future__ import annotations

import json
import os
import sys
import xml.etree.ElementTree as ET
import re
from typing import Any

# --- color -------------------------------------------------------------------
# Single source of truth so the CLI never rolls its own ANSI.

RESET = "\033[0m"
_CODES = {
    "green": "32", "red": "31", "yellow": "33", "magenta": "35",
    "cyan": "36", "dim": "2", "bold": "1", "bold_red": "1;31",
}

STATUS_COLOR = {"pass": "green", "fail": "red", "skip": "yellow",
                "error": "magenta"}
STATUS_GLYPH = {"pass": "\u2713", "fail": "\u2717", "skip": "\u2013",
                "error": "!"}
_ASCII_GLYPH = {"pass": "+", "fail": "x", "skip": "-", "error": "!"}


def _stdout_handles_unicode() -> bool:
    """Can stdout actually encode our glyphs?

    On Windows a *redirected* stdout falls back to the locale encoding
    (cp1252), where the tick raises UnicodeEncodeError -- and a redirected
    stdout is exactly the CI case. Crashing the reporter because of a
    decorative character would be absurd, so fall back to ASCII.
    """
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "".join(STATUS_GLYPH.values()).encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def glyph(status: str) -> str:
    table = STATUS_GLYPH if _stdout_handles_unicode() else _ASCII_GLYPH
    return table.get(status, "?")


def color_enabled(explicit: bool = True, stream=None) -> bool:
    """Colour only when asked for, honoured by the terminal, and not vetoed.

    NO_COLOR is a de-facto standard (no-color.org); a redirected stream means
    the bytes are going into a file or a pipe, where ANSI is noise.
    """
    if not explicit:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty())
    except Exception:  # pragma: no cover - exotic stream objects
        return False


def paint(text: str, name: str, color: bool = True) -> str:
    if not color or name not in _CODES:
        return text
    return f"\033[{_CODES[name]}m{text}{RESET}"


# --- helpers -----------------------------------------------------------------

def _status_of(res: Any) -> str:
    status = getattr(res, "status", None)
    if status:
        return status
    # Tolerate a result object that predates `.status`.
    if getattr(res, "error", None):
        return "error"
    if not getattr(res, "executed", True):
        return "skip"
    return "pass" if getattr(res, "passed", False) else "fail"


def _tag(status: str, color: bool) -> str:
    label = f"{glyph(status)} {status.upper():<5}"
    return paint(label, STATUS_COLOR.get(status, "dim"), color)


def _assertion_detail(a: Any) -> str:
    """`observed vs expected` for one assertion, in the author's own terms."""
    count = getattr(a, "count", None)
    min_count = getattr(a, "min_count", None)
    negate = getattr(a, "negate", False)
    if negate:
        expected = f"expected 0 (negated), observed {count}"
    elif min_count is not None:
        expected = f"expected >={min_count}, observed {count}"
    else:
        expected = f"observed {count}"
    return expected


def _error_block(res: Any, indent: str, color: bool) -> list[str]:
    detail = getattr(res, "error_detail", None) or {}
    code = detail.get("code") or "PRX-E000"
    message = detail.get("message") or getattr(res, "error", "") or "unknown error"
    lines = [f"{indent}{paint('[' + code + ']', 'bold_red', color)} {message}"]
    if detail.get("hint"):
        lines.append(f"{indent}  {paint('hint: ' + detail['hint'], 'dim', color)}")
    ctx = detail.get("context") or {}
    if ctx:
        kv = "  ".join(f"{k}={v!r}" for k, v in ctx.items())
        lines.append(f"{indent}  {paint('context: ' + kv, 'dim', color)}")
    return lines


# --- text --------------------------------------------------------------------

# --- untrusted text ----------------------------------------------------------

# C0/C1 controls minus tab, plus the Unicode bidi overrides and other invisible
# formatting characters. A malicious MCP server controls tool names and
# descriptions, and those are printed straight into the operator's terminal.
_CONTROL = {c: f"\\x{c:02x}" for c in range(0x20) if c != 0x09}
_CONTROL[0x7F] = "\\x7f"
_CONTROL.update({c: f"\\u{c:04x}" for c in range(0x80, 0xA0)})
_BIDI = (0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
         0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF)
_CONTROL.update({c: f"\\u{c:04x}" for c in _BIDI})
_SANITIZE = str.maketrans(_CONTROL)

MAX_UNTRUSTED = 400

# Codepoints XML 1.0 permits. Everything else -- NUL, most C0, lone surrogates
# -- must never reach an XML document, because ElementTree will happily write
# them and no conformant parser will read the result back.
_XML_OK = re.compile(
    "[^"
    "\u0009\u000A\u000D"
    "\u0020-\uD7FF"
    "\uE000-\uFFFD"
    "\U00010000-\U0010FFFF"
    "]")


def xml_safe(text: Any, limit: int = 2000) -> str:
    """Strip codepoints that are illegal in XML 1.0.

    A hostile target controls the error strings that land in `<failure
    message=...>`. One NUL byte makes the whole JUnit artifact unparseable, and
    a CI server that cannot parse the report shows "no test results" -- the run
    goes green by absence, hiding exactly the findings this tool exists to
    surface. Terminal sanitisation does not cover this: NUL is not an escape
    sequence.
    """
    if not isinstance(text, str):
        text = str(text)
    out = _XML_OK.sub("\uFFFD", text)
    if len(out) > limit:
        out = out[:limit] + f"... [+{len(out) - limit} chars]"
    return out


def sanitize(text: Any, limit: int = MAX_UNTRUSTED) -> str:
    """Make target-controlled text safe to print.

    A tool description containing ``ESC [ 2K CR`` can erase the line it was
    printed on and rewrite it -- letting a hostile server make `praxis drift`
    display "no drift detected" while it poisons a tool. Bidi overrides do the
    same job visually. Both are rendered as visible escapes instead, and the
    string is length-capped so one enormous field cannot bury the report.
    """
    if not isinstance(text, str):
        text = str(text)
    out = text.translate(_SANITIZE)
    if len(out) > limit:
        out = out[:limit] + f"... [+{len(out) - limit} chars]"
    return out


def render_text(matrix: Any, color: bool = True, verbose: bool = False) -> str:
    """Per-target grouped report: the thing a human reads after a run."""
    lines: list[str] = []
    runs = list(getattr(matrix, "runs", []))
    multi = len(runs) > 1

    for run in runs:
        header = f"{run.target_name} ({run.target_kind})"
        lines.append(paint(header, "bold", color))
        if getattr(run, "error", None):
            # Whole-target failure: the techniques never got a chance to run.
            lines.extend(_error_block(_ErrShim(run.error), "    ", color))
            lines.append("")
            continue

        for res in run.results:
            status = _status_of(res)
            # Technique metadata comes from a YAML pack that may be
            # third-party; treat it as untrusted before it hits the terminal.
            name = sanitize(getattr(res, "name", "") or "", 120)
            tid = sanitize(res.technique_id, 40)
            lines.append(f"  [{_tag(status, color)}] {tid}  {name}")

            if status == "skip":
                reason = getattr(res, "skipped_reason", None) or "not applicable"
                lines.append(f"        {paint(reason, 'dim', color)}")
            elif status == "error":
                lines.extend(_error_block(res, "        ", color))
            elif status == "fail":
                failed = [a for a in getattr(res, "assertions", [])
                          if not getattr(a, "passed", False)]
                for a in failed:
                    lines.append(f"        {paint('assertion failed:', 'red', color)} "
                                 f"{getattr(a, 'name', '?')}")
                    lines.append(f"          {paint(_assertion_detail(a), 'dim', color)}")
                if not failed and getattr(res, "error", None):
                    lines.append(f"        {paint(str(res.error), 'dim', color)}")
            elif verbose:
                meta = (f"{getattr(res, 'duration_ms', 0.0):.1f}ms  "
                        f"{getattr(res, 'event_count', 0)} events  "
                        f"{len(getattr(res, 'assertions', []))} assertions ok")
                lines.append(f"        {paint(meta, 'dim', color)}")

            if verbose and status in ("pass", "fail"):
                for a in getattr(res, "assertions", []):
                    mark = "ok  " if getattr(a, "passed", False) else "FAIL"
                    lines.append(f"          {paint(mark, 'dim', color)} "
                                 f"{getattr(a, 'name', '?')} "
                                 f"({_assertion_detail(a)})")

        counts = run.counts
        lines.append(f"        {paint(_counts_str(counts), 'dim', color)}")
        lines.append("")

    if multi:
        lines.extend(_summary_matrix(matrix, color))
        lines.append("")
    lines.append(render_summary_line(matrix, color=color))
    return "\n".join(lines)


class _ErrShim:
    """Adapts a bare error dict to what :func:`_error_block` expects."""

    def __init__(self, detail: dict[str, Any]):
        self.error_detail = detail
        self.error = detail.get("message")


def _counts_str(counts: dict[str, int]) -> str:
    order = ("pass", "fail", "skip", "error")
    return "  ".join(f"{k}={counts.get(k, 0)}" for k in order)


def _summary_matrix(matrix: Any, color: bool) -> list[str]:
    """Compact per-target grid — the whole fleet's state in one glance."""
    runs = list(matrix.runs)
    width = max([len(r.target_name) for r in runs] + [6])
    head = f"{'target':<{width}}  pass  fail  skip  error   time"
    out = [paint("summary", "bold", color), paint(head, "dim", color)]
    for r in runs:
        c = r.counts
        row = (f"{r.target_name:<{width}}  "
               f"{c.get('pass', 0):>4}  {c.get('fail', 0):>4}  "
               f"{c.get('skip', 0):>4}  {c.get('error', 0):>5}  "
               f"{r.duration_ms:>6.0f}ms")
        out.append(row)
    return out


def render_summary_line(matrix: Any, color: bool = True) -> str:
    t = matrix.totals
    parts = [
        paint(f"{t.get('pass', 0)} passed", "green", color),
        paint(f"{t.get('fail', 0)} failed", "red", color),
        paint(f"{t.get('skip', 0)} skipped", "yellow", color),
        paint(f"{t.get('error', 0)} errored", "magenta", color),
    ]
    tail = f"{len(matrix.runs)} target(s) in {matrix.duration_ms:.0f}ms"
    return (f"{paint('total', 'bold', color)}: " + ", ".join(parts)
            + f"  — {paint(tail, 'dim', color)}")


# --- json --------------------------------------------------------------------

def render_json(matrix: Any) -> str:
    return json.dumps(matrix.to_dict(), indent=2, default=str)


# --- junit -------------------------------------------------------------------

def render_junit(matrix: Any) -> str:
    """JUnit XML — the lingua franca every CI already knows how to display."""
    suites = ET.Element("testsuites", {
        "name": "praxis",
        "tests": str(sum(matrix.totals.get(k, 0)
                         for k in ("pass", "fail", "skip", "error"))),
        "failures": str(matrix.totals.get("fail", 0)),
        "errors": str(matrix.totals.get("error", 0)),
        "skipped": str(matrix.totals.get("skip", 0)),
        "time": f"{matrix.duration_ms / 1000.0:.3f}",
    })
    for run in matrix.runs:
        counts = run.counts
        suite = ET.SubElement(suites, "testsuite", {
            "name": xml_safe(run.target_name),
            "package": run.target_kind,
            "tests": str(len(run.results)),
            "failures": str(counts.get("fail", 0)),
            "errors": str(counts.get("error", 0)),
            "skipped": str(counts.get("skip", 0)),
            "time": f"{run.duration_ms / 1000.0:.3f}",
        })
        if getattr(run, "error", None):
            # A target that never came up is one synthetic errored testcase,
            # otherwise CI shows a silently empty suite.
            case = ET.SubElement(suite, "testcase", {
                "name": "target-setup", "classname": xml_safe(run.target_name)})
            detail = run.error
            err = ET.SubElement(case, "error", {
                "type": detail.get("code", "PRX-E000"),
                "message": xml_safe(detail.get("message", "target failed"))})
            err.text = xml_safe(detail.get("hint") or "")
            suite.set("tests", "1")
            suite.set("errors", "1")
            continue

        for res in run.results:
            status = _status_of(res)
            case = ET.SubElement(suite, "testcase", {
                "name": xml_safe(f"{res.technique_id} "
                                 f"{getattr(res, 'name', '') or ''}".strip()),
                "classname": xml_safe(f"praxis.{run.target_name}"),
                "time": f"{getattr(res, 'duration_ms', 0.0) / 1000.0:.3f}",
            })
            if status == "skip":
                ET.SubElement(case, "skipped", {
                    "message": xml_safe(getattr(res, "skipped_reason", None) or "skipped")})
            elif status == "error":
                detail = getattr(res, "error_detail", None) or {}
                node = ET.SubElement(case, "error", {
                    "type": detail.get("code", "PRX-E000"),
                    "message": detail.get("message")
                    or str(getattr(res, "error", None) or "error")})
                node.text = xml_safe(detail.get("hint") or "")
            elif status == "fail":
                failed = [a for a in getattr(res, "assertions", [])
                          if not getattr(a, "passed", False)]
                msg = "; ".join(getattr(a, "name", "?") for a in failed) or \
                    str(getattr(res, "error", None) or "assertions failed")
                node = ET.SubElement(case, "failure", {
                    "type": "AssertionFailed", "message": xml_safe(msg)})
                node.text = xml_safe("\n".join(
                    f"{getattr(a, 'name', '?')}: {_assertion_detail(a)}"
                    for a in failed))
    ET.indent(suites, space="  ")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            + ET.tostring(suites, encoding="unicode") + "\n")