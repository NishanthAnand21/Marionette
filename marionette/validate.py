"""Technique + fleet validation — every problem at once, never the first only.

`marionette validate` is the authoring feedback loop.  It works on *raw* YAML
rather than on constructed :class:`~marionette.technique.Technique` objects on
purpose: the model classes raise on the first bad value, which is exactly the
wrong behaviour for a linter.  A technique author wants the whole list.

Severity is a contract:

* ``error``   — the technique is broken or would silently pass. Blocks CI.
* ``warning`` — the technique works but is under-documented or unmapped.

The one non-obvious rule: *a technique with no assertions is an error*.  It
executes, asserts nothing, and reports green forever.  That is the worst
failure mode a detection pack can have.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from .errors import ConfigParseError
from .config import Fleet
from .schema import EVENT_CLASSES
from .technique import Step

__all__ = ["Problem", "validate_file", "validate_dir", "validate_fleet"]

ERROR = "error"
WARNING = "warning"

ID_RE = re.compile(r"^MAR-\d{4}$")

REQUIRED_KEYS = ("id", "name", "steps")

# Args each step verb cannot run without. Checked here so a broken technique
# fails at lint time rather than mid-run against a live target.
REQUIRED_STEP_ARGS: dict[str, tuple[str, ...]] = {
    "call_tool": ("tool",),
    "set_description": ("tool", "description"),
    "mem_write": ("key", "value"),
    "mem_read": ("key",),
    "grant": ("authority",),
    # extended verb surface
    "add_tool": ("name",),
    "remove_tool": ("name",),
    "load_artifact": ("name",),
    "rag_index": ("doc_id",),
    "delegate": ("agent",),
    "set_identity": ("principal",),
    "env_set": ("key", "value"),
    "env_read": ("key",),
    "revoke": ("authority",),
}

# Verbs that only the mock range implements. A technique using one of these
# without declaring it in `requires:` will crash on an MCP target instead of
# skipping cleanly -- so the validator insists the declaration is present.
VERB_CAPABILITY: dict[str, str] = {
    "grant": "grant", "revoke": "revoke", "mem_write": "memory",
    "mem_read": "memory", "set_description": "set_description",
    "add_tool": "add_tool", "remove_tool": "remove_tool",
    "set_system_prompt": "set_system_prompt", "load_artifact": "load_artifact",
    "rag_index": "rag_index", "rag_query": "rag_query", "delegate": "delegate",
    "set_identity": "set_identity", "env_set": "env_set",
    "env_read": "env_read", "send_prompt": "prompt",
}

_COLORS = {ERROR: "\033[31m", WARNING: "\033[33m"}


@dataclass
class Problem:
    """One actionable finding, addressed to whoever authored the file."""

    path: str
    message: str
    severity: str = ERROR
    technique_id: str | None = None

    def render(self, color: bool = False) -> str:
        label = self.severity
        if color:
            label = f"{_COLORS.get(self.severity, '')}{label}\033[0m"
        where = self.path
        if self.technique_id:
            where = f"{where} [{self.technique_id}]"
        return f"{label}: {where}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "message": self.message,
                "severity": self.severity, "technique_id": self.technique_id}


_CATALOG_CACHE: dict[str, Any] | None = None


def load_catalog() -> dict[str, Any]:
    """Load the verified ATLAS catalog shipped in ``reference/``.

    Mapping a technique to an ATLAS id that *exists but means something else*
    is the failure mode that silently passes every other check, so the ids are
    validated against the real catalog rather than a regex.
    """
    global _CATALOG_CACHE
    if _CATALOG_CACHE is not None:
        return _CATALOG_CACHE
    import os
    import yaml as _yaml

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(here, "reference", "atlas-catalog.yaml")
    if not os.path.exists(path):
        _CATALOG_CACHE = {}
        return _CATALOG_CACHE
    with open(path, encoding="utf-8") as fh:
        raw = _yaml.safe_load(fh) or {}
    _CATALOG_CACHE = {
        "techniques": {t["id"]: t for t in raw.get("techniques", [])},
        "tactics": {t["id"]: t for t in raw.get("tactics", [])},
        "asi": {a["id"]: a for a in raw.get("owasp_asi", [])},
        "version": raw.get("version"),
    }
    return _CATALOG_CACHE


def check_atlas_ids(raw: dict[str, Any], path: str,
                    tid: str | None) -> list["Problem"]:
    """Cross-check `atlas:` / `owasp_asi:` against the verified catalog."""
    cat = load_catalog()
    problems: list[Problem] = []
    if not cat:
        # Announce rather than silently pass: a missing catalog disables the
        # strongest check we have, and "valid" would otherwise be a lie.
        return [Problem(
            path=path, technique_id=tid, severity="warning",
            message=("ATLAS catalog not found (reference/atlas-catalog.yaml); "
                     "atlas/owasp id verification was SKIPPED"))]
    techs, asis = cat["techniques"], cat["asi"]

    ids = raw.get("atlas") or []
    if isinstance(ids, list):
        for aid in ids:
            if not isinstance(aid, str):
                continue
            if aid not in techs:
                near = [k for k in techs if k.startswith(aid.split(".")[0] + "."
                        + aid.split(".")[1])][:4] if aid.count(".") >= 1 else []
                problems.append(Problem(
                    path=path, technique_id=tid, severity="error",
                    message=(f"atlas id {aid!r} is not in the verified ATLAS "
                             f"catalog (v{cat['version']})"
                             + (f"; did you mean one of {near}?" if near else ""))))

    ids = raw.get("owasp_asi") or []
    if isinstance(ids, list):
        for aid in ids:
            if isinstance(aid, str) and aid not in asis:
                problems.append(Problem(
                    path=path, technique_id=tid, severity="error",
                    message=f"owasp_asi id {aid!r} is not a valid ASI id "
                            f"(expected ASI01..ASI10)"))
    return problems


def known_capabilities() -> set[str]:
    """Union of the capabilities every registered adapter exposes."""
    # imported lazily so every adapter has registered itself first
    from .targets import known_capabilities as _kc

    return set(_kc())


def _blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict, tuple)):
        return len(value) == 0
    return False


def _check_steps(raw: dict[str, Any], path: str, tid: str | None,
                 out: list[Problem]) -> None:
    steps = raw.get("steps")
    if _blank(steps):
        return  # already reported as a missing required key
    if not isinstance(steps, list):
        out.append(Problem(path, "`steps` must be a list", ERROR, tid))
        return
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            out.append(Problem(path, f"steps[{i}] is not a mapping", ERROR, tid))
            continue
        action = step.get("action")
        if _blank(action):
            out.append(Problem(path, f"steps[{i}] has no `action`", ERROR, tid))
            continue
        if action not in Step.VERBS:
            out.append(Problem(
                path,
                f"steps[{i}] has unknown action {action!r}; "
                f"valid: {sorted(Step.VERBS)}", ERROR, tid))
            continue
        args = step.get("args") or {}
        if not isinstance(args, dict):
            out.append(Problem(path, f"steps[{i}] (`{action}`) `args` must be "
                                     "a mapping", ERROR, tid))
            continue
        for need in REQUIRED_STEP_ARGS.get(action, ()):
            if need not in args or _blank(args.get(need)):
                out.append(Problem(
                    path,
                    f"steps[{i}] action {action!r} is missing required arg "
                    f"`{need}`", ERROR, tid))


def _check_assertions(raw: dict[str, Any], path: str, tid: str | None,
                      out: list[Problem]) -> None:
    assertions = raw.get("assertions")
    if _blank(assertions):
        out.append(Problem(
            path,
            "technique defines no `assertions`; it can never fail and would "
            "report green forever", ERROR, tid))
        return
    if not isinstance(assertions, list):
        out.append(Problem(path, "`assertions` must be a list", ERROR, tid))
        return
    for i, a in enumerate(assertions):
        if not isinstance(a, dict):
            out.append(Problem(path, f"assertions[{i}] is not a mapping",
                               ERROR, tid))
            continue
        etype = a.get("type")
        if _blank(etype):
            out.append(Problem(path, f"assertions[{i}] has no `type` "
                                     "(event class)", ERROR, tid))
        elif etype not in EVENT_CLASSES:
            out.append(Problem(
                path,
                f"assertions[{i}] has unknown event type {etype!r}; "
                f"valid: {sorted(EVENT_CLASSES)}", ERROR, tid))
        if "min_count" in a:
            mc = a["min_count"]
            if not isinstance(mc, int) or isinstance(mc, bool) or mc < 1:
                out.append(Problem(
                    path,
                    f"assertions[{i}] `min_count` must be a positive int, "
                    f"got {mc!r}", ERROR, tid))


def _check_metadata(raw: dict[str, Any], path: str, tid: str | None,
                    out: list[Problem]) -> None:
    if _blank(raw.get("atlas")) and _blank(raw.get("owasp_asi")):
        out.append(Problem(path, "no `atlas` and no `owasp_asi` mapping; the "
                                 "technique is unattributable", WARNING, tid))
    if _blank(raw.get("description")):
        out.append(Problem(path, "empty `description`", WARNING, tid))
    if _blank(raw.get("references")):
        out.append(Problem(path, "no `references`", WARNING, tid))
    if _blank(raw.get("tactic")):
        out.append(Problem(path, "blank `tactic`", WARNING, tid))

    requires = raw.get("requires") or []
    if isinstance(requires, list):
        caps = known_capabilities()
        for cap in requires:
            if cap not in caps:
                out.append(Problem(
                    path,
                    f"`requires` names capability {cap!r} which no registered "
                    f"target adapter exposes; the technique will always skip",
                    WARNING, tid))
    else:
        out.append(Problem(path, "`requires` must be a list", ERROR, tid))


def validate_file(path: str) -> list[Problem]:
    """Every problem in one technique file. Never raises on bad input."""
    out: list[Problem] = []
    if yaml is None:  # pragma: no cover
        return [Problem(path, "PyYAML is required to validate techniques")]
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        return [Problem(path, "file not found")]
    except OSError as exc:
        return [Problem(path, f"could not read file: {exc}")]
    except yaml.YAMLError as exc:
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else exc
        return [Problem(path, f"YAML will not parse: {first}")]

    if raw is None:
        return [Problem(path, "file is empty")]
    if not isinstance(raw, dict):
        return [Problem(path, "top level of a technique file must be a mapping")]

    tid = raw.get("id") if isinstance(raw.get("id"), str) else None

    for key in REQUIRED_KEYS:
        if key not in raw or _blank(raw.get(key)):
            out.append(Problem(path, f"missing or blank required key `{key}`",
                               ERROR, tid))

    raw_id = raw.get("id")
    if not _blank(raw_id):
        if not isinstance(raw_id, str) or not ID_RE.match(raw_id):
            out.append(Problem(
                path,
                f"`id` {raw_id!r} does not match the required format MAR-####",
                ERROR, tid))

    _check_steps(raw, path, tid, out)
    _check_assertions(raw, path, tid, out)
    _check_metadata(raw, path, tid, out)
    _check_requires(raw, path, tid, out)
    out.extend(check_atlas_ids(raw, path, tid))
    return out


def _check_requires(raw: dict[str, Any], path: str, tid: str | None,
                    out: list["Problem"]) -> None:
    """Every mock-only verb used must be declared in `requires:`.

    Without the declaration the technique crashes with an AttributeError on a
    target that lacks the verb, instead of reporting an honest SKIP -- which
    turns a capability mismatch into a spurious failure.
    """
    steps = raw.get("steps")
    if not isinstance(steps, list):
        return
    declared = set(raw.get("requires") or [])
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        cap = VERB_CAPABILITY.get(step.get("action"))
        if cap and cap not in declared:
            out.append(Problem(
                path,
                f"steps[{i}] uses `{step.get('action')}` but `requires:` does "
                f"not declare {cap!r}; it would error instead of skipping on a "
                f"target without it",
                ERROR, tid))


def validate_dir(directory: str) -> list[Problem]:
    """Validate every technique in a directory, plus cross-file id uniqueness."""
    out: list[Problem] = []
    paths = sorted(glob.glob(os.path.join(directory, "*.y*ml")))
    if not paths:
        return [Problem(directory, "no technique files (*.yaml) found here",
                        WARNING)]
    seen: dict[str, str] = {}
    for path in paths:
        out.extend(validate_file(path))
        tid = _peek_id(path)
        if tid is None:
            continue
        if tid in seen:
            out.append(Problem(
                path,
                f"duplicate `id` {tid!r}; already defined in "
                f"{os.path.basename(seen[tid])}", ERROR, tid))
        else:
            seen[tid] = path
    return out


def _peek_id(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except Exception:  # noqa: BLE001 - already reported by validate_file
        return None
    if isinstance(raw, dict) and isinstance(raw.get("id"), str):
        return raw["id"]
    return None


def validate_fleet(path: str) -> list[Problem]:
    """Validate a targets file, turning parse errors into Problems."""
    try:
        fleet = Fleet.load(path)
    except ConfigParseError as exc:
        return [Problem(path, exc.message, ERROR)]
    except Exception as exc:  # noqa: BLE001 - a linter never explodes
        return [Problem(path, f"could not load targets file: {exc}", ERROR)]
    return [Problem(path, msg, ERROR) for msg in fleet.validate()]
