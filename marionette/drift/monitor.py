"""MCP tool-description drift monitor.

The narrow, immediately-useful piece: snapshot the tools an MCP server (or any
Marionette target) advertises, hash each tool's model-facing description, and diff
across snapshots.  The only publicly documented in-the-wild MCP attack
(postmark-mcp: 15 clean versions, then one that BCC'd every outbound email)
would have been caught by exactly this -- a description-hash change on an
already-installed tool.

No product on the market does cross-version description diffing.  It is ~200
lines.  Here they are.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..targets.base import ToolSpec


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@dataclass
class ToolFingerprint:
    name: str
    description_hash: str
    schema_hash: str
    description: str

    @classmethod
    def of(cls, spec: ToolSpec) -> "ToolFingerprint":
        return cls(
            name=spec.name,
            description_hash=_hash(spec.description),
            schema_hash=_hash(json.dumps(spec.input_schema, sort_keys=True)),
            description=spec.description,
        )


@dataclass
class Snapshot:
    target: str
    ts: float = field(default_factory=time.time)
    tools: dict[str, ToolFingerprint] = field(default_factory=dict)

    @classmethod
    def capture(cls, target_name: str, specs: list[ToolSpec]) -> "Snapshot":
        return cls(target=target_name,
                   tools={s.name: ToolFingerprint.of(s) for s in specs})

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "ts": self.ts,
            "tools": {n: vars(fp) for n, fp in self.tools.items()},
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Snapshot":
        return cls(
            target=raw["target"], ts=raw.get("ts", 0.0),
            tools={n: ToolFingerprint(**fp) for n, fp in raw.get("tools", {}).items()},
        )

    def save(self, path: str) -> None:
        # newline="": snapshots are diffed and hashed, so the same tool
        # inventory must not look different merely for having been captured on
        # a different operating system.
        with open(path, "w", encoding="utf-8", newline="") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "Snapshot":
        """Load a snapshot, failing with a typed error rather than a KeyError."""
        from ..errors import ConfigParseError

        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            raise ConfigParseError(f"snapshot not found: {path}",
                                   hint="run `marionette snapshot --out <path>` first",
                                   context={"path": path}) from None
        except OSError as exc:
            raise ConfigParseError(f"could not read snapshot {path}: {exc}",
                                   context={"path": path}) from None
        except json.JSONDecodeError as exc:
            raise ConfigParseError(
                f"snapshot {path} is not valid JSON: {exc}",
                hint="the file may be truncated; re-capture it",
                context={"path": path, "line": exc.lineno}) from None
        if not isinstance(raw, dict):
            raise ConfigParseError(f"snapshot {path} must contain a JSON object",
                                   context={"path": path})
        for key in ("target", "tools"):
            if key not in raw:
                raise ConfigParseError(
                    f"snapshot {path} is missing required key {key!r}",
                    hint="it may be from an incompatible version; re-capture it",
                    context={"path": path})
        try:
            return cls.from_dict(raw)
        except TypeError as exc:
            raise ConfigParseError(
                f"snapshot {path} has a malformed tool fingerprint: {exc}",
                hint="re-capture it with `marionette snapshot`",
                context={"path": path}) from None


# severity of each change class -- a live description mutation is the rug pull
ADDED = "tool_added"
REMOVED = "tool_removed"
DESC_CHANGED = "description_changed"
SCHEMA_CHANGED = "schema_changed"

_SEVERITY = {
    ADDED: "medium",
    REMOVED: "low",
    DESC_CHANGED: "high",       # the postmark-mcp signature
    SCHEMA_CHANGED: "medium",
}


@dataclass
class DriftFinding:
    tool: str
    change: str
    severity: str
    before: str | None = None
    after: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return vars(self)


def diff(old: Snapshot, new: Snapshot,
         allow_cross_target: bool = False) -> list[DriftFinding]:
    """Compare two snapshots of the *same* target.

    Diffing two different servers reports every tool as added or removed, which
    reads exactly like catastrophic drift. That silent-wrong-answer is worse
    than an error, so it is refused unless explicitly allowed.
    """
    if not allow_cross_target and old.target != new.target:
        from ..errors import ConfigParseError

        raise ConfigParseError(
            f"snapshots are from different targets: {old.target!r} vs "
            f"{new.target!r}",
            hint=("drift compares one target over time; pass "
                  "--allow-cross-target if you really mean to diff two servers"),
            context={"old_target": old.target, "new_target": new.target})
    findings: list[DriftFinding] = []
    old_names, new_names = set(old.tools), set(new.tools)

    for name in sorted(new_names - old_names):
        findings.append(DriftFinding(name, ADDED, _SEVERITY[ADDED],
                                     after=new.tools[name].description))
    for name in sorted(old_names - new_names):
        findings.append(DriftFinding(name, REMOVED, _SEVERITY[REMOVED],
                                     before=old.tools[name].description))
    for name in sorted(old_names & new_names):
        o, n = old.tools[name], new.tools[name]
        if o.description_hash != n.description_hash:
            findings.append(DriftFinding(name, DESC_CHANGED,
                                         _SEVERITY[DESC_CHANGED],
                                         before=o.description, after=n.description))
        if o.schema_hash != n.schema_hash:
            findings.append(DriftFinding(name, SCHEMA_CHANGED,
                                         _SEVERITY[SCHEMA_CHANGED]))
    return findings
