"""Technique model + loader.

A technique is one YAML file (the Atomic Red Team model, ported to agents):
metadata, ATLAS/OWASP mapping, an ordered list of steps to execute against a
target, and detection assertions.  Steps are a tiny declarative verb set so
that authoring a technique never requires writing Python.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from .detection import Assertion


@dataclass
class Step:
    action: str
    args: dict[str, Any] = field(default_factory=dict)

    VERBS = frozenset({
        "list_tools", "call_tool", "send_prompt", "grant",
        "mem_write", "mem_read", "set_description", "snapshot",
        # Registry, prompt and supply-chain surface.
        "add_tool", "remove_tool", "set_system_prompt", "load_artifact",
        # Retrieval — the RAG-poisoning sink.
        "rag_index", "rag_query",
        # Multi-agent and identity.
        "delegate", "set_identity",
        # Runtime credential store, and the inverse of `grant`.
        "env_set", "env_read", "revoke",
    })

    def __post_init__(self) -> None:
        if self.action not in self.VERBS:
            raise ValueError(f"unknown step action {self.action!r}; "
                             f"valid: {sorted(self.VERBS)}")


@dataclass
class Technique:
    id: str                         # praxis id, e.g. PRX-0001
    name: str
    atlas: list[str] = field(default_factory=list)   # AML.T#### ids
    owasp_asi: list[str] = field(default_factory=list)  # ASI## ids
    tactic: str = ""
    description: str = ""
    requires: list[str] = field(default_factory=list)  # target capabilities
    steps: list[Step] = field(default_factory=list)
    assertions: list[Assertion] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source_path: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any], source_path: str | None = None
                  ) -> "Technique":
        missing = [k for k in ("id", "name") if not raw.get(k)]
        if missing:
            from .errors import TechniqueParseError

            raise TechniqueParseError(
                f"technique is missing required key(s): {', '.join(missing)}",
                hint="every technique needs at least `id` and `name`; run "
                     "`praxis validate` for the full list of problems",
                context={"path": source_path, "missing": missing})
        return cls(
            id=raw["id"],
            name=raw["name"],
            atlas=raw.get("atlas", []) or [],
            owasp_asi=raw.get("owasp_asi", []) or [],
            tactic=raw.get("tactic", ""),
            description=raw.get("description", "").strip(),
            requires=raw.get("requires", []) or [],
            steps=[Step(s["action"], s.get("args", {}) or {})
                   for s in raw.get("steps", [])],
            assertions=[Assertion.from_yaml(a) for a in raw.get("assertions", [])],
            references=raw.get("references", []) or [],
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: str) -> "Technique":
        if yaml is None:
            raise RuntimeError("PyYAML is required to load techniques "
                               "(pip install pyyaml)")
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return cls.from_dict(raw, source_path=path)


def load_dir(directory: str) -> list[Technique]:
    out = []
    for path in sorted(glob.glob(os.path.join(directory, "*.y*ml"))):
        out.append(Technique.load(path))
    return out
