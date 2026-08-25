"""Target fleet configuration — the contract for multi-target runs.

    # targets.yaml
    defaults:
      timeout: 20
    targets:
      - name: range
        kind: mock
      - name: prod-mail
        kind: mcp
        command: "python -m mypkg.server"
        env: {MCP_TOKEN: "..."}
        timeout: 45
        tags: [prod, email]
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from .errors import ConfigParseError


@dataclass
class TargetSpec:
    """Everything needed to build one target, plus fleet metadata."""

    name: str
    kind: str = "mock"
    command: str | list[str] | None = None
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    # Off by default: a target under test should not inherit operator secrets.
    inherit_env: bool = False
    timeout: float = 20.0
    tags: list[str] = field(default_factory=list)
    enabled: bool = True

    def build_kwargs(self) -> dict[str, Any]:
        """Kwargs for :func:`marionette.targets.build`, minus fleet-only fields."""
        kw: dict[str, Any] = {"name": self.name}
        if self.kind == "mcp":
            kw.update(command=self.command, cwd=self.cwd, env=self.env,
                      inherit_env=self.inherit_env,
                      timeout=self.timeout)
        return kw

    def validate(self) -> list[str]:
        problems = []
        if not self.name:
            problems.append("target has no `name`")
        # The name becomes part of a per-target output filename, so a
        # separator or traversal segment would write outside the operator's
        # chosen directory.
        if any(sep in self.name for sep in ("/", "\\")) or self.name in (".", ".."):
            problems.append(
                f"target name {self.name!r} may not contain a path separator")

        if self.kind == "mcp" and not self.command:
            problems.append(f"target {self.name!r} is kind=mcp but has no `command`")
        if self.timeout <= 0:
            problems.append(f"target {self.name!r} has non-positive timeout")
        return problems


@dataclass
class Fleet:
    targets: list[TargetSpec] = field(default_factory=list)
    source_path: str | None = None

    def enabled(self) -> list[TargetSpec]:
        return [t for t in self.targets if t.enabled]

    def select(self, names: list[str] | None = None,
               tags: list[str] | None = None) -> list[TargetSpec]:
        out = self.enabled()
        if names:
            want = set(names)
            out = [t for t in out if t.name in want]
        if tags:
            want_t = set(tags)
            out = [t for t in out if want_t & set(t.tags)]
        return out

    def validate(self) -> list[str]:
        problems: list[str] = []
        seen: set[str] = set()
        for t in self.targets:
            problems.extend(t.validate())
            if t.name in seen:
                problems.append(f"duplicate target name {t.name!r}")
            seen.add(t.name)
        return problems

    @classmethod
    def load(cls, path: str) -> "Fleet":
        if yaml is None:
            raise ConfigParseError("PyYAML is required to read a targets file",
                                   hint="pip install pyyaml")
        if not os.path.exists(path):
            raise ConfigParseError(f"targets file not found: {path}",
                                   hint="pass --targets-file with a valid path")
        try:
            with open(path, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigParseError(f"could not parse {path}: {exc}") from exc
        if not isinstance(raw, dict) or "targets" not in raw:
            raise ConfigParseError(
                f"{path} has no top-level `targets:` list")
        defaults = raw.get("defaults", {}) or {}
        specs = []
        for i, entry in enumerate(raw["targets"]):
            if not isinstance(entry, dict):
                raise ConfigParseError(
                    f"{path}: targets[{i}] is not a mapping")
            merged = {**defaults, **entry}
            known = set(TargetSpec.__dataclass_fields__)
            unknown = set(merged) - known
            if unknown:
                raise ConfigParseError(
                    f"{path}: targets[{i}] has unknown keys {sorted(unknown)}",
                    hint=f"valid keys: {sorted(known)}")
            specs.append(TargetSpec(**merged))
        fleet = cls(targets=specs, source_path=path)
        problems = fleet.validate()
        if problems:
            raise ConfigParseError(
                f"{path} has {len(problems)} problem(s): " + "; ".join(problems))
        return fleet

    @classmethod
    def single(cls, kind: str = "mock", name: str | None = None,
               command: str | None = None, cwd: str | None = None,
               timeout: float = 20.0) -> "Fleet":
        return cls(targets=[TargetSpec(name=name or kind, kind=kind,
                                       command=command, cwd=cwd,
                                       timeout=timeout)])
