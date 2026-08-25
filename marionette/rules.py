"""Portable detection rules over the Marionette agent event schema.

The gap this closes: there is no Sigma-equivalent for agent telemetry, so every
vendor's prompt-injection / tool-abuse detection is a proprietary silo.  A rule
here is plain YAML over :mod:`marionette.schema` events, so the same file can be
shipped, diffed, reviewed and run against anyone's normalized agent stream.

This is *not* Sigma.  It is deliberately a much smaller language — Sigma's
value is its backend ecosystem, which we cannot honour, and half-implementing
a spec is worse than specifying a small one completely.  The whole matcher is
below and ``docs/event-schema.md`` documents the field surface it runs on.

Grammar (one rule = one YAML document)::

    id: MARR-0001
    title: ...
    status: experimental | stable | deprecated
    level: informational | low | medium | high | critical
    description: ...
    detection:
      selection:                 # a named block = an AND over its predicates
        type: agent.delegation
        provenance: [tool-output, memory]
      filter:
        provenance: user
      condition: selection and not filter
      min_count: 1               # matched events required to fire
      group_by: tool_name        # if set, min_count applies per distinct value
    covers: [MAR-0001]           # documentation only; coverage is measured
    atlas: [AML.T0051.001]
    falsepositives: [...]

Field predicates:

* ``field: value``      equality.  If the *event's* value is a list, this is
                        membership ("authority holds this scope").
* ``field: [a, b]``     matches when the event value equals / intersects any.
* ``field|contains: x`` case-insensitive substring over the value's string
                        form (non-strings are JSON-encoded first, so
                        ``data.tools|contains`` searches a whole tool list).
* ``field|exists: bool``
* ``field|gte: n`` / ``field|lte: n``  numeric comparison.

Field names are dotted paths over the envelope then ``data`` (``data.kind`` and
a bare ``kind`` resolve the same way).

Two field names are banned outright: ``technique_id`` and ``run_id``.  A rule
that keys on them is not a detection — it is a restatement of the attack, and
it would fire on exactly nothing in a real deployment.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml

from .errors import ConfigError
from .schema import AgentEvent, read_jsonl

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("experimental", "test", "stable", "deprecated")

# Keys that would make a rule self-fulfilling: they exist only because Marionette
# generated the traffic, and are absent from any real agent's telemetry.
FORBIDDEN_FIELDS = frozenset({"technique_id", "run_id"})

_OPS = ("contains", "exists", "gte", "lte", "re")


# --- field resolution --------------------------------------------------------

def resolve(ev: AgentEvent, path: str) -> Any:
    """Dotted lookup: envelope first, then ``data``.

    A bare name that is not an envelope field falls through to ``data`` so a
    rule can say ``kind: memory`` instead of ``data.kind: memory``.
    """
    # `[]` fans out over a list, e.g. `data.tools[].description`. The technique
    # assertion engine accepts this syntax, so a rule author will reasonably
    # expect it here too -- and without it the path silently resolves to
    # nothing rather than erroring, which is the worst possible failure mode
    # for a detection rule.
    if "[]" in path:
        head, _, tail = path.partition("[]")
        seq = resolve(ev, head.rstrip(".")) if head.rstrip(".") else None
        if not isinstance(seq, (list, tuple)):
            return None
        tail_parts = [p for p in tail.split(".") if p]
        out = []
        for item in seq:
            cur: Any = item
            for part in tail_parts:
                if isinstance(cur, dict):
                    cur = cur.get(part)
                else:
                    cur = getattr(cur, part, None)
                if cur is None:
                    break
            if cur is not None:
                out.append(cur)
        return out or None

    parts = path.split(".")
    if parts[0] == "data":
        cur: Any = ev.data
        parts = parts[1:]
    elif hasattr(ev, parts[0]):
        cur = getattr(ev, parts[0])
        parts = parts[1:]
    else:
        cur = ev.data
    for part in parts:
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            # Lists are searched as a whole by `contains`; indexing into them
            # is deliberately unsupported (brittle against event ordering).
            return None
        else:
            cur = getattr(cur, part, None)
        if cur is None:
            return None
    return cur


# A rule pattern is operator-written but the text it scans is target-written
# and unbounded. Capping the haystack bounds catastrophic backtracking to
# something survivable without banning useful patterns.
_MAX_HAYSTACK = 64 * 1024


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    text = json.dumps(value, sort_keys=True, default=str)
    return text[:_MAX_HAYSTACK]


def _eq(actual: Any, expected: Any) -> bool:
    """Equality, with list-valued *event* fields treated as membership.

    ``authority: read:secret`` should mean "holds that scope", not "holds
    exactly and only that scope" — otherwise every authority rule breaks the
    moment an unrelated scope is granted.
    """
    if isinstance(actual, list):
        return expected in actual
    return actual == expected


class Predicate:
    """One ``field[|op]: value`` test."""

    __slots__ = ("path", "op", "expected")

    def __init__(self, path: str, op: str | None, expected: Any) -> None:
        self.path, self.op, self.expected = path, op, expected

    def test(self, ev: AgentEvent) -> bool:
        actual = resolve(ev, self.path)
        op, want = self.op, self.expected
        if op is None:
            wants = want if isinstance(want, list) else [want]
            return any(_eq(actual, w) for w in wants)
        if op == "exists":
            return (actual is not None) is bool(want)
        if op == "contains":
            hay = _as_text(actual).lower()
            wants = want if isinstance(want, list) else [want]
            return any(str(w).lower() in hay for w in wants)
        if op == "re":
            hay = _as_text(actual)
            wants = want if isinstance(want, list) else [want]
            return any(re.search(str(w), hay, re.IGNORECASE) for w in wants)
        if op in ("gte", "lte"):
            try:
                n = float(actual)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False
            return n >= float(want) if op == "gte" else n <= float(want)
        raise ConfigError(f"unknown operator {op!r} in field {self.path!r}",
                          hint=f"supported: {', '.join(_OPS)}")


@dataclass
class Selection:
    """A named AND-block of predicates."""

    name: str
    predicates: list[Predicate]

    def test(self, ev: AgentEvent) -> bool:
        return all(p.test(ev) for p in self.predicates)


# --- condition expressions ---------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*)")


def _tokenize(expr: str) -> list[str]:
    out, pos = [], 0
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            raise ConfigError(f"cannot parse condition near {expr[pos:]!r}",
                              hint="supported: names, and, or, not, parentheses")
        out.append(m.group(1))
        pos = m.end()
    return out


class _Cond:
    """Recursive-descent parser for `a and not (b or c)`.

    Small enough to read in one sitting, which is the point: a defender has to
    trust what a rule means before they trust what it found.
    """

    def __init__(self, tokens: list[str], selections: dict[str, Selection]):
        self.toks, self.i, self.sel = tokens, 0, selections

    def parse(self):
        node = self._or()
        if self.i < len(self.toks):
            raise ConfigError(f"trailing tokens in condition: {self.toks[self.i:]}")
        return node

    def _peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self.i += 1
            right, left = self._and(), node
            node = lambda ev, a=left, b=right: a(ev) or b(ev)  # noqa: E731
        return node

    def _and(self):
        node = self._unary()
        while self._peek() == "and":
            self.i += 1
            right, left = self._unary(), node
            node = lambda ev, a=left, b=right: a(ev) and b(ev)  # noqa: E731
        return node

    def _unary(self):
        tok = self._peek()
        if tok == "not":
            self.i += 1
            inner = self._unary()
            return lambda ev, f=inner: not f(ev)
        if tok == "(":
            self.i += 1
            node = self._or()
            if self._peek() != ")":
                raise ConfigError("unbalanced parentheses in rule condition")
            self.i += 1
            return node
        if tok is None:
            raise ConfigError("empty or truncated rule condition")
        self.i += 1
        if tok not in self.sel:
            raise ConfigError(f"condition names unknown selection {tok!r}",
                              hint=f"defined: {', '.join(sorted(self.sel)) or 'none'}")
        sel = self.sel[tok]
        return lambda ev, s=sel: s.test(ev)


# --- rules -------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    title: str
    level: str = "medium"
    status: str = "experimental"
    description: str = ""
    covers: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    min_count: int = 1
    group_by: str | None = None
    source_path: str | None = None
    _matcher: Any = None

    def matches(self, ev: AgentEvent) -> bool:
        return bool(self._matcher(ev))

    def evaluate(self, events: Iterable[AgentEvent]) -> "RuleMatch | None":
        hits = [e for e in events if self.matches(e)]
        if self.group_by:
            groups: dict[Any, list[AgentEvent]] = {}
            for e in hits:
                groups.setdefault(_as_text(resolve(e, self.group_by)), []).append(e)
            hits = [e for g in groups.values() if len(g) >= self.min_count
                    for e in g]
            fired = bool(hits)
        else:
            fired = len(hits) >= self.min_count
        if not fired:
            return None
        return RuleMatch(rule_id=self.id, title=self.title, level=self.level,
                         count=len(hits),
                         event_ids=[e.event_id for e in hits])

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "level": self.level,
                "status": self.status, "description": self.description,
                "covers": self.covers, "atlas": self.atlas,
                "falsepositives": self.falsepositives,
                "min_count": self.min_count, "group_by": self.group_by,
                "source_path": self.source_path}

    # -- loading ------------------------------------------------------------
    @classmethod
    def from_dict(cls, raw: dict[str, Any], path: str | None = None) -> "Rule":
        where = path or raw.get("id", "<rule>")
        if not isinstance(raw, dict):
            raise ConfigError(f"{where}: rule must be a YAML mapping")
        for req in ("id", "title", "detection"):
            if not raw.get(req):
                raise ConfigError(f"{where}: rule is missing `{req}`",
                                  hint="see docs/event-schema.md for the format")
        det = raw["detection"]
        if not isinstance(det, dict):
            raise ConfigError(f"{where}: `detection` must be a mapping")

        selections: dict[str, Selection] = {}
        for name, block in det.items():
            if name in ("condition", "min_count", "group_by"):
                continue
            if not isinstance(block, dict):
                raise ConfigError(
                    f"{where}: selection {name!r} must be a mapping of "
                    f"field -> value")
            preds = []
            for key, value in block.items():
                fieldname, _, op = key.partition("|")
                if fieldname.split(".")[0] in FORBIDDEN_FIELDS:
                    raise ConfigError(
                        f"{where}: rule matches on {fieldname!r}",
                        hint="rules must detect behaviour, not Marionette "
                             "bookkeeping; technique_id/run_id do not exist "
                             "in real agent telemetry")
                preds.append(Predicate(fieldname, op or None, value))
            selections[name] = Selection(name, preds)
        if not selections:
            raise ConfigError(f"{where}: detection defines no selections")

        condition = det.get("condition") or next(iter(selections))
        matcher = _Cond(_tokenize(str(condition)), selections).parse()

        level = str(raw.get("level", "medium"))
        if level not in LEVELS:
            raise ConfigError(f"{where}: unknown level {level!r}",
                              hint=f"one of {', '.join(LEVELS)}")
        status = str(raw.get("status", "experimental"))
        if status not in STATUSES:
            raise ConfigError(f"{where}: unknown status {status!r}",
                              hint=f"one of {', '.join(STATUSES)}")

        return cls(
            id=str(raw["id"]), title=str(raw["title"]), level=level,
            status=status, description=str(raw.get("description", "")).strip(),
            covers=list(raw.get("covers") or []),
            atlas=list(raw.get("atlas") or []),
            falsepositives=list(raw.get("falsepositives") or []),
            min_count=int(det.get("min_count", 1)),
            group_by=det.get("group_by"),
            source_path=path, _matcher=matcher,
        )

    @classmethod
    def load(cls, path: str) -> "Rule":
        try:
            with open(path, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except OSError as exc:
            raise ConfigError(f"could not read rule {path}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in rule {path}: {exc}",
                              hint="one rule per file, top-level mapping") from exc
        return cls.from_dict(raw or {}, path=path)


@dataclass
class RuleMatch:
    """What a fired rule saw — enough to pivot back into the raw stream."""

    rule_id: str
    title: str
    level: str
    count: int
    event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "title": self.title,
                "level": self.level, "count": self.count,
                "event_ids": self.event_ids}


DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "rules")


def load_dir(directory: str) -> list[Rule]:
    """Load every ``*.yml``/``*.yaml`` rule, rejecting duplicate ids."""
    paths = sorted(glob.glob(os.path.join(directory, "*.y*ml")))
    if not paths:
        raise ConfigError(f"no rule YAML found in {directory}",
                          hint="pass --rules with a valid rule pack directory")
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for path in paths:
        rule = Rule.load(path)
        if rule.id in seen:
            raise ConfigError(f"duplicate rule id {rule.id!r}",
                              context={"first": seen[rule.id], "second": path})
        seen[rule.id] = path
        rules.append(rule)
    return sorted(rules, key=lambda r: r.id)


def evaluate(rules: Iterable[Rule], events: Iterable[AgentEvent]) -> list[RuleMatch]:
    events = list(events)
    out = []
    for rule in rules:
        m = rule.evaluate(events)
        if m is not None:
            out.append(m)
    return out


def load_events(path: str) -> list[AgentEvent]:
    try:
        return read_jsonl(path)
    except OSError as exc:
        raise ConfigError(f"could not read events from {path}: {exc}",
                          hint="produce one with `marionette run --events FILE`") from exc
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"{path} is not a valid Marionette event JSONL: {exc}",
                          hint="one JSON object per line, as written by "
                               "`marionette run --events`") from exc


# --- coverage ----------------------------------------------------------------

@dataclass
class TechniqueCoverage:
    technique_id: str
    name: str = ""
    event_count: int = 0
    matches: list[RuleMatch] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        return bool(self.matches)

    def to_dict(self) -> dict[str, Any]:
        return {"technique_id": self.technique_id, "name": self.name,
                "event_count": self.event_count, "covered": self.covered,
                "rules": [m.to_dict() for m in self.matches]}


@dataclass
class CoverageReport:
    """Which techniques the rule pack would have caught — and which it missed.

    The uncovered list is the point of this whole module.  Anyone can claim
    coverage; naming the blind spots is the part that is actually useful, so
    it is a first-class field rather than something a reader has to subtract.
    """

    techniques: list[TechniqueCoverage] = field(default_factory=list)
    rule_count: int = 0
    rule_ids: list[str] = field(default_factory=list)

    @property
    def covered(self) -> list[TechniqueCoverage]:
        return [t for t in self.techniques if t.covered]

    @property
    def uncovered(self) -> list[TechniqueCoverage]:
        return [t for t in self.techniques if not t.covered]

    @property
    def silent_rules(self) -> list[str]:
        """Rules that fired on nothing — dead content, or an unexercised gap."""
        fired = {m.rule_id for t in self.techniques for m in t.matches}
        return sorted(set(self.rule_ids) - fired)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_count": self.rule_count,
            "technique_count": len(self.techniques),
            "covered_count": len(self.covered),
            "uncovered": [t.technique_id for t in self.uncovered],
            "silent_rules": self.silent_rules,
            "techniques": [t.to_dict() for t in self.techniques],
        }


def coverage(rules: Iterable[Rule], events: Iterable[AgentEvent]) -> CoverageReport:
    """Attribute rule hits back to the technique that produced the events.

    ``technique_id`` is used *here* — for attribution after the fact — and is
    forbidden inside rules.  That asymmetry is the honest one: the range knows
    which attack it ran, the detection must not.
    """
    rules = list(rules)
    buckets: dict[str, list[AgentEvent]] = {}
    names: dict[str, str] = {}
    for ev in events:
        tid = ev.technique_id
        if not tid:
            continue  # setup traffic outside any technique
        buckets.setdefault(tid, []).append(ev)
        if ev.type == "marionette.technique.start":
            names[tid] = str(ev.data.get("name") or "")

    out = CoverageReport(rule_count=len(rules), rule_ids=[r.id for r in rules])
    for tid in sorted(buckets):
        evs = buckets[tid]
        out.techniques.append(TechniqueCoverage(
            technique_id=tid, name=names.get(tid, ""),
            event_count=len(evs), matches=evaluate(rules, evs)))
    return out
