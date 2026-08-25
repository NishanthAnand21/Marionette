"""Detection assertions — the half every purple team rebuilds by hand.

A technique declares what its execution *should* look like in the event
stream.  After execution the runner evaluates these predicates over the events
that occurred and records pass/fail/latency.  This is the closed loop the
research found missing: execute -> observe -> assert, versioned in git.

Assertions are intentionally simple, declarative, and expressible in YAML so
technique authors do not write Python.

Field resolution
----------------
A condition key is a dotted path resolved against one event.  There are
exactly two roots and they are tried in this order:

1. **The envelope.**  If the *first* segment names a real :class:`AgentEvent`
   field (``type``, ``tool_name``, ``provenance``, ``data``, ...), the whole
   path is walked from there.  ``data.args.to`` is therefore the explicit way
   to reach into the payload.
2. **The payload.**  Otherwise the whole path is walked inside ``ev.data``.
   ``args.to`` means the same thing as ``data.args.to``.

Anything that cannot be walked to the end is *missing*, which is distinct
from present-and-``None``: ``field: null`` matches an explicit null and does
not match an absent key.  That distinction is the reason for the ``_MISSING``
sentinel rather than plain ``None``.

Counting
--------
``min_count`` is the number of matching events required, and must be a
positive integer -- ``0`` would make a plain assertion vacuously true and a
``negate`` assertion unsatisfiable, so it is rejected at parse time rather
than silently producing a meaningless verdict.  ``negate`` inverts only the
final threshold test: ``count >= min_count`` becomes the failure condition.
``count`` in the result is always the raw number of matches, negated or not,
so a report can show what actually happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import TechniqueValidationError
from .schema import AgentEvent

# Distinct from None so "the key is absent" and "the key is null" are
# different answers. Conditions can legitimately assert `field: null`.
_MISSING = object()

# Condition keys that configure the assertion rather than matching a field.
_RESERVED = frozenset({"name", "min_count", "negate", "field_contains"})


def _walk(root: Any, parts: list[str]) -> Any:
    """Walk a dotted path through dicts and objects, or return ``_MISSING``."""
    cur = root
    for part in parts:
        if isinstance(cur, dict):
            if part not in cur:
                return _MISSING
            cur = cur[part]
        elif hasattr(cur, part):
            cur = getattr(cur, part)
        else:
            # Nothing left to walk into -- a partially resolved path that hits
            # a scalar or None is missing, not None. Reporting it as None would
            # let `field: null` match a typo'd path.
            return _MISSING
    return cur


def _get(ev: AgentEvent, path: str) -> Any:
    """Resolve a condition path against one event. ``_MISSING`` if absent.

    An explicit ``[]`` segment fans out over a list, e.g.
    ``data.tools[].description`` means "the description of any tool in the
    inventory".  Without it, assertions cannot reach inside the collections the
    schema legitimately carries, which pushes authors towards weak count-only
    assertions -- exactly the tautology we are trying to design out.
    """
    if "[]" in path:
        head, _, tail = path.partition("[]")
        seq = _get(ev, head.rstrip(".")) if head.rstrip(".") else _MISSING
        if not isinstance(seq, (list, tuple)):
            return _MISSING
        tail_parts = [p for p in tail.split(".") if p]
        vals = [(_walk(item, tail_parts) if tail_parts else item) for item in seq]
        vals = [v for v in vals if v is not _MISSING]
        return vals if vals else _MISSING

    parts = path.split(".")
    if not parts or not parts[0]:
        return _MISSING
    # Envelope first, but only if the head really is an event field; otherwise
    # the whole path belongs to the payload. The old code walked the head into
    # the envelope and, on failure, retried the *entire dotted path* as a
    # single flat data key -- so `args.to` never resolved at all.
    if parts[0] in AgentEvent.__dataclass_fields__:
        return _walk(ev, parts)
    return _walk(getattr(ev, "data", {}) or {}, parts)


def _contains(hay: Any, needle: str) -> bool:
    """Substring test over a string field; anything else is a non-match.

    ``field_contains`` is deliberately string-only.  Stringifying numbers or
    containers first would make a verdict depend on Python's formatting of a
    value rather than on the value, and would silently turn a mistyped path
    into a match.  A non-string field is a non-match, never a crash -- the old
    code raised ``TypeError`` when the *needle* was a non-string, taking the
    whole technique to ERROR; needles are now type-checked at parse time.
    """
    if isinstance(hay, (list, tuple)):
        # a `[]` fan-out matches when ANY element contains the needle
        return any(isinstance(h, str) and needle in h for h in hay)
    return isinstance(hay, str) and needle in hay


def _match(ev: AgentEvent, cond: dict[str, Any]) -> bool:
    etype = cond.get("type")
    if etype is not None and ev.type != etype:
        return False
    for key, expected in cond.items():
        if key in _RESERVED or key == "type":
            continue
        if _get(ev, key) != expected:
            return False
    for field_path, needle in (cond.get("field_contains") or {}).items():
        if not _contains(_get(ev, field_path), needle):
            return False
    return True


@dataclass
class Assertion:
    """One expectation over the event stream produced by a technique."""

    name: str
    cond: dict[str, Any]
    min_count: int = 1
    negate: bool = False  # detection *should not* see this (e.g. leak blocked)

    @classmethod
    def from_yaml(cls, raw: dict[str, Any]) -> "Assertion":
        if not isinstance(raw, dict):
            raise TechniqueValidationError(
                f"assertion must be a mapping, got {type(raw).__name__}",
                hint="each item under `assertions:` is a `- name: ...` block")
        name = raw.get("name", "unnamed")
        if not isinstance(name, str):
            raise TechniqueValidationError(
                f"assertion `name` must be a string, got {type(name).__name__}",
                context={"name": name})
        # Validate at parse time, not at evaluate time: a bad threshold that
        # only blows up mid-run turns an authoring typo into a runtime ERROR
        # on every target in the fleet.
        mc = raw.get("min_count", 1)
        if isinstance(mc, bool) or not isinstance(mc, int) or mc < 1:
            raise TechniqueValidationError(
                f"assertion {name!r}: `min_count` must be an integer >= 1, "
                f"got {mc!r}",
                hint="min_count: 0 is never meaningful; use `negate: true` to "
                     "assert that something did not happen")
        negate = raw.get("negate", False)
        if not isinstance(negate, bool):
            raise TechniqueValidationError(
                f"assertion {name!r}: `negate` must be true or false, "
                f"got {negate!r}")
        fc = raw.get("field_contains")
        if fc is not None:
            if not isinstance(fc, dict):
                raise TechniqueValidationError(
                    f"assertion {name!r}: `field_contains` must be a mapping "
                    f"of field -> substring, got {type(fc).__name__}")
            for k, v in fc.items():
                if not isinstance(v, str):
                    raise TechniqueValidationError(
                        f"assertion {name!r}: field_contains[{k!r}] must be a "
                        f"string, got {type(v).__name__}",
                        hint="quote it in YAML if it looks like a number")
        return cls(
            name=name,
            cond={k: v for k, v in raw.items()
                  if k not in ("name", "min_count", "negate")},
            min_count=mc,
            negate=negate,
        )

    def evaluate(self, events: list[AgentEvent]) -> "AssertionResult":
        hits = [e for e in events if _match(e, self.cond)]
        met = len(hits) >= self.min_count
        passed = (not met) if self.negate else met
        return AssertionResult(self.name, passed, len(hits), self.min_count,
                               self.negate)


@dataclass
class AssertionResult:
    name: str
    passed: bool
    count: int
    min_count: int
    negate: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "passed": self.passed, "count": self.count,
            "min_count": self.min_count, "negate": self.negate,
        }
