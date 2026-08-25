"""Parallel multi-target execution engine.

The shape of the concurrency is deliberate:

* **Across targets: parallel.**  Every target is an independent world — its own
  subprocess, its own collector, its own state.  They are I/O-bound (we spend
  the run blocked on a child process's stdout), so a thread pool is the right
  tool; there is nothing CPU-bound to be starved by the GIL.

* **Within one target: strictly sequential, in input order.**  Techniques share
  the target's mutable state — memory, granted authority, tool descriptions —
  and some are explicitly ordered against each other (PRX-0007 plants what
  PRX-0008 later reads).  Running them concurrently would make results depend
  on scheduling, which is the opposite of what a security test should be.

* **Connect once per target.**  The old path built and connected a fresh target
  per technique, paying a subprocess spawn plus MCP handshake every time.  Here
  a target is connected once, driven through the whole technique list, and
  closed in a ``finally`` so a crash mid-run still reaps the child.

Isolation is the other half of the contract: one target that cannot connect is
reported as an error on *that* target and nothing else.  No exception escapes
:func:`run_matrix`.
"""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable

from .config import TargetSpec
from .errors import PraxisError, TargetError
from .runner import ERROR, FAIL, PASS, SKIP, TechniqueResult, run_technique
from .targets import build
from .technique import Technique
from .telemetry import Collector

ProgressFn = Callable[[str, object], None]

_STATUSES = (PASS, FAIL, SKIP, ERROR)


@dataclass
class TargetRunResult:
    """Every technique's outcome against a single target."""

    target_name: str
    target_kind: str
    results: list[TechniqueResult] = field(default_factory=list)
    error: dict[str, Any] | None = None   # PraxisError.to_dict() if connect failed
    duration_ms: float = 0.0
    collector: Collector | None = None    # events, for report writers
    skipped: bool = False                 # never started: fail_fast tripped first

    @property
    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in _STATUSES}
        for r in self.results:
            out[r.status] = out.get(r.status, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "target_kind": self.target_kind,
            "results": [r.to_dict() for r in self.results],
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
            "counts": self.counts,
            "skipped": self.skipped,
        }


@dataclass
class MatrixResult:
    """The whole run: every technique against every target."""

    run_id: str
    runs: list[TargetRunResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def totals(self) -> dict[str, int]:
        out = {s: 0 for s in _STATUSES}
        for run in self.runs:
            for k, v in run.counts.items():
                out[k] = out.get(k, 0) + v
        return out

    @property
    def exit_code(self) -> int:
        """2 beats 1 beats 0: an infrastructure error is worse than a finding."""
        t = self.totals
        if t.get(ERROR) or any(r.error for r in self.runs):
            return 2
        if t.get(FAIL):
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "runs": [r.to_dict() for r in self.runs],
            "duration_ms": round(self.duration_ms, 2),
            "totals": self.totals,
            "exit_code": self.exit_code,
        }


def _notify(on_progress: ProgressFn | None, kind: str, payload: object) -> None:
    """Fire a progress callback without ever letting it break the run.

    Called from worker threads: the *caller* owns any locking its renderer
    needs.  A broken CLI printer must not take a security run down with it.
    """
    if on_progress is None:
        return
    try:
        on_progress(kind, payload)
    except Exception:  # noqa: BLE001 - progress is cosmetic, never fatal
        pass


def _errored_run(spec: TargetSpec, techniques: list[Technique],
                 exc: BaseException, duration_ms: float) -> TargetRunResult:
    """A target that never came up: every technique reports as an error."""
    if isinstance(exc, PraxisError):
        detail = exc.to_dict()
        message = exc.message
    else:
        detail = TargetError(f"{type(exc).__name__}: {exc}").to_dict()
        message = f"{type(exc).__name__}: {exc}"
    return TargetRunResult(
        target_name=spec.name, target_kind=spec.kind,
        results=[TechniqueResult(t.id, t.name, status=ERROR, executed=False,
                                 passed=False, error=message,
                                 error_detail=detail)
                 for t in techniques],
        error=detail, duration_ms=duration_ms)


def run_target(spec: TargetSpec, techniques: list[Technique], run_id: str,
               on_progress: ProgressFn | None = None,
               should_stop: Callable[[], bool] | None = None) -> TargetRunResult:
    """Connect one target once, run every technique against it, close it."""
    # fail_fast is checked once, here: a target that has already begun runs its
    # whole list so its state machine (and its subprocess) unwinds cleanly.
    if should_stop is not None and should_stop():
        # Distinguish "never started" from "ran zero techniques": otherwise a
        # truncated fail_fast run is indistinguishable in a report from a
        # clean one, and a progress renderer pairing start/done never finishes.
        run = TargetRunResult(target_name=spec.name, target_kind=spec.kind,
                              skipped=True)
        _notify(on_progress, "target_skipped", run)
        return run
    _notify(on_progress, "target_start", {"target": spec.name, "kind": spec.kind,
                                          "techniques": len(techniques)})
    t0 = time.perf_counter()
    # Fresh collector per target so events from concurrent targets can never
    # interleave into one another's assertion windows.
    collector = Collector(run_id=run_id)
    target = None
    try:
        target = build(spec.kind, **spec.build_kwargs())
        target.collector = collector
        target.connect()
    except Exception as exc:  # noqa: BLE001 - contained, never propagated
        # A handshake that fails *after* the subprocess launched still owns a
        # child, two drain threads and three pipes. The `finally` below only
        # guards the technique loop, which we never reach -- so close here or
        # leak one process per unreachable target.
        if target is not None:
            try:
                target.close()
            except Exception:  # noqa: BLE001 - cleanup must not mask the cause
                pass
        run = _errored_run(spec, techniques, exc,
                           (time.perf_counter() - t0) * 1000)
        run.collector = collector
        _notify(on_progress, "target_done", run)
        return run

    results: list[TechniqueResult] = []
    try:
        for tech in techniques:
            try:
                # Isolation between techniques: the connection is reused for
                # speed, but leftover state is not -- otherwise a technique
                # that shadows a tool or grants authority silently changes the
                # verdict of whatever runs next, and the pack becomes
                # order-dependent.
                target.reset()
                res = run_technique(tech, target, run_id=run_id)
            except Exception as exc:  # noqa: BLE001 - a runner bug is an error,
                # not a crash: keep the other techniques and targets alive.
                res = TechniqueResult(
                    tech.id, tech.name, status=ERROR, executed=False,
                    passed=False, error=f"{type(exc).__name__}: {exc}",
                    error_detail=exc.to_dict() if isinstance(exc, PraxisError)
                    else None)
            results.append(res)
            _notify(on_progress, "technique_done",
                    {"target": spec.name, "result": res})
    finally:
        try:
            target.close()
        except Exception:  # noqa: BLE001 - close failures must not mask results
            pass

    run = TargetRunResult(target_name=spec.name, target_kind=spec.kind,
                          results=results,
                          duration_ms=(time.perf_counter() - t0) * 1000,
                          collector=collector)
    _notify(on_progress, "target_done", run)
    return run


def _is_bad(run: "TargetRunResult") -> bool:
    """A target run that should trip fail_fast."""
    return bool(run.error or run.counts[FAIL] or run.counts[ERROR])


def run_matrix(techniques: list[Technique], specs: list[TargetSpec],
               workers: int = 8, on_progress: ProgressFn | None = None,
               fail_fast: bool = False) -> MatrixResult:
    """Run every technique against every target, targets in parallel.

    ``on_progress(kind, payload)`` is called from worker threads with ``kind``
    in ``{"target_start", "target_done", "technique_done"}``; the caller is
    responsible for its own locking.  Results come back in ``specs`` order
    regardless of completion order, so reports are byte-stable across runs.
    """
    run_id = uuid.uuid4().hex[:12]
    t0 = time.perf_counter()
    if not specs:
        return MatrixResult(run_id=run_id, runs=[])

    # threading.Event, not a plain bool: workers set it themselves the instant
    # their own result is bad. Relying on the main thread to set it while
    # draining completed futures leaves a window in which the next queued
    # target starts before the flag flips -- which made fail_fast racy.
    stop_event = threading.Event()

    def should_stop() -> bool:
        return fail_fast and stop_event.is_set()

    n = max(1, min(int(workers), len(specs)))
    runs: list[TargetRunResult | None] = [None] * len(specs)
    with ThreadPoolExecutor(max_workers=n,
                            thread_name_prefix="praxis-target") as pool:
        def _work(spec):
            run = run_target(spec, techniques, run_id, on_progress, should_stop)
            if fail_fast and _is_bad(run):
                stop_event.set()
            return run

        futures = {pool.submit(_work, spec): i
                   for i, spec in enumerate(specs)}
        # Drain in completion order so fail_fast trips as early as possible;
        # the results array is indexed by spec position, so order is preserved.
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                run = fut.result()
            except Exception as exc:  # noqa: BLE001 - last line of containment
                run = _errored_run(specs[i], techniques, exc, 0.0)
            runs[i] = run
            if fail_fast and _is_bad(run):
                # Already-running targets finish cleanly; nothing new starts.
                stop_event.set()

    return MatrixResult(run_id=run_id,
                        runs=[r for r in runs if r is not None],
                        duration_ms=(time.perf_counter() - t0) * 1000)
