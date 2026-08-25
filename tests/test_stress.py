"""Scale, concurrency and resource behaviour of the engine.

Everything here is in-process (mock targets) except the process-leak test,
which deliberately launches real MCP subprocesses that crash or hang.  The
whole file is written to stay fast: correctness at scale is worth testing on
every commit, and a suite people skip is worth nothing.
"""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

from praxis.config import TargetSpec
from praxis.detection import Assertion
from praxis.engine import run_matrix, run_target
from praxis.runner import ERROR, FAIL, PASS, SKIP
from praxis.schema import TOOL_LIST
from praxis.technique import Step, Technique

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import (enumerate_technique, failing_technique,  # noqa: E402
                      mock_spec)

HOSTILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "hostile_mcp.py")

FLEET_N = 60


def skipping_technique(tid="PRX-9101"):
    """Requires a capability no adapter has, so it must always SKIP."""
    t = enumerate_technique(tid)
    t.name = "Needs A Capability Nobody Has"
    t.requires = ["praxis_capability_that_does_not_exist"]
    return t


def erroring_technique(tid="PRX-9102"):
    """A step with missing arguments blows up mid-dispatch -> ERROR."""
    t = enumerate_technique(tid)
    t.name = "Blows Up Mid-Run"
    t.requires = []
    t.steps = [Step("list_tools"), Step("call_tool", {})]
    t.assertions = [Assertion(name="listed", cond={"type": TOOL_LIST})]
    return t


def mixed_techniques():
    return [enumerate_technique("PRX-9001"),
            failing_technique("PRX-9002"),
            skipping_technique("PRX-9101")]


def fleet(n=FLEET_N, prefix="t"):
    return [mock_spec(f"{prefix}-{i:03d}") for i in range(n)]


# --------------------------------------------------------------------------
# scale
# --------------------------------------------------------------------------
def test_large_fleet_all_results_present_in_input_order():
    specs = fleet()
    techs = mixed_techniques()
    res = run_matrix(techs, specs, workers=8)

    assert len(res.runs) == len(specs)
    assert [r.target_name for r in res.runs] == [s.name for s in specs]
    for run in res.runs:
        assert [r.technique_id for r in run.results] == [t.id for t in techs]
        assert run.error is None
        assert run.counts[PASS] == 1
        assert run.counts[FAIL] == 1
        assert run.counts[SKIP] == 1

    totals = res.totals
    assert totals[PASS] == FLEET_N
    assert totals[FAIL] == FLEET_N
    assert totals[SKIP] == FLEET_N
    assert totals[ERROR] == 0
    assert sum(totals.values()) == FLEET_N * len(techs)
    assert res.exit_code == 1          # failures, no errors
    d = res.to_dict()
    assert d["totals"] == totals and len(d["runs"]) == len(specs)


# --------------------------------------------------------------------------
# determinism under concurrency -- the highest-value test in this file
# --------------------------------------------------------------------------
def _signature(res):
    """Everything about a run that must not depend on scheduling."""
    return [(run.target_name, run.target_kind, run.error is not None,
             tuple((r.technique_id, r.status, r.passed, r.executed,
                    r.event_count, r.skipped_reason, r.error)
                   for r in run.results))
            for run in res.runs]


@pytest.mark.parametrize("attempt", range(20))
def test_identical_results_at_one_worker_and_sixteen(attempt):
    specs = fleet(16, prefix=f"det{attempt}")
    techs = mixed_techniques() + [erroring_technique()]
    serial = run_matrix(techs, specs, workers=1)
    assert {r.status for run in serial.runs for r in run.results} == {
        PASS, FAIL, SKIP, ERROR}, "the matrix must exercise every status"
    parallel = run_matrix(techs, specs, workers=16)
    assert _signature(serial) == _signature(parallel)
    assert serial.totals == parallel.totals
    assert serial.exit_code == parallel.exit_code


def test_repeated_parallel_runs_are_byte_stable():
    specs = fleet(24, prefix="stable")
    techs = mixed_techniques()
    sigs = {str(_signature(run_matrix(techs, specs, workers=16)))
            for _ in range(6)}
    assert len(sigs) == 1


# --------------------------------------------------------------------------
# resources
# --------------------------------------------------------------------------
def _settle(baseline, deadline=5.0):
    """Wait (bounded) for worker threads to finish unwinding."""
    end = time.monotonic() + deadline
    while threading.active_count() > baseline and time.monotonic() < end:
        time.sleep(0.02)
    return threading.active_count()


def test_no_thread_leaks_after_a_large_matrix():
    baseline = threading.active_count()
    run_matrix(mixed_techniques(), fleet(FLEET_N, prefix="thr"), workers=16)
    assert _settle(baseline) == baseline, (
        "engine leaked threads: "
        f"{[t.name for t in threading.enumerate()]}")


@pytest.mark.slow
def test_no_process_leaks_from_crashing_and_hanging_mcp_targets():
    def spec(name, mode, timeout):
        return TargetSpec(name=name, kind="mcp",
                          command=[sys.executable, HOSTILE, mode],
                          timeout=timeout)

    specs = [spec("crash-1", "crash", 5.0),
             spec("hang-1", "hang", 0.4),
             spec("crash-2", "crash", 5.0),
             spec("hang-2", "hang", 0.4),
             TargetSpec(name="missing", kind="mcp",
                        command="praxis-no-such-binary-xyz", timeout=1.0)]
    res = run_matrix([enumerate_technique()], specs, workers=4)
    assert len(res.runs) == len(specs)
    # Every one of them is an error; none of them is a hang or a crash of ours.
    assert res.totals[ERROR] == len(specs)
    assert res.exit_code == 2

    # No child of this process is left running or unreaped.
    deadline = time.monotonic() + 5.0
    leaked = []
    while time.monotonic() < deadline:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            leaked = []
            break
        if pid == 0:
            leaked = ["a child is still running after run_matrix returned"]
            time.sleep(0.05)
            continue
        leaked.append(f"reaped orphan pid {pid} (status {status})")
    assert not leaked, leaked


# --------------------------------------------------------------------------
# event isolation at scale
# --------------------------------------------------------------------------
def test_each_collector_holds_only_its_own_targets_events():
    specs = fleet(40, prefix="iso")
    res = run_matrix(mixed_techniques(), specs, workers=16)
    run_ids = set()
    for run in res.runs:
        assert run.collector is not None
        assert run.collector.events, f"{run.target_name} recorded nothing"
        names = {e.target for e in run.collector.events}
        assert names == {run.target_name}, (
            f"{run.target_name}'s collector saw {sorted(names)}")
        tids = {e.technique_id for e in run.collector.events}
        assert tids <= {"PRX-9001", "PRX-9002", None}
        run_ids |= {e.run_id for e in run.collector.events}
    assert run_ids == {res.run_id}


def test_collectors_are_distinct_objects_per_target():
    res = run_matrix([enumerate_technique()], fleet(20, prefix="obj"),
                     workers=8)
    ids = {id(r.collector) for r in res.runs}
    assert len(ids) == len(res.runs)


# --------------------------------------------------------------------------
# degenerate inputs
# --------------------------------------------------------------------------
def test_empty_technique_list_against_a_fleet():
    res = run_matrix([], fleet(10, prefix="notech"), workers=4)
    assert len(res.runs) == 10
    assert all(r.results == [] for r in res.runs)
    assert res.totals == {PASS: 0, FAIL: 0, SKIP: 0, ERROR: 0}
    assert res.exit_code == 0


def test_empty_target_list_is_an_empty_matrix():
    res = run_matrix(mixed_techniques(), [], workers=8)
    assert res.runs == [] and res.exit_code == 0
    assert res.run_id


def test_empty_both():
    res = run_matrix([], [], workers=0)
    assert res.runs == [] and res.exit_code == 0


@pytest.mark.parametrize("workers", [0, -5, 1, 3, 500])
def test_worker_counts_outside_the_sane_range_still_run_everything(workers):
    specs = fleet(6, prefix=f"w{abs(workers)}")
    res = run_matrix([enumerate_technique()], specs, workers=workers)
    assert [r.target_name for r in res.runs] == [s.name for s in specs]
    assert res.totals[PASS] == len(specs)


def test_duplicate_target_names_are_kept_as_separate_runs():
    specs = [mock_spec("dupe") for _ in range(8)]
    res = run_matrix([enumerate_technique()], specs, workers=8)
    assert len(res.runs) == 8
    assert {r.target_name for r in res.runs} == {"dupe"}
    # Each duplicate still gets its own isolated collector.
    assert len({id(r.collector) for r in res.runs}) == 8
    assert res.totals[PASS] == 8


def test_run_target_handles_a_technique_list_it_cannot_satisfy():
    run = run_target(mock_spec("solo"), [skipping_technique()], run_id="rid")
    assert run.counts[SKIP] == 1
    assert run.collector is not None
    assert run.results[0].skipped_reason
