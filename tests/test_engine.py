"""Engine contract: isolation, ordering, exit codes, concurrency safety."""

import threading
import time

import pytest

from conftest import (TECH_DIR, broken_mcp_spec, enumerate_technique,
                      failing_technique, mock_spec, no_assertion_technique)

engine = pytest.importorskip("praxis.engine")

from praxis.runner import ERROR, FAIL, PASS  # noqa: E402
from praxis.targets.base import _REGISTRY  # noqa: E402
from praxis.targets.mock import MockAgentTarget  # noqa: E402


@pytest.fixture
def slow_kind():
    """A mock whose connect() sleeps, so completion order != input order."""

    class SlowMockTarget(MockAgentTarget):
        kind = "slowmock"

        def connect(self):
            # name is "t<n>"; earlier targets sleep longer, so they finish last.
            try:
                idx = int(self.name.lstrip("t"))
            except ValueError:
                idx = 0
            time.sleep(0.02 * (5 - idx))

    _REGISTRY["slowmock"] = SlowMockTarget
    try:
        yield "slowmock"
    finally:
        _REGISTRY.pop("slowmock", None)


def test_results_come_back_in_input_order(slow_kind):
    specs = [mock_spec(f"t{i}") for i in range(6)]
    for s in specs:
        s.kind = slow_kind
    res = engine.run_matrix([enumerate_technique()], specs, workers=6)
    assert [r.target_name for r in res.runs] == [s.name for s in specs]
    assert res.totals[PASS] == 6


def test_dead_target_is_contained_and_others_still_pass():
    specs = [mock_spec("alive-1"), broken_mcp_spec(), mock_spec("alive-2")]
    res = engine.run_matrix([enumerate_technique()], specs, workers=4)

    by_name = {r.target_name: r for r in res.runs}
    dead = by_name["broken-mcp"]
    assert dead.error is not None
    assert dead.error.get("code", "").startswith("PRX-E")
    assert [r.status for r in dead.results] == [ERROR]

    for name in ("alive-1", "alive-2"):
        assert [r.status for r in by_name[name].results] == [PASS]


def test_exit_code_zero_one_two():
    ok = engine.run_matrix([enumerate_technique()], [mock_spec("a")])
    assert ok.exit_code == 0

    bad = engine.run_matrix([failing_technique()], [mock_spec("a")])
    assert bad.totals[FAIL] == 1
    assert bad.exit_code == 1

    broken = engine.run_matrix([enumerate_technique()],
                               [mock_spec("a"), broken_mcp_spec()])
    assert broken.exit_code == 2


def test_error_outranks_failure_in_exit_code():
    res = engine.run_matrix([failing_technique()],
                            [mock_spec("a"), broken_mcp_spec()])
    assert res.totals[FAIL] >= 1 and res.totals[ERROR] >= 1
    assert res.exit_code == 2


def test_fail_fast_stops_early():
    specs = [mock_spec(f"t{i}") for i in range(6)]
    res = engine.run_matrix([failing_technique()], specs, workers=1,
                            fail_fast=True)
    ran = [r for r in res.runs if r.results]
    assert len(ran) < len(specs), "fail_fast did not stop the matrix early"
    assert res.exit_code != 0


def test_fail_fast_false_runs_everything():
    specs = [mock_spec(f"t{i}") for i in range(6)]
    res = engine.run_matrix([failing_technique()], specs, workers=1,
                            fail_fast=False)
    assert all(r.results for r in res.runs)
    assert res.totals[FAIL] == 6


def test_no_event_leakage_between_concurrent_targets():
    techs = [enumerate_technique("PRX-9001"), enumerate_technique("PRX-9002")]
    specs = [mock_spec(f"t{i}") for i in range(12)]
    res = engine.run_matrix(techs, specs, workers=8)

    solo = engine.run_matrix(techs, [mock_spec("solo")], workers=1)
    expected = [r.event_count for r in solo.runs[0].results]

    for run in res.runs:
        assert [r.event_count for r in run.results] == expected, (
            f"{run.target_name} saw a different number of events than a solo run")
        assert run.collector is not None
        targets_seen = {e.target for e in run.collector.events}
        assert targets_seen == {run.target_name}, (
            f"{run.target_name} collected events from {targets_seen}")

    assert res.totals[PASS] == len(specs) * len(techs)
    assert sum(res.totals.values()) == len(specs) * len(techs)


def test_on_progress_kinds_and_exceptions_are_contained():
    seen = []
    lock = threading.Lock()

    def progress(kind, payload):
        with lock:
            seen.append(kind)
        raise RuntimeError("renderer exploded")

    specs = [mock_spec(f"t{i}") for i in range(4)]
    res = engine.run_matrix([enumerate_technique()], specs, workers=4,
                            on_progress=progress)

    assert res.totals[PASS] == 4, "a broken on_progress took the run down"
    assert set(seen) <= {"target_start", "target_done", "technique_done"}
    assert {"target_start", "target_done", "technique_done"} <= set(seen)
    assert seen.count("target_start") == 4


def test_zero_assertion_technique_is_an_error_not_a_pass():
    res = engine.run_matrix([no_assertion_technique()], [mock_spec("a")])
    result = res.runs[0].results[0]
    assert result.status == ERROR
    assert result.passed is False
    assert "assertion" in (result.error or "")
    assert res.exit_code == 2


def test_empty_spec_list_is_an_empty_matrix():
    res = engine.run_matrix([enumerate_technique()], [])
    assert res.runs == []
    assert res.exit_code == 0


def test_matrix_to_dict_round_trips_totals():
    res = engine.run_matrix([enumerate_technique()],
                            [mock_spec("a"), mock_spec("b")])
    d = res.to_dict()
    assert d["run_id"] == res.run_id
    assert d["totals"] == res.totals
    assert d["exit_code"] == 0
    assert [r["target_name"] for r in d["runs"]] == ["a", "b"]


def test_techniques_are_order_independent():
    """The pack must not depend on the order techniques happen to run in.

    The engine reuses one connection per target, so without a reset between
    techniques one technique's mutations (a shadowed tool, granted authority,
    poisoned memory) silently change the next one's verdict. Before the reset
    landed, only 6 of 25 shuffled orders were green.
    """
    import random

    from praxis.technique import load_dir

    techs = load_dir(TECH_DIR)
    for seed in range(8):
        shuffled = list(techs)
        random.Random(seed).shuffle(shuffled)
        m = engine.run_matrix(shuffled, [mock_spec("range")], workers=1)
        bad = [r.technique_id for r in m.runs[0].results
               if r.status in ("fail", "error")]
        assert not bad, f"seed {seed}: order-dependent failures {bad}"


def test_reset_clears_target_state_between_techniques():
    from praxis.targets import build

    t = build("mock")
    t.grant("read:secret")
    t.mem_write("k", "poisoned", provenance="tool-output")
    t.reset()
    assert "read:secret" not in t.authority, "authority survived reset"
    assert t.memory == {}, "memory survived reset"
    assert "send_email" in {s.name for s in t.list_tools()}, "tools not restored"
