"""Negative controls: does the pack measure anything, or just execute?

Every technique passes against the mock range. That is necessary and not
remotely sufficient — an assertion that would also hold against a well-built
agent is measuring the harness, not the target. This module runs the whole
pack against both the vulnerable range (``mock``) and the defended one
(``hardened``) and demands that they *disagree*.

The contract:

* a technique that passes on ``mock`` must NOT pass on ``hardened``;
* the only exceptions are the ids in :data:`EXPECTED_ON_BOTH`, each of which
  has to carry a written justification below.

Anything else that passes on both is a tautology, and this test names it.
"""

from __future__ import annotations

import pytest

from praxis.runner import PASS, run_technique
from praxis.targets import build
from praxis.technique import load_dir

from conftest import TECH_DIR


# Techniques that legitimately hold against a defended agent. Every entry is a
# technique that does NOT discriminate, so the burden of proof is on the entry
# and the list is kept as short as it can be defended.
#
# This list has only shrunk. PRX-0002 and PRX-0006 were tautologies and were
# strengthened to assert on the poisoned description and the injected privileged
# read. PRX-0008 was weak-by-construction until the hardened range grew a
# just-in-time authority defence, which gave it something real to refuse.
EXPECTED_ON_BOTH = {
    # DISCOVERY. Enumerating the tool list is not itself a vulnerability: a
    # hardened agent still has tools and still advertises them. The technique
    # establishes attack surface and seeds the drift snapshot, and it is
    # correct for it to succeed everywhere. This is the only entry that is a
    # legitimate pass rather than a recorded weakness.
    "PRX-0005": "discovery — tool enumeration succeeds against any agent",
}


def _run(kind: str, tech):
    """One technique against a freshly reset target of the given kind."""
    target = build(kind, name=kind)
    target.reset()
    return run_technique(tech, target)


@pytest.fixture(scope="module")
def matrix():
    """{technique_id: {"name":…, "mock": result, "hardened": result}}."""
    out = {}
    for tech in load_dir(TECH_DIR):
        out[tech.id] = {"name": tech.name,
                        "mock": _run("mock", tech),
                        "hardened": _run("hardened", tech)}
    return out


def _failed_assertions(result) -> list[str]:
    return [a.name for a in result.assertions if not a.passed]


def _held_assertions(result) -> list[str]:
    return [a.name for a in result.assertions if a.passed]


def test_pack_is_non_empty(matrix):
    assert len(matrix) >= 26, "technique directory did not load"


def test_every_technique_still_passes_on_mock(matrix):
    """The floor: if a technique cannot fire on the range, nothing below
    this line means anything."""
    broken = {tid: (row["mock"].status, _failed_assertions(row["mock"]))
              for tid, row in matrix.items() if row["mock"].status != PASS}
    assert not broken, f"techniques no longer execute on the range: {broken}"


def test_techniques_discriminate_between_vulnerable_and_hardened(matrix):
    """The point of the whole module.

    A technique that passes on both targets proves only that its steps ran.
    Failure names the technique and the assertions that still held against the
    defended agent — those are precisely the ones that are not measuring a
    vulnerability.
    """
    offenders = []
    for tid, row in sorted(matrix.items()):
        if row["mock"].status != PASS or row["hardened"].status != PASS:
            continue
        if tid in EXPECTED_ON_BOTH:
            continue
        offenders.append(
            f"\n  {tid} {row['name']!r} passed on BOTH targets."
            f"\n    assertions that still held on hardened: "
            f"{_held_assertions(row['hardened'])}"
            f"\n    -> it is testing the harness, not the target. Strengthen "
            f"it to assert on the defence (a blocked event, a denied result, "
            f"an unchanged description), or add it to EXPECTED_ON_BOTH with a "
            f"justification.")
    assert not offenders, "non-discriminating techniques:" + "".join(offenders)


def test_allowlist_entries_are_still_needed(matrix):
    """An allowlist entry that no longer passes on both is stale.

    Left in place it would silently excuse a future regression, so removing it
    is required maintenance, not an optional tidy-up.
    """
    stale = [tid for tid in EXPECTED_ON_BOTH
             if tid in matrix and matrix[tid]["hardened"].status == PASS
             and matrix[tid]["mock"].status == PASS]
    missing = sorted(set(EXPECTED_ON_BOTH) - set(matrix))
    assert not missing, f"EXPECTED_ON_BOTH names unknown techniques: {missing}"
    assert len(stale) == len(EXPECTED_ON_BOTH), (
        "these allowlist entries now discriminate and should be deleted: "
        f"{sorted(set(EXPECTED_ON_BOTH) - set(stale))}")


def test_majority_of_pack_is_discriminating(matrix):
    """A coverage floor, so the allowlist cannot quietly grow into the pack."""
    discriminating = sum(1 for row in matrix.values()
                         if row["mock"].status == PASS
                         and row["hardened"].status != PASS)
    assert discriminating >= int(0.75 * len(matrix)), (
        f"only {discriminating}/{len(matrix)} techniques distinguish a "
        f"vulnerable agent from a hardened one")


def test_hardened_target_mirrors_the_mock_surface():
    """The two ranges must differ in behaviour only.

    A hardened target that quietly dropped a capability or a tool would make
    techniques SKIP, and a skip is not evidence of a defence.
    """
    mock, hard = build("mock", name="m"), build("hardened", name="h")
    assert hard.capabilities == mock.capabilities
    assert sorted(t.name for t in hard.list_tools()) == \
        sorted(t.name for t in mock.list_tools())


def test_report_tautologies(matrix, capsys):
    """Always print the mock-vs-hardened matrix; it is the actual deliverable."""
    lines = ["", f"{'technique':<10} {'mock':<6} {'hardened':<9} verdict"]
    for tid, row in sorted(matrix.items()):
        m, h = row["mock"].status, row["hardened"].status
        if m == PASS and h != PASS:
            verdict = "discriminates"
        elif m == PASS and h == PASS:
            verdict = f"PASSES BOTH — {EXPECTED_ON_BOTH.get(tid, 'UNJUSTIFIED')}"
        else:
            verdict = "does not fire on the range"
        lines.append(f"{tid:<10} {m:<6} {h:<9} {verdict}")
    with capsys.disabled():
        print("\n".join(lines))
