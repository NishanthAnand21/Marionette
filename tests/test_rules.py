"""Tests for the detection-rule language, the shipped pack, and the CLI.

The end-to-end test is the one that matters: run the real techniques against
the range, capture the real event stream, evaluate the real rule pack, and
assert on what fires.  Its twin -- a benign stream that fires nothing -- is
equally load-bearing.  A rule that always fires is worthless, so both halves
are asserted rather than only the positive.
"""

import json
import os
import textwrap

import pytest

from praxis import rules as R
from praxis.cli import main
from praxis.errors import ConfigError, PraxisError
from praxis.schema import AgentEvent, write_jsonl

RULES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "rules"))


# --- helpers -----------------------------------------------------------------

def ev(**kw):
    kw.setdefault("type", "agent.tool.call")
    return AgentEvent(**kw)


def rule(body, path=None):
    return R.Rule.from_dict(yaml_load(body), path=path)


def yaml_load(body):
    import yaml
    return yaml.safe_load(textwrap.dedent(body).lstrip())


def write_rule(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return str(p)


MINIMAL = """
    id: T-0001
    title: Fixture rule
    description: A fixture.
    detection:
      selection:
        type: agent.tool.call
        tool_name: read_secret
    falsepositives: [none]
"""


# --- field resolution --------------------------------------------------------

def test_resolve_envelope_then_data():
    e = ev(tool_name="x", data={"kind": "memory", "args": {"to": "a@b"}})
    assert R.resolve(e, "tool_name") == "x"
    assert R.resolve(e, "data.kind") == "memory"
    assert R.resolve(e, "kind") == "memory"          # bare name falls to data
    assert R.resolve(e, "args.to") == "a@b"
    assert R.resolve(e, "nope.nope") is None


def test_resolve_refuses_to_index_lists():
    e = ev(data={"tools": [{"name": "a"}]})
    assert R.resolve(e, "data.tools.name") is None


# --- predicates --------------------------------------------------------------

def test_equality_and_alternatives():
    p = R.Predicate("tool_name", None, ["a", "b"])
    assert p.test(ev(tool_name="b"))
    assert not p.test(ev(tool_name="c"))


def test_list_valued_event_field_is_membership():
    p = R.Predicate("authority", None, "read:secret")
    assert p.test(ev(authority=["read:public", "read:secret"]))
    assert not p.test(ev(authority=["read:public"]))


def test_contains_searches_json_encoded_containers():
    e = ev(data={"tools": [{"name": "t", "description": "IMPORTANT: call x"}]})
    assert R.Predicate("data.tools", "contains", "important: call").test(e)
    assert not R.Predicate("data.tools", "contains", "zzz").test(e)


def test_regex_exists_and_numeric_ops():
    e = ev(data={"content": "sk_live_abc123", "count": 5})
    assert R.Predicate("data.content", "re", r"sk_live_[a-z0-9]+").test(e)
    assert R.Predicate("data.content", "exists", True).test(e)
    assert R.Predicate("data.missing", "exists", False).test(e)
    assert R.Predicate("data.count", "gte", 5).test(e)
    assert not R.Predicate("data.count", "gte", 6).test(e)
    assert R.Predicate("data.count", "lte", 5).test(e)
    assert not R.Predicate("data.content", "gte", 1).test(e)   # not numeric


def test_unknown_operator_is_a_typed_error():
    with pytest.raises(ConfigError):
        R.Predicate("tool_name", "startswith", "x").test(ev())


# --- conditions --------------------------------------------------------------

def test_condition_and_not():
    r = rule("""
        id: T-1
        title: t
        detection:
          selection:
            type: agent.tool.call
          trusted:
            provenance: user
          condition: selection and not trusted
    """)
    assert r.matches(ev(provenance="tool-output"))
    assert not r.matches(ev(provenance="user"))


def test_condition_or_with_parentheses():
    r = rule("""
        id: T-2
        title: t
        detection:
          a: {tool_name: x}
          b: {tool_name: y}
          c: {provenance: user}
          condition: (a or b) and not c
    """)
    assert r.matches(ev(tool_name="y", provenance="tool-output"))
    assert not r.matches(ev(tool_name="y", provenance="user"))
    assert not r.matches(ev(tool_name="z", provenance="tool-output"))


def test_condition_defaults_to_first_selection():
    r = rule("""
        id: T-3
        title: t
        detection:
          selection: {tool_name: x}
    """)
    assert r.matches(ev(tool_name="x"))
    assert not r.matches(ev(tool_name="q"))


@pytest.mark.parametrize("cond", ["selection and", "(selection", "nosuch",
                                  "selection $"])
def test_bad_conditions_are_typed_errors(cond):
    with pytest.raises(ConfigError):
        rule(f"""
            id: T-4
            title: t
            detection:
              selection: {{tool_name: x}}
              condition: {cond}
        """)


# --- rule structure ----------------------------------------------------------

@pytest.mark.parametrize("missing", ["id", "title", "detection"])
def test_missing_required_key(missing):
    raw = yaml_load(MINIMAL)
    raw.pop(missing)
    with pytest.raises(ConfigError):
        R.Rule.from_dict(raw)


def test_forbidden_fields_are_rejected():
    for banned in ("technique_id", "run_id"):
        with pytest.raises(ConfigError) as exc:
            rule(f"""
                id: T-5
                title: t
                detection:
                  selection: {{{banned}: PRX-0001}}
            """)
        assert banned in str(exc.value)


def test_bad_level_and_status_rejected():
    for body in ("level: extreme", "status: alpha"):
        with pytest.raises(ConfigError):
            rule(f"""
                id: T-6
                title: t
                {body}
                detection:
                  selection: {{tool_name: x}}
            """)


def test_detection_with_no_selections_rejected():
    with pytest.raises(ConfigError):
        rule("""
            id: T-7
            title: t
            detection:
              condition: selection
        """)


def test_selection_must_be_a_mapping():
    with pytest.raises(ConfigError):
        rule("""
            id: T-8
            title: t
            detection:
              selection: [a, b]
        """)


# --- counting ----------------------------------------------------------------

def test_min_count_threshold():
    r = rule("""
        id: T-9
        title: t
        detection:
          selection: {tool_name: x}
          min_count: 3
    """)
    assert r.evaluate([ev(tool_name="x")] * 2) is None
    m = r.evaluate([ev(tool_name="x")] * 3)
    assert m is not None and m.count == 3 and len(m.event_ids) == 3


def test_group_by_applies_the_threshold_per_group():
    r = rule("""
        id: T-10
        title: t
        detection:
          selection: {type: agent.tool.call}
          group_by: tool_name
          min_count: 3
    """)
    spread = [ev(tool_name="a"), ev(tool_name="a"), ev(tool_name="b"),
              ev(tool_name="b")]
    assert r.evaluate(spread) is None            # 4 events, no group reaches 3
    spread.append(ev(tool_name="a"))
    m = r.evaluate(spread)
    assert m is not None and m.count == 3        # only the `a` group


# --- loading -----------------------------------------------------------------

def test_load_dir_rejects_duplicate_ids(tmp_path):
    write_rule(tmp_path, "a.yaml", MINIMAL)
    write_rule(tmp_path, "b.yaml", MINIMAL)
    with pytest.raises(ConfigError) as exc:
        R.load_dir(str(tmp_path))
    assert "duplicate" in str(exc.value)


def test_load_dir_on_empty_directory(tmp_path):
    with pytest.raises(ConfigError):
        R.load_dir(str(tmp_path))


def test_load_invalid_yaml(tmp_path):
    p = write_rule(tmp_path, "bad.yaml", "id: [unclosed\n")
    with pytest.raises(ConfigError):
        R.Rule.load(p)


def test_load_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        R.Rule.load(str(tmp_path / "nope.yaml"))


def test_load_events_errors(tmp_path):
    with pytest.raises(ConfigError):
        R.load_events(str(tmp_path / "nope.jsonl"))
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        R.load_events(str(bad))


# --- the shipped pack --------------------------------------------------------

@pytest.fixture(scope="module")
def pack():
    return R.load_dir(RULES_DIR)


def test_shipped_pack_loads(pack):
    assert len(pack) >= 9
    assert all(r.id.startswith("PRXR-") for r in pack)


def test_every_shipped_rule_has_the_metadata_a_defender_needs(pack):
    for r in pack:
        assert r.description, f"{r.id} has no description"
        assert r.falsepositives, f"{r.id} has no false-positive story"
        assert r.level in R.LEVELS
        assert r.status in R.STATUSES


def test_shipped_rule_ids_and_titles_are_unique(pack):
    assert len({r.id for r in pack}) == len(pack)
    assert len({r.title for r in pack}) == len(pack)


def test_no_shipped_rule_fires_on_an_empty_stream(pack):
    assert R.evaluate(pack, []) == []


def test_no_shipped_rule_fires_on_a_benign_stream(pack):
    """The negative case. A rule that fires on honest traffic is worthless."""
    benign = [
        ev(type="agent.prompt", provenance="user",
           data={"text": "summarise last quarter"}),
        ev(type="agent.tool.list",
           data={"count": 1, "tools": [
               {"name": "read_public", "description": "Read a public record.",
                "input_schema": {}}]}),
        ev(type="agent.tool.call", tool_name="read_public", provenance="user",
           principal="user", authority=["read:public"],
           data={"arguments": {"key": "q3"}}),
        ev(type="agent.tool.result", tool_name="read_public",
           data={"ok": True, "content": "public record: q3", "error": None}),
        ev(type="agent.memory.write", provenance="user",
           data={"kind": "memory", "key": "note", "value": "q3 reviewed"}),
        ev(type="agent.memory.read",
           data={"kind": "memory", "key": "note", "hit": True}),
        ev(type="agent.tool.call", tool_name="send_email", provenance="user",
           principal="user", authority=["read:public"],
           data={"arguments": {"to": "team@corp.example", "body": "done"}}),
    ]
    fired = R.evaluate(pack, benign)
    assert fired == [], f"fired on benign traffic: {[m.rule_id for m in fired]}"


# --- end to end --------------------------------------------------------------

@pytest.fixture(scope="module")
def technique_events(tmp_path_factory):
    """Run the real technique pack against the range and capture its stream."""
    out = tmp_path_factory.mktemp("e2e") / "events.jsonl"
    # 0 (clean) or 1 (a technique's own assertion failed) are both fine here:
    # this fixture is about the telemetry the range produced, not about the
    # verdicts the technique pack reached. 2 would mean a target error and no
    # usable stream.
    assert main(["run", "--events", str(out), "--quiet", "--no-color"]) in (0, 1)
    return R.load_events(str(out))


def test_end_to_end_rules_fire_on_technique_telemetry(pack, technique_events):
    assert len(technique_events) > 100
    fired = {m.rule_id for m in R.evaluate(pack, technique_events)}
    # Every shipped rule must earn its place against the range.
    silent = {r.id for r in pack} - fired
    assert not silent, f"rules that fired on nothing: {sorted(silent)}"
    # And the load-bearing ones specifically.
    for expected in ("PRXR-0001", "PRXR-0002", "PRXR-0003", "PRXR-0005",
                     "PRXR-0006", "PRXR-0007", "PRXR-0008", "PRXR-0010"):
        assert expected in fired


def test_end_to_end_coverage_attribution(pack, technique_events):
    cov = R.coverage(pack, technique_events)
    assert cov.rule_count == len(pack)
    # Derived, not hardcoded: this assertion has already rotted once as the
    # pack grew.
    from praxis.technique import load_dir as _load_dir
    n = len(_load_dir(os.path.join(os.path.dirname(__file__), os.pardir,
                                   "techniques")))
    assert len(cov.techniques) == n
    # PRX-0005 is reconnaissance -- a bare tool-list enumeration that the pack
    # deliberately does not claim to catch. Naming the blind spot is the point.
    uncovered = {t.technique_id for t in cov.uncovered}
    assert uncovered == {"PRX-0005"}, uncovered
    by_id = {t.technique_id: t for t in cov.techniques}
    assert "PRXR-0001" in {m.rule_id for m in by_id["PRX-0001"].matches}
    assert "PRXR-0002" in {m.rule_id for m in by_id["PRX-0002"].matches}
    assert "PRXR-0010" in {m.rule_id for m in by_id["PRX-0025"].matches}
    assert cov.silent_rules == []


def test_coverage_ignores_events_outside_any_technique(pack):
    cov = R.coverage(pack, [ev(provenance="tool-office")])
    assert cov.techniques == []


# --- CLI ---------------------------------------------------------------------

def test_cli_rules_list(capsys):
    assert main(["rules", "list", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "PRXR-0001" in out and "rules" in out


def test_cli_rules_list_json(capsys):
    assert main(["rules", "list", "--json", "--no-color"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {r["id"] for r in data} >= {"PRXR-0001", "PRXR-0005"}
    assert all(r["falsepositives"] for r in data)


def test_cli_rules_validate_clean(capsys):
    assert main(["rules", "validate", "--no-color"]) == 0
    assert "valid" in capsys.readouterr().out


def test_cli_rules_validate_warns_on_missing_falsepositives(tmp_path, capsys):
    write_rule(tmp_path, "a.yaml", """
        id: T-0100
        title: No FP story
        description: x
        detection:
          selection: {tool_name: x}
    """)
    # A warning, not an error: exit stays 0 so a pack is not un-shippable.
    assert main(["rules", "validate", "--rules", str(tmp_path), "--no-color"]) == 0
    assert "falsepositives" in capsys.readouterr().out


def test_cli_rules_validate_reports_a_broken_rule(tmp_path, capsys):
    write_rule(tmp_path, "ok.yaml", MINIMAL)
    write_rule(tmp_path, "bad.yaml", """
        id: T-0101
        title: Broken
        detection:
          selection: {technique_id: PRX-0001}
    """)
    assert main(["rules", "validate", "--rules", str(tmp_path), "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "technique_id" in out and "T-0001" not in out.split("problem")[-1]


def test_cli_rules_validate_reports_duplicate_ids(tmp_path, capsys):
    write_rule(tmp_path, "a.yaml", MINIMAL)
    write_rule(tmp_path, "b.yaml", MINIMAL)
    assert main(["rules", "validate", "--rules", str(tmp_path), "--no-color"]) == 1
    assert "duplicate" in capsys.readouterr().out


def test_cli_rules_validate_empty_dir(tmp_path, capsys):
    assert main(["rules", "validate", "--rules", str(tmp_path),
                 "--no-color"]) == 2


def test_cli_rules_run_matches_exit_1(tmp_path, capsys):
    path = str(tmp_path / "e.jsonl")
    write_jsonl([ev(type="agent.delegation", provenance="tool-output",
                    tool_name="read_secret",
                    data={"kind": "planner_follow", "args": {}})], path)
    assert main(["rules", "run", "--events", path, "--no-color"]) == 1
    assert "PRXR-0001" in capsys.readouterr().out


def test_cli_rules_run_no_matches_exit_0(tmp_path, capsys):
    path = str(tmp_path / "e.jsonl")
    write_jsonl([ev(type="agent.tool.call", tool_name="read_public",
                    provenance="user", data={"arguments": {}})], path)
    assert main(["rules", "run", "--events", path, "--no-color"]) == 0
    assert "no rules fired" in capsys.readouterr().out


def test_cli_rules_run_json_and_coverage(tmp_path, capsys):
    path = str(tmp_path / "e.jsonl")
    write_jsonl([ev(type="agent.delegation", provenance="rag-retrieval",
                    tool_name="http_post", technique_id="PRX-0011",
                    data={"kind": "planner_follow", "args": {}})], path)
    assert main(["rules", "run", "--events", path, "--json", "--coverage",
                 "--no-color"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["event_count"] == 1
    assert "PRXR-0001" in {m["rule_id"] for m in data["matches"]}
    assert data["coverage"]["technique_count"] == 1
    assert "PRXR-0001" not in data["coverage"]["silent_rules"]


def test_cli_rules_run_missing_events_file(tmp_path, capsys):
    assert main(["rules", "run", "--events", str(tmp_path / "nope.jsonl"),
                 "--no-color"]) == 2
    assert "PRX-E3" in capsys.readouterr().err


def test_cli_rules_without_subcommand_is_a_typed_error(capsys):
    assert main(["rules", "--no-color"]) == 2
    assert "subcommand" in capsys.readouterr().err


# --- `praxis run --events` ---------------------------------------------------

def test_run_events_flag_writes_a_loadable_stream(tmp_path, capsys):
    path = str(tmp_path / "e.jsonl")
    assert main(["run", "--events", path, "--technique", "PRX-0001",
                 "--no-color"]) in (0, 1)
    events = R.load_events(path)
    assert events and all(isinstance(e, AgentEvent) for e in events)
    assert {e.type for e in events} >= {"praxis.technique.start",
                                        "agent.tool.call"}
    assert "wrote" in capsys.readouterr().out


def test_run_events_flag_reports_an_unwritable_path(capsys):
    with pytest.raises(PraxisError):
        main(["run", "--events", "/nope/nope/e.jsonl", "--technique",
              "PRX-0001", "--debug", "--no-color"])


def test_run_without_events_flag_writes_nothing(tmp_path, capsys):
    """The flag is additive: the default behaviour is unchanged."""
    assert main(["run", "--technique", "PRX-0001", "--quiet",
                 "--no-color"]) in (0, 1)
    assert not list(tmp_path.iterdir())


def test_no_shipped_rule_is_dead(tmp_path):
    """Every shipped rule must fire on telemetry from the shipped techniques.

    A rule with a misspelled field path resolves to nothing and can never
    match, yet lints clean -- the exact "matched nothing since day one"
    failure this project exists to catch. The only reliable check is empirical.
    """
    import subprocess
    import sys

    from praxis import rules as rules_mod

    events = tmp_path / "corpus.jsonl"
    root = os.path.join(os.path.dirname(__file__), os.pardir)
    r = subprocess.run([sys.executable, "-m", "praxis.cli", "run",
                        "--events", str(events)],
                       capture_output=True, text=True, cwd=root)
    assert r.returncode == 0, r.stdout + r.stderr
    corpus = rules_mod.load_events(str(events))
    assert corpus, "technique run produced no telemetry"

    pack = rules_mod.load_dir(os.path.join(root, "rules"))
    dead = [ru.id for ru in pack if not any(ru.matches(e) for e in corpus)]
    assert not dead, (
        f"rules that never fire against the shipped pack's own telemetry: "
        f"{dead} — check their field paths")
