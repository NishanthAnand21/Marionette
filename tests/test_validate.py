"""Validator contract: the shipped pack is clean, and every rule actually bites."""

import os

import pytest

from conftest import GOOD_TECHNIQUE, TECH_DIR, write_yaml
from praxis.validate import (Problem, validate_dir, validate_file,
                             validate_fleet)


def errors(problems):
    return [p for p in problems if p.severity == "error"]


def warnings(problems):
    return [p for p in problems if p.severity == "warning"]


def messages(problems):
    return " | ".join(p.message for p in problems)


# --- the shipped pack --------------------------------------------------------

def test_shipped_techniques_have_zero_errors():
    problems = validate_dir(TECH_DIR)
    assert errors(problems) == [], messages(errors(problems))


@pytest.mark.parametrize(
    "path", sorted(p for p in os.listdir(TECH_DIR) if p.endswith(".yaml")))
def test_each_shipped_technique_file_is_clean(path):
    problems = validate_file(os.path.join(TECH_DIR, path))
    assert errors(problems) == [], messages(errors(problems))


def test_good_fixture_is_completely_clean(good_technique_yaml):
    assert validate_file(good_technique_yaml) == []


# --- negative cases ----------------------------------------------------------

BAD_ID = GOOD_TECHNIQUE.replace("id: PRX-9001", "id: PRX-9")
NO_ID = GOOD_TECHNIQUE.replace("id: PRX-9001\n", "")
BLANK_NAME = GOOD_TECHNIQUE.replace("name: Fixture Technique", 'name: ""')
NO_STEPS = GOOD_TECHNIQUE.replace("  - action: list_tools\n", "")
BAD_ACTION = GOOD_TECHNIQUE.replace("action: list_tools", "action: rm_rf")
MISSING_STEP_ARG = GOOD_TECHNIQUE.replace(
    "  - action: list_tools", "  - action: call_tool\n    args: {args: {}}")
MISSING_DESC_ARG = GOOD_TECHNIQUE.replace(
    "  - action: list_tools",
    "  - action: set_description\n    args: {tool: read_public}")
MISSING_MEM_ARG = GOOD_TECHNIQUE.replace(
    "  - action: list_tools", "  - action: mem_write\n    args: {key: k}")
MISSING_GRANT_ARG = GOOD_TECHNIQUE.replace(
    "  - action: list_tools", "  - action: grant\n    args: {}")
BAD_EVENT_TYPE = GOOD_TECHNIQUE.replace("type: agent.tool.list",
                                        "type: agent.tool.telepathy")
NO_ASSERTIONS = GOOD_TECHNIQUE.split("assertions:")[0] + \
    "references:\n  - https://example.invalid/fixture\n"
BAD_MIN_COUNT = GOOD_TECHNIQUE.replace("min_count: 1", "min_count: 0")
NEGATIVE_MIN_COUNT = GOOD_TECHNIQUE.replace("min_count: 1", "min_count: -3")
STRING_MIN_COUNT = GOOD_TECHNIQUE.replace("min_count: 1", 'min_count: "lots"')
UNPARSEABLE = "id: PRX-9001\nname: [unclosed\nsteps:\n  - action: list_tools\n"


@pytest.mark.parametrize("body,needle", [
    (BAD_ID, "PRX-####"),
    (NO_ID, "required key `id`"),
    (BLANK_NAME, "required key `name`"),
    (NO_STEPS, "required key `steps`"),
    (BAD_ACTION, "unknown action 'rm_rf'"),
    (MISSING_STEP_ARG, "missing required arg `tool`"),
    (MISSING_DESC_ARG, "missing required arg `description`"),
    (MISSING_MEM_ARG, "missing required arg `value`"),
    (MISSING_GRANT_ARG, "missing required arg `authority`"),
    (BAD_EVENT_TYPE, "unknown event type 'agent.tool.telepathy'"),
    (NO_ASSERTIONS, "no `assertions`"),
    (BAD_MIN_COUNT, "`min_count` must be a positive int"),
    (NEGATIVE_MIN_COUNT, "`min_count` must be a positive int"),
    (STRING_MIN_COUNT, "`min_count` must be a positive int"),
    (UNPARSEABLE, "YAML will not parse"),
], ids=["bad-id", "no-id", "blank-name", "no-steps", "unknown-action",
        "missing-tool-arg", "missing-description-arg", "missing-mem-value",
        "missing-authority", "unknown-event-type", "no-assertions",
        "min-count-zero", "min-count-negative", "min-count-string",
        "unparseable"])
def test_negative_case_produces_expected_problem(tmp_path, body, needle):
    path = write_yaml(tmp_path, "case.yaml", body)
    problems = validate_file(path)
    assert errors(problems), "expected at least one error, got none"
    assert any(needle in p.message for p in problems), messages(problems)
    assert all(p.path == path for p in problems)


def test_unparseable_yaml_does_not_raise(tmp_path):
    path = write_yaml(tmp_path, "broken.yaml", UNPARSEABLE)
    problems = validate_file(path)   # must not raise
    assert len(problems) == 1
    assert problems[0].severity == "error"


def test_multiple_problems_are_all_reported(tmp_path):
    body = BAD_ID.replace("action: list_tools", "action: rm_rf")
    body = body.replace("type: agent.tool.list", "type: nope")
    path = write_yaml(tmp_path, "many.yaml", body)
    problems = errors(validate_file(path))
    assert len(problems) >= 3, messages(problems)
    joined = messages(problems)
    assert "PRX-####" in joined and "rm_rf" in joined and "nope" in joined


def test_duplicate_ids_across_files(tmp_path):
    write_yaml(tmp_path, "a.yaml", GOOD_TECHNIQUE)
    write_yaml(tmp_path, "b.yaml", GOOD_TECHNIQUE.replace(
        "name: Fixture Technique", "name: Duplicate Twin"))
    problems = errors(validate_dir(str(tmp_path)))
    assert len(problems) == 1
    assert "duplicate `id` 'PRX-9001'" in problems[0].message
    assert problems[0].path.endswith("b.yaml")


def test_distinct_ids_in_a_dir_are_fine(tmp_path):
    write_yaml(tmp_path, "a.yaml", GOOD_TECHNIQUE)
    write_yaml(tmp_path, "b.yaml", GOOD_TECHNIQUE.replace("PRX-9001", "PRX-9002"))
    assert errors(validate_dir(str(tmp_path))) == []


def test_missing_file_is_a_problem_not_an_exception(tmp_path):
    problems = validate_file(str(tmp_path / "nope.yaml"))
    assert len(problems) == 1 and problems[0].severity == "error"


def test_empty_file(tmp_path):
    path = write_yaml(tmp_path, "empty.yaml", "\n")
    assert [p.message for p in validate_file(path)] == ["file is empty"]


# --- warnings ---------------------------------------------------------------

@pytest.mark.parametrize("body,needle", [
    (GOOD_TECHNIQUE.replace("atlas: [AML.T0007]\n", "")
                   .replace("owasp_asi: [ASI07]\n", ""), "no `atlas`"),
    (GOOD_TECHNIQUE.replace("description: A fixture used by the test suite.",
                            'description: ""'), "empty `description`"),
    (GOOD_TECHNIQUE.split("references:")[0], "no `references`"),
    (GOOD_TECHNIQUE.replace("tactic: discovery", 'tactic: ""'), "blank `tactic`"),
    (GOOD_TECHNIQUE.replace("requires: [list_tools]", "requires: [time_travel]"),
     "capability 'time_travel'"),
], ids=["unmapped", "no-description", "no-references", "blank-tactic",
        "unknown-capability"])
def test_warning_cases(tmp_path, body, needle):
    path = write_yaml(tmp_path, "warn.yaml", body)
    problems = validate_file(path)
    assert errors(problems) == [], messages(errors(problems))
    assert any(needle in p.message for p in warnings(problems)), \
        messages(problems)


def test_known_capabilities_are_not_warned_about(tmp_path):
    body = GOOD_TECHNIQUE.replace("requires: [list_tools]",
                                  "requires: [call_tool, memory, snapshot]")
    path = write_yaml(tmp_path, "caps.yaml", body)
    assert [p for p in validate_file(path) if "capability" in p.message] == []


def test_empty_directory_warns(tmp_path):
    problems = validate_dir(str(tmp_path))
    assert errors(problems) == []
    assert warnings(problems)


# --- Problem rendering ------------------------------------------------------

def test_problem_render_plain_and_color():
    p = Problem("techniques/x.yaml", "something is off", "error", "PRX-0001")
    plain = p.render()
    assert "techniques/x.yaml" in plain
    assert "PRX-0001" in plain
    assert "something is off" in plain
    assert "\033[" not in plain
    assert "\033[" in p.render(color=True)


def test_problem_defaults_to_error():
    assert Problem("f", "m").severity == "error"


# --- fleets -----------------------------------------------------------------

GOOD_FLEET = """
defaults:
  timeout: 20
targets:
  - name: range
    kind: mock
  - name: prod
    kind: mcp
    command: "python -m server"
    tags: [prod]
"""


def test_validate_fleet_clean(tmp_path):
    p = tmp_path / "targets.yaml"
    p.write_text(GOOD_FLEET, encoding="utf-8")
    assert validate_fleet(str(p)) == []


@pytest.mark.parametrize("body", [
    "targets:\n  - name: broken\n    kind: mcp\n",          # mcp w/o command
    "targets: [[unclosed\n",                                 # bad YAML
    "defaults: {}\n",                                        # no targets key
    "targets:\n  - name: a\n    kind: mock\n    wat: 1\n",   # unknown key
    "targets:\n  - name: a\n    kind: mock\n  - name: a\n    kind: mock\n",
], ids=["mcp-no-command", "bad-yaml", "no-targets-key", "unknown-key",
        "duplicate-name"])
def test_validate_fleet_malformed(tmp_path, body):
    p = tmp_path / "targets.yaml"
    p.write_text(body, encoding="utf-8")
    problems = validate_fleet(str(p))   # must not raise
    assert problems and all(isinstance(x, Problem) for x in problems)
    assert all(x.severity == "error" for x in problems)


def test_validate_fleet_missing_file(tmp_path):
    problems = validate_fleet(str(tmp_path / "nope.yaml"))
    assert len(problems) == 1
    assert "not found" in problems[0].message
