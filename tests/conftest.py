"""Shared fixtures + YAML helpers for the Marionette test suite."""

import os
import textwrap

import pytest

from marionette.config import TargetSpec
from marionette.detection import Assertion
from marionette.schema import TOOL_LIST
from marionette.technique import Step, Technique

TECH_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "techniques"))


def write_yaml(tmp_path, name, body):
    """Write a technique YAML into tmp_path and return its path as str."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return str(p)


# A minimal technique that is valid on every axis the validator checks.
GOOD_TECHNIQUE = textwrap.dedent("""
    id: MAR-9001
    name: Fixture Technique
    tactic: discovery
    atlas: [AML.T0007]
    owasp_asi: [ASI07]
    description: A fixture used by the test suite.
    requires: [list_tools]
    steps:
      - action: list_tools
    assertions:
      - name: tools listed
        type: agent.tool.list
        min_count: 1
    references:
      - https://example.invalid/fixture
""")


def enumerate_technique(tid="MAR-9001"):
    """The programmatic twin of GOOD_TECHNIQUE — one step, one assertion."""
    return Technique(
        id=tid, name="Fixture Technique", tactic="discovery",
        atlas=["AML.T0007"], requires=["list_tools"],
        steps=[Step("list_tools")],
        assertions=[Assertion(name="tools listed", cond={"type": TOOL_LIST})],
    )


def failing_technique(tid="MAR-9002"):
    """Executes fine, but asserts something that never happens."""
    t = enumerate_technique(tid)
    t.name = "Always Fails"
    t.assertions = [Assertion(name="impossible",
                              cond={"type": TOOL_LIST, "tool_name": "nope"})]
    return t


def no_assertion_technique(tid="MAR-9003"):
    t = enumerate_technique(tid)
    t.name = "Asserts Nothing"
    t.assertions = []
    return t


def mock_spec(name):
    return TargetSpec(name=name, kind="mock")


def broken_mcp_spec(name="broken-mcp"):
    """kind=mcp pointing at a command that cannot possibly launch."""
    return TargetSpec(name=name, kind="mcp",
                      command="marionette-no-such-binary-xyz --stdio", timeout=2.0)


@pytest.fixture
def good_technique_yaml(tmp_path):
    return write_yaml(tmp_path, "MAR-9001-good.yaml", GOOD_TECHNIQUE)
