"""#950 — the two defects in the write-time close path, pinned as properties rather than lines."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402

from defender.investigation import challenge_gate  # noqa: E402
from defender.investigation.close_tool import register_close_tool  # noqa: E402
from defender.investigation.review.projector import parse_investigation  # noqa: E402
from defender.investigation.review.reply import (  # noqa: E402
    HOLDS,
    Unreadable,
    citable_refs,
    read_composer_reply,
)
from defender.agents import MAIN_DEF  # noqa: E402
from defender.investigation.tools import AgentDeps, register_tools  # noqa: E402
from defender.tests.support.runtime.permissions._review_bundle import bundle, composer_reply  # noqa: E402

DEFENDER = Path(__file__).resolve().parents[3]
GOLDEN = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-sshpivot-ab3" / "investigation.md"

#: The tools that write ONE SHARED ARTIFACT — the roster this file's serialization rule is
WRITERS = ("append_block", "fix_row", "close_investigation")

#: The writers a role gets from `ToolSet(write=True)` — CORPUS_AUTHOR and LEAD_AUTHOR grant these,
WRITE_ROLE_WRITERS = ("write_file", "edit_file")

#: Two ways a model spells a scalar field as a container. Both are unhashable, which is the
#: property that turned a refusal into a crash; `frozenset`/`set` membership raises on them.
UNHASHABLE = ([HOLDS], {"finding": HOLDS})


@pytest.fixture(scope="module")
def main_tools() -> dict:
    """MAIN's real tool roster, registered once"""
    agent = Agent("test", deps_type=AgentDeps)
    register_tools(agent, MAIN_DEF.tools)
    register_close_tool(
        agent,
        stages=bundle(composer=composer_reply(finding="holds")),
        bounds=challenge_gate.default_bounds(),
    )
    return dict(agent._function_toolset.tools)


# the writer serialization rule
def test_every_writer_main_can_call_is_sequential(main_tools):
    """The rule `append_block` and `fix_row` already followed, applied to the roster."""
    missing = [
        n for n in WRITERS
        if n in main_tools and not getattr(main_tools[n], "sequential", False)
    ]
    assert not missing, (
        f"writer tool(s) {missing} are registered without sequential=True — two calls in one "
        f"model response would run concurrently and one write would be lost"
    )


@pytest.fixture(scope="module")
def write_role_tools() -> dict:
    """The roster a write-granting role gets. `MAIN_DEF.tools` carries `write=False`, so the two
    tools `ToolSet(write=True)` registers are invisible to `main_tools` — and they are shared-artifact
    writers on the roles that DO grant them, which is where the lesson corpus is authored."""
    agent = Agent("test", deps_type=AgentDeps)
    register_tools(agent, replace(MAIN_DEF.tools, write=True))
    return dict(agent._function_toolset.tools)


def test_every_write_role_writer_is_sequential(write_role_tools):
    """The same rule over the roster `main_tools` cannot reach."""
    missing = [
        n for n in WRITE_ROLE_WRITERS
        if n in write_role_tools and not getattr(write_role_tools[n], "sequential", False)
    ]
    assert not missing, (
        f"writer tool(s) {missing} are registered without sequential=True — two calls in one "
        f"model response would run concurrently and one write would be lost"
    )


def test_the_write_role_roster_is_actually_registered(write_role_tools):
    """The control for the test above, whose `n in tools` guard would otherwise pass vacuously."""
    assert set(WRITE_ROLE_WRITERS) <= set(write_role_tools), (
        f"expected {WRITE_ROLE_WRITERS} among {sorted(write_role_tools)}"
    )


def test_the_writer_roster_is_actually_registered(main_tools):
    """The control for the test above, whose `n in tools` guard would otherwise let a renamed
    or unregistered writer pass vacuously."""
    assert set(WRITERS) <= set(main_tools), f"expected {WRITERS} among {sorted(main_tools)}"


# the closed-vocabulary rule, both sites
@pytest.fixture(scope="module")
def refs():
    return citable_refs(parse_investigation(GOLDEN.read_text(encoding="utf-8")))


@pytest.mark.parametrize("finding", [*UNHASHABLE, "nonsense"], ids=["list", "dict", "near-miss"])
def test_a_non_member_finding_is_unreadable_however_it_is_spelled(finding, refs):
    text = json.dumps({"finding": finding, "review": "the close holds", "ask": None})
    with pytest.raises(Unreadable):
        read_composer_reply(text, refs=refs)


def test_a_real_finding_still_reads(refs):
    """The positive control: the guard refuses precisely, it does not refuse everything."""
    text = json.dumps({"finding": HOLDS, "review": "the close holds", "ask": None})
    assert read_composer_reply(text, refs=refs).finding == HOLDS
