"""Disposition vocabulary reaches the model as a schema enum, and the host still gates: sync entry and tool lane refuse near-misses and escape invisible characters."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from dataclasses import replace as _with_fixture_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.exceptions import ModelRetry  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._vocab import DISPOSITION_VALUES  # noqa: E402
from defender.agents import MAIN_DEF  # noqa: E402
from defender.runtime import challenge_gate  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.close_tool import (  # noqa: E402
    close_investigation,
    register_close_tool,
)
from defender.runtime.tools import AgentDeps  # noqa: E402
from defender.tests.support.runtime.permissions._review_bundle import bundle, composer_reply  # noqa: E402
from defender.tests.e2e._replay_harness import ToolRoster, Turn  # noqa: E402

GOLDEN = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "e2e" / "golden-v2sshd"

LACED = "beni\u200bgn"

NEAR_MISSES = ("Benign", "benign ", LACED, "totally-benign", "")


def _deps(tmp_path: Path):
    """MAIN's deps through the REAL `bind` seam — the real compiled policy, the real gate."""
    run_dir = tmp_path / fixture_uuid("run")
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "alert.json").write_bytes((GOLDEN / "alert.json").read_bytes())
    (run_dir / "investigation.md").write_bytes((GOLDEN / "investigation.md").read_bytes())
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    return _with_fixture_run_1165(bind(MAIN_DEF, run_dir, defender_dir=dfn), run=_fixture_run_1165(run_dir)), run_dir



def _stages():
    """The close's four review stages, answering without a provider."""
    return bundle(composer=composer_reply(finding="holds"))


def _drive_tool(tmp_path: Path, disposition: str | None = None):
    """Register the REAL close tool on an agent and run it against a scripted model."""
    deps, run_dir = _deps(tmp_path)
    turns = [Turn(text="reading the alert")]
    if disposition is not None:
        turns = [
            Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
            Turn(text="acknowledged; stopping"),
        ]
    script = ToolRoster(turns)
    agent = Agent(FunctionModel(script), deps_type=AgentDeps)
    register_close_tool(agent, stages=_stages(), bounds=challenge_gate.default_bounds())
    with override_allow_model_requests(False):
        agent.run_sync("close this investigation", deps=deps)
    assert script.tool_defs is not None, "the model was never called"
    return script, run_dir


def _close_tool_def(script: ToolRoster):
    """The one tool `register_close_tool` put in front of the model."""
    defs = script.tool_defs or []
    names = [t.name for t in defs]
    assert names == ["close_investigation"], (
        f"the close tool is not the registered roster: {names}"
    )
    return defs[0]


def _disposition_property(tool_def) -> dict:
    """The `disposition` argument's own schema, following a `$ref` if the annotation made one."""
    schema = tool_def.parameters_json_schema
    prop = schema.get("properties", {}).get("disposition")
    assert prop is not None, (
        f"the tool advertises no `disposition` argument at all: {schema}"
    )
    ref = prop.get("$ref")
    if ref:
        prop = schema.get("$defs", {}).get(ref.rsplit("/", 1)[-1], {})
    return prop


# O1 — the vocabulary is stated to the model structurally, derived from its owner.


def test_the_registered_tool_advertises_the_owners_vocabulary(tmp_path):
    """O1. The schema the MODEL is offered carries `DISPOSITION_VALUES`, in the owner's order."""
    script, _run_dir = _drive_tool(tmp_path)
    prop = _disposition_property(_close_tool_def(script))

    assert DISPOSITION_VALUES, "the vocabulary owner is empty; the comparison below is vacuous"
    assert prop.get("enum") == list(DISPOSITION_VALUES), (
        "the model is not told the disposition vocabulary structurally — the schema's enum is "
        f"{prop.get('enum')!r}, the owner's members are {list(DISPOSITION_VALUES)!r}. The "
        f"whole advertised argument schema is {prop!r}"
    )


# NU2 — the hint must not become the gate.


# O2 — no value outside the vocabulary commits, by EITHER entry path.


@pytest.mark.parametrize("disposition", NEAR_MISSES)
def test_the_sync_host_entry_refuses_every_near_miss(tmp_path, disposition):
    """O2, the lane with no tool-argument validation anywhere in front of it."""
    deps, run_dir = _deps(tmp_path)

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, disposition, stages=_stages())

    assert "disposition must be exactly one of" in str(excinfo.value)
    assert not (run_dir / "report.md").exists(), (
        f"{disposition!r} committed a disposition through the sync host entry"
    )


@pytest.mark.parametrize("disposition", [["benign"], {"disposition": "benign"}, 1, None])
def test_the_sync_host_entry_denies_a_non_string_rather_than_crashing(tmp_path, disposition):
    """O2's unhashable arm, and the one near miss the string list above cannot express."""
    deps, run_dir = _deps(tmp_path)

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, disposition, stages=_stages())

    assert "disposition must be exactly one of" in str(excinfo.value)
    assert not (run_dir / "report.md").exists()


def test_the_tool_lane_refuses_a_value_outside_the_vocabulary(tmp_path):
    """O2, the model-facing lane, driven end to end through the registered tool."""
    script, run_dir = _drive_tool(tmp_path, disposition="totally-benign")

    seen = "\n".join(script.seen)
    assert "disposition must be exactly one of" in seen, (
        f"the model was never told why its close was refused. Saw: {seen!r}"
    )
    assert not (run_dir / "report.md").exists(), (
        "an out-of-vocabulary disposition committed a report through the tool lane"
    )


def test_a_member_of_the_vocabulary_commits_through_the_tool_lane(tmp_path):
    """O2's positive control on the MODEL-FACING lane, and it has to be on this lane."""
    script, run_dir = _drive_tool(tmp_path, disposition="inconclusive")

    seen = "\n".join(script.seen)
    assert "disposition must be exactly one of" not in seen, (
        f"a member of the vocabulary was refused on the tool lane. Saw: {seen!r}"
    )
    report = run_dir / "report.md"
    assert report.exists(), "a valid disposition did not commit through the tool lane"
    assert "disposition: inconclusive" in report.read_text(encoding="utf-8"), (
        f"the committed report does not carry the disposition: {report.read_text()!r}"
    )


# O3 — the refusal distinguishes an invisible character from a valid value.


def test_the_refusal_escapes_an_invisible_character_rather_than_echoing_it(tmp_path):
    """O3 (#722). `beni<U+200B>gn` comes back repr-escaped, on both lanes."""
    deps, run_dir = _deps(tmp_path)

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, LACED, stages=_stages())
    message = str(excinfo.value)

    assert repr(LACED) == "'beni\\u200bgn'", (
        "python's repr no longer escapes U+200B, so the assertions below are about the wrong "
        "thing — the retry text needs another way to make the character visible"
    )
    assert "'beni\\u200bgn'" in message, (
        f"the refusal does not show the invisible character: {message!r}"
    )
    assert LACED not in message, (
        "the refusal echoes the laced value raw, so the model reads its own rejected answer "
        f"as identical to a valid one: {message!r}"
    )
    assert not (run_dir / "report.md").exists()

    # The same text, on the lane the model actually reads it from.
    script, tool_run_dir = _drive_tool(tmp_path / "tool", disposition=LACED)
    seen = "\n".join(script.seen)
    assert "'beni\\u200bgn'" in seen, (
        f"the model was handed a refusal that hides the character it must fix: {seen!r}"
    )
    assert LACED not in seen, (
        "the model was handed the laced value raw, so its rejected answer reads as identical "
        f"to a valid one: {seen!r}"
    )
    assert not (tool_run_dir / "report.md").exists()
