"""Disposition vocabulary reaches the model as a schema enum, and the host still gates: sync entry and tool lane refuse near-misses and escape invisible characters."""
from __future__ import annotations

from defender.tests.support.runtime.engine._spec992 import closing_record, is_closed, never_closed
from defender.tests.storage.verdict_1534 import _spec1534 as V
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
from defender.investigation import challenge_gate  # noqa: E402
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.investigation.close_tool import (  # noqa: E402
    close_investigation,
    register_close_tool,
)
from defender.investigation.tools import AgentDeps  # noqa: E402
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
    from defender.tests.support.runtime.engine._spec923 import with_session_store

    deps = _with_fixture_run_1165(bind(MAIN_DEF, run_dir, defender_dir=dfn), run=_fixture_run_1165(run_dir))
    return with_session_store(deps, tmp_path), run_dir



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


# The vocabulary is stated to the model structurally, derived from its owner.


def test_the_registered_tool_advertises_the_owners_vocabulary(tmp_path):
    """The schema the MODEL is offered carries `DISPOSITION_VALUES`, in the owner's order."""
    script, _run_dir = _drive_tool(tmp_path)
    prop = _disposition_property(_close_tool_def(script))

    assert DISPOSITION_VALUES, "the vocabulary owner is empty; the comparison below is vacuous"
    assert prop.get("enum") == list(DISPOSITION_VALUES), (
        f"the advertised enum is {prop.get('enum')!r}, the owner's members are "
        f"{list(DISPOSITION_VALUES)!r}; schema: {prop!r}"
    )


# No value outside the vocabulary commits, by EITHER entry path.


@pytest.mark.parametrize("disposition", [
    *NEAR_MISSES,
    pytest.param(["benign"], id="list"),
    pytest.param({"disposition": "benign"}, id="dict"),
    1,
    None,
])
def test_the_sync_host_entry_refuses_every_near_miss(tmp_path, disposition):
    """The lane with no tool-argument validation in front of it. Non-strings, unhashable ones
    included, are refused rather than crashing the check."""
    deps, run_dir = _deps(tmp_path)

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, disposition, stages=_stages())

    assert "disposition must be exactly one of" in str(excinfo.value)
    assert never_closed(run_dir), (
        f"{disposition!r} committed a disposition through the sync host entry"
    )


def test_the_tool_lane_refuses_a_value_outside_the_vocabulary(tmp_path):
    """The model-facing lane, driven end to end through the registered tool."""
    script, run_dir = _drive_tool(tmp_path, disposition="totally-benign")

    seen = "\n".join(script.seen)
    assert "disposition must be exactly one of" in seen, (
        f"the model was never told why its close was refused. Saw: {seen!r}"
    )
    assert never_closed(run_dir), (
        "an out-of-vocabulary disposition committed a report through the tool lane"
    )


def test_a_member_of_the_vocabulary_commits_through_the_tool_lane(tmp_path):
    """The positive control for the tool-lane refusal, on that same lane."""
    script, run_dir = _drive_tool(tmp_path, disposition="inconclusive")

    seen = "\n".join(script.seen)
    assert "disposition must be exactly one of" not in seen, (
        f"a member of the vocabulary was refused on the tool lane. Saw: {seen!r}"
    )
    assert is_closed(run_dir), "a valid disposition did not commit through the tool lane"
    assert closing_record(run_dir).disposition == "inconclusive"


# The refusal distinguishes an invisible character from a valid value.


def test_the_refusal_escapes_an_invisible_character_rather_than_echoing_it(tmp_path):
    """`beni<U+200B>gn` comes back repr-escaped, on both lanes (#722)."""
    deps, run_dir = _deps(tmp_path)

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, LACED, stages=_stages())
    message = str(excinfo.value)

    assert repr(LACED) == "'beni\\u200bgn'", (
        "python's repr no longer escapes U+200B, so the assertions below test the wrong thing"
    )
    assert "'beni\\u200bgn'" in message, (
        f"the refusal does not show the invisible character: {message!r}"
    )
    assert LACED not in message, (
        "the refusal echoes the laced value raw, so the model reads its own rejected answer "
        f"as identical to a valid one: {message!r}"
    )
    assert never_closed(run_dir)

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
    assert never_closed(tool_run_dir)


# The close's two writes (review record, report) are both attempted; only the report's fault is the close's (#1342 r4 M2, r5).


def _a_directory_where_the_review_record_goes(run_dir: Path) -> Path:
    from defender.records import RunPaths

    planted = RunPaths(run_dir).review_record(1)
    planted.mkdir(parents=True)
    return planted


def _warned_about_turn_1(caplog) -> list[str]:
    """Log records at WARNING or above whose message names turn 1 (D-x: the wording is free, the level and the turn are not)."""
    import logging
    import re

    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and re.search(r"turn\W*1\b", r.getMessage(), re.IGNORECASE)]




def test_a_refused_close_is_the_closes_refusal_whatever_the_record_write_did(tmp_path):
    """The close's gate refuses the document and the review record cannot be written either: the model is told the very
    message a close with a healthy record gives, and nothing of the record's fault. (M2; the report validator is retired, #1534)"""
    from defender.tests.support.runtime.engine._spec923 import gapless

    healthy_deps, healthy_dir = _deps(tmp_path / "healthy")
    (healthy_dir / "investigation.md").write_text(gapless(), encoding="utf-8")
    with pytest.raises(ModelRetry) as healthy:
        close_investigation(healthy_deps, "inconclusive", stages=_stages())

    deps, run_dir = _deps(tmp_path / "faulty")
    (run_dir / "investigation.md").write_text(gapless(), encoding="utf-8")
    record = _a_directory_where_the_review_record_goes(run_dir)
    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, "inconclusive", stages=_stages())

    message = str(excinfo.value)
    assert "close blocked" in message, f"fixture control: the gate refused the document: {message!r}"
    assert message == str(healthy.value), f"the record's fault changed what the model was told: {message!r}"
    assert record.name not in message
    assert never_closed(run_dir)


def test_a_closing_record_the_close_wrote_stays_final_when_the_review_record_write_failed(tmp_path):
    """The closing record commits and the review record cannot be written: the close stands, so a second close is refused as already closed and neither the closing record nor the review record is touched. (M2: terminality follows the closing record alone)"""
    deps, run_dir = _deps(tmp_path)
    record = _a_directory_where_the_review_record_goes(run_dir)
    close_investigation(deps, "inconclusive", stages=_stages())
    committed = closing_record(run_dir)
    assert committed.disposition == "inconclusive"

    with pytest.raises(ModelRetry) as excinfo:
        close_investigation(deps, "benign", stages=_stages())

    assert "already closed" in str(excinfo.value), f"a second close was not refused as a closed one: {excinfo.value!s}"
    assert closing_record(run_dir) == committed, "the second close overwrote the committed record"
    assert record.is_dir(), "the second close replaced the directory in the record's place"
    assert not any(record.iterdir()), "the second close wrote the review record"


def test_a_closing_record_that_cannot_be_written_is_the_error_raised_not_the_review_records(tmp_path, caplog):
    """Both writes fail (a row already stands for the run): the error raised is the closing record's, not the review record's, and the lost record is still logged at WARNING or above naming its turn. (M2, D-x)"""
    import logging

    from defender.records.session_store import ClosingRecordExists

    deps, run_dir = _deps(tmp_path)
    record = _a_directory_where_the_review_record_goes(run_dir)
    V.plant(deps.session_store, V.a_record(run_dir.name))

    with caplog.at_level(logging.INFO), pytest.raises(ClosingRecordExists) as excinfo:
        close_investigation(deps, "inconclusive", stages=_stages())

    assert record.name not in str(excinfo.value), f"the record's fault was raised: {excinfo.value!r}"
    assert _warned_about_turn_1(caplog), "the lost review record was not logged (WARNING or above, naming turn 1) when the closing record failed too"


def test_a_review_record_that_cannot_be_written_is_logged_at_warning_or_above_naming_its_turn_and_the_close_stands(
        tmp_path, caplog):
    """The report commits but the review record cannot be written: no raise, the close stands, and a record at WARNING or above names the turn whose record was lost. (M2, D-x)"""
    import logging

    deps, run_dir = _deps(tmp_path)
    _a_directory_where_the_review_record_goes(run_dir)

    with caplog.at_level(logging.INFO):
        result = close_investigation(deps, "inconclusive", stages=_stages())

    assert is_closed(run_dir)
    assert result.record_path is None
    assert _warned_about_turn_1(caplog), \
        f"nothing at WARNING or above names the turn whose record was lost: {[r.getMessage() for r in caplog.records]}"


def test_a_review_record_that_is_written_logs_no_record_fault_warning(tmp_path, caplog):
    """Control for the record-fault log: a close whose record lands logs no record-fault warning (nothing at WARNING or above naming the turn). (M2, D-x)"""
    import logging

    deps, run_dir = _deps(tmp_path)

    with caplog.at_level(logging.INFO):
        close_investigation(deps, "inconclusive", stages=_stages())

    assert is_closed(run_dir)
    assert _warned_about_turn_1(caplog) == []
