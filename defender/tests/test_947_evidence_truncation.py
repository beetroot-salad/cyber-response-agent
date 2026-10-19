from __future__ import annotations

import logging

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelResponse  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender.tests import _1255_snapshot as S  # noqa: E402
from defender.tests.e2e._replay_harness import Turn  # noqa: E402

pytestmark = pytest.mark.e2e

CHUNKS = S.chunks(3)

#: The source's second lead: dispatched AFTER the branch point, so it is the evidence the arm
#: must not hold.
EARLY, LATE = "l-001", "l-002"


def _lead(lead: str) -> tuple[Turn, Turn]:
    """A gather lead that makes one real query (so it leaves a table row, a payload, a claim and
    a summary under its own id) and reports."""
    return (Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                        "params": {"native_query": f"user.name:{lead}"}})]),
            Turn(text=f"{lead}: measured"))


def _source(tmp_path) -> tuple[S.Driven, int]:
    """A real source: one fence, an early lead, an inert call (the branch point), a late lead.
    Returns it and the row of the inert call's MAIN response."""
    source = S.drive_source(
        tmp_path, (S.append(CHUNKS[0]), S.dispatch(EARLY), S.echo("x"), S.dispatch(LATE),
                   S.done()),
        leads={EARLY: _lead(EARLY), LATE: _lead(LATE)})
    point = S.tool_calling_responses(source.store)[2]  # `echo x`
    message = S.message_at(source.store, point)
    assert isinstance(message, ModelResponse), "the branch point moved"
    assert S.calls_of(message), "the branch point moved"
    return source, point


def _rows(run) -> set[str]:
    return {r["lead_id"] for r in read_jsonl_rows(run.paths.executed_queries)}


def _files(root) -> dict[str, bytes]:
    """Every regular file under `root`, by relative path (links are not followed)."""
    return {str(p.relative_to(root)): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def _launched(arm: S.Driven) -> None:
    refused = S.refused_at_launch(arm)
    assert refused is None, (
        f"the arm was refused at launch ({refused}) — the source was driven (so it has its fork "
        "snapshot) and the branch point is a tool-calling MAIN response outside any retry streak")


def test_the_arm_holds_the_leads_the_branch_point_held_and_no_later_one(tmp_path):
    source, point = _source(tmp_path)
    assert {EARLY, LATE, S.CORRELATION_LEAD} <= _rows(source), (
        f"the source's table does not hold all three leads: {_rows(source)}")
    for lead in (EARLY, LATE):
        assert source.paths.payload(lead, 0).exists(), f"the source has no payload for {lead}"

    arm = S.drive_arm(tmp_path, S.spec_for(source, point), S.Recorder([S.done()]))

    _launched(arm)
    assert _rows(arm) == {S.CORRELATION_LEAD, EARLY}, (
        f"the arm's table holds {_rows(arm)}; the branch point held the correlation lead and "
        f"{EARLY} only")
    for artifact in (arm.paths.payload(EARLY, 0), arm.paths.lead_claim(EARLY),
                     arm.paths.gather_summary(EARLY)):
        assert artifact.exists(), f"the arm lost the early lead's {artifact.name}"
    for artifact in (arm.paths.payload(LATE, 0), arm.paths.lead_claim(LATE),
                     arm.paths.gather_summary(LATE)):
        assert not artifact.exists(), (
            f"the source's later lead reached the arm: {artifact.name} — it holds the answers "
            "the pair exists to not share")


def test_the_source_runs_own_evidence_is_left_whole(tmp_path):
    source, point = _source(tmp_path)
    before = _files(source.run_dir)
    assert source.paths.payload(LATE, 0).exists()

    arm = S.drive_arm(tmp_path, S.spec_for(source, point),
                      S.Recorder([S.echo("arm-only"), S.done()]))

    _launched(arm)
    assert arm.main.calls >= 2, "the arm did not run its own script"
    assert _files(source.run_dir) == before, "the arm changed files in the SOURCE's run folder"


#: A marker no honest file holds: planted in the source's account of itself, it must not turn up
#: anywhere in the arm's folder.
ACCOUNT = "the source run's own account\n"


ACCOUNTS = {
    "report": lambda paths: paths.report,
    "tool trace": lambda paths: paths.tool_trace,
    "wire log": lambda paths: paths.wire_log,
    "budget.json": lambda paths: paths.report.parent / "budget.json",
    "circuit_breaker.json": lambda paths: paths.report.parent / "circuit_breaker.json",
}


@pytest.mark.parametrize("artifact", sorted(ACCOUNTS))
def test_the_arm_does_not_inherit_the_source_runs_own_account_of_itself(tmp_path, artifact):
    source, point = _source(tmp_path)
    planted = ACCOUNTS[artifact](source.paths)
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text(ACCOUNT, encoding="utf-8")
    assert ACCOUNT in planted.read_text(encoding="utf-8")

    arm = S.drive_arm(tmp_path, S.spec_for(source, point), S.Recorder([S.done()]))

    _launched(arm)
    holders = [name for name, data in _files(arm.run_dir).items() if ACCOUNT.encode() in data]
    assert holders == [], (
        f"the arm inherited the source's {artifact} (found in {holders}) — its own record of "
        "its own run now opens with another run's")


LINKABLE = {
    "queries table": lambda paths: paths.executed_queries,
    "gather_raw": lambda paths: paths.gather_raw,
    "gather_summaries": lambda paths: paths.gather_summaries,
}


@pytest.mark.parametrize("name", sorted(LINKABLE))
def test_a_link_wearing_an_artifacts_name_is_refused_rather_than_followed(tmp_path, caplog, name):
    source, point = _source(tmp_path)
    spec = S.spec_for(source, point)
    _launched(S.drive_arm(tmp_path, spec, S.Recorder([S.done()]), name="control",
                          run_id="control-1255"))

    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "0.json").write_text('{"owner": "not this run"}', encoding="utf-8")
    secret_file = tmp_path / "secret.jsonl"
    secret_file.write_text('{"lead_id": "l-999", "seq": 0, "owner": "not this run"}\n',
                           encoding="utf-8")
    target = LINKABLE[name](source.paths)
    if target.is_dir():
        import shutil
        shutil.rmtree(target)
    else:
        target.unlink()
    target.symlink_to(secret if name != "queries table" else secret_file)
    caplog.clear()  # the control's own lines (today: its D1 refusal) are not this arm's
    caplog.set_level(logging.INFO)

    arm = S.drive_arm(tmp_path, spec, S.Recorder([S.done()]), name="linked", run_id="linked-1255")

    assert S.refused_at_launch(arm) is not None, (
        f"an arm was launched over a source whose {name} is a link out of the run folder")
    assert arm.summary.get("exit_reason") == "BranchError", arm.summary
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(target.name in line for line in errors), (
        f"the refusal does not name the linked artifact `{target.name}`: {errors}")
    assert b"not this run" not in b"".join(_files(arm.run_dir).values()), (
        "the link's target crossed into the arm wearing an artifact's name")
