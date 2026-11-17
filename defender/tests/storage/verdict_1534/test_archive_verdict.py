"""#1534 sketch: archived worlds' verdicts are read from the source lineage's database through the episode's arm roster,
keyed by each arm's run id; the archive copies no `report.md` (OD5, Flows "Learning: archived worlds").

Entry: the judge's one entry (`_judge_921.grade` -> `learning.judge.grade_episode`) over `accepted_episode`, with an arm
roster, the arms' session pointers and one shared database planted beside it (the fixture builds none)."""
from __future__ import annotations

from pathlib import Path

from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.judge import _judge_921 as J

DECLARED = {"a": "benign", "b": "malicious", "c": "malicious"}


def _with_arm_verdicts(ep: Path, tmp_path: Path, verdicts: dict[str, str | None], **row: str) -> dict[str, str]:
    """The episode's roster (world UUID -> arm id) and one shared source database, shaped as a branch leaves it: the
    source's main session holding one response, one fork per arm, and each arm's pointer naming the database and its
    fork (the route `job_entry._family_cost` reads). A verdict row per label in `verdicts` (`None`: no row), `row`
    passed to every row. Every archived `report.md` removed. Returns label -> arm id."""
    from defender.records import Run
    from defender.records import session_store as ss
    from defender.tests.storage.ids_1187 import _spec1187 as R
    from defender.tests.support.jobs._jobs1342 import _response
    from defender.tests.support.shared._locations_1210 import fixture_runs_base

    arms = {label: R.new_id() for label in DECLARED}
    (ep / "runs").mkdir(exist_ok=True)
    R.write_roster(ep, {T.world_id(ep, label): arm for label, arm in arms.items()})
    with V.run_store(tmp_path / "source-runs", "verdict-1534-source") as store:
        main = store.new_session(agent_id="main")
        at = store.append(main, _response("claude-sonnet-4-6", {"input_tokens": 1}), agent_id="main")[-1]
        for label, arm in arms.items():
            (ep / "runs" / arm).mkdir()
            fork = store.fork(main, at)
            ss.write_case_pointer(Run.under(fixture_runs_base(ep / "runs"), arm), case_id=store.case_id,
                                  store_path=store.path, session_id=fork)
            (ep / "worlds" / T.world_id(ep, label) / "report.md").unlink(missing_ok=True)
        database = Path(store.path)
    for label, disposition in verdicts.items():
        if disposition is not None:
            V.plant_verdict(database, arms[label], disposition=disposition, **row)
    return arms


def test_od5_the_judge_reads_each_worlds_verdict_through_the_roster(tmp_path):
    """Each graded world's verdict is its arm's record in the shared database; no archived report is read. (OD5)"""
    ep = J.accepted_episode(tmp_path, dispositions=DECLARED)
    _with_arm_verdicts(ep, tmp_path, {"a": "benign", "b": "malicious", "c": "benign"})

    rows = J.rows(J.grade(ep))
    assert {label: rows[label].get("verdict") for label in ("b", "c")} == {"b": "malicious", "c": "benign"}
    assert not any(rows[label].get("ungradable") for label in ("b", "c")), rows


def test_od5_a_world_whose_arm_has_no_record_is_refused_as_an_unreadable_verdict(tmp_path):
    """An arm with no record: that world is not graded, as a world with no archived report is not today. (OD5, V-READ)"""
    ep = J.accepted_episode(tmp_path, dispositions=DECLARED)
    _with_arm_verdicts(ep, tmp_path, {"a": "benign", "b": "malicious", "c": None})

    rows = J.rows(J.grade(ep))
    assert rows["b"].get("verdict") == "malicious", rows["b"]
    assert not rows["b"].get("ungradable"), rows["b"]
    assert rows["c"].get("ungradable") is True, rows["c"]
    # FORCED CHOICE: the tier. Today a missing report is `ungradable` (missing input) and a headless one `malformed`;
    # the design says only "refuses".
    assert "verdict" in str(rows["c"].get("ungradable_reason")), rows["c"]


def test_od7_the_judge_prompt_carries_the_records_fields_and_not_the_summary(tmp_path):
    """The world's verdict reaches the judge as a host rendering of the record's fields (its cause sentence included),
    never the summary. World b's record differs from its declared disposition, so the manifest cannot answer. (OD7)"""
    cause = "the evidence gathered cannot discriminate what the challenge review left unsettled"
    ep = J.accepted_episode(tmp_path, dispositions=DECLARED)
    _with_arm_verdicts(ep, tmp_path, {"a": "benign", "b": "unresolved", "c": "malicious"},
                       outcome="forced-inconclusive", cause=cause)

    # FORCED CHOICE: the standalone render is handed only the episode's bound reader (`render.py:388,421`); how it
    # reaches the roster is open. Driven here through the run module's own assembler, as `test_render._world_prompt`.
    ctx = J.render_at(ep, "b")
    prompt = J.mod("learning.judge.run")._build_prompt(ctx, J.read_manifest_at(ep))[0]
    assert cause in prompt, "the record's cause did not reach the judge"
    assert "sudo chain" not in prompt, "the verdict's summary reached the judge prompt (OD7)"
    assert "report.md" not in prompt  # lint-run-records: ok — a test oracle
