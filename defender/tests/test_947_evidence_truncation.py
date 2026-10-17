"""#947 Part C, re-seated on #1255's branch point (D1) — an arm holds the evidence its branch
point names, and nothing past it.

#920 gave a sibling the source run's whole evidence; #947 cut it BY LEAD: `branch.leads_at`
answered which gather leads existed at the branch point, and a census of three sources (the
queries table, `gather_raw/`, `gather_summaries/`) plus a pending-dispatch bookkeeping of the
source's MAIN conversation decided which files crossed. The property was always the same one:
the source ran ON past the fork, its later leads carry the answers the pair exists to not
share, and an arm that holds them is measuring agreement with the source's conclusion rather
than a difference from it.

#1255 (design rev 4, "Fork snapshot", P2) REPLACES THE MECHANISM, not the property: "This
replaces today's per-file cut rules (fence counting, lead selection)." The host records what
the run holds when each MAIN response arrives (append-only files by length, rewritable by
content, write-once by hash), and an arm restores that. Nothing decides which LEADS cross any
more, so the eleven tests that pinned `leads_at`'s answers and the pending-dispatch rules
behind it are retired (listed below). The tests kept here are the ones about what the arm ends
up holding, driven as the design has it: on a REAL source run (the fork snapshot is whatever
production wrote while it ran, `_1255_snapshot.drive_source`) and a branch point that is a
tool-calling MAIN response (D1). Expected red today (class a): such a branch point is refused
by `branch.validate`.

WHAT THESE ARE EVIDENCE FOR (recheck review RC-L3): all ten tests are REGRESSIONS OVER D1, not
evidence for the snapshot (P2). Today's lead-cut copy gives an arm the same holdings, so a
D1-only lift passes every one of them: they pin the property (no later lead's evidence, the
source left whole, no account of the source's own run, a link refused rather than followed),
not the mechanism that keeps it. What only the snapshot can show is
`e2e/test_1255_snapshot_restore.py`'s.

RETIRED, and where each property now lives
------------------------------------------
Every `leads_at` test stood on a store row hand-written by `_branch_947.legal_source`: a run
with no fork snapshot is the pre-#1255 shape, which N4 refuses at launch, so none of them can
reach its assertion once the change lands.

* `test_a_lead_counts_from_the_turn_its_dispatch_returned` (3 cases),
  `test_a_dispatch_still_in_flight_at_the_branch_claims_nothing`,
  `test_a_lead_dispatched_but_never_answered_is_never_inherited`,
  `test_a_refusal_clears_the_claim_before_any_later_return_can_pop_it`,
  `test_a_refused_retry_does_not_remove_an_inherited_undispatched_lead`,
  `test_a_refused_dispatch_does_not_land_for_whoever_reuses_its_call_id`,
  `test_a_dispatch_counts_however_the_provider_spelled_its_arguments` (2 cases): the dispatch
  bookkeeping that decided WHICH LEADS had landed. The snapshot is taken when a response
  arrives, so "which leads existed" is whatever the run had written then; there is no
  bookkeeping to get wrong. Where the branch point falls on a dispatch is D1's re-run rule:
  `e2e/test_1255_snapshot_branch_point.py` (a gather call at the branch turn is re-run, never
  inherited).
* `test_a_lead_no_dispatch_accounts_for_survives_every_branch_point`,
  `test_a_lead_named_only_by_a_table_row_still_crosses`,
  `test_a_lead_claimed_without_a_captured_row_still_crosses`,
  `test_a_lead_known_only_by_its_summary_still_crosses`: the "leads no dispatch accounts for"
  fallback (lead-0's reserved ids, a payload-less row, a claim-only lead, a summary-only lead).
  Each crossed because a census of three sources said so; the snapshot restores every file the
  run held by its recorded length or hash whoever wrote it. The lead-0 half is
  `e2e/test_1255_snapshot_restore.py::test_p2_append_only_and_write_once_files_are_restored_up_to_the_cut`
  (the correlation lead's rows, claim, summary and payload byte for byte), and
  `e2e/test_920_branch_resume.py` (a resumed run does not redo turn-0 work).
* `test_the_inherited_table_keeps_the_order_the_source_wrote_it_in`: order was a hazard of
  grouping rows by lead; the table is now cut to a recorded length, which cannot reorder.
  `test_p2_append_only_…` asserts the arm's table OPENS on the source's rows through the cut.
* `test_the_alert_is_inherited_verbatim` and
  `test_a_sibling_that_already_has_its_alert_is_not_refused_as_seeded`: since #1222 the front
  door places the alert at the sibling's setup from the episode's copy and the resume seeder
  does not rewrite it (`alert_front_door_1222/test_1222_alert_place.py::test_p152_…`); every arm
  `_1255_snapshot.drive_arm` launches already has its alert in its folder.
* `test_the_sibling_does_not_inherit_the_source_runs_own_account_of_itself`, three of its eight
  cases: `policy_denials.jsonl`, `lessons_loaded.jsonl` and `review_record.1.json` are now
  RESTORED up to the cut (P2 reverses G7 and G16): `test_1255_snapshot_restore`'s p2 and D2
  tests assert it. The other five stay below.

The property each retired test shared, "a later lead's evidence does not reach the arm", is
`test_the_arm_holds_the_leads_the_branch_point_held_and_no_later_one` below.
"""
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
    assert isinstance(message, ModelResponse) and S.calls_of(message), "the branch point moved"
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
    """Regression over D1 (the successor of `test_the_sibling_inherits_the_leads_the_branch_
    point_held_and_no_later_one` and the `leads_at` family): the arm's queries table, payload
    tree, claims and summaries carry the branch point's leads only. The source ran on to
    dispatch `l-002` after
    the branch point (`echo x`); the arm, which dispatches nothing, holds none of it.

    All of a lead's artifacts together, because they are one lead: a table row whose payload is
    missing reads to every offline reader as a payload this episode LOST, and a payload with no
    row behind it is evidence no reader joins.

    Positive control, same arm: it holds the early lead's row, payload, claim and summary and
    the correlation lead's row — and the SOURCE holds the late lead's, so its absence from the
    arm is the cut's, not a script that never produced it."""
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
    """Restoring happens in the ARM's folder: the source keeps every file it ever wrote, byte
    for byte. COPIED, never moved or shared — the source is the base of the comparison, and an
    arm that edited it would make the pair's control depend on how many arms ran against it.

    Positive control: the arm launched and made its own call, and the source folder holds the
    late lead the arm does not."""
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


#: Where each artifact lives, by the repository's own layout (never a spelled path). The two
#: counters are the exception: no run writes them since #1235, so there is no accessor — the
#: old names are spelled, and that is the point (a STRAY file at a name a reader once trusted).
ACCOUNTS = {
    "report": lambda paths: paths.report,
    "tool trace": lambda paths: paths.tool_trace,
    "wire log": lambda paths: paths.wire_log,
    "budget.json": lambda paths: paths.report.parent / "budget.json",
    "circuit_breaker.json": lambda paths: paths.report.parent / "circuit_breaker.json",
}


@pytest.mark.parametrize("artifact", sorted(ACCOUNTS))
def test_the_arm_does_not_inherit_the_source_runs_own_account_of_itself(tmp_path, artifact):
    """Nothing that records how the SOURCE run went crosses to the arm.

    `report.md` is the source's disposition — inherited, it hands the arm the answer the pair
    exists to not share. The counters (`budget.json`, `circuit_breaker.json`) are the source's
    spend and fault tallies (since #1235 they live in memory and no run writes them, so this
    plants a stray file at the old name; since #1255 the arm's counters are RESTORED from the
    fork snapshot, never read from a file). The wire log is MAIN's whole transcript plus every
    gather payload verbatim, unreadable to the agents of its own run; and `tool_trace.jsonl` is
    the projection the visualizer reads, which would render one run's trace under another's id.

    The arm RUNS now (so it writes a trace and a wire log of its own): the assertion is that
    the source's planted text is nowhere in the arm's folder. Positive control: the marker is in
    the source's file, and the arm reached its model."""
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
    """A source artifact that is a LINK is refused at launch, loudly, and its target's bytes
    never reach the arm under that name.

    A real hazard: the run folder is the box's rw bind, so a link at an artifact's name is
    something the model wrote. A plain copy writes the TARGET's bytes into the arm under the
    artifact's name, where the resumed model, the offline readers and every later gate take
    them for in-run evidence. REFUSED, NOT SKIPPED: an arm silently missing the evidence its own
    history names reads as a run that gathered nothing — the same shape as the branch working.
    The refusal is a `BranchError` that names the artifact (as the pre-#1255 test's
    `pytest.raises(BranchError, match=<name>)` did): today that is the lstat-based copy's, after
    #1255 the restore's ("a restore that does not match refuses the arm at launch").

    Positive control on the same source and branch point: before the link is planted an arm
    launches."""
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
