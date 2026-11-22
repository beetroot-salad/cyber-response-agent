"""#1546 PR9: `decide(facts, uploads, ended_by)` is pure and total over the closed `ended_by` members; its evidence state
follows r8's rules 1-7 over every generated combination, `complete` implies `clean`, only the applier's inputs are
promoted, `lesser` re-derives. No database: the store cases are in `test_ending_apply_1546.py`."""
from __future__ import annotations

import dataclasses
import itertools
from typing import Any

import pytest

from defender.tests.support.jobs._ending1546 import (
    BUNDLE,
    EPISODE_PAGE,
    ENDED_BY,
    KNOWLEDGE,
    PENDING,
    REFUSED,
    RUN_PAGE,
    STARTED,
    UP,
    arm_page,
    closing_found,
    decide,
    findings_screened,
    inv_outcome,
    learning_outcome,
    refused,
    up,
)

ARM = "11111111-1111-4111-8111-111111111111"
STATES = {"complete", "partial", "none", "lost"}
KEEPS = {"complete", "partial", "lost"}  # the states whose uploaded rows are promoted

# Outcome classes of an investigation: (facts of the outcome, decided, ends completed when run to its end).
INV_CLASSES: dict[str, tuple[dict[str, Any], bool, bool]] = {
    "none": ({}, False, False),
    "refused": (refused("outcome"), False, False),
    "complete_clean": ({"outcome": inv_outcome()}, True, True),
    "tainted": ({"outcome": inv_outcome(scrub="tainted")}, True, False),
    "not_run_after_close": ({"outcome": inv_outcome(scrub="not_run")}, False, False),
    "no_report": ({"outcome": inv_outcome(report_committed=False, closing=None, scrub="not_run")}, False, False),
    "setup_refused": ({"outcome": inv_outcome(setup="refused", box="not_started", report_committed=False, closing=None,
                                              scrub="not_run")}, True, False),
    "unparseable": ({"outcome": inv_outcome(closing={"found": "could_not_look", "wording": "unreadable"})}, True, False),
}
LEARN_CLASSES: dict[str, tuple[dict[str, Any], bool, bool]] = {
    "none": ({}, False, False),
    "refused": (refused("outcome"), False, False),
    "completed": ({"outcome": learning_outcome()}, True, True),
    "completed_findings_refused": ({"outcome": learning_outcome(findings={"state": "refused", "reason": "x"})}, True, True),
    "failed": ({"outcome": learning_outcome("failed", reason="entry_error")}, True, False),
    "stopped": ({"outcome": learning_outcome("stopped")}, False, False),
}
#: Whether the run's own outcome decides the stage on this ending (the others end it themselves, or fall back).
OUTCOME_COUNTS = ("exited", "exited_failed", "stopped", "lapsed", "not_launched")


def expected_state(by: str, started: bool, decided: bool, completed: bool, bundle_up: bool, all_up: bool) -> str:
    """r8 "Evidence state", first match wins, over class labels (not over facts)."""
    if not started:
        return "none"
    if by in ("cancelled", "offboarded", "expired_in_queue"):
        return "none"
    if by == "lapsed" and not decided:
        return "none"
    if completed and all_up:
        return "complete"
    if completed:
        return "lost"
    return "partial" if bundle_up else "none"


def investigation_cases():
    for by, started, oc, bundle, page_fact, page_up in itertools.product(
            [b for b in ENDED_BY if b != "expired_in_queue"], (True, False), INV_CLASSES, (UP, PENDING, REFUSED, None),
            ("rendered", "render_failed", "none", None), (UP, PENDING, REFUSED, None)):
        yield by, started, oc, bundle, page_fact, page_up


def _inv_input(started, oc, bundle, page_fact, page_up):
    facts: dict[str, Any] = {"knowledge": KNOWLEDGE, **INV_CLASSES[oc][0]}
    if started:
        facts["started"] = STARTED
    if page_fact:
        facts["page"] = {"page": page_fact}
    uploads = {name: up(st) for name, st in ((BUNDLE, bundle), (RUN_PAGE, page_up)) if st}
    return facts, uploads


def _check_end(got, by, started, decided, completed, uploads, owed):
    if by == "stopped" and not decided:
        assert type(got).__name__ == "HandBack"
        return
    assert type(got).__name__ == "End", (by, got)
    bundle_up = uploads.get(BUNDLE, {}).get("status") == UP
    all_up = all(uploads.get(o, {}).get("status") == UP for o in owed)
    stage_completed = completed and by in OUTCOME_COUNTS and by != "not_launched"
    if stage_completed:
        assert got.stage == "completed", (by, got.stage)
    want = expected_state(by, started, decided, stage_completed, bundle_up, all_up)
    assert got.evidence_state == want, (by, started, uploads, got.stage)
    uploaded = {o for o, u in uploads.items() if u["status"] == UP}
    assert set(got.promote) == (uploaded if want in KEEPS else set())
    assert got.follow_ons.auto_learning_job is (want == "complete")
    if want == "complete":
        assert got.stage == "completed"


@pytest.mark.parametrize("by", [b for b in ENDED_BY if b != "expired_in_queue"])
def test_the_investigation_evidence_state_follows_rules_one_to_seven_over_every_combination(by):
    """Every ended_by x started x outcome class x upload status yields exactly one state per the table, promoting
    exactly the uploaded rows when kept, and `complete` implies a `clean` completed run. (PR9, A-O4, A-O3)"""
    seen = 0
    for by_, started, oc, bundle, page_fact, page_up in investigation_cases():
        if by_ != by:
            continue
        facts, uploads = _inv_input(started, oc, bundle, page_fact, page_up)
        owed = [BUNDLE] + ([RUN_PAGE] if page_fact == "rendered" else [])
        got = decide("investigation", facts, uploads, by)
        _, decided, completed = INV_CLASSES[oc]
        _check_end(got, by, started, decided, completed, uploads, owed)
        if getattr(got, "evidence_state", None) == "complete":
            assert got.scrub == "clean"
        seen += 1
    assert seen == 2 * len(INV_CLASSES) * 4 * 4 * 4


def learning_cases():
    for by, started, oc, bundle, episode, arm_fact, arm_up in itertools.product(
            ENDED_BY, (True, False), LEARN_CLASSES, (UP, PENDING, None), (UP, REFUSED, None),
            ("rendered", "render_failed", None), (UP, PENDING, None)):
        yield by, started, oc, bundle, episode, arm_fact, arm_up


@pytest.mark.parametrize("by", ENDED_BY)
def test_the_learning_evidence_state_follows_the_rules_with_a_page_owed_per_rendered_arm(by):
    """The learning job's must-push set is its bundle, episode page and the page of each `arm/<id>` fact that
    rendered; the same rules and promotion apply. (PR8, PR9, A-O4)"""
    for by_, started, oc, bundle, episode, arm_fact, arm_up in learning_cases():
        if by_ != by:
            continue
        facts: dict[str, Any] = {"arms": {"roster": [{"run_id": ARM}]}, **LEARN_CLASSES[oc][0]}
        if started:
            facts["started"] = STARTED
        if arm_fact:
            facts[f"arm/{ARM}"] = {"scrub": "clean", "page": arm_fact}
        uploads = {n: up(s) for n, s in ((BUNDLE, bundle), (EPISODE_PAGE, episode), (arm_page(ARM), arm_up)) if s}
        owed = [BUNDLE, EPISODE_PAGE] + ([arm_page(ARM)] if arm_fact == "rendered" else [])
        _, decided, completed = LEARN_CLASSES[oc]
        got = decide("learning", facts, uploads, by)
        _check_end(got, by, started, decided, completed, uploads, owed)


def test_a_complete_run_is_the_only_end_that_queues_the_auto_learning_job_and_a_completed_verdict_sets_the_alert_outcome():
    """Follow-ons are values: the auto learning job only when `complete`; the alert outcome with a completed verdict even
    when its evidence is `lost`; neither for a failed end. (PR9)"""
    facts, ups = _inv_input(True, "complete_clean", UP, "rendered", UP)
    full = decide("investigation", facts, ups, "exited")
    lost = decide("investigation", facts, {BUNDLE: up(UP), RUN_PAGE: up(REFUSED)}, "exited")
    tainted = decide("investigation", *_inv_input(True, "tainted", UP, "rendered", UP), "exited")
    assert (full.evidence_state, full.follow_ons.auto_learning_job, full.follow_ons.alert_outcome) == ("complete", True, True)
    assert (lost.evidence_state, lost.follow_ons.auto_learning_job, lost.follow_ons.alert_outcome) == ("lost", False, True)
    assert (tainted.follow_ons.auto_learning_job, tainted.follow_ons.alert_outcome) == (False, False)


@pytest.mark.parametrize("by", ["offboarded", "cancelled", "not_launched"])
def test_an_ending_before_or_around_the_run_ends_by_its_own_words_and_reads_none(by):
    """Cancel and offboard abort (their reasons), never reach the run's outcome, and leave `none`; not launched fails
    `worker_error`. (PR9, rule 2)"""
    facts, ups = _inv_input(True, "complete_clean", UP, "rendered", UP)
    got = decide("investigation", facts, ups, by)
    want = {"cancelled": ("aborted", "cancelled"), "offboarded": ("aborted", "tenant_offboarded"),
            "not_launched": ("failed", "worker_error")}[by]
    assert (got.stage, got.failure_reason) == want
    assert got.disposition is None
    if by != "not_launched":
        assert (got.evidence_state, set(got.promote)) == ("none", set())


@pytest.mark.parametrize(("oc", "by", "stage", "reason", "disposition", "scrub"), [
    ("complete_clean", "exited", "completed", None, "benign", "clean"),
    ("tainted", "exited", "failed", "no_report", None, "tainted"),
    ("not_run_after_close", "exited", "failed", "no_report", None, "not_run"),
    ("no_report", "exited", "failed", "no_report", None, "not_run"),
    ("setup_refused", "exited", "failed", "setup_refused", None, "not_run"),
    ("unparseable", "exited", "unparseable", None, None, "clean"),
    ("none", "exited", "failed", "no_report", None, "not_run"),
    ("none", "exited_failed", "failed", "worker_error", None, "not_run"),
    ("refused", "exited", "failed", "bad_record", None, "not_run"),
    ("complete_clean", "lapsed", "completed", None, "benign", "clean"),
    ("tainted", "lapsed", "failed", "no_report", None, "tainted"),
    ("none", "lapsed", "failed", "lease_lapsed", None, "not_run"),
    ("no_report", "lapsed", "failed", "lease_lapsed", None, "not_run"),
    ("complete_clean", "stopped", "completed", None, "benign", "clean"),
])
def test_the_stage_is_todays_rules_reading_scrub_clean_and_a_decided_verdict_survives_a_take_over(
        oc, by, stage, reason, disposition, scrub):
    """Stage rules: a tainted run is `failed/no_report` saying why in `scrub`; a decided verdict is kept on take-over,
    an undecided one lapses; a refused outcome is `bad_record`, never decided. (Stage, D8, D9)"""
    facts, ups = _inv_input(True, oc, UP, "rendered" if oc == "complete_clean" else None, UP)
    got = decide("investigation", facts, ups, by)
    assert (got.stage, got.failure_reason, got.disposition, got.scrub) == (stage, reason, disposition, scrub)


def test_a_found_closing_record_gives_its_disposition_whatever_it_is():
    """The disposition is the outcome's closing record's (every vocabulary word), not a fixed one. (Stage)"""
    from defender._vocab import DISPOSITION_VALUES

    for word in DISPOSITION_VALUES:
        facts, ups = _inv_input(True, "complete_clean", UP, "rendered", UP)
        facts["outcome"] = inv_outcome(closing=closing_found(word))
        assert decide("investigation", facts, ups, "exited").disposition == word


def test_a_never_closed_or_unreadable_record_after_a_committed_close_is_unparseable():
    """`never_closed` and `could_not_look` end `unparseable`. (Stage)"""
    for found in ({"found": "never_closed"}, {"found": "could_not_look", "wording": "w"}):
        facts, ups = _inv_input(True, "complete_clean", UP, "rendered", UP)
        facts["outcome"] = inv_outcome(closing=found)
        assert decide("investigation", facts, ups, "exited").stage == "unparseable"


@pytest.mark.parametrize("by", ["cancelled", "lapsed", "offboarded"])
def test_a_cost_after_a_cancel_offboard_or_take_over_is_the_last_staged_progress_marked_a_lower_limit(by):
    """D15: not the outcome's figure; the last `progress` and the lower-limit mark. After a normal exit, the outcome's
    figure with its own mark. (D15)"""
    facts, ups = _inv_input(True, "complete_clean", UP, "rendered", UP)
    facts["progress"] = {"cost_usd": 0.17}
    cut = decide("investigation", facts, ups, by)
    assert (cut.cost_usd, cut.cost_is_lower_limit) == (0.17, True)
    done = decide("investigation", facts, ups, "exited")
    assert (done.cost_usd, done.cost_is_lower_limit) == (0.42, False)


def test_a_learning_cost_after_take_over_is_its_last_staged_sibling_cost_as_a_lower_limit():
    """D15 for a learning job: the last `progress` sibling cost. (D15)"""
    facts = {"started": STARTED, "outcome": learning_outcome(cost=9.0),
             "progress": {"stage": "judge", "fork_message_id": "m-1", "sibling_cost_usd": 2.5}}
    got = decide("learning", facts, {}, "lapsed")
    assert got.sibling_cost_usd == 2.5


@pytest.mark.parametrize("kind", ["investigation", "learning"])
def test_a_stop_gives_the_job_back_only_when_it_decided_nothing(kind):
    """`stopped` and undecided -> `HandBack` (cost and knowledge, no state); stopped and decided -> an `End`. (PR9)"""
    if kind == "investigation":
        undecided = {"started": STARTED, "knowledge": KNOWLEDGE, "progress": {"cost_usd": 0.3}}
        decided = {**undecided, "outcome": inv_outcome()}
    else:
        undecided = {"started": STARTED, "progress": {"stage": "judge", "fork_message_id": "m", "sibling_cost_usd": 0.3}}
        decided = {**undecided, "outcome": learning_outcome()}
    hand = decide(kind, undecided, {BUNDLE: up()}, "stopped")
    assert type(hand).__name__ == "HandBack"
    assert not hasattr(hand, "evidence_state")
    end = decide(kind, decided, {BUNDLE: up()}, "stopped")
    assert type(end).__name__ == "End" and end.stage == "completed"


def test_a_lapsed_learning_job_that_decided_keeps_its_screened_findings_and_one_that_did_not_lapses():
    """D10: a decided learning take-over carries the screened rows to store; a `stopped` outcome is not decided. (D10)"""
    row = {"finding_id": "j/w-b/0/0"}
    facts = {"started": STARTED, "outcome": learning_outcome(findings=findings_screened(row))}
    kept = decide("learning", facts, {BUNDLE: up()}, "lapsed")
    assert (kept.stage, kept.publish_state) == ("completed", "done")
    assert [r["finding_id"] for rows in kept.findings.values() for r in rows] == ["j/w-b/0/0"]
    refused_findings = decide("learning", {**facts, "outcome": learning_outcome(findings={"state": "refused", "reason": "r"})},
                              {}, "lapsed")
    assert (refused_findings.stage, refused_findings.publish_state) == ("completed", "refused")
    lapsed = decide("learning", {"started": STARTED, "outcome": learning_outcome("stopped")}, {}, "lapsed")
    assert (lapsed.stage, lapsed.failure_reason) == ("failed", "lease_lapsed")


@pytest.mark.parametrize(("by", "status", "reason"), [("offboarded", "skipped", "tenant_offboarded"),
                                                      ("expired_in_queue", "skipped", "expired"),
                                                      ("lapsed", "failed", "lease_lapsed")])
def test_a_learning_ending_by_the_system_has_its_own_status_and_reason_and_no_evidence(by, status, reason):
    """Queue expiry, offboarding and an undecided take-over end by their words; state `none`. (rule 2, 3)"""
    got = decide("learning", {"started": STARTED}, {BUNDLE: up()}, by)
    assert (got.status, got.reason, got.evidence_state) == (status, reason, "none")


@pytest.mark.parametrize(("facts", "by", "stage", "reason"), [
    ({"result": {"outcome": "ready"}}, "exited", "completed", None),
    ({"result": {"outcome": "ready"}}, "lapsed", "completed", None),
    ({}, "exited", "failed", "no_record"),
    ({**refused("result")}, "exited", "failed", "bad_record"),
    ({}, "exited_failed", "failed", "worker_error"),
    ({}, "stopped", "failed", "worker_stopped"),
    ({}, "lapsed", "failed", "worker_lost"),
    ({}, "offboarded", "failed", "tenant_offboarded"),
])
@pytest.mark.parametrize("kind", ["readiness", "adoption", "drain"])
def test_a_host_request_is_decided_by_its_staged_result_and_a_refused_result_is_bad_record(kind, facts, by, stage, reason):
    """Readiness, adoption and drain: decided by a staged `result`; a refused one reads `bad_record`, none `no_record`;
    never retried. (Decided, PR9)"""
    got = decide("host_request", facts, {}, by)
    assert (got.stage, got.failure_reason) == (stage, reason)
    assert got.evidence_state is None


@pytest.mark.parametrize("kind", ["investigation", "learning", "host_request"])
def test_ended_by_is_closed(kind):
    """A value outside the members is refused, not guessed at. (PR9)"""
    from defender.jobs import ending

    with pytest.raises((TypeError, ValueError)):
        ending.decide({}, {}, "exited", kind=kind)
    assert decide(kind, {}, {}, "exited") is not None  # the control: a member is accepted


def test_decide_is_pure_and_deterministic():
    """The same inputs give equal decisions and leave the inputs unchanged. (PR9)"""
    import copy

    facts, ups = _inv_input(True, "complete_clean", UP, "rendered", UP)
    before = copy.deepcopy((facts, ups))
    first, second = decide("investigation", facts, ups, "exited"), decide("investigation", facts, ups, "exited")
    assert first == second
    assert (facts, ups) == before


@pytest.mark.parametrize("oc", ["complete_clean", "tainted", "unparseable"])
def test_lesser_ends_weaken_in_turn_and_each_keeps_the_rules_consistent(oc):
    """`lesser` strips knowledge to the unreadable marker, then to the barest `failed/worker_error` with no cost or
    knowledge; each step re-derives the state for its stage (partial when the bundle is up), promotes the uploaded rows,
    queues no auto job, and the chain ends. (PR9)"""
    from defender.jobs import ending

    facts, ups = _inv_input(True, oc, UP, "rendered", UP)
    decision = decide("investigation", facts, ups, "exited")
    chain = [decision]
    for _ in range(4):
        nxt = ending.lesser(chain[-1])
        if nxt == chain[-1]:
            break
        chain.append(nxt)
    else:
        pytest.fail("lesser never reached a fixed point")
    assert len(chain) >= 2
    barest = chain[-1]
    assert (barest.stage, barest.failure_reason, barest.cost_usd, barest.knowledge) == ("failed", "worker_error", None, None)
    assert barest.follow_ons.auto_learning_job is False
    assert barest.evidence_state == "partial" and set(barest.promote) == {BUNDLE, RUN_PAGE}
    for step in chain[1:]:
        assert dataclasses.is_dataclass(step)
        assert step.evidence_state in STATES


def test_a_lesser_hand_back_stays_a_hand_back():
    """A hand-back is never turned into an ending. (PR9)"""
    from defender.jobs import ending

    hand = decide("investigation", {"started": STARTED, "progress": {"cost_usd": 1.0}}, {}, "stopped")
    assert type(ending.lesser(hand)).__name__ == "HandBack"
