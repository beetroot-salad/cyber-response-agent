"""#1546 sketch (r6), "The end function": one function in `jobs`, called by every owner ending, deciding stage, scrub,
evidence state and what is promoted from the ending path plus the claim's staged facts and uploads. One case per
precedence rule (A-O3, A-O4, A-O10), pure: no database. The worker and store cases (`test_investigation_end`,
`test_takeover_handback`) show the same rules through the real end transaction.

Seam (missing): `jobs.ending.decide(path=, kind=, facts={name: body}, uploads={object: {"status", "scrub"}})` ->
an object with `stage`, `failure_reason`, `disposition`, `scrub`, `evidence_state`, `promote` (set of objects),
`decided`, and for a learning job `findings` (the rows to insert, or None). FORCED CHOICE: r6 lists the outputs
("stage, disposition, cost, knowledge, scrub, publish_state, findings to insert, evidence state, uploads to promote")
but not whether the function reads the rows itself inside the transaction (it says "read in the transaction") or is
handed them; the pure form is picked so its table is testable alone.
"""
from __future__ import annotations

from typing import Any

import pytest

from defender.tests.evidence_1546._support import (
    EPISODE_PAGE,
    KNOWLEDGE,
    RUN_PAGE,
    STARTED,
    arm_page,
    ending_module,
    inv_outcome,
    learning_outcome,
)

UP = {"status": "uploaded", "scrub": None}
REFUSED = {"status": "refused", "scrub": None}
ARM_A, ARM_B = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"


def inv(outcome: dict | None = None, *, started: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {"knowledge": KNOWLEDGE}
    if started:
        out["started"] = STARTED
    if outcome is not None:
        out["outcome"] = outcome
    return out


def learn(outcome: dict | None = None, *, arms: tuple[str, ...] = (ARM_A, ARM_B)) -> dict[str, Any]:
    out: dict[str, Any] = {"started": STARTED, "arms": {"roster": [{"run_id": a} for a in arms]}}
    if outcome is not None:
        out["outcome"] = outcome
    return out


ALL_INV = {"bundle": UP, RUN_PAGE: UP}
ALL_LEARN = {"bundle": UP, EPISODE_PAGE: UP, arm_page(ARM_A): {"status": "uploaded", "scrub": "clean"},
             arm_page(ARM_B): {"status": "uploaded", "scrub": "clean"}}

# (id, path, kind, facts, uploads, expected subset)
CASES = [
    ("r4-complete", "end", "investigation", inv(inv_outcome()), ALL_INV,
     {"stage": "completed", "disposition": "benign", "scrub": "clean", "evidence_state": "complete",
      "promote": {"bundle", RUN_PAGE}, "decided": True}),
    ("r5-lost-page-refused", "end", "investigation", inv(inv_outcome()), {"bundle": UP, RUN_PAGE: REFUSED},
     {"stage": "completed", "disposition": "benign", "evidence_state": "lost", "promote": {"bundle"}}),
    # A-O10 / D2 / "Done when": a tainted investigation ends failed, scrub tainted, partial, its bundle accepted.
    # FORCED CHOICE: its failure_reason (today's `no_report` with "the scrub did not verify" wording, or a new
    # reason such as `tainted`); r6 says only `failed`. Provisional: `no_report`.
    ("r6-tainted-partial", "end", "investigation", inv(inv_outcome(scrub="tainted")), ALL_INV,
     {"stage": "failed", "failure_reason": "no_report", "scrub": "tainted", "evidence_state": "partial",
      "promote": {"bundle", RUN_PAGE}, "decided": True}),
    # Not decided (today's rule), but the bundle is uploaded: rule 6.
    ("r6-not-run-partial", "end", "investigation", inv(inv_outcome(scrub="not_run")), {"bundle": UP},
     {"stage": "failed", "failure_reason": "no_report", "scrub": "not_run", "evidence_state": "partial",
      "promote": {"bundle"}, "decided": False}),
    # Rule 1 beats a staged outcome: the helper refused setup before the container started.
    ("r1-no-started", "end", "investigation",
     inv(inv_outcome(setup="refused", box="not_started", report_committed=False, closing=None, scrub="not_run"),
         started=False), {},
     {"stage": "failed", "failure_reason": "setup_refused", "evidence_state": "none", "promote": set(),
      "decided": True}),
    ("r2-cancel", "cancel", "investigation", inv(inv_outcome()), ALL_INV,
     {"evidence_state": "none", "promote": set()}),
    ("r2-offboard", "offboard", "investigation", inv(inv_outcome()), ALL_INV,
     {"evidence_state": "none", "promote": set()}),
    # Decision 3 / r6 Stage: take-over keeps a decided verdict, no rerun; nothing is promoted (Promotion: `end` only).
    ("r3-takeover-decided", "take-over", "investigation", inv(inv_outcome()), ALL_INV,
     {"stage": "completed", "disposition": "benign", "evidence_state": "lost", "promote": set(), "decided": True}),
    # Decision 2: a tainted run is decided, so a take-over keeps it failed.
    ("r3-takeover-tainted", "take-over", "investigation", inv(inv_outcome(scrub="tainted")), ALL_INV,
     {"stage": "failed", "scrub": "tainted", "evidence_state": "lost", "promote": set(), "decided": True}),
    ("r3-takeover-undecided", "take-over", "investigation", inv(None), {"bundle": UP},
     {"stage": "failed", "failure_reason": "lease_lapsed", "scrub": "not_run", "evidence_state": "none",
      "promote": set(), "decided": False}),
    ("r7-no-outcome", "end", "investigation", inv(None), {"bundle": UP},
     {"stage": "failed", "scrub": "not_run", "evidence_state": "none", "promote": set()}),
    # FORCED CHOICE: an `unparseable` end (close committed, record unreadable). Rules 4-6 name only `completed` and
    # `failed`, so a literal reading gives rule 7 (`none`, nothing promoted) though the run is decided and its bundle
    # uploaded; must-push is undefined for it too (no closing record, so no page?). Provisional: the literal reading.
    ("r7-unparseable", "end", "investigation",
     inv(inv_outcome(closing={"found": "could_not_look", "wording": "the store could not be read"})), {"bundle": UP},
     {"stage": "unparseable", "evidence_state": "none", "promote": set(), "decided": True}),
    # Learning: must-push = bundle + episode page + a page per roster arm that ended with a verdict.
    ("l-r4-complete", "end", "learning", learn(learning_outcome()), ALL_LEARN,
     {"stage": "completed", "evidence_state": "complete", "promote": set(ALL_LEARN)}),
    # FORCED CHOICE: "every roster arm that ended with a verdict". Nothing staged says which arms ended with one:
    # the `arms` fact is the roster before the first arm runs, the outcome carries no per-arm list, and an arm with no
    # page has no upload row to carry its `scrub`. B pushed nothing here: is the job `complete` (B had no verdict) or
    # `lost` (B's page is missing)? Provisional: `lost`, i.e. every roster arm is must-push.
    ("l-r5-arm-page-missing", "end", "learning", learn(learning_outcome()),
     {k: v for k, v in ALL_LEARN.items() if k != arm_page(ARM_B)},
     {"stage": "completed", "evidence_state": "lost"}),
    # Decision 3: a decided learning job's findings are stored on take-over (screened as on `end`).
    ("l-r3-takeover-decided", "take-over", "learning", learn(learning_outcome()), ALL_LEARN,
     {"stage": "completed", "evidence_state": "lost", "promote": set(), "decided": True}),
    ("l-stopped-undecided", "take-over", "learning", learn(learning_outcome("stopped")), ALL_LEARN,
     {"evidence_state": "none", "promote": set(), "decided": False}),
    # hand-back: no state, nothing promoted (A-O4: the check keys on terminal status, not `finished_at`).
    ("l-hand-back", "hand-back", "learning", learn(None), {"bundle": UP},
     {"evidence_state": None, "promote": set()}),
]


@pytest.mark.parametrize(("path", "kind", "facts", "ups", "expected"), [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_the_end_function_decides_by_rule_precedence(path, kind, facts, ups, expected):
    """The ending path and staged rows decide stage, scrub, evidence state and promotion, first rule winning.
    (r6 "The end function": Decided, Stage, Evidence state 1-7, Promotion; A-O3, A-O4, A-O10)"""
    ending = ending_module()
    got = ending.decide(path=path, kind=kind, facts=facts, uploads=ups)
    seen = {k: (set(getattr(got, k)) if k == "promote" else getattr(got, k)) for k in expected}
    assert seen == expected


def test_complete_implies_clean_and_a_terminal_end_with_no_outcome_reads_not_run():
    """`complete` implies `scrub = clean`; any terminal row with no outcome gets `none`, `not_run`. (A-O4, A-O10)"""
    ending = ending_module()
    for path, kind, facts, ups, _ in [c[1:] for c in CASES]:
        got = ending.decide(path=path, kind=kind, facts=facts, uploads=ups)
        if got.evidence_state == "complete" and kind == "investigation":
            assert got.scrub == "clean"
        if "outcome" not in facts and path != "hand-back" and kind == "investigation":
            assert (got.evidence_state, got.scrub) == ("none", "not_run")


def test_a_learning_takeover_of_a_decided_job_hands_back_its_screened_findings():
    """Decision 3: on take-over a decided learning job's staged findings are screened and stored as on `end`;
    `publish_state` follows #1487. FORCED CHOICE: the screen (`learning.judge.enqueue.screen_findings`) lives in
    `learning`, above `jobs` in the import order, and `take_over` runs in the store with no worker read; so either the
    screen moves down to `jobs`, or the end function returns unscreened rows for a caller to screen, or take-over is
    driven by the worker. Exposed here: `decide` is in `jobs`, yet must output screened rows."""
    from defender.tests.support.jobs import _findings1487 as F

    job = "33333333-3333-4333-8333-333333333333"
    outcome = learning_outcome(findings=F.ok([F.defender_row(job, 0)]))
    got = ending_module().decide(path="take-over", kind="learning", facts=learn(outcome), uploads=ALL_LEARN)
    assert got.stage == "completed"
    assert [row["finding_id"] for rows in got.findings.values() for row in rows] == [f"{job}/w-b/0/0"]
