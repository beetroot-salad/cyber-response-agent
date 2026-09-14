"""#992 — the close's contract once `inconclusive` spends the review (demand #0, O1, M1, the
key flow, and the driver's own lanes).

Every test here is one demand of `spec-flow/specs/spec_graph_992.yaml`, named by that demand's
`discharged_by`. RED against 67d29090 is the expected state: `NO_REVIEW_DISPOSITIONS` still
carries `inconclusive`, so every close below that should spend a review commits first with
`CAUSE_NOT_REVIEWED` and dispatches nothing.

Two ledger corrections shape this module. C16 is REFUTED (G4/x1): no replay here is "repaired"
against an unbound bundle, because the harness binds a `holds` composer by default — the
unbound spellings are driven on purpose where a demand is about them. And the per-close review
floor is TWO calls, not three (x10/a2): the ablation lens is dispatched only when a strong
belief move cites an edge, so the sparse companion is the two-call fixture and the golden the
three-call one.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from defender._vocab import DISPOSITION_ENUM, HOST_ONLY_DISPOSITION
from defender.runtime.close_tool import (
    CAUSE_NOT_REVIEWED,
    CHALLENGED,
    FORCED_INCONCLUSIVE,
    STANDS,
    close_investigation,
)
from defender.tests import _spec923
from defender.tests._frames680 import frame_salt_of
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests._spec992 import (
    CEILING_EXAMINED,
    CEILING_QUESTION_MARKERS,
    CONFIDENT,
    GAP,
    SHIPPED_CAUSES,
    bounds,
    ceiling_companion,
    close_with,
    deps_over,
    frontmatter,
    gap,
    holds,
    host_text,
    raises,
    record,
    record_files,
    recording,
    refusal,
    report_text,
    review_state,
    sparse_companion,
    trace_files,
    trace_rows,
)

#: The causes a STANDING `inconclusive` may commit after §7 FK-10: the five the design named
#: plus the seventh member for the ceiling-held arm. `CAUSE_NOT_REVIEWED` is `unresolved`'s
#: alone (d0's resolution).
STANDING_CAUSES = frozenset(SHIPPED_CAUSES[1:]) | {CEILING_EXAMINED}


def _tool_lane_return(tmp_path: Path, disposition: str, stages) -> str:
    """The string the MODEL is handed back by the registered close tool, through MAIN's real
    composition root and a scripted model — the tool lane, as distinct from the sync host
    entry."""
    from pydantic_ai.models import override_allow_model_requests

    from defender.tests._invlang_warn_836 import build_main_agent
    from defender.tests.e2e._replay_harness import ReplayFn, Turn

    deps, _run_dir = deps_over(tmp_path, ceiling_companion())
    agent = build_main_agent(
        ReplayFn([
            Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
            Turn(text="done"),
        ]),
        review_stages=stages.bundle(),
    )
    with override_allow_model_requests(False):
        result = asyncio.run(agent.run("close it", deps=deps))
    returns = [
        part.content
        for message in result.all_messages()
        for part in getattr(message, "parts", ())
        if getattr(part, "part_kind", "") == "tool-return"
        and getattr(part, "tool_name", "") == "close_investigation"
    ]
    assert len(returns) == 1, f"expected one close return, saw {returns!r}"
    return str(returns[0])


def test_inconclusive_close_return_contract(tmp_path):
    """Driving the sync host close with `inconclusive` and a bound bundle returns a
    `CloseResult` whose `outcome` is `stands` or `challenged` and never `forced-inconclusive`;
    on `stands` report.md carries `disposition: inconclusive`, `outcome: stands`, a `cause`
    from {the seventh CEILING_EXAMINED member, EVIDENCE_CANNOT_DISCRIMINATE,
    NOTHING_LEFT_TO_ASK, TURN_BUDGET_SPENT, REVIEW_INCOMPLETE} — never CAUSE_NOT_REVIEWED,
    which is `unresolved`'s alone (§7 FK-10) — and a `failure_kind` key iff the machinery
    failed, and the numbered record carries `verdict: stands` / `reviewed_disposition:
    inconclusive`; on `challenged` no report.md exists, the record says `challenged`, and the
    message carries the ask inside a fresh untrusted frame; the tool lane returns exactly
    `result.message`."""
    # `stands` — the review completed and held the ceiling claim.
    deps, run_dir = deps_over(tmp_path / "stands", ceiling_companion())
    stood = close_investigation(deps, GAP, stages=recording(holds()).bundle())
    assert stood.outcome == STANDS
    assert stood.outcome != FORCED_INCONCLUSIVE
    fm = frontmatter(run_dir)
    assert fm["disposition"] == GAP
    assert fm["outcome"] == STANDS
    assert fm["cause"] in STANDING_CAUSES, fm["cause"]
    assert fm["cause"] != CAUSE_NOT_REVIEWED
    assert "failure_kind" not in fm, "a review that completed is not a machinery failure"
    rec = record(run_dir, 1)
    assert rec["verdict"] == STANDS
    assert rec["reviewed_disposition"] == GAP

    # `stands` with the machinery broken — the `failure_kind` key is the one difference.
    deps, run_dir = deps_over(tmp_path / "broken", ceiling_companion())
    broken = close_investigation(
        deps, GAP,
        stages=recording(faults={"composer": raises(RuntimeError("provider dropped"))}).bundle(),
    )
    assert broken.outcome == STANDS
    fm = frontmatter(run_dir)
    assert fm["disposition"] == GAP
    assert fm["cause"] in STANDING_CAUSES
    assert fm["failure_kind"] == broken.failure_kind
    assert broken.failure_kind is not None

    # `challenged` — nothing committed, the ask handed back framed.
    deps, run_dir = deps_over(tmp_path / "challenged", ceiling_companion())
    challenged = close_investigation(deps, GAP, stages=recording(gap("l-005")).bundle())
    assert challenged.outcome == CHALLENGED
    assert not (run_dir / "report.md").exists(), "a challenged close committed a report"
    assert record(run_dir, 1)["verdict"] == CHALLENGED
    assert "l-005" in challenged.message
    assert frame_salt_of(challenged.message, "untrusted"), "the ask reached the run unframed"

    # The model lane hands back exactly `result.message` — nothing structured reaches it.
    twin_deps, _twin_dir = deps_over(tmp_path / "twin", ceiling_companion())
    twin = close_investigation(twin_deps, GAP, stages=recording(holds()).bundle())
    assert _tool_lane_return(tmp_path / "tool", GAP, recording(holds())) == twin.message


def test_inconclusive_spends_the_review(tmp_path):
    """An `inconclusive` close that has paid its entry price dispatches the support lens, the
    ablation lens (when a strong belief move cites an edge) and the composer — each leaves an
    `ok: true` trace row under wire_logs — and its record and report never carry
    CAUSE_NOT_REVIEWED."""
    stages = recording(holds())
    deps, run_dir = deps_over(tmp_path, ceiling_companion())
    result = close_with(deps, GAP, stages)

    assert sorted(stages.calls[:2]) == ["ablation", "support"], f"the inconclusive close dispatched {stages.calls} — the review was not spent"
    assert stages.calls[2:] == ["composer"], f"the inconclusive close dispatched {stages.calls} — the review was not spent"
    for role in ("support", "ablation", "composer"):
        rows = trace_rows(run_dir, role)
        assert rows, f"{role} left no `ok: true` row: {rows}"
        assert rows[0].get("ok") is True, f"{role} left no `ok: true` row: {rows}"
    assert result.cause != CAUSE_NOT_REVIEWED
    assert frontmatter(run_dir)["cause"] != CAUSE_NOT_REVIEWED
    assert CAUSE_NOT_REVIEWED not in json.dumps(record(run_dir, 1))


def test_no_review_set_is_exactly_unresolved(tmp_path):
    """Driving every member of DISPOSITION_ENUM on its own lane (the four model members
    through the model lane, `unresolved` through `forced=True`), only `unresolved` commits
    without a stage call; `inconclusive` now joins the three confident members in spending a
    review, and a confident member on the forced lane still spends it — `NO_REVIEW_DISPOSITIONS`
    is exactly `(unresolved,)` by observation, and the `forced` flag buys no bypass of its own."""
    spent_nothing: set[str] = set()
    for member in sorted(DISPOSITION_ENUM):
        stages = recording(holds())
        forced = member == HOST_ONLY_DISPOSITION
        deps, _run_dir = deps_over(
            tmp_path / member,
            _spec923.pays_every_price(GAP if forced else member),
        )
        result = close_with(deps, member, stages, forced=forced)
        assert result.outcome == STANDS, (member, result)
        if not stages.calls:
            spent_nothing.add(member)
    assert spent_nothing == {HOST_ONLY_DISPOSITION}, (
        f"the members that commit without a stage call are {sorted(spent_nothing)}"
    )

    # A confident member on the FORCED lane still spends the review: the set is matched by
    # value, never keyed on the flag.
    stages = recording(holds())
    deps, _run_dir = deps_over(tmp_path / "forced-confident", _spec923.pays_every_price(CONFIDENT))
    close_with(deps, CONFIDENT, stages, forced=True)
    assert stages.calls, "a host-forced confident close committed unreviewed"


def test_gates_ahead_of_the_review_spend_no_stage(tmp_path):
    """An `inconclusive` close that owes its entry price, is refused as already closed, sits
    inside the flagged-row window, or fails the structure check is refused before any stage is
    called — no lens or composer runs and no trace row is written; a malformed `state`/`cap`
    field, receipts pushing the block past `_MAX_CEILING_FRONTMATTER_BYTES`, and an absent or
    empty companion are refused at the same price gate, and a second close attempt after a
    terminal commit is refused before any price or stage with report.md never re-written.
    Positive control: the same bundle on a paid close is dispatched."""
    from defender.tests._invlang_warn_836 import WARN_ROW, attr_block

    pre_gate = {
        "owes-its-price": _spec923.gapless(),
        "malformed-state": _spec923.paid("state=bogus ref=l-002 note=not a member"),
        "over-cap-receipts": _spec923.paid(*(
            f"state=nothing-to-try cap=fake-system-{i:03d}.fake-verb note=capability {i:03d}"
            for i in range(100)
        )),
        "flagged-row-window": _spec923.paid() + attr_block(WARN_ROW),
        "structure-check": _spec923.paid() + attr_block(
            "l-001|v-001|class|bastion", "l-001|v-001|class|workstation",
        ),
        "absent-companion": None,
        "empty-companion": "",
    }
    for name, companion in pre_gate.items():
        stages = recording(holds())
        deps, run_dir = deps_over(tmp_path / name, companion)
        refusal(deps, GAP, stages)
        assert stages.calls == [], f"{name}: the refused close spent {stages.calls}"
        assert trace_files(run_dir) == [], f"{name}: a trace row was written"
        assert not (run_dir / "report.md").exists(), f"{name}: a refused close committed"

    # Already closed: the terminal check sits ahead of the price and the review.
    stages = recording(holds())
    deps, run_dir = deps_over(tmp_path / "terminal", ceiling_companion())
    assert close_with(deps, GAP, stages).outcome == STANDS
    committed = report_text(run_dir)
    dispatched = len(stages.calls)
    text = refusal(deps, GAP, stages)
    assert "already closed" in text
    assert len(stages.calls) == dispatched, "the second attempt spent a stage"
    assert report_text(run_dir) == committed, "report.md was re-written"

    # Positive control: on a paid close the same bundle IS dispatched.
    stages = recording(holds())
    deps, _run_dir = deps_over(tmp_path / "control", ceiling_companion())
    close_with(deps, GAP, stages)
    assert stages.calls, "the recording bundle records nothing even on a close that reviews"


def test_inconclusive_close_whose_record_has_no_strong_belief_move(tmp_path):
    """An `inconclusive` close whose record carries no strong belief move dispatches the
    support lens and the composer only — two calls — writes a `skipped` ablation trace row
    carrying no `ok` key, and the composer's ceiling sentence is unchanged (a2: the two-call
    floor is the base behaviour on a confident close today)."""
    stages = recording(holds())
    deps, run_dir = deps_over(tmp_path, sparse_companion())
    result = close_with(deps, GAP, stages)

    assert result.outcome == STANDS
    assert stages.calls == ["support", "composer"], stages.calls
    rows = trace_rows(run_dir, "ablation")
    assert rows, f"the skipped lens left no `skipped` row: {rows}"
    assert rows[0].get("skipped"), f"the skipped lens left no `skipped` row: {rows}"
    assert "ok" not in rows[0], "a lens that never ran is recorded as one that answered"
    host = host_text(stages.prompt("composer")).lower()
    for marker in CEILING_QUESTION_MARKERS:
        assert marker in host, f"the composer's host text lost {marker!r} on the two-call floor"


def test_first_close_attempt_refused_pre_gate_leaves_no_residue(tmp_path):
    """An `inconclusive` close refused before the gate (entry price owed) leaves `ReviewState`
    untouched — turns 0, raised_asks empty, closed False — and writes no trace row and no
    record: the only ReviewState writers are `_route` on CHALLENGED and `_commit`. Positive
    control: a challenged `inconclusive` attempt on a paid companion DOES write the watermark
    and a numbered record."""
    stages = recording(holds())
    deps, run_dir = deps_over(tmp_path / "refused", _spec923.gapless())
    refusal(deps, GAP, stages)
    state = review_state(deps)
    assert state.turns == 0
    assert state.raised_asks == {}
    assert state.closed is False
    assert trace_files(run_dir) == []
    assert record_files(run_dir) == []

    deps, run_dir = deps_over(tmp_path / "control", ceiling_companion())
    assert close_with(deps, GAP, recording(gap("l-005"))).outcome == CHALLENGED
    state = review_state(deps)
    assert state.turns == 1
    assert "l-005" in state.raised_asks
    assert record_files(run_dir) == [1]


def _challenged_inconclusive(tmp_path: Path):
    """A run whose `inconclusive` close was challenged once: turns 1, one watermark, one record."""
    deps, run_dir = deps_over(tmp_path, ceiling_companion())
    assert close_with(deps, GAP, recording(gap("l-005"))).outcome == CHALLENGED
    return deps, run_dir


def test_forced_close_ignores_inflight_review_bookkeeping(tmp_path):
    """The driver's forced `unresolved` close after a challenged `inconclusive` neither resets
    nor routes on `turns`/`raised_asks`; the driver's guard consults `closed` only, and the
    forced commit leaves the counters as the challenge left them — the forced close dispatches
    no stage and commits `unresolved` with `closed` set."""
    deps, run_dir = _challenged_inconclusive(tmp_path)
    before = review_state(deps)
    turns, asks = before.turns, dict(before.raised_asks)
    assert turns == 1
    assert asks

    stages = recording(holds())
    _run, _truncated, exit_reason = _spec923.drive_to_retry_exhaustion(
        deps, review_stages=stages.bundle(),
    )
    assert exit_reason == "UnexpectedModelBehavior", "the forced-close limb never ran"
    assert stages.calls == [], f"the forced close dispatched {stages.calls}"
    after = review_state(deps)
    assert after.closed is True
    assert after.disposition == HOST_ONLY_DISPOSITION
    assert after.turns == turns, "the forced close reset or advanced the turn counter"
    assert after.raised_asks == asks, "the forced close touched the watermark"
    assert frontmatter(run_dir)["disposition"] == HOST_ONLY_DISPOSITION


def test_driver_forced_unresolved_survives_after_a_challenged_inconclusive(tmp_path):
    """A run whose `inconclusive` close was challenged and which then exhausts the tool-retry
    budget is force-closed `unresolved` by the driver with `cause: CAUSE_NOT_REVIEWED` and no
    `ceiling_test` block — the receipts remain in investigation.md — exactly as any run cut
    short is; the earlier challenged attempt's record and trace rows survive on disk beside
    the forced `unresolved` report."""
    deps, run_dir = _challenged_inconclusive(tmp_path)
    challenged_record = record(run_dir, 1)
    challenged_rows = {role: trace_rows(run_dir, role) for role in trace_files(run_dir)}
    assert challenged_rows, "the challenged attempt left no trace rows to survive"

    _run, truncated_by, exit_reason = _spec923.drive_to_retry_exhaustion(deps)
    assert exit_reason == "UnexpectedModelBehavior"
    assert truncated_by is not None

    fm = frontmatter(run_dir)
    assert fm["disposition"] == HOST_ONLY_DISPOSITION
    assert fm["outcome"] == STANDS
    assert fm["cause"] == CAUSE_NOT_REVIEWED
    assert "ceiling_test" not in fm, "a forced `unresolved` carried the receipts"
    assert "ceiling_test (" not in report_text(run_dir)
    assert "ceiling_test" in (run_dir / "investigation.md").read_text(encoding="utf-8")
    assert record(run_dir, 1) == challenged_record, "the challenged record was overwritten"
    for role, rows in challenged_rows.items():
        assert trace_rows(run_dir, role)[: len(rows)] == rows, f"{role}'s rows were lost"


def test_usage_limit_exceeded_after_a_challenged_inconclusive(tmp_path):
    """A run whose `inconclusive` close was challenged and which then hits
    `UsageLimitExceeded` ends with no report.md and no forced commit; the numbered record of
    the challenged attempt is the distinguishing residue on disk (C17-adjacent: the driver's
    limit arm forces nothing)."""
    from defender.runtime import driver
    from defender.tests._invlang_warn_836 import build_main_agent

    deps, run_dir = _challenged_inconclusive(tmp_path)
    stages = recording(holds())
    agent = build_main_agent(_spec923.StuckModel(), review_stages=stages.bundle())
    _run, truncated_by, exit_reason = asyncio.run(driver._drive_agent(
        agent, "go", deps, _spec923.NullStore(), "sid",
        bounds(extra_turns=1, base_request_limit=1),
    ))
    assert exit_reason == "UsageLimitExceeded", exit_reason
    assert truncated_by is not None
    assert not (run_dir / "report.md").exists(), "the request-limit exit forced a commit"
    assert stages.calls == []
    assert review_state(deps).closed is False
    assert record_files(run_dir) == [1]
    assert record(run_dir, 1)["verdict"] == CHALLENGED


def test_disposition_threaded_seams(tmp_path):
    """`composer_projection` accepts the reviewed disposition and renders a different host
    sentence for `inconclusive` than for a confident close, and `_route`/`_fail` receive it —
    the gate never re-derives which disposition it is reviewing from anything but the argument
    the close handed it: the gate driven with `inconclusive` over a companion that concludes
    `inconclusive` routes every arm to `disposition: inconclusive`, and driven with a confident
    keyword over the same companion routes to that keyword."""
    from defender.runtime import challenge_gate
    from defender.runtime.review.projector import composer_projection, parse_investigation

    companion = parse_investigation(ceiling_companion())
    readings = {"support": "l-001 moves h-002"}
    ceiling = host_text(composer_projection(
        companion, readings, "ab" * 8, ablated=None, disposition=GAP,
    ).text)
    confident = host_text(composer_projection(
        companion, readings, "ab" * 8, ablated=None, disposition=CONFIDENT,
    ).text)
    assert ceiling != confident, "one host sentence for both dispositions"
    for marker in CEILING_QUESTION_MARKERS:
        assert marker in ceiling.lower()

    def _gate(name: str, disposition: str, stages):
        deps, _run_dir = deps_over(tmp_path / name, ceiling_companion())
        return asyncio.run(challenge_gate.challenge_gate(
            deps, disposition, stages=stages.bundle(), bounds=challenge_gate.default_bounds(),
        ))

    routed = _gate("route", GAP, recording(gap(None)))
    assert routed.disposition == GAP, routed
    assert routed.outcome == STANDS
    failed = _gate("fail", GAP, recording(faults={"support": raises(RuntimeError("down"))}))
    assert failed.disposition == GAP, failed
    assert failed.outcome == STANDS
    confident_verdict = _gate("confident", CONFIDENT, recording(gap(None)))
    assert confident_verdict.disposition == HOST_ONLY_DISPOSITION
    assert confident_verdict.outcome == FORCED_INCONCLUSIVE

