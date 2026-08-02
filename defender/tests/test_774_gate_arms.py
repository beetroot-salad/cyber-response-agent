"""#774 part 2 — when the gate fires, what each arm does, and the two bounds it runs on.

Every test here is one demand of `defender/tests/spec_graph_774.yaml`, named by that demand's
`discharged_by`.

THE DESIGN'S CENTRAL MECHANISM IS REFUTED AND IS NOT PINNED HERE. "Reject the write and force
another turn" has no framework support: a tool refusal is a raw retry, the shared retry budget
is 10, and the eleventh raises an error none of the driver's handlers catches (K12), so a
stubborn model turns a refusal-based gate into an uncaught crash. Nothing structurally compels
a further turn either — every tool returns a string, there is no output validator, no end
strategy and no after-run hook in use (K13). What is pinned is RS6's correction: the gate's own
cap sits below the retry budget, the disposition is simply not committed until the gate is
satisfied, and exhaustion forces the unresolved close rather than killing the run.

RS14 set both bounds — two forced turns, one refinement round, grace reset PER GATE ATTEMPT —
so the fires-and-passes and exhausts-and-caps paths are executable rather than prose.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.core.directions import directions_for  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.tests._gate774 import (  # noqa: E402
    BASE_REQUEST_LIMIT,
    CHALLENGED,
    DECLINED,
    FAST_TIMEOUT,
    EVIDENCE_SILENT,
    FORCED_CAP,
    FORCED_NONDISCRIMINATING,
    RETRY_BUDGET,
    ROUNDS,
    TURNS,
    UNCHALLENGED,
    REVIEW_FAILED,
    FakeReviewStages,
    StageFault,
    decline,
    frontmatter_of,
    main_deps,
    projection_of,
    report_text,
    run_dir_with_alert,
    spec_import,
    tail,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    NeverEndsModel,
    ReplayFn,
    Turn,
    drive,
)

pytestmark = pytest.mark.e2e

SETTLED = [("the pivot was provisioned", "l-001", "the session was unauthorized")]
UNSETTLED = [("the pivot was provisioned", None, "the session was unauthorized")]
TWO_UNSETTLED = UNSETTLED + [("the destination was in scope", None, "it was not")]


def _close(deps, disposition, stages=None, **kw):
    close_investigation = spec_import("defender.runtime.close_tool", "close_investigation")
    return close_investigation(deps, disposition, stages=stages or FakeReviewStages(), **kw)


def _bounds(**kw):
    Bounds = spec_import("defender.runtime.challenge_gate", "Bounds")
    return Bounds(**({"extra_turns": TURNS, "grace_rounds": ROUNDS,
                      "stage_timeout": FAST_TIMEOUT} | kw))


def test_a_draft_inconclusive_close_commits_without_invoking_the_gate(tmp_path):
    """The gate reviews confident closes only. A draft inconclusive disposition commits
    straight through: no review stage is called, and the recorded disposition is the drafted
    one on the unchallenged arm.

    The accepted consequence, recorded rather than assumed: after this change unresolved runs
    are reviewed by nothing, and the gate manufactures unresolved runs on two of its own arms.
    That non-obligation was granted on the ground that the offline pipeline serviced exactly
    those cases, and this run's scope removes that ground."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages()
    result = _close(deps, "inconclusive", stages)
    assert stages.calls == [], "an inconclusive draft must not spend a review call"
    assert result.outcome == UNCHALLENGED
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"


def test_counter_direction_comes_from_the_existing_map_against_the_live_disposition(tmp_path):
    """The direction the challenger argues is read off the existing disposition-to-direction
    map, unmodified — a confident malicious close is challenged from the benign side and a
    confident benign close from the malicious side.

    Observable: the challenger fake records the direction it was handed, and it is the one
    the shipped map returns for the live disposition — not a second copy of the mapping
    written into the gate."""
    for disposition in ("malicious", "benign"):
        expected = [d.name for d in directions_for(disposition)]
        assert len(expected) == 1, f"{disposition} must select exactly one counter-direction"
        deps, _run = main_deps(tmp_path / disposition)
        stages = FakeReviewStages(challenger=[tail(SETTLED)])
        _close(deps, disposition, stages)
        prompt = stages.challenger.only().prompt
        assert expected[0] in prompt, (
            f"the challenger argued something other than {expected[0]} for {disposition}"
        )


def test_a_request_limited_run_never_reaches_the_gate(tmp_path):
    """NEGATIVE. A run that exhausts its request ceiling ends as truncated and never reaches a
    close, so the gate never fires and no review stage is ever called on it — the design's own
    non-obligation, and the reason the raised ceiling matters at all.

    Positive control: the same fakes on a run that DOES reach the close fire all three stages
    (`test_a_surviving_story_with_silent_rows_refuses_the_close_and_counts_a_turn`).

    Observable: the truncated run leaves no report.md, and the stage fakes recorded nothing."""
    run_dir = run_dir_with_alert(tmp_path)
    stages = FakeReviewStages()
    model = NeverEndsModel(run_dir)
    result = drive(run_dir, run_id="r-limit", salt="sess-salt", main=model,
                   review_stages=stages)
    assert result["output"] is None, "a request-limited run reports no output"
    assert stages.calls == [], "a truncated run must never reach the review"
    assert not (run_dir / "report.md").exists()


def test_a_surviving_story_with_silent_rows_refuses_the_close_and_counts_a_turn(tmp_path):
    """The challenged arm. The counter-story survives the coherence checker and the projection
    is silent on a requirement the challenger declared unsettled: the disposition is NOT
    committed, the tool hands back the discriminating material, and the per-run turn counter
    moves by one.

    Not a tool refusal: the correction RS6 folded in is that the close simply does not commit,
    because the framework's retry path cannot carry a forced turn (K12) and nothing compels one
    (K13).

    Observable: the arm, no report.md on disk, and a turn counted on the run's review state."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "empty-projection"), ("l-002", "has-projection")])],
    )
    result = _close(deps, "malicious", stages)
    assert result.outcome == CHALLENGED
    assert not (run_dir / "report.md").exists(), "the challenged arm must not commit"
    assert len(stages.challenger.calls) == 1
    assert len(stages.projection.calls) == 1
    assert result.turns_used == 1, f"one forced turn must be counted, got {result.turns_used}"


def test_a_surviving_story_with_no_silent_rows_forces_inconclusive_immediately(tmp_path):
    """A counter-story that survives but that every executed lead speaks to gives the gate
    nothing to send the investigator after: it records inconclusive at once rather than
    spending a turn that cannot help.

    Observable: the forced-nondiscriminating arm, an inconclusive disposition on disk, and
    exactly one review attempt — no turn was spent."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "has-projection")])],
    )
    result = _close(deps, "malicious", stages)
    assert result.outcome == FORCED_NONDISCRIMINATING
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"
    assert result.turns_used == 0


def test_the_attempt_past_the_bound_forces_inconclusive_instead_of_gating(tmp_path):
    """The cap arm, driven at RS14's real value rather than described. After two forced turns
    the third attempt records inconclusive instead of gating again, so a stubborn or
    unsatisfiable investigation terminates rather than looping.

    Observable: the first two closes take the challenged arm, the third takes the cap arm and
    commits an inconclusive disposition; the review state shows the bound consumed."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "empty-projection")])],
    )
    arms = [_close(deps, "malicious", stages).outcome for _ in range(TURNS + 1)]
    assert arms[:TURNS] == [CHALLENGED] * TURNS, f"expected {TURNS} challenged arms, got {arms}"
    assert arms[TURNS] == FORCED_CAP
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"


def test_a_story_no_executed_lead_can_touch_takes_its_own_arm(tmp_path):
    """RS13. A third arm for "the evidence cannot speak to the story", distinct from both "it
    discriminated" and "it disagreed". It covers the every-lead-silent case and the
    no-lead-executed case, which the two-branch split reads as opposite evidence when both mean
    the same thing.

    Without it the gate spends a forced turn exactly where another turn cannot help —
    challenging a story the investigation never tested — and burns the raised ceiling doing it.

    Observable: both degenerate shapes reach the same dedicated arm, that arm is neither the
    challenged nor the nondiscriminating one, and no turn is spent."""
    for label, rows in (("every-lead-silent", [("l-001", "no-projection"),
                                               ("l-002", "empty-projection")]),
                        ("no-lead-executed", [])):
        deps, run_dir = main_deps(tmp_path / label)
        stages = FakeReviewStages(challenger=[tail(UNSETTLED)],
                                  projection=[projection_of(rows)])
        result = _close(deps, "malicious", stages)
        assert result.outcome == EVIDENCE_SILENT, f"{label} took {result.outcome}"
        assert result.turns_used == 0, f"{label} spent a turn a turn cannot help"
        assert frontmatter_of(run_dir / "report.md")["reason"] == EVIDENCE_SILENT


def test_a_challenger_that_declines_to_argue_leaves_the_confident_close_standing(tmp_path):
    """RS17. A challenger that reads the case and has no counter-story to write DECLINES, and
    the investigator's confident close stands. The decline is recorded and judged; it is not an
    unresolvable case.

    This arm and the one for a review that could not complete were a single value until the
    reconciliation caught it. They mean opposite things: a decline is the challenger having
    nothing to say about a case it understood, a review failure is the machinery breaking. One
    leaves the disposition alone, the other overrides it — so sharing a value shares the
    downstream handling too, which is the same collapse the malformed arm exists to prevent in
    the mirror direction.

    Observable: the decline arm, the drafted confident disposition surviving onto disk rather
    than being overridden to inconclusive, and no turn spent. The control is the complementary
    condition on the same address: the review machinery failing instead takes a different arm
    and does force inconclusive."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(challenger=[decline()])
    result = _close(deps, "malicious", stages)
    assert result.outcome == DECLINED
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "malicious", (
        "a deliberate decline must leave the investigator's confident close standing"
    )
    assert result.turns_used == 0
    deps2, run2 = main_deps(tmp_path / "broke")
    broken = _close(deps2, "malicious",
                    FakeReviewStages(challenger_fault=StageFault(raises=RuntimeError("down"))))
    assert broken.outcome == REVIEW_FAILED, "control: a broken review must not read as a decline"
    assert frontmatter_of(run2 / "report.md")["disposition"] == "inconclusive"


def test_a_second_forced_turn_does_not_re_raise_a_gap_already_raised(tmp_path):
    """NEGATIVE. A second forced turn must hand back a gap the first did not already raise; a
    relabelled repeat of the same requirement makes the second turn a tax rather than a probe,
    and the model has no way to tell it was already asked.

    Positive control on the same address: the FIRST forced turn does hand the material back
    (`test_the_challenged_arm_does_hand_back_the_discriminating_material`).

    Observable: across two challenged arms in one run, the recommended leads' identities are
    disjoint, and the review state records what was already raised.

    REPAIR (phase F): the two attempts must be driven with genuinely different stage replies.
    A single-element (repeating) fake script hands turn two byte-identical input to turn one,
    which no implementation can satisfy: a working dedup collapses turn two's material to
    nothing (failing the `repeat` assertion below), and no dedup reproduces turn one's material
    exactly (failing the disjointness assertion). Turn two's script repeats l-001 (already
    raised) alongside a genuinely new l-002, so the assertion is satisfiable only when l-001 is
    filtered and l-002 is not."""
    deps, _run = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED), tail(TWO_UNSETTLED)],
        projection=[projection_of([("l-001", "empty-projection")]),
                    projection_of([("l-001", "empty-projection"), ("l-002", "empty-projection")])],
    )
    first = _close(deps, "malicious", stages)
    second = _close(deps, "malicious", stages)
    assert first.outcome == second.outcome == CHALLENGED
    ids = {lead.lead_id for lead in first.material}
    repeat = {lead.lead_id for lead in second.material}
    assert repeat, "the second forced turn handed back nothing"
    assert not (ids & repeat), f"the second forced turn re-raised {ids & repeat}"


def test_the_forced_turn_cap_is_rejected_when_it_reaches_the_shared_retry_budget(tmp_path):
    """The cap must sit strictly below the framework's shared tool-retry budget of 10, and a
    configuration that reaches it is refused at construction rather than discovered as an
    uncaught crash mid-run.

    Observable: a cap at and above the retry budget raises; the shipped value is accepted and
    is strictly below it."""
    assert driver.DEFAULT_TOOL_RETRIES == RETRY_BUDGET, (
        "the shared retry budget moved; the cap's headroom argument must be re-derived"
    )
    for bad in (RETRY_BUDGET, RETRY_BUDGET + 1):
        with pytest.raises(ValueError, match="retry"):
            _bounds(extra_turns=bad)
    assert _bounds().extra_turns < RETRY_BUDGET


def test_a_stubborn_model_exhausting_the_retry_budget_closes_unresolved_instead_of_crashing(tmp_path):
    """RS6. A model that keeps retrying a call the gate will not accept must not take the run
    down. Today the eleventh retry raises an error none of the driver's four handlers catches,
    so it escapes the entry point — the sharpest constraint on the design's stated mechanism.

    Driven with the real primitive rather than a fake: the model repeatedly writes report.md,
    which the narrowed allow-list refuses, and the refusal is a real retry against the real
    budget.

    Observable: the run returns normally, no exception escapes, and the run ends with a
    recorded inconclusive disposition rather than a partial trace and a traceback."""
    run_dir = run_dir_with_alert(tmp_path)
    stubborn = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"),
                                         "content": report_text("benign")})])
        for _ in range(RETRY_BUDGET + 3)
    ])
    result = drive(run_dir, run_id="r-stubborn", salt="sess-salt", main=stubborn,
                   review_stages=FakeReviewStages())
    assert isinstance(result, dict), "the driver must handle retry exhaustion, not raise"
    assert (run_dir / "report.md").exists(), (
        "exhaustion must force the unresolved close, not leave the run with no disposition"
    )
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"


def test_the_raised_request_ceiling_is_read_from_the_forced_turn_cap_not_a_literal(tmp_path):
    """RS7, and the requirement the human attached to it. Forced turns consume the same request
    limit that terminates investigations, so the ceiling is raised by the cap — and it is READ
    FROM the cap rather than restated as a literal, so the two cannot be moved independently.

    Separating the review's allowance from the investigation's was recommended and not taken;
    one budget is kept, which is why the interaction returns the moment the cap changes.

    Observable: the ceiling tracks two different cap values, and equals the base limit plus the
    cap in both — a literal would hold one of the two and fail the other."""
    raised_request_limit = spec_import(
        "defender.runtime.challenge_gate", "raised_request_limit",
    )
    assert driver.DEFAULT_REQUEST_LIMIT == BASE_REQUEST_LIMIT
    seen = {n: raised_request_limit(_bounds(extra_turns=n)) for n in (1, TURNS, 4)}
    assert seen == {n: BASE_REQUEST_LIMIT + n for n in (1, TURNS, 4)}, (
        f"the ceiling does not track the cap: {seen}"
    )


def test_a_run_the_gate_never_fires_on_still_gets_the_raised_ceiling(tmp_path):
    """RS7's accepted consequence, pinned rather than noted: every run pays the raised ceiling
    whether or not the gate ever fires. A run that never closes at all — and therefore never
    reaches the gate — still gets the raised allowance, because the ceiling is a property of
    the run, not of a review that happened.

    Observable: a model that never stops makes base-plus-cap requests before the limit
    terminates it, where today it makes exactly the base number."""
    run_dir = run_dir_with_alert(tmp_path)
    model = NeverEndsModel(run_dir)
    result = drive(run_dir, run_id="r-ceiling", salt="sess-salt", main=model,
                   review_stages=FakeReviewStages())
    assert model.calls == BASE_REQUEST_LIMIT + TURNS, (
        f"the run did not get the raised ceiling: {model.calls} requests"
    )
    assert result["requests"] == BASE_REQUEST_LIMIT + TURNS


def test_the_reviews_own_calls_cannot_push_the_investigation_into_the_request_limit(tmp_path):
    """The review's three model calls per attempt must not be charged against the allowance
    that terminates the investigation, or the gate converts closes it would have reviewed into
    truncations — and the design's own text says a truncated run never reaches a close, so the
    gate would erase its own subjects.

    The pre-existing gap where the run's cost sum omits every gather subagent call is NOT
    fixed here; that failure clause is already true today, independent of this change.

    Observable: a run driven to the cap, with three stage calls per attempt, still ends on its
    own terms rather than truncated, and the main agent's request count is untouched by the
    review."""
    run_dir = run_dir_with_alert(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "empty-projection")])],
    )
    turns = [Turn(tool_calls=[("close_investigation", {"disposition": "malicious"})])
             for _ in range(TURNS + 1)] + [Turn(text="done")]
    model = ReplayFn(turns)
    result = drive(run_dir, run_id="r-starve", salt="sess-salt", main=model,
                   review_stages=stages)
    assert len(stages.calls) >= 3 * (TURNS + 1), "the review did not run on every attempt"
    assert result["requests"] == model.calls, (
        "the review's own calls were charged to the investigation's request count"
    )
    assert result["output"] is not None, "the review truncated the run it was reviewing"


def test_the_extra_turn_bound_is_injected_not_literal(tmp_path):
    """SEAM. The forced-turn cap is a value the gate is handed, not a constant read at the
    call site — a scenario must be able to drive the cap arm without editing the runtime, and
    the ceiling that is derived from it must move with it.

    Observable: driving the gate with a cap of one takes the cap arm on the second attempt,
    where the shipped value takes it on the third."""
    deps, _run = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "empty-projection")])],
    )
    arms = [_close(deps, "malicious", stages, bounds=_bounds(extra_turns=1)).outcome
            for _ in range(2)]
    assert arms == [CHALLENGED, FORCED_CAP], f"the injected cap was not honoured: {arms}"


def test_the_grace_bound_is_injected_not_literal(tmp_path):
    """SEAM. The refinement-round bound is a value the gate is handed too. Its reset scope is
    per gate attempt, and a scenario must be able to drive both a round that is granted and a
    round that is refused without editing the runtime.

    Observable: at a grace bound of one an incoherent counter-story gets exactly one
    refinement round before it scores as incoherent; the challenger fake records the second
    call and no third."""
    deps, _run = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        coherence_checker=["INCOHERENT", "INCOHERENT"],
        projection=[projection_of([("l-001", "empty-projection")])],
    )
    _close(deps, "malicious", stages, bounds=_bounds(grace_rounds=1))
    assert len(stages.challenger.calls) == 2, (
        f"one refinement round means two challenger calls, got {len(stages.challenger.calls)}"
    )


def test_zero_is_refused_for_either_bound(tmp_path):
    """RS14 made both bounds real, so this is a test rather than prose. Zero is refused for
    either bound rather than accepted silently.

    At zero the forced-turn cap collapses the first challenged arm into the cap arm, leaving no
    room for the turn the gate exists to force. At zero the grace bound disables the only
    stated evidence-strength signal: the rounds-consumed count is the sole place a cold pass
    reads differently from a thrice-refined one, and at zero every story reports zero.

    Observable: both zero configurations are refused at construction; the shipped values are
    accepted."""
    for kw in ({"extra_turns": 0}, {"grace_rounds": 0}):
        with pytest.raises(ValueError, match="zero|positive"):
            _bounds(**kw)
    assert _bounds().extra_turns == TURNS
    assert _bounds().grace_rounds == ROUNDS


def test_a_second_gate_attempt_starts_with_a_full_grace_budget(tmp_path):
    """RS14's reset scope, which was as unset as the value. Grace resets PER GATE ATTEMPT, not
    per run: per-run means a second challenge inherits an exhausted budget and can never refine
    at all, which silently turns every later attempt into a cold pass.

    Observable: an incoherent story on the first attempt consumes its round; the second attempt
    in the same run still gets its own round, and the record shows rounds-consumed per attempt
    rather than one running total."""
    deps, _run = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        coherence_checker=["INCOHERENT", "COHERENT", "INCOHERENT", "COHERENT"],
        projection=[projection_of([("l-001", "empty-projection")])],
    )
    first = _close(deps, "malicious", stages)
    second = _close(deps, "malicious", stages)
    assert first.rounds_used == ROUNDS, f"first attempt: {first.rounds_used}"
    assert second.rounds_used == ROUNDS, (
        f"the second attempt inherited an exhausted grace budget: {second.rounds_used}"
    )


def test_review_counters_live_in_a_mutable_container_and_are_per_run(tmp_path):
    """SEAM. The turn and grace counters are new state on a frozen deps object that carries
    exactly one mutable container and no integer counter anywhere, with no in-place field
    assignment in the runtime — so the counters follow that precedent through a container or a
    small holder. An int field on the deps object cannot.

    Observable: the counters move across the calls that should update them while the deps
    object stays frozen, and two runs' states are independent — a second investigation in the
    same process starts at zero."""
    ReviewState = spec_import("defender.runtime.challenge_gate", "ReviewState")
    first, _run_a = main_deps(tmp_path / "a")
    second, _run_b = main_deps(tmp_path / "b")
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "empty-projection")])],
    )
    _close(first, "malicious", stages)
    state_a = ReviewState.of(first)
    state_b = ReviewState.of(second)
    assert state_a.turns == 1, f"the turn counter did not move: {state_a}"
    assert state_b.turns == 0, "a second run inherited the first run's counters"
    with pytest.raises((AttributeError, TypeError)):
        first.review_state = state_b  # the deps object stays frozen
