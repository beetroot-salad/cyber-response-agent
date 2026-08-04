"""#774 part 2 — when the gate fires, what each condition does, and the two bounds it runs on.

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

from defender.agents import MAIN_DEF  # noqa: E402
from defender.learning.core.directions import directions_for  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.tests._gate774 import (  # noqa: E402
    BASE_REQUEST_LIMIT,
    CHALLENGED,
    FAST_TIMEOUT,
    FORCED_INCONCLUSIVE,
    RETRY_BUDGET,
    ROUNDS,
    STANDS,
    TURNS,
    FakeReviewStages,
    RenderWatcher,
    StageFault,
    decline,
    frontmatter_of,
    main_deps,
    one_fresh_lead_per_turn,
    projection_of,
    recording_store_factory,
    report_text,
    run_dir_with_alert,
    spec_import,
    tail,
    worktree_package_guard,  # noqa: F401 — session-scoped autouse guard, see _gate774
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
    straight through: no review stage is called, and the drafted disposition STANDS.

    The value this now returns is shared with every other condition that leaves the drafted
    disposition alone. What separates this one is not a label but the observation that no
    review stage was driven at all — which is what "the gate was never invoked" actually
    means, and it is the assertion below rather than a spelling.

    The accepted consequence, recorded rather than assumed: after this change unresolved runs
    are reviewed by nothing, and the gate manufactures unresolved runs on several of its own
    conditions.
    That non-obligation was granted on the ground that the offline pipeline serviced exactly
    those cases, and this run's scope removes that ground."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages()
    result = _close(deps, "inconclusive", stages)
    assert stages.calls == [], "an inconclusive draft must not spend a review call"
    assert result.outcome == STANDS
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

    Observable: the confident disposition is overridden on disk, no turn was spent, and the
    review did not FAIL — the override is a finding about the evidence, which is what the
    absent failure kind says now that both conditions share one outcome value."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "has-projection")])],
    )
    result = _close(deps, "malicious", stages)
    assert result.outcome == FORCED_INCONCLUSIVE
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"
    assert result.turns_used == 0
    assert result.failure_kind is None, (
        "a story every lead speaks to is a finding about the evidence, not a review that "
        "broke — and the failure kind is what carries that difference now"
    )


def test_the_attempt_past_the_bound_forces_inconclusive_instead_of_gating(tmp_path):
    """The bound, driven at RS14's real value rather than described. After two forced turns
    the third attempt records inconclusive instead of gating again, so a stubborn or
    unsatisfiable investigation terminates rather than looping.

    REPAIR: every attempt is scripted a discriminating lead none of the earlier ones raised, so
    the ONLY thing that can stop the third attempt is the bound. The old scenario repeated one
    lead, which makes attempt two fully-overlapping — refused its turn by the sibling demand,
    and the run then terminates before the bound is ever reached. Attempt three having
    something genuinely new to ask is also what makes this the cap and not the overlap rule:
    the bound has to bite on a run that could still have been asked something.

    The cap no longer has a value of its own — it commits the same override every other
    condition that refuses a confident finding commits — so the bound is observed on the TURN
    COUNT the capped attempt reports rather than on a spelling. That is the stronger reading
    anyway: an implementation that commits at the right moment for the wrong reason reports a
    turn count that does not equal the bound.

    Observable: the first two closes continue the investigation, the third commits an
    inconclusive disposition having spent exactly the bound's worth of turns."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=one_fresh_lead_per_turn(TURNS + 1),
    )
    results = [_close(deps, "malicious", stages) for _ in range(TURNS + 1)]
    outcomes = [r.outcome for r in results]
    assert outcomes[:TURNS] == [CHALLENGED] * TURNS, (
        f"expected {TURNS} forced turns before the bound bit, got {outcomes}"
    )
    assert outcomes[TURNS] == FORCED_INCONCLUSIVE
    assert results[TURNS].turns_used == TURNS, (
        f"the attempt past the bound reports {results[TURNS].turns_used} turns spent, not the "
        f"bound's {TURNS} — it committed for some reason other than the bound"
    )
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"


def test_a_story_no_executed_lead_can_touch_spends_no_turn(tmp_path):
    """RS13, re-keyed onto what it was always about. "Every executed lead is silent" and "no
    lead was executed at all" both mean the evidence cannot speak to the story, and the
    two-branch split read them as OPPOSITE evidence — so one of them spent a forced turn
    exactly where another turn cannot help, and burned the raised ceiling doing it.

    What RS13 bought was never a distinct spelling; it was that neither shape gates. The
    spelling is gone with the rest of the vocabulary, and the assertions that remain are the
    ones that kill the split: both shapes commit, neither continues the investigation, neither
    spends a turn, and neither hands anything back. An implementation that reads the two as
    opposites fails all four on one of them.

    Dropped as label-only: that this condition is a DIFFERENT value from the one where every
    lead speaks to the story. Both override a confident finding, both spend no turn, and no
    consumer ever distinguished them — the difference is a sentence for a human, and it is the
    cause's now.

    Observable: both degenerate shapes commit an inconclusive disposition, neither continues
    the investigation, neither spends a turn, and neither returns material."""
    for label, rows in (("every-lead-silent", [("l-001", "no-projection"),
                                               ("l-002", "empty-projection")]),
                        ("no-lead-executed", [])):
        deps, run_dir = main_deps(tmp_path / label)
        stages = FakeReviewStages(challenger=[tail(UNSETTLED)],
                                  projection=[projection_of(rows)])
        result = _close(deps, "malicious", stages)
        assert result.outcome != CHALLENGED, (
            f"{label} gated on a story the evidence cannot speak to — the forced turn's cost "
            f"with no probe it can buy"
        )
        assert result.outcome == FORCED_INCONCLUSIVE, f"{label} took {result.outcome}"
        assert result.turns_used == 0, f"{label} spent a turn a turn cannot help"
        assert result.material == (), f"{label} handed back material it has no lead for"
        assert frontmatter_of(run_dir / "report.md")["outcome"] == FORCED_INCONCLUSIVE
        assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"


def test_a_challenger_that_declines_to_argue_leaves_the_confident_close_standing(tmp_path):
    """RS17. A challenger that reads the case and has no counter-story to write DECLINES, and
    the investigator's confident close stands. The decline is recorded and judged; it is not an
    unresolvable case.

    This condition and a review that could not complete were a single value until the
    reconciliation caught it. They mean opposite things: a decline is the challenger having
    nothing to say about a case it understood, a review failure is the machinery breaking.

    RS17 fixed that by splitting the value. The value is now gone again — but the split is
    NOT, because it never rested on the spelling. A decline leaves the disposition standing
    and a failure overrides it, which puts them in different halves of the two-member committed
    vocabulary; and a failure carries a typed failure kind where a decline carries none. Two
    independent observables where there used to be one label, so the collapse strengthens this
    demand rather than weakening it.

    Observable: the drafted confident disposition survives onto disk, no turn is spent, and no
    failure kind is reported. The control is the complementary condition on the same address:
    the review machinery failing overrides the disposition AND names a failure kind, and the
    two write different causes."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(challenger=[decline()])
    result = _close(deps, "malicious", stages)
    assert result.outcome == STANDS
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "malicious", (
        "a deliberate decline must leave the investigator's confident close standing"
    )
    assert result.turns_used == 0
    assert result.failure_kind is None, (
        "a deliberate decline is a verdict the challenger reached, not the machinery breaking"
    )
    deps2, run2 = main_deps(tmp_path / "broke")
    broken = _close(deps2, "malicious",
                    FakeReviewStages(challenger_fault=StageFault(raises=RuntimeError("down"))))
    assert broken.outcome == FORCED_INCONCLUSIVE, (
        "control: a broken review must not leave a confident close standing the way a "
        "deliberate decline does"
    )
    assert broken.failure_kind is not None, (
        "control: a broken review reports no failure kind, so nothing typed separates it from "
        "a challenger that read the case and had nothing to say"
    )
    assert frontmatter_of(run2 / "report.md")["disposition"] == "inconclusive"
    assert broken.cause != result.cause, (
        "the two conditions the split exists to keep apart write the same cause, so a human "
        "reading either case cannot tell which happened"
    )


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


def test_a_second_attempt_whose_discriminators_were_all_already_raised_spends_no_turn(tmp_path):
    """EXPECTED RED, and the SOLE holder of this behaviour. A forced turn whose discriminating
    leads were ALL already raised must not be taken: it provably cannot surface anything the
    investigator was not already asked for, so the turn is not spent and the gate closes on
    what it has.

    Today that attempt takes the challenged arm, advances the run's turn counter, and hands the
    model back a message saying there is nothing new to investigate — the tax without the
    probe. Four sibling scenarios used to require exactly that and three more survived it only
    by accident of check ordering. All seven had their SCENARIO repaired — one genuinely new
    lead per attempt — rather than their intents retired, because what each of them pins (the
    bound, the per-run counters, the review's cost, the record series) is untouched by this
    rule. That leaves this the only test asserting it, so it refuses the near-misses itself.

    Three legs, one per way an implementation can skip a turn for the wrong reason:

      A — the plain repeat: the second attempt names the same single discriminating lead again.
      B — a DIFFERENT reply whose discriminating members are still wholly already raised (the
          repeated lead silent again, a second lead confirming the story). This refuses a skip
          keyed on the reply being the same as last time, or on the row set repeating: the rule
          is about which leads were RAISED, never about what the projection happened to say.
      C — the control, and the leg that stops the rule swallowing the mechanism it guards. The
          second attempt names the already-raised lead AND a genuinely new one; the turn IS
          spent and the new lead comes back. This refuses "skip whenever any lead repeats",
          "skip on every attempt after the first", and "skip whenever the sets overlap at all".

    THE ELEVENTH ARM QUESTION IS CLOSED HERE, AND THE ANSWER IS THAT THERE ISN'T ONE. This
    test used to also require the value taken to be neither the evidence-cannot-speak one nor
    the nondiscriminating one, because both of those RECORDED that no executed lead's evidence
    discriminated — false on this run, where one lead's evidence is genuinely silent and is a
    real discriminator. That assertion pinned a label: it was asking for a value whose spelling
    did not lie, and it drove the implementer to report the bound as exhausted on a run that
    stopped early precisely because it had nothing left to ask.

    With the outcome collapsed to "the confident finding did not stand", no spelling can lie
    about why — because no spelling says why. The claim moves to the cause, and it is checked
    as a DISTINCTION rather than as content: a run stopped by the overlap rule and a run
    stopped by the bound both commit the same outcome and must not write the same cause. That
    is the whole of what a new arm would have bought, at no vocabulary cost.

    Observable: on full overlap the turn count does not move, nothing is handed back, the run
    reaches a recorded inconclusive disposition, and its cause differs from the one a genuinely
    capped run writes; on partial overlap the turn is spent and the new lead returns."""
    causes = {}
    for label, second_rows in (
        ("plain-repeat", [("l-001", "empty-projection")]),
        ("same-leads-different-reply",
         [("l-001", "empty-projection"), ("l-002", "has-projection")]),
    ):
        deps, run_dir = main_deps(tmp_path / label)
        stages = FakeReviewStages(
            challenger=[tail(UNSETTLED)],
            projection=[projection_of([("l-001", "empty-projection")]),
                        projection_of(second_rows)],
        )
        first = _close(deps, "malicious", stages)
        assert first.outcome == CHALLENGED
        assert [x.lead_id for x in first.material] == ["l-001"]
        second = _close(deps, "malicious", stages)
        assert len(stages.projection.calls) == 2, (
            f"{label}: the second attempt never ran the projection, so the decision was not "
            f"taken on that attempt's own evidence"
        )
        assert second.turns_used == first.turns_used, (
            f"{label}: a turn was spent re-raising a gap already raised: "
            f"{first.turns_used} -> {second.turns_used}"
        )
        assert second.outcome != CHALLENGED, (
            f"{label}: the gate gated again on nothing new — the model is told to investigate "
            f"further and handed no lead to investigate"
        )
        assert second.material == (), f"{label}: material came back on an attempt that did not gate"
        assert second.outcome == FORCED_INCONCLUSIVE, (
            f"{label}: the attempt took {second.outcome} — it must close on what it has"
        )
        assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive", (
            f"{label}: the attempt neither gated usefully nor closed on what it had"
        )
        causes[label] = frontmatter_of(run_dir / "report.md")["cause"]

    capped_deps, capped_dir = main_deps(tmp_path / "genuinely-capped")
    capped_stages = FakeReviewStages(challenger=[tail(UNSETTLED)],
                                     projection=one_fresh_lead_per_turn(TURNS + 1))
    for _ in range(TURNS + 1):
        capped = _close(capped_deps, "malicious", capped_stages)
    assert capped.outcome == FORCED_INCONCLUSIVE, "control: the capped run must commit too"
    capped_cause = frontmatter_of(capped_dir / "report.md")["cause"]
    for label, cause in causes.items():
        assert cause != capped_cause, (
            f"{label}: a run that stopped because it had nothing left to ask writes the same "
            f"cause as one that exhausted the forced-turn bound — the two conditions are "
            f"indistinguishable to anyone reading the case, which is exactly what an eleventh "
            f"vocabulary member was proposed to fix"
        )

    deps, _run = main_deps(tmp_path / "partial-overlap")
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "empty-projection")]),
                    projection_of([("l-001", "empty-projection"),
                                   ("l-002", "empty-projection")])],
    )
    first = _close(deps, "malicious", stages)
    second = _close(deps, "malicious", stages)
    assert second.outcome == CHALLENGED, (
        f"control: an attempt carrying a lead nobody has been asked about took "
        f"{second.outcome} — the rule fires on any repeat rather than on full overlap"
    )
    assert second.turns_used == first.turns_used + 1, (
        "control: a turn that can still surface something must be spent"
    )
    assert [x.lead_id for x in second.material] == ["l-002"]


def test_a_refinement_round_carries_the_prior_story_and_the_gap_the_check_named(tmp_path):
    """EXPECTED RED. A refinement round is a SECOND ASK, not a retry. The round exists because
    the coherence checker found the counter-story internally inconsistent, so the round has to
    carry the story that failed and the specific inconsistency that was named — otherwise the
    challenger is re-asked the identical question and the grace budget buys a coin flip.

    The rounds-consumed count is the design's only stated evidence-strength signal: a story
    that survived one refinement is supposed to read differently from a cold pass. A
    contextless retry makes that number mean nothing.

    Observable: the second challenger call's prompt carries the first round's counter-story
    and the coherence checker's own stated gap; the first call's prompt carries neither, so
    the two calls are not the same prompt twice."""
    story = "the pivot was an approved break-glass workflow"
    gap = "INCOHERENT: break-glass approvals are logged and no approval row exists"
    deps, _run = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED, story=story), tail(UNSETTLED, story=story)],
        coherence_checker=[gap, "COHERENT"],
        projection=[projection_of([("l-001", "empty-projection")])],
    )
    _close(deps, "malicious", stages, bounds=_bounds(grace_rounds=1))
    calls = stages.challenger.calls
    assert len(calls) == 2, f"the refinement round did not run: {len(calls)} challenger calls"
    assert story not in calls[0].prompt, (
        "control: the first round cannot already carry a story that does not exist yet"
    )
    assert story in calls[1].prompt, "the refinement round does not carry the story it refines"
    assert gap in calls[1].prompt, (
        "the refinement round does not carry the inconsistency the coherence checker named — "
        "it is a contextless retry of the same question"
    )


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

    EXPECTED RED, and this is the repair that makes the demand discriminate at all. Moving the
    cap alone proves nothing: the base is what a cheating implementation restates, and the
    shipped base and a hardcoded copy of it are the same number, so the old assertion held for
    both. The base becomes a value the bounds object carries, alongside the cap the bounds
    object already carries — the injection point, rather than the suppression of the discipline
    this suite states in its own preamble. The suite's own baseline constant STAYS a fixed
    record of the shipped default; it is not the injection point, and the two must not be
    conflated or the sibling test below disagrees with this one about what "the base" is.

    Observable: the ceiling tracks a MOVED base and a MOVED cap independently — every
    combination equals base plus cap — and the shipped default bounds still carry the shipped
    base."""
    raised_request_limit, Bounds = spec_import(
        "defender.runtime.challenge_gate", "raised_request_limit", "Bounds",
    )
    assert driver.DEFAULT_REQUEST_LIMIT == BASE_REQUEST_LIMIT, (
        "the shipped base moved; this suite's record of it must be re-derived"
    )
    assert Bounds(extra_turns=TURNS, grace_rounds=ROUNDS).base_request_limit == BASE_REQUEST_LIMIT, (
        "the shipped default bounds do not carry the shipped base"
    )
    seen = {(base, cap): raised_request_limit(_bounds(base_request_limit=base, extra_turns=cap))
            for base in (BASE_REQUEST_LIMIT, 7, 41) for cap in (1, TURNS, 4)}
    assert seen == {(base, cap): base + cap for base, cap in seen}, (
        f"the ceiling does not track both terms: {seen}"
    )


def test_a_run_the_gate_never_fires_on_still_gets_the_raised_ceiling(tmp_path):
    """RS7's accepted consequence, pinned rather than noted: every run pays the raised ceiling
    whether or not the gate ever fires. A run that never closes at all — and therefore never
    reaches the gate — still gets the raised allowance, because the ceiling is a property of
    the run, not of a review that happened.

    EXPECTED RED, same repair as its sibling above and for the same reason: counting
    base-plus-two discriminated nothing while the shipped cap was two and the cheat's literal
    was two. The run is driven with a base and a cap BOTH moved off their shipped values, so
    the observed ceiling can only follow if it is computed from what the run was handed.

    Observable: a model that never stops makes exactly moved-base-plus-moved-cap requests
    before the limit terminates it, and the run reports the same number."""
    run_dir = run_dir_with_alert(tmp_path)
    model = NeverEndsModel(run_dir)
    moved_base, moved_cap = 8, 3
    result = drive(run_dir, run_id="r-ceiling", salt="sess-salt", main=model,
                   review_stages=FakeReviewStages(),
                   bounds=_bounds(base_request_limit=moved_base, extra_turns=moved_cap))
    assert model.calls == moved_base + moved_cap, (
        f"the run did not get the ceiling it was handed: {model.calls} requests"
    )
    assert result["requests"] == moved_base + moved_cap


def test_the_message_stores_request_limit_mirror_moves_with_the_raised_ceiling(tmp_path):
    """EXPECTED RED. The component that decides what to record in the run's message store
    mirrors the framework's request-limit check so a round that never actually happens is not
    committed anyway. That mirror is pinned to the UNRAISED base while the run is given the
    raised one, so the two rounds the raise exists to buy are withheld from the store and skip
    the history-compaction path entirely — even though those rounds genuinely execute and the
    model is handed raw, unrendered history for them.

    This is the drift the two ceiling demands above exist to prevent, already shipped, in the
    place nobody was looking: the ceiling has exactly three readers and this is the third.
    No reported defect named it and no test covered it.

    The store's eventual CONTENTS cannot see this — the round after a withheld one re-ingests
    what was withheld — so the observable is which rounds reached the compaction path. Only
    the doomed round, the one the framework refuses, may be withheld from it.

    Observable: on a run driven to a ceiling it was handed, every round that actually happened
    reaches the render path and exactly one round — the last — does not."""
    run_dir = run_dir_with_alert(tmp_path)
    factory, captured = recording_store_factory()
    model = RenderWatcher(run_dir, captured)
    moved_base, moved_cap = 8, 2
    drive(run_dir, run_id="r-mirror", salt="sess-salt", main=model,
          review_stages=FakeReviewStages(), store_factory=factory,
          bounds=_bounds(base_request_limit=moved_base, extra_turns=moved_cap))
    assert model.calls == moved_base + moved_cap, (
        f"the run did not reach the ceiling it was handed: {model.calls}"
    )
    deltas = model.render_deltas(captured)
    steady = max(set(deltas), key=deltas.count)
    withheld = [i for i, d in enumerate(deltas) if d != steady]
    assert withheld == [len(deltas) - 1], (
        f"rounds withheld from the compaction path: {withheld} of {len(deltas)} — only the "
        f"doomed final round may be, and rounds {withheld[:-1]} genuinely happened "
        f"(per-round render counts {deltas})"
    )


def test_the_reviews_own_calls_cannot_push_the_investigation_into_the_request_limit(tmp_path):
    """The review's three model calls per attempt must not be charged against the allowance
    that terminates the investigation, or the gate converts closes it would have reviewed into
    truncations — and the design's own text says a truncated run never reaches a close, so the
    gate would erase its own subjects.

    The pre-existing gap where the run's cost sum omits every gather subagent call is NOT
    fixed here; that failure clause is already true today, independent of this change.

    REPAIR: each of the three close attempts gets its own fresh discriminating lead. With one
    lead repeated, attempt two is a fully-overlapping attempt — refused its turn, so it COMMITS
    — and the third close is then refused outright by the terminality rule, leaving this test
    counting the stage calls of two attempts against a bound written for three.

    Observable: a run driven to the cap, with three stage calls per attempt, still ends on its
    own terms rather than truncated, and the main agent's request count is untouched by the
    review."""
    run_dir = run_dir_with_alert(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=one_fresh_lead_per_turn(TURNS + 1),
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
    call site — a scenario must be able to drive the commit the bound forces without editing
    the runtime, and
    the ceiling that is derived from it must move with it.

    REPAIR: the second attempt is scripted its own fresh discriminating lead. Repeating one
    lead left two independent reasons the second attempt could decline to gate — the injected
    cap, and the fully-overlapping-attempt rule — so the outcome no longer told them apart, and
    which of the two an implementation checked first decided whether this test passed.

    Observable: driving the gate with a cap of one commits on the second attempt, having spent
    exactly one turn, where the shipped value would still be gating."""
    deps, _run = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=one_fresh_lead_per_turn(2),
    )
    attempts = [_close(deps, "malicious", stages, bounds=_bounds(extra_turns=1))
                for _ in range(2)]
    outcomes = [a.outcome for a in attempts]
    assert outcomes == [CHALLENGED, FORCED_INCONCLUSIVE], (
        f"the injected cap was not honoured: {outcomes}"
    )
    assert attempts[1].turns_used == 1, (
        f"the second attempt committed having spent {attempts[1].turns_used} turns, not the "
        f"injected cap of 1 — something other than the cap stopped it"
    )


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

    At zero the forced-turn cap collapses the first forced turn into an immediate commit, leaving no
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

    REPAIR: the second attempt gets its own fresh discriminating lead, so it is a genuine
    second gate attempt. Repeating one lead makes it a fully-overlapping attempt, which is
    refused its turn — and then what this test reads as "the second attempt's grace budget"
    would be whatever rounds count that refusal happens to report. The projection runs once per
    ROUND rather than once per attempt, so the script is per round; only the coherent round's
    reply is ever classified, and it is that one that has to carry the fresh lead.

    Observable: an incoherent story on the first attempt consumes its round; the second attempt
    in the same run still gets its own round, and the record shows rounds-consumed per attempt
    rather than one running total."""
    deps, _run = main_deps(tmp_path)
    first_attempt, second_attempt = one_fresh_lead_per_turn(2)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        coherence_checker=["INCOHERENT", "COHERENT", "INCOHERENT", "COHERENT"],
        projection=[first_attempt, first_attempt, second_attempt, second_attempt],
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

    REPAIR: the two bindings are taken over the SAME run directory. The old scenario used two
    different temp run dirs, which a process-global keyed on the run directory passes
    identically — and a process-global keyed on the run directory is exactly what the counters
    had to move off. The observation is BEHAVIOURAL: what each binding's own close reports,
    not what field the state is stored in. Requiring the state to be readable as an attribute
    on the dependencies object was retired as vestigial — the per-run behaviour is the
    contract, and the frozen-deps check below is kept because it is a different claim.

    REPAIR (second): each of the three attempts is scripted its own fresh discriminating lead.
    The counter only advances on a turn the gate actually spends, and with one lead repeated
    the first binding's SECOND attempt is fully overlapping — refused its turn — so this test
    would read a counter that correctly did not move as a counter that failed to advance.

    Observable: two independent bindings over one run directory hold independent counters —
    the second's first attempt is its own first forced turn, not the first's second — while
    the deps object refuses in-place assignment."""
    ReviewState = spec_import("defender.runtime.challenge_gate", "ReviewState")
    shared = tmp_path / "one-run"
    first, run_dir = main_deps(shared)
    second = bind(MAIN_DEF, run_dir, defender_dir=first.defender_dir, salt="sess-salt")
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=one_fresh_lead_per_turn(3),
    )
    a1 = _close(first, "malicious", stages)
    a2 = _close(first, "malicious", stages)
    b1 = _close(second, "malicious", stages)
    assert (a1.turns_used, a2.turns_used) == (1, 2), (
        f"one binding's own counter did not advance: {(a1.turns_used, a2.turns_used)}"
    )
    assert b1.turns_used == 1, (
        f"a second binding over the same run directory inherited the first's counter "
        f"({b1.turns_used}) — the state is shared by directory, not held per run"
    )
    with pytest.raises((AttributeError, TypeError)):
        first.review_state = ReviewState()  # the deps object stays frozen
