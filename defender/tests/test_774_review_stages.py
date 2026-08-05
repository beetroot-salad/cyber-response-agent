"""#774 part 3 — the three review stages: their inputs, their grants, their outputs, and what
happens when one of them does not complete.

Every test here is one demand of `spec-flow/specs/spec_graph_774.yaml`, named by that demand's
`discharged_by`.

TWO REFUTATIONS SHAPE THIS FILE AND ARE PINNED AS CORRECTIONS, NOT DESCRIBED:

* The blinding decision is a GRANT decision, not an input decision. At write time the review
  role's run dir IS the live investigation's dir, and both grant surfaces admit it
  unconditionally ahead of any read-roots widening (K28) — so narrowing extra read roots
  discharges nothing. Enforcement is no file-read grant at all, following the inlined-input
  pattern both existing pipeline stages already use (K30).
* Salt inheritance is NOT a general property of subagent binds (PR7/PR8). The live
  main-to-gather bind is the sole shared-salt case in the tree; every learning stage mints its
  own and two stage entrypoints cannot even accept a threaded value. A review role built on
  the gather precedent would hold the delimiter of the frame its own output returns inside.

THE COHERENCE CHECKER'S NAME WAS RESOLVED BY THE HUMAN AT AUTHORING TIME, not left to default:
`coherence_checker`, and every identifier in this suite spells it exactly. The name has to make
the role's limit legible — it receives only the counter-story and has no payload access, so it
can establish that a story contradicts itself but never that it is false. "Incoherent" and
"false" are verdicts this design deliberately separates, and the placeholder invited conflating
them.
"""
from __future__ import annotations

import json
import time

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.agent_definition import bind  # noqa: E402
from defender.tests._gate774 import (  # noqa: E402
    CHALLENGED,
    COMMITTED_OUTCOMES,
    FAILURE_KINDS,
    FAST_TIMEOUT,
    FORCED_INCONCLUSIVE,
    HANG_SECONDS,
    INCOHERENT,
    INFERENCE_TAGS,
    OBSERVATION_TAGS,
    ROUNDS,
    STAGE_ERROR,
    STANDS,
    TIMEOUT,
    TURNS,
    UNREADABLE,
    FakeReviewStages,
    StageFault,
    declared_lead_columns,
    frontmatter_of,
    golden_document,
    lead_cell,
    lead_rows,
    main_deps,
    permuted_lead_document,
    projection_of,
    run_dir_with_alert,
    spec_import,
    tail,
    worktree_package_guard,  # noqa: F401 — session-scoped autouse guard, see _gate774
)
from defender.tests.e2e._replay_harness import ReplayFn, Turn, drive  # noqa: E402

pytestmark = pytest.mark.e2e

#: The two knobs' environment names. Named once here so no assertion repeats a string that
#: could drift against the runtime's own spelling.
REVIEW_TIMEOUT_ENV = "DEFENDER_REVIEW_STAGE_TIMEOUT_SECONDS"
SUBAGENT_TIMEOUT_ENV = "LEARNING_SUBAGENT_TIMEOUT_SECONDS"

SETTLED = [("the pivot was provisioned", "l-001", "the session was unauthorized")]
UNSETTLED = [("the pivot was provisioned", None, "the session was unauthorized")]


def _close(deps, disposition, stages=None, **kw):
    close_investigation = spec_import("defender.runtime.close_tool", "close_investigation")
    return close_investigation(deps, disposition, stages=stages or FakeReviewStages(), **kw)


def _bounds(**kw):
    Bounds = spec_import("defender.runtime.challenge_gate", "Bounds")
    return Bounds(**({"extra_turns": TURNS, "grace_rounds": ROUNDS,
                      "stage_timeout": FAST_TIMEOUT} | kw))


def _record_path(run_dir, turn=1):
    review_record_path = spec_import("defender.runtime.challenge_gate", "review_record_path")
    return review_record_path(run_dir, turn)


def _seeded(deps, run_dir):
    """Put a REAL completed working document on disk, so every assertion about what the
    challenger does and does not receive is made against a real one."""
    (run_dir / "investigation.md").write_text(golden_document(), encoding="utf-8")
    return deps


def test_the_challengers_input_carries_observations_and_no_inference_layer(tmp_path):
    """The challenger receives the observation layer only: the graph facts, what was learned
    about them, and the real payloads — and no hypothesis weight, resolution verdict,
    authorization verdict or conclusion.

    Dropping only the concluding block was rejected: in three of three real completed working
    documents the resolution and authorization rows already name the settled interpretation in
    plain English, so the cut has to be at the observation/inference boundary, not the
    inference/conclusion one.

    The residual is accepted and stated: filtering is by block type, so a kept block's prose can
    still imply the reached disposition. What is withheld is the reached DISPOSITION; what is
    not withheld is the direction of reasoning.

    Observable: the assembled prompt the challenger fake records carries the observed-graph and
    learned-fact rows of the real document, and carries none of its inference blocks. The lead
    block is NOT asserted here — it arrives projected, and which of its columns arrive is a
    row-content property this test's altitude cannot see; that is its own demand."""
    deps, run_dir = main_deps(tmp_path)
    _seeded(deps, run_dir)
    stages = FakeReviewStages(challenger=[tail(SETTLED)])
    _close(deps, "malicious", stages)
    prompt = stages.challenger.only().prompt
    for tag in OBSERVATION_TAGS:
        assert tag in prompt, f"the observation layer is missing {tag!r}"
    for tag in INFERENCE_TAGS:
        assert tag not in prompt, f"the inference layer leaked {tag!r} to the challenger"


def test_the_challenger_sees_lead_identity_but_not_the_hypotheses_each_lead_tests(tmp_path):
    """RS18. The lead block reaches the challenger PROJECTED, not whole.

    Lead identity has to arrive: the challenger's own output contract requires it to name a
    lead id per settled assertion, so withholding the block entirely would make its contract
    unsatisfiable. But a lead row also carries the ids of the hypotheses the lead was run to
    test, and that is belief structure — the investigator's own inference, on the far side of
    the line the human drew when they cut the challenger's input at the observation layer.

    So the cut is per COLUMN, not per block: ids and targets arrive, the hypothesis pointers
    and the scheduling state do not. A demand asserting that a tag is present cannot express
    this — which is exactly how the whole block came to be admitted — so this one reads the
    rows.

    Observable: every lead id and target in the real document reaches the prompt; no hypothesis
    id from any lead row does, and none of the withheld columns' values appear."""
    deps, run_dir = main_deps(tmp_path)
    _seeded(deps, run_dir)
    stages = FakeReviewStages(challenger=[tail(SETTLED)])
    _close(deps, "malicious", stages)
    prompt = stages.challenger.only().prompt
    source = lead_rows(golden_document())
    assert source, "the fixture carries no lead rows to project"
    for row in source:
        assert row[0] in prompt, f"lead id {row[0]} did not reach the challenger"
        assert row[3] in prompt, f"lead {row[0]}'s target did not reach the challenger"
    hypothesis_ids = {h for row in source for h in row[4].split(",") if h.startswith("h-")}
    assert hypothesis_ids, "the fixture carries no hypothesis pointers to withhold"
    for hid in hypothesis_ids:
        assert hid not in prompt, f"lead rows carried hypothesis pointer {hid} to the challenger"


def test_the_new_roles_cannot_reach_the_live_working_document(tmp_path):
    """NEGATIVE, on all four cells. Neither new role holds a file-read grant or a confined-bash
    grant of any kind — not a narrowed one. At write time the role's run dir is the
    investigation's own dir and both grant surfaces admit it first and unconditionally, so a
    narrowing leaves the working document readable and the observation-layer cut undone.

    Positive control on the same cells: the role still receives its observation-layer input,
    inlined host-side (`test_the_challenger_still_receives_its_observation_layer_input`) — the
    same bytes reach it through the sanctioned path.

    Observable: both roles' declared tool sets carry neither capability, and a compiled policy
    for either admits no read of the live working document."""
    from defender.runtime.agent_definition import compile_policy_for

    CHALLENGER_DEF, COHERENCE_CHECKER_DEF = spec_import(
        "defender.runtime.review_roles", "CHALLENGER_DEF", "COHERENCE_CHECKER_DEF",
    )
    run_dir = run_dir_with_alert(tmp_path)
    for defn in (CHALLENGER_DEF, COHERENCE_CHECKER_DEF):
        assert not defn.tools.read, f"{defn.role} holds a file-read grant"
        assert not defn.tools.bash, f"{defn.role} holds a confined-bash grant"
        assert defn.bash_shapes == (), f"{defn.role} declares bash shapes"
        policy = compile_policy_for(defn, run_dir)
        assert str(run_dir) not in repr(policy), (
            f"{defn.role}'s compiled policy still reaches the live run dir"
        )


def test_the_challenger_still_receives_its_observation_layer_input(tmp_path):
    """POSITIVE CONTROL for the no-grant negative above, on the same cells: with no read grant
    at all the challenger is not blinded to the case — the same observation-layer bytes reach
    it, rendered host-side and inlined, which is the dominant pattern in the tree and the one
    both existing pipeline stages already follow.

    Observable: the challenger fake records a prompt carrying the real document's observed-graph
    rows and the alert, and it made no tool call to obtain them."""
    deps, run_dir = main_deps(tmp_path)
    _seeded(deps, run_dir)
    stages = FakeReviewStages(challenger=[tail(SETTLED)])
    _close(deps, "malicious", stages)
    call = stages.challenger.only()
    for tag in (":V ", ":E "):
        assert tag in call.prompt, (
            "the observation rows did not reach the challenger through the inlined path"
        )
    assert "sshd" in call.prompt, "the real payload text did not reach the challenger"


def test_the_challenger_tail_declares_unsettled_requirements_with_settled_by_and_if_false(tmp_path):
    """The challenger's output contract, as the merged pilot fixed it: what the account NEEDS
    that the data does not show either way — per assertion a `settled_by` limb and an
    `if_false` limb, with the fold forbidden from dropping any unsettled item.

    Observable: a tail whose unsettled items are complete parses and drives the gate; a tail
    missing either limb overrides the confident disposition rather than being silently read as
    an empty requirement list — which would leave the close STANDING, on the reading that the
    counter-story was fully settled, off a reply the gate could not read at all. Three
    conditions, three different outcomes, so the assertion discriminates without a spelling
    for "malformed": gated, overridden, or left standing.

    REPAIR: each malformed case gets its own run directory named by its ENUMERATION INDEX.
    Naming it from a prefix of the case's own JSON collided the two cases onto one directory —
    both begin `{"assert` — so the second never ran and the contract was asserted only against
    whichever case happened to be first. An index is collision-proof by construction rather
    than merely less likely, and it stays that way under any later widening of the tail's
    shape."""
    deps, _run = main_deps(tmp_path)
    good = FakeReviewStages(challenger=[tail(UNSETTLED)],
                            projection=[projection_of([("l-001", "empty-projection")])])
    assert _close(deps, "malicious", good).outcome == CHALLENGED
    incomplete = ({"assertion": "a"}, {"assertion": "a", "settled_by": None})
    for index, missing in enumerate(incomplete):
        deps2, _r = main_deps(tmp_path / f"incomplete-{index}")
        broken = json.dumps({"counter_story": "s", "requirements": [missing]})
        stages = FakeReviewStages(challenger_fault=StageFault(malformed=broken))
        outcome = _close(deps2, "malicious", stages).outcome
        assert outcome != STANDS, (
            f"an incomplete requirement {missing} was read as a settled counter-story and left "
            f"the confident close standing"
        )
        assert outcome == FORCED_INCONCLUSIVE, (
            f"an incomplete requirement {missing} was not rejected: {outcome}"
        )


def test_the_discriminating_set_is_silence_measured_against_declared_unsettled_requirements(tmp_path):
    """The discriminator is the JOIN — the projection's silence measured against the
    challenger's own declared-unsettled list — and neither half alone.

    This is a decision, not a reading. The design says the discriminator is the projection's
    silent rows and explicitly NOT a generated artifact; the merged pilot's load-bearing result
    is exactly such a generated list. All three independent readers answered one side of it
    without noticing they had decided anything.

    Observable: a lead the projection marks silent that the challenger never declared unsettled
    does NOT enter the discriminating set; a lead in both does. A test that only drove the
    first half would pass with either half wired."""
    deps, _run = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger=[tail(UNSETTLED)],
        projection=[projection_of([("l-001", "empty-projection"),
                                   ("l-009", "empty-projection")])],
    )
    result = _close(deps, "malicious", stages)
    assert result.outcome == CHALLENGED
    picked = {lead.lead_id for lead in result.material}
    assert picked == {"l-001"}, (
        f"the discriminating set is not the join of silence and declared-unsettled: {picked}"
    )


def test_the_challengers_exploration_menu_follows_the_direction_it_argues(tmp_path):
    """The exploration affordance is direction-conditional, mirroring the disjoint affordances
    the two existing actors have today: the technique menu when the counter-story argued is
    malicious, prior-close ticket history when it is benign — never both, never the wrong one.

    Carried as a known gap rather than closed here: nothing validates menu compliance today.
    No check anywhere reads a cited technique table back against the menu the role was given,
    and neither judge direction receives a menu at all.

    Observable: the prompt the challenger fake records carries the affordance its direction
    selects and not the other one, for both directions."""
    from defender.learning.pipeline.malicious_actor import mitre_corpus

    tactics = {tid for _t, tid, _n in mitre_corpus.CORPUS}
    seen = {}
    for disposition in ("benign", "malicious"):
        deps, _run = main_deps(tmp_path / disposition)
        stages = FakeReviewStages(challenger=[tail(SETTLED)])
        _close(deps, disposition, stages)
        seen[disposition] = stages.challenger.only().prompt
    malicious_menu = any(tid in seen["benign"] for tid in tactics)
    assert malicious_menu, "a benign close is challenged maliciously and needs the menu"
    assert not any(tid in seen["malicious"] for tid in tactics), (
        "the technique menu reached the benign counter-direction"
    )
    assert "closed" in seen["malicious"].lower(), (
        "the benign counter-direction did not get prior-close ticket history"
    )


def _eligible_closed_ticket() -> dict:
    """A REAL closed ticket the real sampler accepts — built here, through the real
    eligibility filter, rather than a canned seed object.

    Every field is one the filter genuinely reads: a key that is not this case's, a resolution
    that parses to a benign disposition, a seed-eligibility comment, and an event time inside
    the sampler's own lookback window. Constructing it in the test means the eligibility rules
    are re-probed on every run instead of a stale assumption being pinned once."""
    from datetime import UTC, datetime, timedelta

    from defender.scripts.case_history import case_ticket

    marker, _sep = case_ticket._seed_marker_and_separator(case_ticket._load_mapping())
    when = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    return {
        "key": "CASE-9001",
        "resolution": "benign — the destination host was reachable by design",
        "labels": ["sig:v2-cross-tier-ssh-pivot", f"evt:{when}"],
        "comments": [{"body": f"{marker}true"}],
    }


def test_the_closed_ticket_lister_is_a_value_the_challengers_input_builder_is_handed(tmp_path):
    """EXPECTED RED. SEAM. The challenger's input builder takes the closed-ticket lister as an
    injected value, defaulted, so a scenario can hand it a result without launching the
    subprocess the real lister shells out to.

    The seam is the contract, not scaffolding: the lister is a literal empty lambda at the
    production call site, deliberately, because fetching tickets means a subprocess inside a
    latency-bounded review. That makes the branch that renders a history section unreachable —
    so nothing establishes the section can exist at all, and the cold-start demand's positive
    control below cannot be written without this. A dependency the design gives no seam is a
    seam the contract owes.

    The parameter is DEFAULTED: a mandatory one would force every existing call site that
    reaches the challenger indirectly to change, for a value only a test supplies.

    Observable: the builder called with no lister still builds (production is untouched), and
    the same builder handed a lister returning one eligible ticket reaches that ticket's own
    content."""
    from defender.learning.core.directions import directions_for

    build_challenger_input = spec_import(
        "defender.runtime.review_roles", "build_challenger_input",
    )
    deps, _run = main_deps(tmp_path)
    direction = directions_for("malicious")[0]
    default_prompt = build_challenger_input(deps, "malicious", direction)
    assert "Argue the counter-disposition" in default_prompt, (
        "control: the builder's existing three-argument call must keep working unchanged"
    )
    ticket = _eligible_closed_ticket()
    injected = build_challenger_input(
        deps, "malicious", direction, list_closed_fn=lambda _label: [ticket],
    )
    assert ticket["key"] in injected, (
        "the injected lister's own result never reached the prompt — the seam exists but "
        "nothing is threaded through it"
    )


def test_an_empty_affordance_sample_omits_the_section_rather_than_sending_it_empty(tmp_path):
    """EXPECTED RED. The cold-start case: the prior-close sampler returns nothing eligible.
    The section is omitted from the prompt entirely rather than sent as an empty list — an
    empty menu reads to a model as "there are no prior closes", which is a claim the sampler
    never made.

    REPAIR: the pair is driven in ONE test, because the omission half alone is satisfied by a
    fixed sentence that is present and empty in substance — which is exactly what shipped, and
    exactly what three string-absence checks could not see. The complementary condition needs
    the seam the sibling demand above mints.

    The empty case is driven three ways that are genuinely different situations: no eligible
    tickets on disk at all (the live cold start), and a lister INVOKED that returns a real
    empty list. "Nobody asked" and "we asked and there were none" must render the same, and
    neither may render as a claim.

    Observable: with an empty result the prompt carries no history section and none of the
    sample's own shape; with one eligible ticket supplied through the same path it carries a
    section containing that ticket's case id and its recorded reason."""
    from defender.learning.core.directions import directions_for

    build_challenger_input = spec_import(
        "defender.runtime.review_roles", "build_challenger_input",
    )
    deps, run_dir = main_deps(tmp_path)
    direction = directions_for("malicious")[0]
    ticket = _eligible_closed_ticket()

    stages = FakeReviewStages(challenger=[tail(SETTLED)])
    result = _close(deps, "malicious", stages)
    live_cold = stages.challenger.only().prompt
    invoked_cold = build_challenger_input(deps, "malicious", direction,
                                          list_closed_fn=lambda _label: [])
    for label, prompt in (("live cold start", live_cold), ("invoked, empty", invoked_cold)):
        assert ticket["key"] not in prompt
        assert "closed-ticket history" not in prompt.lower(), (
            f"{label}: an affordance section was sent with nothing in it"
        )
        for empty in ("()", "[]"):
            assert empty not in prompt, f"{label}: an affordance section was sent empty"
    assert result.outcome is not None
    assert (run_dir / "report.md").exists()

    warm = build_challenger_input(deps, "malicious", direction,
                                  list_closed_fn=lambda _label: [ticket])
    assert "closed-ticket history" in warm.lower(), (
        "POSITIVE CONTROL: a non-empty sample produces no section at all, so nothing "
        "establishes the section the empty case is supposed to omit can ever exist"
    )
    assert ticket["key"] in warm, "the section rendered without the sample's own case id"
    assert "reachable by design" in warm, (
        "the section rendered without the sample's own recorded reason"
    )


def test_unparseable_output_never_scores_as_challenger_incoherence(tmp_path):
    """Output that will not parse — a truncated response, or a reply that is not a verdict —
    must not be scored as the challenger's REASONING being incoherent. Incoherence is a
    challenger-quality signal, and folding infrastructure noise into it inflates the apparent
    rate.

    THIS USED TO BE A CLAIM ABOUT TWO SPELLINGS AND IS NOW A CLAIM ABOUT TWO BEHAVIOURS AND A
    TYPED FIELD, which together are what it was always for. Both conditions override the
    confident finding, so the outcome cannot separate them; what does is that they cost
    different things. An incoherent story gets its refinement round — the gate re-asks the
    challenger, spends the grace budget, and records the requirements the story did produce. A
    reply the gate cannot read is terminal on the spot: no second ask, no grace consumed, an
    empty requirement list. An implementation that scores unparseable output as incoherence
    spends a refinement round on a stage that already failed, and fails here.

    THE RATE IS THE OTHER HALF, AND IT NEEDS A KEY SOMETHING CAN COUNT. "Folding infrastructure
    noise into the incoherence rate" is a claim about arithmetic over many runs, and the
    vocabulary collapse briefly left it with nowhere to live: the two conditions commit the same
    outcome, and the human-readable cause is a sentence whose wording this suite deliberately
    never fixes, so no query can key on it. The human's decision puts it back in a typed field
    of its own. That is a re-keying of this demand's metric half, not a retirement of it, and it
    is the stronger form — a slug a count can group by, rather than two prose strings that have
    to differ.

    Observable: the unreadable replies leave the grace budget untouched and the challenger
    called once; the incoherent story spends the whole grace budget and is asked twice; and the
    two name DIFFERENT typed failure kinds, both inside the closed vocabulary, so a count over
    finished runs can separate them."""
    seen = {}
    for label, stages in (
        ("truncated", FakeReviewStages(challenger_fault=StageFault(malformed='{"counter_'))),
        ("not-a-verdict", FakeReviewStages(challenger_fault=StageFault(malformed="I cannot."))),
        ("incoherent", FakeReviewStages(challenger=[tail(UNSETTLED)],
                                        coherence_checker=["INCOHERENT"])),
    ):
        deps, run_dir = main_deps(tmp_path / label)
        result = _close(deps, "malicious", stages)
        seen[label] = (result, len(stages.challenger.calls),
                       json.loads(_record_path(run_dir).read_text(encoding="utf-8")))
    for label in ("truncated", "not-a-verdict"):
        result, calls, record = seen[label]
        assert result.outcome == FORCED_INCONCLUSIVE, f"{label} took {result.outcome}"
        assert result.rounds_used == 0, (
            f"{label}: a reply the gate could not read still spent {result.rounds_used} "
            f"refinement round(s) — it is being scored as challenger incoherence"
        )
        assert calls == 1, f"{label}: the gate re-asked a stage whose reply it could not read"
        assert not record["requirement_list"], (
            f"{label}: a requirement list was recorded off a reply that did not parse"
        )
    incoherent, incoherent_calls, incoherent_record = seen["incoherent"]
    assert incoherent.outcome == FORCED_INCONCLUSIVE
    assert incoherent.rounds_used == ROUNDS, (
        f"the incoherent story did not spend its grace budget: {incoherent.rounds_used}"
    )
    assert incoherent_calls == ROUNDS + 1, (
        f"an incoherent story must be re-asked once per granted round, got {incoherent_calls} "
        f"challenger calls"
    )
    assert incoherent_record["requirement_list"], (
        "the incoherent story's own requirement list is absent from the record"
    )
    truncated = seen["truncated"][0]
    assert truncated.failure_kind in FAILURE_KINDS, (
        f"a reply the gate could not read names no countable failure kind: "
        f"{truncated.failure_kind!r}"
    )
    assert incoherent.failure_kind in FAILURE_KINDS, (
        f"a story that never became coherent names no countable failure kind: "
        f"{incoherent.failure_kind!r}"
    )
    assert truncated.failure_kind != incoherent.failure_kind, (
        "infrastructure noise and a challenger whose reasoning did not hold together are the "
        "same typed value, so an incoherence rate computed over finished runs counts both — "
        "which is the inflated rate this demand exists to prevent"
    )


def test_a_review_that_cannot_complete_does_not_silently_commit_the_close(tmp_path):
    """RS9. A review that cannot complete closes the case as unresolved and records why — the
    only reading that satisfies both the challenged-before-it-commits obligation and the
    unresolvable-closes-as-unresolvable-with-its-reason obligation together.

    The accepted cost, recorded rather than discovered: a flaky model call turns a would-be
    confident close into an unresolved one.

    EXPECTED RED on its second leg, which is a distinct symptom of the same bug rather than a
    restatement of the sibling above. What gets RECORDED matters independently of what arm the
    gate reports: today an unreadable projection commits a report whose reason says the
    evidence could not speak to the story — a finding ABOUT THE INVESTIGATION — when in fact
    the review never completed. A fix that only re-labelled the returned outcome would green
    the sibling and leave this red, so both are needed.

    WHAT CARRIES "the review broke" NOW THAT THE ARM IS GONE is the typed failure kind, which
    is a stronger place for it than a spelling was: it is already a closed vocabulary of its
    own (timeout, error, unreadable) and it is on both the return and the record. The report's
    free-text cause carries the human-readable half, and it is checked against the cause a
    GENUINELY SILENT projection writes — a review that could not be read must not read like a
    finding about the evidence, which is exactly the confusion the old arm existed to prevent.

    Observable: with the challenger call raising, and again with the projection returning
    something unreadable, the drafted confident disposition is NOT what lands on disk — the
    recorded disposition is inconclusive, a failure kind is named, and the cause is not the one
    a run whose evidence genuinely could not speak to the story writes."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger_fault=StageFault(raises=RuntimeError("provider 503")),
    )
    result = _close(deps, "malicious", stages)
    assert result.outcome == FORCED_INCONCLUSIVE
    fm = frontmatter_of(run_dir / "report.md")
    assert fm["disposition"] == "inconclusive", "a failed review silently committed the close"
    assert fm["outcome"] in COMMITTED_OUTCOMES
    assert result.failure_kind is not None, "a review that could not run named no failure kind"
    assert "challenger" in result.detail

    deps2, run2 = main_deps(tmp_path / "unreadable-projection")
    unreadable = _close(deps2, "malicious",
                        FakeReviewStages(challenger=[tail(UNSETTLED)],
                                         projection_fault=StageFault(malformed="not json at all")))
    fm2 = frontmatter_of(run2 / "report.md")
    assert fm2["disposition"] == "inconclusive"
    assert unreadable.failure_kind is not None, (
        "a projection the gate could not read failed the review with no named failure kind, so "
        "nothing typed says the review never completed"
    )

    deps3, run3 = main_deps(tmp_path / "genuinely-silent")
    silent = _close(deps3, "malicious",
                    FakeReviewStages(challenger=[tail(UNSETTLED)],
                                     projection=[projection_of([])]))
    assert silent.failure_kind is None, (
        "control: a valid, readable, zero-row projection is a finding about the evidence and "
        "must not be reported as a review that failed"
    )
    assert frontmatter_of(run3 / "report.md")["cause"] != fm2["cause"], (
        "a review that could not be read at all writes the same cause as one whose evidence "
        "genuinely could not speak to the story — the case records a conclusion about the "
        "investigation for something that never completed"
    )


def test_any_review_stage_that_cannot_complete_closes_the_case_unresolved_with_its_reason(tmp_path):
    """F7. The settled policy was written over "the challenger call raises or times out", but
    three calls run per attempt and two of them concurrently — so a critic-only or
    projection-only fault in the same window was uncovered. The policy covers ANY review stage
    failing to complete.

    EXPECTED RED, and this is the half the policy never reached. "Failing to complete" is not
    only the stage CALL breaking: a stage that RETURNS something the gate cannot read has not
    completed either. Two shapes, both driven, both grounded in what the real dependency does:
    a reply that is not JSON at all, and a reply that is well-formed JSON whose rows lack the
    fields the classifier reads — the likelier of the two, because a confused model emits valid
    JSON. Today both are swallowed by a handler around the parse step and silently reclassified
    as a finding about the EVIDENCE, with no failure kind at all: an unreadable review is
    recorded as a conclusion about the investigation.

    The boundary is stated so an implementation cannot drift past it: the policy routes on
    whether the output could be READ, never on how many rows it carried. A legitimately empty
    projection — valid, readable, zero rows because no executed lead touches the story — is a
    real finding, and with the outcome vocabulary collapsed the thing that says so is the
    ABSENCE of a failure kind rather than a spelling of its own. Both override the confident
    disposition; only one of them is the machinery failing. Collapsing that distinction too
    would make genuine silence read as a broken review, and the fix for the unreadable reply is
    made at the point both paths share.

    Observable: each of the three stages faulted alone overrides the disposition with a named
    failure kind and a detail naming that stage; both unreadable projection replies do the
    same; and the well-formed empty reply overrides the disposition with NO failure kind."""
    faults = {
        "challenger": {"challenger_fault": StageFault(raises=RuntimeError("down"))},
        "coherence_checker": {"coherence_checker_fault": StageFault(raises=RuntimeError("down"))},
        # #791: the live projection stage's dispatch key is re-keyed off its own role name
        # (never the retired offline oracle's) — the detail a fault reports now names it
        # "projection", not "oracle".
        "projection": {"projection_fault": StageFault(raises=RuntimeError("down"))},
    }
    for stage, kw in faults.items():
        deps, run_dir = main_deps(tmp_path / stage)
        stages = FakeReviewStages(challenger=[tail(UNSETTLED)], **kw)
        result = _close(deps, "malicious", stages)
        assert result.outcome == FORCED_INCONCLUSIVE, f"a {stage}-only fault took {result.outcome}"
        assert result.failure_kind is not None, f"a {stage}-only fault named no failure kind"
        assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"
        assert stage in result.detail, f"the detail does not name {stage}"

    unreadable = {
        "not-json": "not json at all",
        "wrong-shaped-rows": json.dumps({"leads": [{"oops": 1}]}),
    }
    for label, reply in unreadable.items():
        deps, run_dir = main_deps(tmp_path / f"projection-{label}")
        stages = FakeReviewStages(challenger=[tail(UNSETTLED)],
                                  projection_fault=StageFault(malformed=reply))
        result = _close(deps, "malicious", stages)
        assert result.outcome == FORCED_INCONCLUSIVE, (
            f"a projection reply the gate cannot read ({label}) took {result.outcome}"
        )
        assert result.failure_kind is not None, (
            f"the {label} reply failed the review with no named failure kind, so an unreadable "
            f"review is indistinguishable from a finding about the evidence"
        )
        assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"

    deps, silent_dir = main_deps(tmp_path / "legitimately-empty")
    empty = _close(deps, "malicious",
                   FakeReviewStages(challenger=[tail(UNSETTLED)],
                                    projection=[projection_of([])]))
    assert empty.outcome == FORCED_INCONCLUSIVE
    assert empty.failure_kind is None, (
        "CONTROL: a valid, readable, zero-row projection is a real finding about the evidence "
        f"and must not be reported as a review that failed — got {empty.failure_kind!r}"
    )
    assert frontmatter_of(silent_dir / "report.md")["outcome"] == FORCED_INCONCLUSIVE

    deps, run_dir = main_deps(tmp_path / "control")
    control = _close(deps, "malicious",
                     FakeReviewStages(challenger=[tail(UNSETTLED)],
                                      projection=[projection_of([("l-001", "has-projection")])]))
    assert control.outcome == FORCED_INCONCLUSIVE, "control: no fault must not decline"
    assert control.failure_kind is None, (
        "control: an unfaulted review reports a failure kind, so the assertions above are "
        "green on a field that is always set"
    )


def test_each_review_stage_call_carries_an_explicit_timeout_a_test_can_drive(tmp_path):
    """SEAM. The deadline is a value threaded into each stage call, readable and drivable from
    a test rather than buried in whichever helper the stage happens to route through.

    Assuming a deadline already exists was rejected, and the probe says why in both directions:
    the live path's own precedent for awaiting a subagent from a tool body carries no
    wall-clock bound at all (PS1), while the offline stage runner wraps every call in a
    per-role, env-backed one (PS2). Neither is the review stages' by inheritance — no seam
    exists yet — so which one they take is a design choice this demand makes explicit.

    Observable: every stage call the fakes record carries a positive deadline, and the deadline
    a scenario injects is the one the calls are driven with — a literal buried in the runtime
    would ignore it."""
    deps, _run = main_deps(tmp_path)
    stages = FakeReviewStages(challenger=[tail(UNSETTLED)])
    _close(deps, "malicious", stages, bounds=_bounds(stage_timeout=FAST_TIMEOUT))
    assert stages.calls, "no stage was driven"
    for call in stages.calls:
        assert call.timeout is not None, f"{call.role} was driven with no deadline"
        assert call.timeout == FAST_TIMEOUT, (
            f"{call.role} ignored the injected deadline and used {call.timeout!r}"
        )


def test_a_stage_that_never_returns_is_bounded_by_wall_clock_not_a_request_count_cap(tmp_path):
    """The bound is a WALL CLOCK bound that fires on a call which is simply still pending.

    This is the demand that fails if the review stages inherit the precedent nearest to them.
    The live tool-body-awaits-a-subagent path — structurally the same shape the close tool's
    review will be invoked from — has a request-COUNT cap and two structured-failure catches,
    and a count cap cannot fire while one call is still outstanding (PS1). A test asserting
    only that "a limit exists" would pass against that and still hang forever in production.
    A real per-call wall-clock bound does exist in this tree, on the offline stage runner
    (PS2), and it is the one to copy.

    Observable: a stage left pending is ended by the injected deadline in well under the time
    it would have run for, the gate reaches the review-failed arm, and the run records an
    inconclusive disposition rather than blocking."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(challenger=[tail(UNSETTLED)],
                              projection_fault=StageFault(hangs=True))
    started = time.monotonic()
    result = _close(deps, "malicious", stages, bounds=_bounds(stage_timeout=FAST_TIMEOUT))
    elapsed = time.monotonic() - started
    assert result.outcome == FORCED_INCONCLUSIVE, "a stage left pending did not fail closed"
    assert result.failure_kind is not None, "a stage left pending named no failure kind"
    assert elapsed < HANG_SECONDS, (
        f"the call ran {elapsed:.2f}s — the deadline never fired; a request-count cap cannot "
        f"end a pending call"
    )
    assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"


def test_a_timed_out_review_is_observably_distinct_from_one_that_failed(tmp_path):
    """A review that ran out of time and a review that broke must be tellable apart.

    Where a deadline does exist in this tree it produces no distinguishable signal: the
    timeout branch and the generic-exception branch raise the identical exception type,
    separated only by a message substring and a `__cause__` no caller reads, and every catch
    site found treats it as one blanket type (PS4). Inheriting that leaves the gate unable to
    tell "the model is slow" from "the model is broken" — one is a capacity problem and the
    other is a defect, and they get different responses from whoever reads the fleet.

    NOT a new arm. RS9 is settled: any review that cannot complete fails closed on the
    review-failed arm with its reason, and minting yet another arm here would re-open a human
    decision. The distinction is carried in the recorded reason and in the record's own typed
    field, which is what RS5 pins the record for.

    Observable: both conditions take the review-failed arm and record an inconclusive disposition,
    and their recorded reasons and record fields differ — with the difference readable as a
    typed value, not by matching a substring of a message."""
    seen = {}
    for label, kw in (
        ("timeout", {"projection_fault": StageFault(hangs=True)}),
        ("failure", {"projection_fault": StageFault(raises=RuntimeError("provider 500"))}),
    ):
        deps, run_dir = main_deps(tmp_path / label)
        stages = FakeReviewStages(challenger=[tail(UNSETTLED)], **kw)
        result = _close(deps, "malicious", stages,
                        bounds=_bounds(stage_timeout=FAST_TIMEOUT))
        assert result.outcome == FORCED_INCONCLUSIVE, f"{label} did not fail closed"
        assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"
        seen[label] = (result.failure_kind,
                       json.loads(_record_path(run_dir).read_text(encoding="utf-8")))
    assert seen["timeout"][0] != seen["failure"][0], (
        f"a timed-out review and a failed one report the same kind: {seen['timeout'][0]!r}"
    )
    assert seen["timeout"][0] == "timeout"
    assert seen["failure"][0] == "error"
    assert seen["timeout"][1]["failure_kind"] != seen["failure"][1]["failure_kind"], (
        "the record cannot tell a slow review from a broken one"
    )


def test_a_failed_review_names_a_typed_failure_kind_the_fleet_can_be_counted_by(tmp_path):
    """The ONE vocabulary this collapse adds back, and the case for each of its four members.

    Collapsing ten outcomes to three left every way a review can fail to deliver committing the
    same value, and left the only surviving distinction between them in a sentence whose wording
    this suite deliberately never pins. That is fine for a human reading one case and useless for
    the question the fleet asks — how often does the review break, and how — because prose nobody
    promised to keep stable is not a key anything can group by.

    SMALL, AND EACH MEMBER EARNS ITS PLACE BY A DIFFERENT RESPONSE, which is the bar set after
    ten members turned out to name conditions nothing acted on. A stage still pending at its
    deadline is capacity — move the bound, or the provider is slow, and the right answer may be
    to do nothing. A stage call that raised is a defect with a traceback to read. A stage that
    ANSWERED outside its own output contract has nothing down at all: the prompt or the contract
    is what needs work. And a stage that answered inside its contract whose content still could
    not be used is the challenger-quality signal — the counter-story never settled into internal
    consistency — which is the member the field exists for, because folding it into the
    unreadable one is precisely the inflated incoherence rate a sibling demand refuses.

    ABSENCE IS THE FIFTH STATE AND IS DRIVEN AS THE CONTROL. An override the EVIDENCE produced
    is a finding about the case, not a review that failed, so it names no kind at all — without
    that leg every assertion here is green against a field something always sets.

    WHERE IT HAS TO LAND. The value is countable only where counting happens. The numbered
    review record is read by no shipped code, so a value only on the record is a value only this
    suite can see; report.md is the file the run index and every downstream reader already open.
    It goes on both, and the two must agree, or the fleet's answer depends on which file was
    asked.

    Observable: production publishes the same closed four-member vocabulary this suite names;
    four conditions each reach their own member on the return, on the numbered record and in the
    report's frontmatter, with the four pairwise distinct; and a review that completed and
    overrode the finding on the evidence names no kind on any of the three."""
    published = spec_import("defender.runtime.close_tool", "FAILURE_KINDS")
    assert set(published) == set(FAILURE_KINDS), (
        f"production's failure-kind vocabulary is not the one this suite pins: "
        f"{sorted(published)} vs {sorted(FAILURE_KINDS)}"
    )
    conditions = (
        # a stage still pending when its deadline fires — capacity
        (TIMEOUT, {"projection_fault": StageFault(hangs=True)}),
        # a stage call that raised — a defect
        (STAGE_ERROR, {"challenger_fault": StageFault(raises=RuntimeError("provider 500"))}),
        # a stage that answered outside its own output contract — the same member the
        # unreadable-projection path takes, because nothing is down in either case
        (UNREADABLE, {"challenger_fault": StageFault(malformed="I cannot.")}),
        # a stage that answered inside its contract with content the gate still cannot use
        (INCOHERENT, {"coherence_checker": ["INCOHERENT"]}),
    )
    seen = {}
    for expected, kw in conditions:
        deps, run_dir = main_deps(tmp_path / expected)
        result = _close(deps, "malicious",
                        FakeReviewStages(challenger=[tail(UNSETTLED)], **kw),
                        bounds=_bounds())
        assert result.outcome == FORCED_INCONCLUSIVE, (
            f"{expected}: a review that could not deliver let the finding stand"
        )
        assert result.failure_kind == expected, (
            f"the condition this vocabulary exists to separate reports "
            f"{result.failure_kind!r}, not {expected!r}"
        )
        record = json.loads(_record_path(run_dir).read_text(encoding="utf-8"))
        assert record["failure_kind"] == expected, (
            f"{expected}: the review record disagrees with the return: "
            f"{record['failure_kind']!r}"
        )
        fm = frontmatter_of(run_dir / "report.md")
        assert fm.get("failure_kind") == expected, (
            f"{expected}: report.md carries {fm.get('failure_kind')!r} — the file every "
            f"shipped reader already opens cannot be counted by category, and the record that "
            f"can is read by nothing"
        )
        seen[expected] = result.failure_kind
    assert len(set(seen.values())) == len(conditions), (
        f"two of the four conditions collapse onto one member, so the distinction that member "
        f"was added for is not actually made: {seen}"
    )

    deps, control_dir = main_deps(tmp_path / "evidence-override")
    control = _close(deps, "malicious",
                     FakeReviewStages(challenger=[tail(UNSETTLED)],
                                      projection=[projection_of([("l-001", "has-projection")])]))
    assert control.outcome == FORCED_INCONCLUSIVE, (
        "control: the complementary condition must reach the same outcome, or the four "
        "assertions above are separated by the outcome rather than by the kind"
    )
    assert control.failure_kind is None, (
        f"CONTROL: an override the evidence produced names {control.failure_kind!r} — the "
        f"field is set on every close, so counting by it counts everything"
    )
    control_record = json.loads(_record_path(control_dir).read_text(encoding="utf-8"))
    assert control_record["failure_kind"] is None, (
        "CONTROL: the record names a failure kind for a review that did not fail"
    )
    assert not frontmatter_of(control_dir / "report.md").get("failure_kind"), (
        "CONTROL: report.md names a failure kind for a review that did not fail"
    )


def test_the_review_stage_deadline_defaults_to_450_seconds_and_is_env_overridable(
    tmp_path, monkeypatch,
):
    """The shipped deadline is 450 seconds, expressed the way this tree expresses its sibling
    per-role deadlines: an env-backed accessor with the value as its default, not a literal
    buried in a call — so an operator can move it without a code change.

    Why 450 and not a fifth new number: the merged pilot measured a gate firing at roughly
    three to five minutes on an eleven-lead case, so this is about 1.5x the observed worst
    case. Ordinary slowness will not trip it, which is what makes the timeout-versus-failure
    distinction a signal rather than noise, and it stays inside an analyst's tolerance for a
    blocked live investigation — the tree's 1800-second authoring values would not.

    THIS IS THE ONE PLACE THE NUMBER IS WRITTEN in the suite. Every other assertion about the
    deadline reads it from the accessor, because a value hardcoded in two places passes when
    both drift together.

    Observable: with no override the accessor returns 450; with an override it returns the
    override; and the gate's own default bounds read from the accessor rather than restating
    it — a buried literal survives the first assertion and fails this one."""
    stage_timeout, Bounds = spec_import(
        "defender.runtime.challenge_gate", "stage_timeout", "Bounds",
    )
    monkeypatch.delenv(REVIEW_TIMEOUT_ENV, raising=False)
    assert stage_timeout() == 450, "the shipped review-stage deadline is not 450 seconds"
    monkeypatch.setenv(REVIEW_TIMEOUT_ENV, "12")
    assert stage_timeout() == 12, "the deadline is not env-backed"
    assert Bounds(extra_turns=TURNS, grace_rounds=ROUNDS).stage_timeout == stage_timeout(), (
        "the gate's default deadline is a literal rather than the configured value"
    )


def test_moving_the_generic_subagent_deadline_does_not_move_the_reviews(monkeypatch):
    """NEGATIVE. The review stages' deadline and the tree's existing generic subagent deadline
    hold the same number today and are separate controls. The reuse is a coincidence of value,
    not a shared setting: a later change to the offline knob must not silently move the live
    gate's, and because they agree today that coupling would be invisible until it mattered.

    Positive control, on the same address under the complementary condition: the review's own
    knob does move the review's deadline — otherwise this passes against an accessor that
    ignores its environment entirely.

    Observable: with the sibling knob moved, the review deadline is unchanged; with the
    review's own knob moved, it changes."""
    from defender.learning.core import config as learning_config

    stage_timeout = spec_import("defender.runtime.challenge_gate", "stage_timeout")
    monkeypatch.delenv(REVIEW_TIMEOUT_ENV, raising=False)
    monkeypatch.delenv(SUBAGENT_TIMEOUT_ENV, raising=False)
    baseline = stage_timeout()
    assert learning_config.subagent_timeout() == baseline, (
        "control: the two knobs agree today, which is what makes a coupling easy to miss"
    )
    monkeypatch.setenv(SUBAGENT_TIMEOUT_ENV, "7")
    assert learning_config.subagent_timeout() == 7, "control: the sibling knob does move"
    assert stage_timeout() == baseline, (
        "the review deadline is wired to the generic subagent knob"
    )
    monkeypatch.setenv(REVIEW_TIMEOUT_ENV, "9")
    assert stage_timeout() == 9, "the review deadline ignores its own knob"


def test_a_review_roles_bind_mints_a_fresh_salt_and_never_receives_the_sessions(tmp_path):
    """SEAM. The review roles' bind follows the learning-stage precedent — it mints its own
    salt and never receives the investigation's.

    Precedenting them on the gather bind, which explicitly threads the investigation's own
    salt, was rejected: salt inheritance is not general — the gather bind is the sole
    shared-salt case in the tree and every learning stage mints its own. Inheriting the session
    salt would hand a role that reads attacker-influenced payloads the delimiter of the frame
    its own output returns inside, and the wrap does no content inspection or escaping, so a
    reader that has seen a salt can close that frame.

    Observable: the deps a review-role bind produces carry a salt that is neither the session's
    nor a second role's; the gather bind, driven on the same session for contrast, still shares
    it — which is what makes the assertion discriminating rather than vacuous."""
    from defender.agents import GATHER_DEF

    CHALLENGER_DEF, bind_review_role = spec_import(
        "defender.runtime.review_roles", "CHALLENGER_DEF", "bind_review_role",
    )
    deps, run_dir = main_deps(tmp_path)
    dfn = deps.defender_dir
    gather_deps = bind(GATHER_DEF, run_dir, salt=deps.salt, defender_dir=dfn)
    assert gather_deps.salt == deps.salt, (
        "control: the live gather bind is the tree's one shared-salt case"
    )
    first = bind_review_role(CHALLENGER_DEF, run_dir, defender_dir=dfn)
    second = bind_review_role(CHALLENGER_DEF, run_dir, defender_dir=dfn)
    assert first.salt != deps.salt, "the review role inherited the session's salt"
    assert first.salt != second.salt, "the review role's salt is not per-invocation"


def test_a_review_role_with_no_usable_model_config_fails_at_startup_not_once_per_investigation(
    tmp_path, monkeypatch, capsys,
):
    """A role with no usable model configuration fails at STARTUP, before an investigation pays
    for a review it cannot complete.

    Relying on the agent build to raise was rejected as provider-dependent: one provider family
    raises immediately on a missing key, another performs no key check at all and defers to the
    first live API call — so a demand written against "fails at build" would be silently true
    for one provider and silently false for the other.

    Leaving the failure to first use was rejected because of what it composes with: the agent is
    built fresh on every stage call, and the gate fails closed — so a misconfigured role does
    not stop the fleet, it downgrades confident investigations to unresolved one at a time,
    each after paying its full budget.

    REPAIR, on two counts.

    The failure is read off its CONTENT — the role the preflight names — not off a non-zero
    return, which every unrelated startup fault shares. A preflight covering only the pre-#774
    investigator-and-gather pair returns success on this input, so naming the role is the
    whole discrimination.

    And the key-absence leg is RETIRED rather than repaired, which is the honest answer to what
    the probes found. Isolating a run from a provider key means clearing four sources in strict
    precedence, ending at the main checkout's own environment file reached through git's common
    directory — and neither production caller exposes a seam that can redirect that last leg.
    The old leg pointed one variable at a missing file and passed only where that file happened
    not to carry that provider's key; for the provider every role in this tree actually resolves
    to, the key IS on disk there, which is precisely why the leg was red locally and green in
    CI. A test whose green depends on which secrets a developer's machine happens to hold is
    not a test. The model-configuration leg needs no isolation at all: the provider lookup
    fails before any key is read.

    SUBSTITUTION, recorded: the demand's stated subject is a REVIEW role, and the two review
    roles have no model setting of their own — they read the investigator's, so misconfiguring
    one necessarily misconfigures the investigator and the preflight names the investigator.
    The property is real and testable for every role that owns its setting; the subject is
    substituted for one that does, and the demand's intent — a misconfigured role fails at
    startup rather than once per investigation — is unchanged.

    Observable: with a role outside the pre-#774 pair pointed at a model no provider claims,
    the startup preflight fails and its message names THAT role; with the same configuration
    sound, it passes."""
    from defender.agents import AGENTS
    from defender.runtime import providers
    from defender.runtime.agent_role import AgentRole

    preflight = spec_import("defender.run", "preflight_role_models")
    CHALLENGER_DEF = spec_import("defender.runtime.review_roles", "CHALLENGER_DEF")
    var = providers.provider_for(CHALLENGER_DEF.model()).api_key_var
    monkeypatch.setenv(var, "sk-present")
    assert preflight() == 0, "control: the preflight passes when every role's config is sound"

    subject = AGENTS[AgentRole.JUDGE]
    assert subject.role not in (AgentRole.MAIN, AgentRole.GATHER), (
        "the subject must sit outside the pre-#774 pair or the widening is untested"
    )
    monkeypatch.setenv("JUDGE_MODEL", "no-provider-claims-this-model-9999")
    capsys.readouterr()
    assert preflight() != 0, (
        "a role outside the investigator-and-gather pair with an unusable model config did "
        "not fail at startup — the preflight is still the pre-#774 two-role check"
    )
    reported = capsys.readouterr().err
    assert subject.role.name in reported, (
        f"the preflight failed without naming the role at fault, so an operator cannot tell "
        f"it from any other startup fault: {reported!r}"
    )


def test_the_coherence_checker_receives_the_counter_story_and_nothing_else(tmp_path):
    """RS10. The coherence checker receives the counter-story and nothing else. Internal
    consistency is the only job it can do without payload access, and that constraint is what
    keeps it honest — a critic that can see the evidence stops checking coherence and starts
    re-litigating the case.

    Observable: the prompt this stage records carries the challenger's counter-story and none of
    the observation layer, the alert, or the projection's rows."""
    deps, run_dir = main_deps(tmp_path)
    _seeded(deps, run_dir)
    story = "the destination host was reachable by design"
    stages = FakeReviewStages(challenger=[tail(UNSETTLED, story=story)],
                              projection=[projection_of([("l-001", "empty-projection")])])
    _close(deps, "malicious", stages)
    prompt = stages.coherence_checker.only().prompt
    assert story in prompt, "the counter-story did not reach the coherence checker"
    for leaked in (":V ", ":E ", "sshd", "l-001"):
        assert leaked not in prompt, f"the coherence checker was handed {leaked!r}"


def test_the_projection_stage_input_is_built_from_the_live_run_not_a_learning_run_dir(tmp_path):
    """RS10. The projection stage gets a live-shaped input contract built from the run's OWN
    directory, not the learning-run geography it needs today.

    The design's claim that this stage is reused unchanged is withdrawn: its existing invocation
    threads a learning run directory and a story-derived trace prefix, and a live investigation
    supplies neither.

    Observable: the projection call records the live run's own directory and the live lead ids;
    nothing in what it was handed names a learning run dir or a story stem."""
    deps, run_dir = main_deps(tmp_path)
    (run_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"lead_id": "l-001", "system": "elastic"}), encoding="utf-8",
    )
    stages = FakeReviewStages(challenger=[tail(UNSETTLED)],
                              projection=[projection_of([("l-001", "empty-projection")])])
    _close(deps, "malicious", stages)
    call = stages.projection.only()
    assert str(run_dir) in call.prompt or "l-001" in call.prompt, (
        "the projection was not built from the live run's own directory"
    )
    assert "learning/runs" not in call.prompt, "a learning run dir reached the live projection"
    assert "actor_" not in call.prompt, "a story-derived trace prefix reached the live projection"


def test_the_review_stages_are_driven_through_an_injection_seam_on_the_entry_point(tmp_path):
    """SEAM. The three review stages are model-backed agent runs made from inside a tool body.
    Without a value the run is handed, they are live provider calls and no hermetic scenario can
    drive any arm of this gate — so the seam is part of the contract, not test scaffolding, and
    it lives on the entry point beside the five that already exist.

    Observable: a full replayed investigation driven with the injected stages reaches a recorded
    disposition, all three stages record the calls the gate made through the seam, and no real
    provider call was attempted."""
    run_dir = run_dir_with_alert(tmp_path)
    (run_dir / "investigation.md").write_text(golden_document(), encoding="utf-8")
    stages = FakeReviewStages(challenger=[tail(UNSETTLED)],
                              projection=[projection_of([])])
    turns = [Turn(tool_calls=[("close_investigation", {"disposition": "malicious"})]),
             Turn(text="done")]
    result = drive(run_dir, run_id="r-seam", salt="sess-salt", main=ReplayFn(turns),
                   review_stages=stages)
    assert result["output"] is not None
    for stage in (stages.challenger, stages.coherence_checker, stages.projection):
        assert stage.calls, (
            f"the gate did not drive {stage.role} through the injected seam"
        )
    assert frontmatter_of(run_dir / "report.md")["outcome"] == FORCED_INCONCLUSIVE


def test_the_lead_table_is_read_by_its_declared_header_not_by_column_position(tmp_path):
    """EXPECTED RED. The observation-layer cut projects the lead table to identity columns, and
    it must select them by the header the document DECLARES, not by fixed column positions.

    The cut is the one input-selection decision already settled: the challenger sees the graph
    facts and what was learned about them, never the investigator's belief structure. But the
    document the cut reads is authored by the investigator itself, and nothing validates the
    column order it chooses. Read by position, an investigator that writes its lead table with
    the columns in a different order pushes the wrong values through — silently, with no
    exception and no mismatch signal — so the guarantee is enforced by a convention the
    document's own author controls, and the next edit to the document format breaks it
    invisibly.

    Driven, not argued: the permuted document declares its own header honestly and swaps two
    columns in both the header and every row. A reader keyed on the declared names sees the
    same values under the same names; the shipped reader relabels one lead's target as its name.

    Positive control on the same address: the canonical document, whose column order happens to
    match the hardcoded positions, projects correctly either way — which is exactly why the
    defect is invisible today.

    Observable: for both documents, every lead's projected `name` and `target` equal what the
    SOURCE document declares under those names."""
    permuted = permuted_lead_document()
    canonical = golden_document()
    assert declared_lead_columns(permuted) != declared_lead_columns(canonical), (
        "control: the permuted fixture must actually declare a different column order"
    )
    for label, document in (("canonical", canonical), ("permuted", permuted)):
        deps, run_dir = main_deps(tmp_path / label)
        (run_dir / "investigation.md").write_text(document, encoding="utf-8")
        stages = FakeReviewStages(challenger=[tail(SETTLED)])
        _close(deps, "malicious", stages)
        prompt = stages.challenger.only().prompt
        projected = lead_rows(prompt)
        assert projected, f"{label}: no lead rows reached the challenger"
        columns = declared_lead_columns(prompt)
        for index, row in enumerate(projected):
            for column in ("id", "name", "target"):
                expected = lead_cell(document, index, column)
                got = row[columns.index(column)]
                assert got == expected, (
                    f"{label}: lead row {index}'s {column} arrived as {got!r} but the "
                    f"document declares {expected!r} — the cut reads by column position, so "
                    f"the author's own column order decides what the challenger is told"
                )


def test_a_projection_naming_a_lead_the_investigation_never_executed_fails_the_review(tmp_path):
    """EXPECTED RED. The host computes the executed-lead list and puts it in the projection
    stage's own prompt. The identifiers that come back must be a SUBSET of the list that went
    out; one that is not routes to the review-failure arm.

    Nothing bounds them today. An invented identifier — or one belonging to a different run —
    flows straight into the discriminating set and is handed to the investigator as a lead to
    go investigate, which spends a forced turn on a lead that does not exist. That is the
    forced turn's own economy inverted, reached from a direction no demand covered: the gate
    charges the investigation for a hallucination.

    Positive control on the same address under the complementary condition: a projection naming
    only leads the investigation did execute takes its ordinary arm and does hand material back
    — so the failure arm is the out-of-list identifier, not the projection stage being unusable.

    Observable: with one row naming a lead the run never executed, the review fails closed with
    a named failure kind and nothing is handed back; with every row naming an executed lead,
    the same shapes reach the challenged arm."""
    executed = "l-001"
    for label, rows, expect_failure in (
        ("in-list", [(executed, "empty-projection")], False),
        ("out-of-list", [(executed, "empty-projection"), ("l-999", "empty-projection")], True),
    ):
        deps, run_dir = main_deps(tmp_path / label)
        assert (run_dir / "gather_raw" / f"{executed}.lead.json").is_file(), (
            "control: the in-list lead is a lead the run genuinely executed"
        )
        assert not (run_dir / "gather_raw" / "l-999.lead.json").exists(), (
            "control: the violation names a lead this run never executed"
        )
        stages = FakeReviewStages(challenger=[tail(UNSETTLED)],
                                  projection=[projection_of(rows)])
        result = _close(deps, "malicious", stages)
        if not expect_failure:
            assert result.outcome == CHALLENGED, (
                f"control: an in-list projection took {result.outcome}"
            )
            assert [lead.lead_id for lead in result.material] == [executed]
            continue
        assert result.outcome == FORCED_INCONCLUSIVE, (
            f"a projection naming a lead the investigation never executed took "
            f"{result.outcome} — the identifier flowed into the discriminating set unchecked"
        )
        assert result.failure_kind is not None
        assert "l-999" not in {lead.lead_id for lead in result.material}, (
            "an unexecuted lead was handed back for the investigator to spend a turn on"
        )


def test_the_projection_stage_runs_under_a_role_of_its_own(tmp_path):
    """EXPECTED RED. The projection stage gets a role of its own, distinct from the
    challenger's and distinct from the offline learning oracle that happens to share its name.

    The design's whole argument for keeping this stage unleadable is that it is blind: single
    story, never told which side is being challenged, because a comparative judgment by an
    agent that knows which side is being argued can be led. Today that blindness lives in
    prompt text — the stage is the challenger's own role definition re-bound at one call site,
    so the role enum, the registry, the policy-compile surface and the startup preflight each
    count two review roles where the design describes three. The consequence is not
    bookkeeping: the direction-conditional exploration affordance already settled for the
    challenger names, by construction, the side being argued, so the next edit to the
    challenger's role leaks the direction into the stage built to be blind — through an edit
    nobody would think to review against this.

    Observable: a projection role definition exists, its role is its own enum member and not
    the offline oracle's, the registry the startup preflight iterates carries it, and its bind
    produces deps under that role with no read grant and no bash grant of any kind."""
    from defender.agents import AGENTS
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.agent_role import AgentRole

    PROJECTION_DEF, CHALLENGER_DEF, bind_review_role = spec_import(
        "defender.runtime.review_roles",
        "PROJECTION_DEF", "CHALLENGER_DEF", "bind_review_role",
    )
    assert PROJECTION_DEF.role is not CHALLENGER_DEF.role, (
        "the projection stage is still the challenger's role re-bound, so its blindness is a "
        "property of prompt text rather than of structure"
    )
    assert PROJECTION_DEF.role is not AgentRole.ORACLE, (
        "the live projection stage bound the OFFLINE learning oracle's role — a different "
        "thing, and the worst kind of wrong join, because it resolves"
    )
    assert PROJECTION_DEF.role in AGENTS, (
        "the projection role is absent from the registry the startup preflight and the "
        "policy-compile surface both iterate, so neither covers it"
    )
    run_dir = run_dir_with_alert(tmp_path)
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    assert not PROJECTION_DEF.tools.read, "the projection role holds a file-read grant"
    assert not PROJECTION_DEF.tools.bash, "the projection role holds a confined-bash grant"
    assert PROJECTION_DEF.bash_shapes == ()
    assert str(run_dir) not in repr(compile_policy_for(PROJECTION_DEF, run_dir))
    deps = bind_review_role(PROJECTION_DEF, run_dir, defender_dir=dfn)
    assert deps.role is PROJECTION_DEF.role


def test_the_operators_model_override_reaches_the_review_stages(monkeypatch):
    """EXPECTED RED. The model an operator names for one investigation reaches the review
    stages too, and the shipped default they fall back to has ONE home.

    Driven both directions before this was written: an override naming a model no provider
    serves passed the real startup preflight clean while the investigator was about to run on
    that broken name, and changing the override never moved any review stage's resolved model.
    The stages resolve through a function of zero parameters — structurally incapable of
    receiving the override — which also re-implements the default fallback with its own copy of
    the model id, on the stated grounds of an import cycle. So a perfectly working override
    buys the review nothing, and the startup check validates a model the run will not use.

    Observable: the review path's resolver returns the operator's explicit override when given
    one, prefers it over the ambient setting exactly as the investigator's resolver does, and
    with neither supplied returns the same shipped default the investigator's resolver
    returns."""
    from defender.runtime import driver

    resolve_review_model = spec_import(
        "defender.runtime.review_roles", "resolve_review_model",
    )
    override = "claude-operator-chose-this-9999"
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)
    assert resolve_review_model(override) == override, (
        "the operator's per-run model choice does not reach the review stages at all"
    )
    assert resolve_review_model(None) == driver.resolve_main_model(None), (
        "the review path keeps a second home for the shipped default, which drifts the first "
        "time that default moves"
    )
    monkeypatch.setenv("DEFENDER_MODEL", "ambient-setting-9999")
    assert resolve_review_model(override) == override, (
        "the explicit override does not outrank the ambient setting the way it does for the "
        "investigator"
    )
    assert resolve_review_model(None) == "ambient-setting-9999"
