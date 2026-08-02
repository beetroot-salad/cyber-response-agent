"""#774 part 3 — the three review stages: their inputs, their grants, their outputs, and what
happens when one of them does not complete.

Every test here is one demand of `defender/tests/spec_graph_774.yaml`, named by that demand's
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
    REVIEW_FAILED,
    EVIDENCE_SILENT,
    FAST_TIMEOUT,
    FORCED_NONDISCRIMINATING,
    HANG_SECONDS,
    INCOHERENT,
    INFERENCE_TAGS,
    MALFORMED,
    OBSERVATION_TAGS,
    ROUNDS,
    TURNS,
    FakeReviewStages,
    StageFault,
    frontmatter_of,
    golden_document,
    lead_rows,
    main_deps,
    projection_of,
    run_dir_with_alert,
    spec_import,
    tail,
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
    missing either limb is rejected as malformed rather than silently read as an empty
    requirement list, which would take the immediate-inconclusive arm for the wrong reason."""
    deps, _run = main_deps(tmp_path)
    good = FakeReviewStages(challenger=[tail(UNSETTLED)],
                            projection=[projection_of([("l-001", "empty-projection")])])
    assert _close(deps, "malicious", good).outcome == CHALLENGED
    for missing in ({"assertion": "a"}, {"assertion": "a", "settled_by": None}):
        deps2, _r = main_deps(tmp_path / json.dumps(missing, sort_keys=True)[:8])
        broken = json.dumps({"counter_story": "s", "requirements": [missing]})
        stages = FakeReviewStages(challenger_fault=StageFault(malformed=broken))
        assert _close(deps2, "malicious", stages).outcome == MALFORMED, (
            f"an incomplete requirement {missing} was not rejected"
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


def test_an_empty_affordance_sample_omits_the_section_rather_than_sending_it_empty(tmp_path):
    """The cold-start case: the prior-close sampler returns nothing eligible. The section is
    omitted from the prompt entirely rather than sent as an empty list, inheriting the existing
    actor's behaviour — an empty menu reads to a model as "there are no prior closes", which is
    a claim the sampler never made.

    Observable: with no eligible tickets on disk the recorded prompt carries no affordance
    section header at all, and the review still runs to a verdict."""
    from defender.learning.tickets import ticket_seeds

    deps, run_dir = main_deps(tmp_path)
    cold = ticket_seeds.sample_seeds(
        {"rule": {"name": "sshd-pivot"}}, "case-x", "case-x",
        list_closed_fn=lambda _label: [], signature_label_fn=lambda _a: "sshd-pivot",
    )
    assert cold == [], "control: an empty closed-ticket pool is what a cold start looks like"
    stages = FakeReviewStages(challenger=[tail(SETTLED)])
    result = _close(deps, "malicious", stages)
    prompt = stages.challenger.only().prompt
    assert "prior close" not in prompt.lower(), "an empty affordance section was sent"
    for empty in ("()", "[]"):
        assert empty not in prompt, "an affordance section was sent empty"
    assert result.outcome is not None
    assert (run_dir / "report.md").exists()


def test_unparseable_output_never_scores_as_challenger_incoherence(tmp_path):
    """A sixth arm for output that will not parse — a truncated response, or a reply that is not
    a verdict — kept distinct from the value meaning the challenger's REASONING was incoherent.
    That value is a challenger-quality signal, and merging infrastructure noise into it inflates
    the apparent incoherence rate.

    Observable: a truncated reply takes the malformed arm; a well-formed reply the coherence
    checker rejects takes the incoherent arm; the two arms are different values, at the first
    attempt and inside a refinement round alike."""
    outcomes = {}
    for label, stages in (
        ("truncated", FakeReviewStages(challenger_fault=StageFault(malformed='{"counter_'))),
        ("not-a-verdict", FakeReviewStages(challenger_fault=StageFault(malformed="I cannot."))),
        ("incoherent", FakeReviewStages(challenger=[tail(UNSETTLED)],
                                        coherence_checker=["INCOHERENT"])),
    ):
        deps, _run = main_deps(tmp_path / label)
        outcomes[label] = _close(deps, "malicious", stages).outcome
    assert outcomes["truncated"] == outcomes["not-a-verdict"] == MALFORMED
    assert outcomes["incoherent"] == INCOHERENT
    assert MALFORMED != INCOHERENT


def test_a_review_that_cannot_complete_does_not_silently_commit_the_close(tmp_path):
    """RS9. A review that cannot complete closes the case as unresolved and records why — the
    only reading that satisfies both the challenged-before-it-commits obligation and the
    unresolvable-closes-as-unresolvable-with-its-reason obligation together.

    The accepted cost, recorded rather than discovered: a flaky model call turns a would-be
    confident close into an unresolved one.

    Observable: with the challenger call raising, the drafted confident disposition is NOT what
    lands on disk — the recorded disposition is inconclusive, the arm is the review-failed one, and
    the reason names the stage that failed."""
    deps, run_dir = main_deps(tmp_path)
    stages = FakeReviewStages(
        challenger_fault=StageFault(raises=RuntimeError("provider 503")),
    )
    result = _close(deps, "malicious", stages)
    assert result.outcome == REVIEW_FAILED
    fm = frontmatter_of(run_dir / "report.md")
    assert fm["disposition"] == "inconclusive", "a failed review silently committed the close"
    assert fm["reason"] == REVIEW_FAILED
    assert "challenger" in result.reason


def test_any_review_stage_that_cannot_complete_closes_the_case_unresolved_with_its_reason(tmp_path):
    """F7. The settled policy was written over "the challenger call raises or times out", but
    three calls run per attempt and two of them concurrently — so a critic-only or
    projection-only fault in the same window was uncovered. The policy covers ANY review stage
    failing to complete.

    Observable: each of the three stages, faulted alone while its siblings return cleanly,
    reaches the review-failed arm with an inconclusive disposition and a reason naming that stage.
    The all-succeed control does NOT decline, so the assertion is not green for want of a
    working path."""
    faults = {
        "challenger": {"challenger_fault": StageFault(raises=RuntimeError("down"))},
        "coherence_checker": {"coherence_checker_fault": StageFault(raises=RuntimeError("down"))},
        "oracle": {"projection_fault": StageFault(raises=RuntimeError("down"))},
    }
    for stage, kw in faults.items():
        deps, run_dir = main_deps(tmp_path / stage)
        stages = FakeReviewStages(challenger=[tail(UNSETTLED)], **kw)
        result = _close(deps, "malicious", stages)
        assert result.outcome == REVIEW_FAILED, f"a {stage}-only fault took {result.outcome}"
        assert frontmatter_of(run_dir / "report.md")["disposition"] == "inconclusive"
        assert stage in result.reason, f"the reason does not name {stage}"
    deps, run_dir = main_deps(tmp_path / "control")
    control = _close(deps, "malicious",
                     FakeReviewStages(challenger=[tail(UNSETTLED)],
                                      projection=[projection_of([("l-001", "has-projection")])]))
    assert control.outcome == FORCED_NONDISCRIMINATING, "control: no fault must not decline"


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
    assert result.outcome == REVIEW_FAILED, "a stage left pending did not fail closed"
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
        assert result.outcome == REVIEW_FAILED, f"{label} did not fail closed"
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
    tmp_path, monkeypatch,
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

    Observable: with the review role's provider key absent, the all-roles startup preflight
    fails before any model turn is driven; with it present the same preflight passes."""
    from defender.runtime import providers

    preflight = spec_import("defender.run", "preflight_role_models")
    CHALLENGER_DEF = spec_import("defender.runtime.review_roles", "CHALLENGER_DEF")
    var = providers.provider_for(CHALLENGER_DEF.model()).api_key_var
    monkeypatch.setenv(var, "sk-present")
    assert preflight() == 0, "control: the preflight passes when every role's key is present"
    monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(tmp_path / "absent.env"))
    assert preflight() != 0, (
        "a review role with no usable model config did not fail at startup"
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
    assert frontmatter_of(run_dir / "report.md")["reason"] == EVIDENCE_SILENT
