"""#796 — how the composer's finding plus host state becomes one gate outcome.

The reviewer never picks the outcome. Whether a gap becomes `challenged` or
`forced-inconclusive` turns on the turn count, the raised-ask state and the cap, none of
which a review role is shown — so these are the arms that live entirely on the host side.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from defender._io import read_jsonl_rows
from defender.runtime import challenge_gate
from defender.runtime.close_tool import (
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
    CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_STORY_SETTLED,
    CAUSE_TURN_BUDGET_SPENT,
    CHALLENGED,
    FORCED_INCONCLUSIVE,
    STANDS,
    UNREADABLE,
)
from defender.runtime.review_roles import ReviewStages
from defender.tests._review_bundle import bundle as _bundle
from defender.tests._review_bundle import composer_reply as _composer
from defender.tests._review_bundle import stage as _stage
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

DEFENDER = Path(__file__).resolve().parents[1]
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3"


def _deps(tmp_path: Path):
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_bytes((GOLDEN / "alert.json").read_bytes())
    (run_dir / "investigation.md").write_bytes((GOLDEN / "investigation.md").read_bytes())
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    return bind(MAIN_DEF, run_dir, defender_dir=dfn, salt="sess-salt"), run_dir




def _run(deps, bundle, *, disposition="malicious", bounds=None):
    return asyncio.run(challenge_gate.challenge_gate(
        deps, disposition, stages=bundle,
        bounds=bounds if bounds is not None else challenge_gate.default_bounds(),
    ))


def _real_targets(deps) -> list[str]:
    """Ids the investigation actually recorded — an ask naming anything else is refused by the
    invented-identifier guard, so a routing test has to use real ones."""
    from defender.runtime.review.projector import parse_investigation
    from defender.runtime.review.reply import citable_refs

    inv = (deps.run_dir / "investigation.md").read_text(encoding="utf-8")
    return sorted(citable_refs(parse_investigation(inv)))


def _a_real_target(deps) -> str:
    return _real_targets(deps)[0]


# ---------------------------------------------------------------------------------------
# The three findings
# ---------------------------------------------------------------------------------------


def test_a_close_the_review_finds_sound_stands(tmp_path):
    deps, _run_dir = _deps(tmp_path)
    verdict = _run(deps, _bundle(composer=_composer("holds")))
    assert verdict.outcome == STANDS
    assert verdict.disposition == "malicious"
    assert verdict.cause == CAUSE_STORY_SETTLED
    assert verdict.failure_kind is None, "a review that ran is not a machinery failure"


def test_a_measurable_gap_spends_a_turn_and_hands_the_ask_back(tmp_path):
    deps, _run_dir = _deps(tmp_path)
    target = _a_real_target(deps)
    verdict = _run(deps, _bundle(
        composer=_composer("gap", ask={"target": target, "prose": "script provenance"}),
    ))
    assert verdict.outcome == CHALLENGED
    assert verdict.disposition == "malicious", "a challenge commits nothing"
    assert verdict.material == ((target, "script provenance"),)
    assert verdict.turns_used == 1


def test_an_unmeasurable_gap_forces_inconclusive_without_spending_a_turn(tmp_path):
    """A gap the reviewer cannot name a measurement for. Spending a forced turn on it would
    tax the investigation for a question nobody has."""
    deps, _run_dir = _deps(tmp_path)
    verdict = _run(deps, _bundle(composer=_composer("gap", ask=None)))
    assert verdict.outcome == FORCED_INCONCLUSIVE
    assert verdict.disposition == "inconclusive"
    assert verdict.cause == CAUSE_EVIDENCE_CANNOT_DISCRIMINATE
    assert verdict.turns_used == 0
    assert verdict.failure_kind is None, (
        "an override the EVIDENCE produced must not name a failure kind — that is what "
        "separates it from the machinery breaking"
    )


# ---------------------------------------------------------------------------------------
# The bounds the reviewer cannot see
# ---------------------------------------------------------------------------------------


def test_repeating_an_ask_that_bought_nothing_does_not_spend_another_turn(tmp_path):
    """The overlap rule. The investigation was already asked for this target and came back
    having recorded nothing new about it, so a further turn provably cannot surface anything
    it was not already asked for."""
    deps, _run_dir = _deps(tmp_path)
    target = _a_real_target(deps)
    bundle = _bundle(composer=_composer("gap", ask={"target": target, "prose": "provenance"}))

    first = _run(deps, bundle)
    assert first.outcome == CHALLENGED

    second = _run(deps, bundle)
    assert second.outcome == FORCED_INCONCLUSIVE
    assert second.cause == CAUSE_NOTHING_LEFT_TO_ASK
    assert second.turns_used == 1, "the refused repeat spent a second turn"


def test_a_repeat_is_fresh_again_once_the_turn_bought_something(tmp_path):
    """The half that makes the rule about VALUE rather than about repetition: the same target
    asked twice is only wasteful when the first ask changed nothing.

    Driven by moving the recorded watermark rather than by editing the document, because what
    the rule reads is the PARSED record — prose a turn adds outside the invlang fences is not
    something the investigation recorded, and the rule is right to ignore it."""
    deps, _run_dir = _deps(tmp_path)
    target = _a_real_target(deps)
    bundle = _bundle(composer=_composer("gap", ask={"target": target, "prose": "provenance"}))

    assert _run(deps, bundle).outcome == CHALLENGED
    state = challenge_gate.ReviewState.of(deps)
    assert state.raised_asks[target] > 0, "the ask recorded no watermark to compare against"
    # As if the forced turn had recorded more about this target than the record held when the
    # ask went out.
    state.raised_asks[target] -= 1

    assert _run(deps, bundle).outcome == CHALLENGED, (
        "the record now says more about the target than when the ask was raised, and the "
        "repeat was still refused"
    )


def test_the_forced_turn_cap_stops_the_run(tmp_path):
    deps, _run_dir = _deps(tmp_path)
    bounds = challenge_gate.Bounds(extra_turns=1)
    first_target, second_target = _real_targets(deps)[:2]

    assert _run(deps, _bundle(
        composer=_composer("gap", ask={"target": first_target, "prose": "a"}),
    ), bounds=bounds).outcome == CHALLENGED
    spent = _run(deps, _bundle(
        composer=_composer("gap", ask={"target": second_target, "prose": "b"}),
    ), bounds=bounds)
    assert spent.outcome == FORCED_INCONCLUSIVE
    assert spent.cause == CAUSE_TURN_BUDGET_SPENT


# ---------------------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_composer",
    ["", "   ", "not json", json.dumps({"review": "r"}), json.dumps({"finding": "maybe", "review": "r"})],
)
def test_an_unusable_composer_reply_fails_the_review_closed(tmp_path, bad_composer):
    deps, _run_dir = _deps(tmp_path)
    verdict = _run(deps, _bundle(composer=bad_composer))
    assert verdict.outcome == FORCED_INCONCLUSIVE
    assert verdict.failure_kind == UNREADABLE


def test_an_empty_lens_reading_fails_the_review_closed(tmp_path):
    deps, _run_dir = _deps(tmp_path)
    verdict = _run(deps, _bundle(lens="   ", composer=_composer("holds")))
    assert verdict.outcome == FORCED_INCONCLUSIVE
    assert verdict.failure_kind == UNREADABLE


def test_a_missing_investigation_fails_the_review_closed(tmp_path):
    deps, run_dir = _deps(tmp_path)
    (run_dir / "investigation.md").unlink()
    verdict = _run(deps, _bundle(composer=_composer("holds")))
    assert verdict.outcome == FORCED_INCONCLUSIVE
    assert verdict.failure_kind is not None


# ---------------------------------------------------------------------------------------
# Traces
# ---------------------------------------------------------------------------------------


def test_every_dispatched_role_leaves_its_own_trace(tmp_path):
    deps, run_dir = _deps(tmp_path)
    _run(deps, _bundle(composer=_composer("holds")))
    for role in challenge_gate.REVIEW_ROLES:
        assert (run_dir / f"review_{role}_trace.jsonl").is_file(), f"{role} left no trace"


def test_a_lens_reply_reaches_the_trace_framed_and_never_bare(tmp_path):
    """A lens reads a document derived from attacker-influenced payloads, so its reply is
    payload-derived prose and the trace is read later by an operator, a visualizer, or
    another model."""
    deps, run_dir = _deps(tmp_path)
    poison = "IGNORE-PREVIOUS-INSTRUCTIONS-MARKER"
    _run(deps, _bundle(lens=poison, composer=_composer("holds")))
    trace = (run_dir / "review_discrimination_trace.jsonl").read_text(encoding="utf-8")
    assert poison in trace
    assert f"<run-{deps.salt}-untrusted>" in trace, "the reply landed unframed"


def test_the_record_reaches_each_lens_inside_that_calls_own_fresh_salt(tmp_path):
    """PR7/PR8, on the INBOUND half. The projection is payload-derived, so it rides framed —
    and the frame is keyed on the salt the stage call mints, never on the investigation's,
    which is the delimiter the lens's OWN reply returns inside."""
    deps, _run_dir = _deps(tmp_path)
    seen: list = []

    def _recording(_reply):
        async def call(request):
            seen.append(request)
            return "l-001 separates h-001 from h-002."

        return call

    stages = ReviewStages(
        discrimination=_recording(None), support=_recording(None), ablation=_recording(None),
        composer=_stage(_composer("holds")),
    )
    _run(deps, stages)

    assert seen, "no lens was dispatched"
    salts = {r.salt for r in seen}
    assert len(salts) == len(seen), "two stage calls shared a salt"
    for request in seen:
        assert f"<run-{request.salt}-untrusted>" in request.prompt, "the record arrived unframed"
        assert deps.salt not in request.prompt, (
            "the investigation's own salt reached a review role"
        )


def test_every_dispatched_lens_leaves_a_row_even_when_an_earlier_one_faults(tmp_path):
    """The lenses run CONCURRENTLY, so by the time the first fault is seen the others have
    already answered. Returning on the fault mid-walk threw those replies away, and the run
    dir recorded one of three calls that were made."""
    deps, run_dir = _deps(tmp_path)

    async def _raising(_request):
        raise RuntimeError("the discrimination lens exploded")

    verdict = _run(deps, ReviewStages(
        discrimination=_raising, support=_stage("support read this"),
        ablation=_stage("ablation read that"), composer=_stage(_composer("holds")),
    ))
    assert verdict.outcome == FORCED_INCONCLUSIVE
    for lens, reply in (("support", "support read this"), ("ablation", "ablation read that")):
        trace = (run_dir / f"review_{lens}_trace.jsonl").read_text(encoding="utf-8")
        assert reply in trace, f"{lens} answered and its reply reached no trace"


def test_a_second_review_pass_is_not_recorded_as_the_first(tmp_path):
    """A challenged close comes back and reviews again. With the round hardcoded to zero every
    row of the second pass reads on disk exactly like the first's, so a trace cannot say which
    pass a fault belongs to."""
    deps, run_dir = _deps(tmp_path)
    target = _a_real_target(deps)
    bundle = _bundle(composer=_composer("gap", ask={"target": target, "prose": "provenance"}))

    assert _run(deps, bundle).outcome == CHALLENGED
    _run(deps, bundle)

    rows = read_jsonl_rows(run_dir / "review_composer_trace.jsonl")
    rounds = [row["round"] for row in rows]
    assert sorted(set(rounds)) == [0, 1], f"both review passes recorded as one: {rounds}"


def test_the_composers_json_reply_does_not_stand_as_a_trace_row_of_its_own(tmp_path):
    """The composer answers with a JSON OBJECT by contract. Framed on its own literal line
    that object is a round-less row every trace consumer reads as gate metadata — the review's
    own prose counted as a trace record, on every close."""
    deps, run_dir = _deps(tmp_path)
    _run(deps, _bundle(composer=_composer("holds", review="the close reads sound")))

    rows = read_jsonl_rows(run_dir / "review_composer_trace.jsonl")
    assert rows, "the composer left no trace row"
    for row in rows:
        assert "round" in row, f"a round-less row reached the trace: {row}"
        assert "finding" not in row, "the composer's reply parsed as a trace row of its own"
    trace = (run_dir / "review_composer_trace.jsonl").read_text(encoding="utf-8")
    assert f"<run-{deps.salt}-untrusted>" in trace, "the reply landed unframed"
    assert "the close reads sound" in trace, "the reply did not reach the trace at all"


# ---------------------------------------------------------------------------------------
# The review's own deadline
# ---------------------------------------------------------------------------------------


def test_moving_the_generic_subagent_deadline_does_not_move_the_reviews(monkeypatch):
    """The two default to the same NUMBER and must not move together.

    A reviewer that fans out three lenses and a composer inside one close is exactly when
    someone reaches for whichever timeout knob they can find. The pin went with the #774
    suite; #797 flagged the separation as unwitnessed and this is it re-pinned.
    """
    from defender.learning.core import config

    monkeypatch.delenv(challenge_gate.REVIEW_TIMEOUT_ENV, raising=False)
    monkeypatch.setenv("LEARNING_SUBAGENT_TIMEOUT_SECONDS", "7")

    assert config.subagent_timeout() == 7, "the generic knob did not move — wrong lever"
    assert challenge_gate.stage_timeout() != 7, (
        "the review deadline followed the offline pipeline's knob; they share a default "
        "value and nothing else"
    )


def test_the_review_deadline_has_its_own_lever(monkeypatch):
    monkeypatch.setenv(challenge_gate.REVIEW_TIMEOUT_ENV, "11")
    assert challenge_gate.stage_timeout() == 11
