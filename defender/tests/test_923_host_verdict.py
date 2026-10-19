"""#923 - the verdict the host reaches (`unresolved`): every host-terminated close commits it; model closes do not."""
from __future__ import annotations

import asyncio

import pytest

from defender._vocab import DISPOSITION_ENUM, DISPOSITION_VALUES
from defender.runtime import challenge_gate
from defender.runtime.close_tool import (
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
    CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_REVIEW_INCOMPLETE,
    CAUSE_TURN_BUDGET_SPENT,
    FAILURE_KINDS,
    FORCED_INCONCLUSIVE,
    REPORT_CAUSES,
)
from defender.tests import _review_bundle
from defender.tests._invlang_warn_836 import recording_stages
from defender.tests._spec923 import (
    BYPASS_BY_MEMBER,
    GAP_MEMBER,
    MEMBER,
    PAYING_ROW,
    ab3_deps,
    close,
    committed,
    committed_verdict,
    drive_to_retry_exhaustion,
    gapless,
    main_deps,
    paid,
    pays_every_price,
    real_targets,
)
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)


def _overrule(deps, *, ask=None, bounds=None):
    """One close through the real gate whose composer reports a gap."""
    return close(
        deps, "malicious",
        stages=_review_bundle.bundle(composer=_review_bundle.composer_reply("gap", ask=ask)),
        bounds=bounds,
    )


# Demand #0 — the return-value contract.

def test_a_host_terminated_close_commits_the_fifth_member_verbatim(tmp_path):
    """Every host-terminated close commits the literal string `unresolved` into `report.md`'s frontmatter `disposition` field, verbatim and unnormalized."""
    deps, run_dir = ab3_deps(tmp_path)
    _overrule(deps)

    assert committed_verdict(run_dir) == MEMBER, (
        "the host's own verdict did not reach the committed report verbatim"
    )
    frontmatter = committed(run_dir)
    assert frontmatter["disposition"] == MEMBER
    assert frontmatter["outcome"] == FORCED_INCONCLUSIVE, (
        "the OUTCOME name moved with the verdict — it is a different vocabulary, spanning a "
        "different sink, and moving it silently re-keys every reader of a close attempt"
    )
    assert MEMBER in DISPOSITION_VALUES
    assert DISPOSITION_VALUES[-1] == MEMBER, (
        "the member was inserted rather than appended — the refusal text and the tool schema "
        "are read in one round trip, so its place in the ordered tuple is load-bearing"
    )


# O2 — the five producers (coverage) and the universal (the obligation).

def test_all_three_gate_overrule_arms_commit_the_new_state(tmp_path):
    """Each of the gate's three overrule arms — evidence-cannot-discriminate, nothing-left-to-ask, turn-budget-spent — commits `unresolved`, and `cause`..."""
    deps, run_dir = ab3_deps(tmp_path / "arm1")
    assert _overrule(deps).cause == CAUSE_EVIDENCE_CANNOT_DISCRIMINATE
    assert committed_verdict(run_dir) == MEMBER

    deps2, run2 = ab3_deps(tmp_path / "arm2")
    target = real_targets(deps2)[0]
    assert _overrule(deps2, ask={"target": target, "prose": "provenance"}).outcome == "challenged"
    second = _overrule(deps2, ask={"target": target, "prose": "provenance"})
    assert second.cause == CAUSE_NOTHING_LEFT_TO_ASK
    assert committed_verdict(run2) == MEMBER

    deps3, run3 = ab3_deps(tmp_path / "arm3")
    first_target, second_target = real_targets(deps3)[:2]
    bounds = challenge_gate.Bounds(extra_turns=1)
    assert _overrule(
        deps3, ask={"target": first_target, "prose": "a"}, bounds=bounds,
    ).outcome == "challenged"
    spent = _overrule(deps3, ask={"target": second_target, "prose": "b"}, bounds=bounds)
    assert spent.cause == CAUSE_TURN_BUDGET_SPENT
    assert committed_verdict(run3) == MEMBER

    # The four causes stay four and stay apart: a single sentence for every overrule would make
    # the operator's only "which arm" signal unreadable.
    assert len({
        CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_NOTHING_LEFT_TO_ASK,
        CAUSE_TURN_BUDGET_SPENT, CAUSE_REVIEW_INCOMPLETE,
    }) == 4
    assert {
        CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_NOTHING_LEFT_TO_ASK,
        CAUSE_TURN_BUDGET_SPENT, CAUSE_REVIEW_INCOMPLETE,
    } <= set(REPORT_CAUSES)


def _raising_stage(exc: BaseException):
    async def call(_request):
        raise exc

    return call


def _slow_stage(seconds: float):
    async def call(_request):
        await asyncio.sleep(seconds)
        return _review_bundle.LENS_READING

    return call


def test_a_review_that_timed_out_raised_or_was_unreadable_emits_the_new_state(tmp_path):
    """`challenge_gate._fail` — reached when a review stage times out, raises, returns text outside its own output contract, or has no reviewer bound to..."""
    from defender.runtime.review_roles import ReviewStages

    lens = _review_bundle.LENS_READING
    cases = {
        "raises": (ReviewStages(
            support=_raising_stage(RuntimeError("the provider dropped the call")),
            ablation=_raising_stage(RuntimeError("the provider dropped the call")),
            composer=_review_bundle.stage(_review_bundle.composer_reply("holds")),
        ), None),
        "times-out": (ReviewStages(
            support=_slow_stage(5.0), ablation=_slow_stage(5.0),
            composer=_review_bundle.stage(_review_bundle.composer_reply("holds")),
        ), challenge_gate.Bounds(stage_timeout=0.05)),
        "unreadable": (_review_bundle.bundle(composer="not the contract", lens=lens), None),
        "no-bundle-bound": (None, None),
    }

    for name, (stages, bounds) in cases.items():
        deps, run_dir = ab3_deps(tmp_path / name)
        verdict = close(deps, "malicious", stages=stages, bounds=bounds)
        assert verdict.outcome == FORCED_INCONCLUSIVE, name
        assert verdict.cause == CAUSE_REVIEW_INCOMPLETE, name
        assert verdict.failure_kind in FAILURE_KINDS, name
        assert committed_verdict(run_dir) == MEMBER, (
            f"{name}: the review-failure arm still manufactures the analyst-facing verdict"
        )


def test_the_drivers_retry_exhaustion_close_commits_the_new_state(tmp_path):
    """The driver's retry-exhaustion limb — `forced=True`, no model left — commits `unresolved` AND still takes the immediate no-review path."""
    stages = recording_stages("holds")
    deps, run_dir = main_deps(tmp_path, gapless())

    _run, truncated_by, exit_reason = drive_to_retry_exhaustion(deps, review_stages=stages.bundle())

    assert exit_reason == "UnexpectedModelBehavior", "the forced-close limb never ran"
    assert truncated_by is not None
    assert committed_verdict(run_dir) == MEMBER
    assert stages.calls == [], (
        f"the forced close dispatched {stages.calls} — it fell through into the gate, which is "
        f"the path that re-commits the old keyword inside the fault handler"
    )
    assert committed(run_dir).get("failure_kind") is None, (
        "the forced close recorded a review failure kind — it went through `_fail`"
    )


def test_the_investigating_models_own_close_still_commits_inconclusive(tmp_path):
    """The investigating model reporting that it could not settle the case still commits `inconclusive` — priced, and the only remaining producer of that..."""
    deps, run_dir = main_deps(tmp_path, paid(PAYING_ROW))
    result = close(deps, GAP_MEMBER)
    assert result.outcome == "stands"
    assert committed_verdict(run_dir) == GAP_MEMBER
    assert GAP_MEMBER in DISPOSITION_ENUM


def test_a_model_authored_new_state_close_is_refused_without_spending_a_review(tmp_path):
    """A close tool call supplying `unresolved` is refused, nothing is committed, and no review stage is dispatched — the model is OFFERED the member by..."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime.close_tool import DispositionArg

    advertised = DispositionArg.__metadata__[0].json_schema_extra["enum"]
    assert MEMBER in advertised, "the schema half of the divergence is gone"
    assert advertised == list(DISPOSITION_VALUES)

    stages = recording_stages("holds")
    deps, run_dir = main_deps(tmp_path, paid(PAYING_ROW))
    with pytest.raises(ModelRetry) as e:
        close(deps, MEMBER, stages=stages.bundle())

    assert MEMBER in str(e.value)
    assert not (run_dir / "report.md").exists(), "the refused close committed anyway"
    assert stages.calls == [], f"the refused close spent a review: {stages.calls}"


# O3 — the committed report partitions on `disposition` alone.

def test_no_host_terminated_run_appears_in_the_gap_set(tmp_path):
    """Partition committed reports on `disposition` ALONE"""
    from defender._report import read_report

    host_deps, host_run = ab3_deps(tmp_path / "host-overruled")
    _overrule(host_deps)

    fail_deps, fail_run = ab3_deps(tmp_path / "host-review-failed")
    close(fail_deps, "malicious", stages=None)

    model_deps, model_run = main_deps(tmp_path / "model", paid(PAYING_ROW))
    close(model_deps, GAP_MEMBER)

    host_terminated = {host_run, fail_run}
    gap_set = set()
    for run_dir in (host_run, fail_run, model_run):
        report = read_report(run_dir / "report.md")
        assert report.disposition is not None, run_dir
        if report.disposition == GAP_MEMBER:
            gap_set.add(run_dir)

    assert gap_set == {model_run}, (
        "a host-terminated run is in the analyst's gap set — the partition is not readable "
        "from the committed verdict alone"
    )
    for run_dir in host_terminated:
        assert committed_verdict(run_dir) == MEMBER

    rows = committed(model_run).get("ceiling_test")
    rows = [rows] if isinstance(rows, str) else list(rows or [])
    assert rows, "a report in the gap set names no gap — the set carries no finding"


# Survival, and the branch the whole partition rests on.

def test_the_frameworks_forced_close_is_not_refused_by_the_new_price(tmp_path):
    """The framework's retry-exhaustion close still commits a `report.md`"""
    from pydantic_ai.exceptions import ModelRetry

    deps, run_dir = main_deps(tmp_path, gapless())
    _run, _truncated_by, exit_reason = drive_to_retry_exhaustion(deps)
    assert exit_reason == "UnexpectedModelBehavior"
    assert (run_dir / "report.md").is_file(), (
        "the framework's own close was refused by the new price and the run has no disposition"
    )
    assert committed_verdict(run_dir) == MEMBER

    model_deps, model_run = main_deps(tmp_path / "model", gapless())
    with pytest.raises(ModelRetry) as e:
        close(model_deps, GAP_MEMBER)
    assert "close blocked" in str(e.value)
    assert not (model_run / "report.md").exists(), (
        "the same gapless document bought a model-authored close — the exemption above is a "
        "hole rather than the framework's own path"
    )


def test_the_no_review_bypass_matches_both_verdicts_and_no_others(tmp_path):
    """The no-review bypass matches BOTH uncertain verdicts — `inconclusive` and `unresolved` — and NO others, and the `forced` flag buys no bypass of..."""
    assert set(BYPASS_BY_MEMBER) == set(DISPOSITION_ENUM), (
        f"the vocabulary and this expectation disagree: "
        f"+{sorted(set(DISPOSITION_ENUM) - set(BYPASS_BY_MEMBER))} "
        f"-{sorted(set(BYPASS_BY_MEMBER) - set(DISPOSITION_ENUM))} — a member joined the enum "
        f"without anyone deciding whether the no-review bypass matches it, which is exactly "
        f"the drift a two-literal expectation cannot see"
    )

    observed: dict[str, bool] = {}
    for member in sorted(DISPOSITION_ENUM):
        stages = recording_stages("holds")
        # The host-only member is not a legal `conclude` keyword, so its document concludes the
        # member the MODEL may author; the price dispatches on the close's argument regardless.
        concluded = GAP_MEMBER if member == MEMBER else member
        deps, run_dir = main_deps(tmp_path / f"member-{member}", pays_every_price(concluded))
        close(deps, member, stages=stages.bundle(), forced=member == MEMBER)
        assert (run_dir / "report.md").is_file(), f"{member} did not commit at all"
        observed[member] = bool(stages.calls)

    assert observed == BYPASS_BY_MEMBER, (
        f"the bypass reviews {observed}; the settled branch is {BYPASS_BY_MEMBER} — `True` is "
        f"a member that must still spend a review and `False` one the branch skips"
    )

    forced_stages = recording_stages("holds")
    deps, run_dir = main_deps(tmp_path / "forced-confident", pays_every_price("malicious"))
    close(deps, "malicious", stages=forced_stages.bundle(), forced=True)
    assert (run_dir / "report.md").is_file()
    assert forced_stages.calls, (
        "a confident close spent no review because it was FORCED — the bypass is keyed on the "
        "flag as well as on the verdict, which is the disjunct J4 rejected: it makes the host "
        "able to commit any verdict unreviewed, and it is invisible to every case above"
    )
