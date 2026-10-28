"""#992 — the run page's reviewed/unreviewed split over two populations: a reviewed `inconclusive`
dir driven through the real close, and a pre-#992 one written by hand (no `reviewed` field, no
traces). Every reader keyed on the split must agree within each population."""
from __future__ import annotations

import shutil
from pathlib import Path

from defender.investigation.challenge_gate import REVIEW_ROLES
from defender.investigation.close_tool import (
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
    CAUSE_NOT_REVIEWED,
    CAUSE_TURN_BUDGET_SPENT,
    STANDS,
)
from defender.presentation.visualize_run import _gate_badge_html
from defender.presentation.visualize_runtime import (
    _BYPASS_NOTE, _PRE_RECORD_NOTE, render_review_gate,
)
from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests.support.runtime.engine._spec992 import (
    CEILING_EXAMINED,
    CONFIDENT,
    GAP,
    bounds,
    ceiling_companion,
    close_with,
    deps_over,
    frontmatter,
    gap,
    holds,
    parsed_report,
    pre_change_inconclusive_dir,
    record,
    recording,
    reviewed_inconclusive_dir,
    trace_files,
)


def test_visualizer_renders_a_reviewed_inconclusive(tmp_path):
    """A reviewed `inconclusive` renders as a reviewed attempt with its role traces, while a
    pre-#992 dir and a forced `unresolved` read 'not reviewed': `_was_reviewed` reads the
    record's own `reviewed` field."""
    reviewed = reviewed_inconclusive_dir(tmp_path)
    assert frontmatter(reviewed)["cause"] == CEILING_EXAMINED
    assert record(reviewed, 1)["reviewed_disposition"] == GAP
    assert record(reviewed, 1)["reviewed"] is True
    assert trace_files(reviewed) == list(REVIEW_ROLES)
    html, n = render_review_gate(reviewed, parsed_report(reviewed))
    assert n == 1, "the reviewed inconclusive attempt does not count as reviewed"
    assert "not reviewed" not in html
    assert "rv-stands" in html
    for role in REVIEW_ROLES:
        assert f">{role}<" in html, f"{role}'s trace card is missing"
    assert "gate: stands" in _gate_badge_html(parsed_report(reviewed))

    assert "inconclusive" not in _BYPASS_NOTE, _BYPASS_NOTE
    assert "unresolved" in _BYPASS_NOTE

    historical = pre_change_inconclusive_dir(tmp_path)
    assert frontmatter(historical)["cause"] == CAUSE_NOT_REVIEWED
    html, n = render_review_gate(historical, parsed_report(historical))
    assert n == 0, "an unreviewed inconclusive dir (no `reviewed` field) counts as reviewed"
    assert "not reviewed" in html
    assert "rv-stands" not in html
    assert "not reviewed" in _gate_badge_html(parsed_report(historical))

    deps, driver_forced = deps_over(tmp_path / "driver-forced", ceiling_companion())
    assert close_with(deps, "unresolved", recording(holds()), forced=True).outcome == STANDS
    assert frontmatter(driver_forced)["cause"] == CAUSE_NOT_REVIEWED
    assert "not reviewed" in _gate_badge_html(parsed_report(driver_forced))


def test_headline_badge_for_a_ceiling_held_versus_an_unaffordable_gap(tmp_path):
    """A ceiling-held `inconclusive` gets the `gate: stands` badge; an unaffordable gap (either
    override cause) gets the same `forced-inconclusive` badge as a confident override."""
    held = reviewed_inconclusive_dir(tmp_path, name="held")
    deps, cannot = deps_over(tmp_path / "cannot", ceiling_companion())
    assert close_with(deps, GAP, recording(gap(None))).outcome == "forced-inconclusive"
    one_turn = bounds(extra_turns=1)
    deps, spent = deps_over(tmp_path / "spent", ceiling_companion())
    assert close_with(deps, GAP, recording(gap("l-004")), bounds=one_turn).outcome == "challenged"
    assert close_with(deps, GAP, recording(gap("l-005")), bounds=one_turn).outcome == "forced-inconclusive"
    twin, confident = deps_over(tmp_path / "confident", ceiling_companion())
    assert close_with(twin, CONFIDENT, recording(gap(None))).outcome == "forced-inconclusive"

    badges = {run.parent.name: _gate_badge_html(parsed_report(run)) for run in (held, cannot, spent, confident)}
    assert "gate: stands" in badges["held"], badges
    assert "gate-stands" in badges["held"], badges
    assert badges["cannot"] == badges["spent"] == badges["confident"], badges
    assert "gate: forced-inconclusive" in badges["cannot"], badges
    assert "gate-forced" in badges["cannot"], badges
    assert all("not reviewed" not in b for b in badges.values())
    causes = {run.parent.name: frontmatter(run)["cause"] for run in (held, cannot, spent)}
    assert set(causes.values()) == {
        CEILING_EXAMINED, CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_TURN_BUDGET_SPENT,
    }, causes


def _split_answers(run_dir: Path) -> dict:
    """Every run-page reader keyed on the reviewed/unreviewed split, one answer each: the
    § Review gate count and section guard, the per-attempt badge and bypass note, the role
    cards and the headline badge."""
    report = parsed_report(run_dir)
    html, n = render_review_gate(run_dir, report)
    badge = _gate_badge_html(report)
    return {
        "count": n,
        "section-guard": "not reviewed" in html.split("attempt 1")[0] if "attempt 1" in html else "not reviewed" in html,
        "attempt-badge-reviewed": "rv-stands" in html,
        "bypass-note": (_BYPASS_NOTE in html) or (_PRE_RECORD_NOTE in html),
        "live-bypass-note": _BYPASS_NOTE in html,
        "role-cards": all(f">{role}<" in html for role in REVIEW_ROLES),
        "headline-not-reviewed": "not reviewed" in badge,
    }


def test_every_reader_of_the_reviewed_split_agrees_on_both_populations(tmp_path):
    """Every reader of `_was_reviewed`'s answer agrees within each population, though both share
    a `reviewed_disposition`; a reviewed record whose trace files are gone still counts as
    reviewed (only its role cards go)."""
    reviewed_dir = reviewed_inconclusive_dir(tmp_path)
    historical_dir = pre_change_inconclusive_dir(tmp_path)
    reviewed = _split_answers(reviewed_dir)
    historical = _split_answers(historical_dir)

    assert reviewed == {
        "count": 1, "section-guard": False, "attempt-badge-reviewed": True,
        "bypass-note": False, "live-bypass-note": False, "role-cards": True,
        "headline-not-reviewed": False,
    }, reviewed
    assert historical == {
        "count": 0, "section-guard": True, "attempt-badge-reviewed": False,
        "bypass-note": True, "live-bypass-note": False, "role-cards": False,
        "headline-not-reviewed": True,
    }, historical

    # The two populations are told apart by the record's own word, not by the disposition on
    # it — which is the same string in both.
    assert record(reviewed_dir, 1)["reviewed_disposition"] == GAP
    assert record(historical_dir, 1)["reviewed_disposition"] == GAP
    assert record(reviewed_dir, 1)["reviewed"] is True
    assert "reviewed" not in record(historical_dir, 1)

    traceless_dir = reviewed_inconclusive_dir(tmp_path, name="traceless")
    shutil.rmtree(traceless_dir / "wire_logs")
    assert trace_files(traceless_dir) == []
    traceless = _split_answers(traceless_dir)
    assert traceless == {**reviewed, "role-cards": False}, traceless
