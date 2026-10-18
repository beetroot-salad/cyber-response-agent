"""#797 — the retirement's own negatives, and the fail-closed posture it leaves behind.
"""
from __future__ import annotations

from dataclasses import replace as _with_live_run_1165
from defender.tests._spec1077 import fixture_run as _live_run_1165

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-v2sshd"


def _main_deps(tmp_path: Path):
    """MAIN's deps through the REAL `bind` seam — the real compiled policy, the real gate."""
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_bytes((GOLDEN / "alert.json").read_bytes())
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    return _with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=dfn), run=_live_run_1165(run_dir)), run_dir


def test_797_a_confident_close_fails_closed_when_no_stage_is_bound(tmp_path):
    """A confident disposition reviewed through an UNBOUND bundle commits `inconclusive`, and
    says on disk that the MACHINERY is what failed."""
    pytest.importorskip("pydantic_ai")
    from defender._frontmatter import split_frontmatter
    from defender.runtime.close_tool import (
        CAUSE_REVIEW_INCOMPLETE,
        FORCED_INCONCLUSIVE,
        STAGE_ERROR,
        close_investigation,
    )
    from defender.runtime.review_roles import ReviewStages

    deps, run_dir = _main_deps(tmp_path)
    (run_dir / "investigation.md").write_bytes((GOLDEN / "investigation.md").read_bytes())
    result = close_investigation(deps, "malicious", stages=ReviewStages())

    assert result.outcome == FORCED_INCONCLUSIVE, (
        f"a confident close returned {result.outcome!r} with no reviewer bound"
    )
    assert result.cause == CAUSE_REVIEW_INCOMPLETE
    assert result.failure_kind == STAGE_ERROR, (
        f"the override names {result.failure_kind!r} — a gate with no reviewer is the "
        "machinery failing, not a finding about the evidence"
    )

    fm, _raw, _body = split_frontmatter((run_dir / "report.md").read_text(encoding="utf-8"))
    # #923: a machinery-forced override commits the HOST's own verdict, `unresolved` — not
    # the model's `inconclusive`, which now means "the model itself could not settle this" and
    # carries an entry price no host-forced close can pay. The drafted confident disposition
    # still never reaches disk unreviewed; only the spelling of the override moved.
    assert fm["disposition"] == "unresolved", (
        f"report.md committed {fm['disposition']!r} — the drafted confident disposition "
        "reached disk unreviewed"
    )
    assert fm["outcome"] == FORCED_INCONCLUSIVE
    assert fm["failure_kind"] == STAGE_ERROR

    record = json.loads(Path(result.record_path).read_text(encoding="utf-8"))
    assert record["failure_kind"] == STAGE_ERROR
    assert "not bound" in record["detail"], (
        "the review record does not say WHY the review could not run — an operator reading "
        f"the run gets an anonymous stage error: {record['detail']!r}"
    )

    # The twin, updated for #992: the gate now reviews `inconclusive` too, so an UNBOUND bundle
    # fails IT closed the same way — overridden to `unresolved` with `CAUSE_REVIEW_INCOMPLETE`
    # and a `failure_kind`, never the un-gated `CAUSE_NOT_REVIEWED` #923 pinned here before
    # #992.
    bypass_deps, bypass_dir = _main_deps(tmp_path / "bypass")
    # `inconclusive` carries its own entry price — a `ceiling_test` row naming a source or
    # capability — collected before the gate is ever reached. The golden fixture's own
    # investigation.md already names its gaps there, so writing it is what keeps this control
    # about the GATE (an unbound bundle) rather than about the price.
    (bypass_dir / "investigation.md").write_bytes((GOLDEN / "investigation.md").read_bytes())
    bypass = close_investigation(bypass_deps, "inconclusive", stages=ReviewStages())
    assert bypass.outcome == FORCED_INCONCLUSIVE
    assert bypass.cause == CAUSE_REVIEW_INCOMPLETE
    assert bypass.failure_kind == STAGE_ERROR, (
        "an unbound bundle on an inconclusive close is the machinery failing, exactly as it "
        "is on a confident close"
    )
    bypass_fm, _r, _b = split_frontmatter(
        (bypass_dir / "report.md").read_text(encoding="utf-8")
    )
    assert bypass_fm["disposition"] == "unresolved"
    assert bypass_fm["failure_kind"] == STAGE_ERROR
    bypass_record = json.loads(
        (bypass_dir / "review_record.1.json").read_text(encoding="utf-8")
    )
    assert bypass_record["reviewed_disposition"] == "inconclusive"


