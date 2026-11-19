"""#797: the fail-closed posture the review retirement leaves — a close with no stage bound
commits `inconclusive`."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from dataclasses import replace as _with_live_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _live_run_1165

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = REPO_ROOT / "defender"
GOLDEN = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"


def _main_deps(tmp_path: Path):
    """MAIN's deps through the real `bind`: the real compiled policy and gate."""
    from defender.agents import MAIN_DEF
    from defender.investigation.agent_definition import bind

    run_dir = tmp_path / fixture_uuid("797-run")
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_bytes((GOLDEN / "alert.json").read_bytes())
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    from defender.tests.support.runtime.engine._spec923 import with_session_store

    deps = _with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=dfn), run=_live_run_1165(run_dir))
    return with_session_store(deps, tmp_path), run_dir


def test_797_a_confident_close_fails_closed_when_no_stage_is_bound(tmp_path):
    """A confident disposition reviewed through an UNBOUND bundle commits `inconclusive`, and
    says on disk that the MACHINERY is what failed."""
    pytest.importorskip("pydantic_ai")
    from defender.investigation.close_tool import (
        CAUSE_REVIEW_INCOMPLETE,
        FORCED_INCONCLUSIVE,
        STAGE_ERROR,
        close_investigation,
    )
    from defender.investigation.review_roles import ReviewStages

    deps, run_dir = _main_deps(tmp_path)
    (run_dir / "investigation.md").write_bytes((GOLDEN / "investigation.md").read_bytes())
    result = close_investigation(deps, "malicious", stages=ReviewStages())

    assert result.outcome == FORCED_INCONCLUSIVE, (
        f"a confident close returned {result.outcome!r} with no reviewer bound"
    )
    assert result.cause == CAUSE_REVIEW_INCOMPLETE
    assert result.failure_kind == STAGE_ERROR, (
        f"the override names {result.failure_kind!r}, not a stage error"
    )

    from defender.tests.support.runtime.engine._spec923 import committed

    fm = committed(run_dir)
    assert fm["disposition"] == "unresolved", (
        f"the closing record committed {fm['disposition']!r} unreviewed"
    )
    assert fm["outcome"] == FORCED_INCONCLUSIVE
    assert fm["failure_kind"] == STAGE_ERROR

    record = json.loads(Path(result.record_path).read_text(encoding="utf-8"))
    assert record["failure_kind"] == STAGE_ERROR
    assert "not bound" in record["detail"], (
        f"the review record does not say why the review could not run: {record['detail']!r}"
    )

    bypass_deps, bypass_dir = _main_deps(tmp_path / "bypass")
    (bypass_dir / "investigation.md").write_bytes((GOLDEN / "investigation.md").read_bytes())
    bypass = close_investigation(bypass_deps, "inconclusive", stages=ReviewStages())
    assert bypass.outcome == FORCED_INCONCLUSIVE
    assert bypass.cause == CAUSE_REVIEW_INCOMPLETE
    assert bypass.failure_kind == STAGE_ERROR, (
        "an inconclusive close with no reviewer is not a stage error"
    )
    bypass_fm = committed(bypass_dir)
    assert bypass_fm["disposition"] == "unresolved"
    assert bypass_fm["failure_kind"] == STAGE_ERROR
    bypass_record = json.loads(
        (bypass_dir / "review_record.1.json").read_text(encoding="utf-8")
    )
    assert bypass_record["reviewed_disposition"] == "inconclusive"
