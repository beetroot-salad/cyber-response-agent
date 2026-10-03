"""#1120 piece 1 — the launcher refuses a bad tenant before spending anything, observed by a
detector that can see the spend (code review, max).

The spec's O3 matrix watches the launcher for a box launch only, with the billable role
preflight replaced by a silent no-op. Here the preflight records each call.
"""
from __future__ import annotations

from pathlib import Path

from defender.learning.branch import cli as branch_cli
from defender.tests import _triplet_947 as T
from defender.tests.tenant_1078_pass_a import _spec1078 as P
from defender.tests.tenant_1120_piece1 import _spec1120 as H


def _no_tenant_root(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    root.mkdir()
    return root


def test_the_launcher_refuses_before_its_role_preflight(tmp_path: Path, monkeypatch) -> None:
    """A source under a data root holding no tenant: the launch is refused, and the role
    preflight (which sources a billable provider key) was never called."""
    root = _no_tenant_root(tmp_path)
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
    calls: list[object] = []

    def recording_preflight(model: str | None = None) -> int:
        calls.append(model)
        return 0

    source = root / H.TID / "runs" / T.SOURCE_RUN_ID
    try:
        got: object = branch_cli.main(
            [str(source), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", P.CONTINUATION],
            spawn=T.FakeSpawn(), preflight=recording_preflight)
    except SystemExit as refused:
        got = refused
    assert isinstance(got, BaseException) or got != 0, f"the launch was not refused: {got!r}"
    assert calls == [], f"the role preflight ran before the refusal: {calls}"
