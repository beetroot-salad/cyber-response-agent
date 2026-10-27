"""The launcher refuses a bad tenant before its billable role preflight."""
from __future__ import annotations

from pathlib import Path

from defender.cli.learning import branch as branch_entry
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H


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
        got: object = branch_entry.main(
            [str(source), str(T.BRANCH_MESSAGE_ID), *T.retired_continuation_argv()],
            spawn=T.FakeSpawn(), preflight=recording_preflight)
    except SystemExit as refused:
        got = refused
    assert isinstance(got, BaseException) or got != 0, f"the launch was not refused: {got!r}"
    assert calls == [], f"the role preflight ran before the refusal: {calls}"
