"""#1120 piece 1 — the launcher and `held_out` refuse a bad tenant before spending anything,
observed by detectors that can see the spend (code review, max).

The spec's O3 matrix watches the launcher for a box launch only, with the billable role
preflight replaced by a silent no-op, and watches `held_out` for its report header, which it
never prints without fixtures. Here the preflight records each call, and `held_out` is pointed
at an empty fixtures folder, so reaching `report()` at all prints "no held-out fixtures found".
"""
from __future__ import annotations

from pathlib import Path

from defender.evals import held_out
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


def test_held_out_refuses_before_scoring(tmp_path: Path, monkeypatch, capsys) -> None:
    """`held_out --tenant acme` with no such tenant: exit 2, and `report()` was never reached
    (it would say there are no fixtures under the empty folder it was given)."""
    root = _no_tenant_root(tmp_path)
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    rc = held_out.main(["--tenant", H.TID, "--fixtures-dir", str(fixtures)])
    text = capsys.readouterr()
    assert rc == 2, text
    assert "no held-out fixtures found" not in text.err + text.out, text
    assert "# Held-out eval" not in text.out, text
