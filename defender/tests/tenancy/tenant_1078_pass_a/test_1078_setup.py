"""The one-tenant guard is gone (#1214 O7); a used tenant is accepted again and nothing is written.

`tenant.py setup`, `new-id` and the row `create_tenant` wrote are retired (#1214 F-12, O6); see the successor map in
slice-Re-report.md.
"""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

TID = H.VALID_ID


def _rowless_empty(root: Path, tmp: Path) -> None:
    (root / "old").mkdir(parents=True)


def _rowless_populated(root: Path, tmp: Path) -> None:
    (root / "old" / "runs" / "r1").mkdir(parents=True)
    (root / "old" / "runs" / "r1" / "report.md").write_text("x\n", encoding="utf-8")


def _dangling_symlink(root: Path, tmp: Path) -> None:
    (root / "ghost").symlink_to(tmp / "nowhere")


def _another_tenant(root: Path, tmp: Path) -> None:
    H.place_knowledge(root, fixture_uuid("tenant:other"))


@pytest.mark.parametrize("plant", [_rowless_empty, _rowless_populated, _dangling_symlink, _another_tenant],
                         ids=["rowless-empty-folder", "rowless-populated-folder", "dangling-symlink", "another-tenant"])
def test_o10_what_made_a_data_root_not_fresh_refuses_nothing_now(tmp_path, plant):
    """#1214 O7: a data root with other entries (a rowless folder, a dangling link, another tenant) no longer
    refuses the tenant placed in it; the entries are left as they were."""
    root = tmp_path / "data"
    H.place_knowledge(root, TID)
    assert H.accept(root, TID).id == TID  # control: alone, accepted
    plant(root, tmp_path)
    before = H.census(root)
    assert H.accept(root, TID).id == TID
    assert H.census(root) == before
    assert not hasattr(H.tenant(), "refuse_foreign_data_root"), "the one-tenant guard still exists"
    if plant is _dangling_symlink:
        assert (root / "ghost").is_symlink() and not (tmp_path / "nowhere").exists()  # noqa: PT018 — one fact: the link is left, dangling


def test_a_tenant_that_already_has_runs_is_accepted_again_and_nothing_is_written(tmp_path):
    """Acceptance of a tenant holding runs and sessions is read-only and repeatable; the rows the old setup
    re-run protected (#1214 O6, O7)."""
    root = tmp_path / "data"
    H.place_knowledge(root, TID)
    base = H.runs_dir(root, TID)
    (base / "r1").mkdir(parents=True)
    (base / "r1" / "report.md").write_text("disposition: benign\n", encoding="utf-8")
    H.sessions_dir(root, TID).mkdir()
    (H.sessions_dir(root, TID) / "case-1.db").write_bytes(b"SQLite format 3\x00")
    assert H.accept(root, TID).id == TID
    before = H.census(root)
    assert H.accept(root, TID).id == TID
    assert H.census(root) == before, "a second acceptance wrote something under <T>/"
