"""A folder tenant.py cannot read is a refusal, never a traceback."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
from defender.tests.tenancy.tenant_1120_piece1 import test_1120_scaffold as S

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 directory")


def test_setup_over_an_unreadable_tenant_folder_refuses(tmp_path: Path) -> None:
    """`<root>/<T>` at mode 000 with no row: setup refuses naming the data root."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    folder = H.tenant_folder(root)
    folder.chmod(0)
    try:
        H.assert_refused(H.setup(tenant_py, root), "[tenant.py]", str(root))
    finally:
        folder.chmod(0o755)


def test_scaffold_into_an_unreadable_target_refuses(tmp_path: Path) -> None:
    target = S._empty_dir(tmp_path / "acme")
    target.chmod(0)
    try:
        S._refused(S._scaffold(H.TID, target, home=S._home(tmp_path / "cfg")), str(target))
    finally:
        target.chmod(0o755)
    assert not any(target.iterdir())
