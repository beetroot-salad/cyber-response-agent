"""A folder tenant.py cannot read is a refusal, never a traceback."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 directory")


def test_check_over_an_unreadable_tenant_folder_refuses(tmp_path: Path) -> None:
    """`<root>/<T>` at mode 000: `check <T>` (the tenant active in the directory) refuses naming the data root."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    folder = H.tenant_folder(root)
    folder.chmod(0)
    try:
        H.assert_refused(H.check(tenant_py, root, H.TID, seed=[H.TID]), "[tenant.py]", str(root))
    finally:
        folder.chmod(0o755)
