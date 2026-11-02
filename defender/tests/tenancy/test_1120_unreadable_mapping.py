"""An unreadable case-record file is a finding of `check`, never a traceback."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file anyway; CI runs unprivileged")
def test_an_unreadable_case_record_is_named_by_check(tmp_path: Path) -> None:
    """case-record.yaml at mode 000: `check <id>` exits 1 naming it. Control: mode restored, check is clean. r4 tenant check."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    record = H.settings_dir(root) / "case-record.yaml"
    record.write_text('system: "ticket"\n', encoding="utf-8")
    record.chmod(0)
    try:
        H.assert_refused(H.check(tenant_py, root, H.TID), "[tenant.py]", "settings/case-record.yaml")
    finally:
        record.chmod(0o644)
    H.assert_clean(H.check(tenant_py, root, H.TID))
