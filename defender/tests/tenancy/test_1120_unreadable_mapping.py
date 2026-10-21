"""An unreadable case-history mapping is a refusal, never a traceback."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import os
from pathlib import Path

import pytest

from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file anyway; CI runs unprivileged")
def test_an_unreadable_mapping_is_named_by_setup_and_check(tmp_path: Path) -> None:
    """mapping.yaml at mode 000: setup exits 1 naming it and writes no row; `check <id>` over
    the same tenant with its row exits 1 naming it. Control: mode restored, setup is clean."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    mapping = H.settings_dir(root) / "systems" / "case-history" / "mapping.yaml"
    mapping.chmod(0)
    try:
        H.assert_refused(H.setup(tenant_py, root), "[tenant.py]", "systems/case-history/mapping.yaml")
        assert not location_path(H.row_path)(root).exists(), "the refused setup wrote the row"
        H.plant_row(root)
        H.assert_refused(H.check(tenant_py, root, H.TID), "[tenant.py]", "systems/case-history/mapping.yaml")
        location_path(H.row_path)(root).unlink()
    finally:
        mapping.chmod(0o644)
    H.assert_clean(H.setup(tenant_py, root))
