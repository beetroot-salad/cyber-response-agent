"""#1120 piece 1 — a folder `tenant.py` cannot read is a refusal, never a traceback (code
review, max).

The operator's clone now creates `<root>/<T>` before setup runs, so a `<T>` left unreadable
(another user's clone, umask 077) is an ordinary state. Setup's fresh-root probe listed it
raw and died with a `PermissionError` traceback; `scaffold` did the same over an unreadable
target.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H
from defender.tests.tenant_1120_piece1 import test_1120_scaffold as S

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 directory")


def test_setup_over_an_unreadable_tenant_folder_refuses(tmp_path: Path) -> None:
    """`<root>/<T>` at mode 000 with no row: setup exits 1 with `[tenant.py]`, naming the data
    root, and no traceback."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    folder = H.tenant_folder(root)
    folder.chmod(0)
    try:
        H.assert_refused(H.setup(tenant_py, root), "[tenant.py]", str(root))
    finally:
        folder.chmod(0o755)


def test_scaffold_into_an_unreadable_target_refuses(tmp_path: Path) -> None:
    """An empty target directory at mode 000: scaffold exits non-zero naming it, with no
    traceback, and the target is still empty."""
    target = S._empty_dir(tmp_path / "acme")
    target.chmod(0)
    try:
        S._refused(S._scaffold(H.TID, target, home=S._home(tmp_path / "cfg")), str(target))
    finally:
        target.chmod(0o755)
    assert not any(target.iterdir())
