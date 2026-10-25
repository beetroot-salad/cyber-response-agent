"""Fixtures for #1108 P4's contract; the machinery lives in `_support.py` (slice S0)."""
from __future__ import annotations

import pytest

from ._support import published_tenant


@pytest.fixture
def p4_tenant(tmp_path, data_root):
    """The fixture tenant under this test's own data root (`DEFENDER_DATA_ROOT`), its clone a
    real git repo with a live loopback origin, published once for real (`PublishedTenant`)."""
    with published_tenant(tmp_path / "forge", root=data_root) as published:
        yield published
