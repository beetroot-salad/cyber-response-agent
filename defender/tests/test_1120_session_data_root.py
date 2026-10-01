"""#1120 piece 1 — a fixture that runs before a test's own data root still sees a tmp one
(code review on PR #1157).

Module-scoped fixtures are set up ahead of the function-scoped `data_root`, so they once saw
whatever `DEFENDER_DATA_ROOT` the launching shell exported — in the devcontainer, the host's
real data root, which a module-scoped replay then set its tenant up inside. conftest's
session-scoped guard replaces it with a tmp directory first.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.tests._data_root_1078 import DATA_ROOT_ENV


@pytest.fixture(scope="module")
def module_scoped_root() -> str | None:
    return os.environ.get(DATA_ROOT_ENV)


def test_a_module_scoped_fixture_sees_a_session_tmp_data_root(
        module_scoped_root: str | None, tmp_path_factory, data_root: Path) -> None:
    """The value a module-scoped fixture read is a directory under this session's basetemp,
    and is not the test's own root (it was read before that one was set)."""
    assert module_scoped_root is not None, "a module-scoped fixture saw no data root at all"
    base = tmp_path_factory.getbasetemp()
    assert Path(module_scoped_root).is_relative_to(base), (
        f"a module-scoped fixture saw {module_scoped_root}, outside the session's {base}")
    assert Path(module_scoped_root) != data_root
