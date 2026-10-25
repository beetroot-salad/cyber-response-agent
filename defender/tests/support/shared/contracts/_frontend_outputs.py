"""Serialize tests that snapshot the in-tree frontend build outputs to prove a build writes nothing there (#1279)."""
from __future__ import annotations

import fcntl
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def frontend_outputs_lock():
    """Hold one process-shared lock through each test's snapshot, action and restoration."""
    with (Path(tempfile.gettempdir()) / "defender-frontend-tests.lock").open("a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
