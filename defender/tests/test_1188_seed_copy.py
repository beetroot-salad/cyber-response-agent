"""#1188 amendment 3 follow-up: the branch fork's artifact copies read capped, no-follow, and
refuse as `BranchError`.

The sibling's evidence is copied out of the source run dir, a box's rw bind. The copy reads
through `_io.read_plain_bytes`: opened no-follow and judged on the open descriptor (no window
between an lstat check and a link-following open), capped at `READ_LIMIT`. Every refusal is the
module's `BranchError`, which its callers treat as "this fork is refused", never a raw `OSError`
partway through the copy.
"""
from __future__ import annotations

import os

import pytest

from defender.runtime.branch import _seed
from defender.runtime.branch._spec import BranchError

MiB = 1024 * 1024


def test_a_plain_artifact_is_copied_byte_for_byte(tmp_path):
    src = tmp_path / "src.json"
    src.write_bytes(b'{"a": 1}\r\n\xff')
    dst = tmp_path / "dst.json"
    _seed._copy_artifact(src, dst)
    assert dst.read_bytes() == b'{"a": 1}\r\n\xff'


def test_an_artifact_past_the_cap_is_a_branch_error_and_nothing_is_written(tmp_path):
    src = tmp_path / "big.json"
    with open(src, "wb") as f:
        f.truncate(64 * MiB + 1)
    dst = tmp_path / "dst.json"
    with pytest.raises(BranchError, match="read limit"):
        _seed._copy_artifact(src, dst)
    assert not dst.exists()


def test_a_hard_linked_artifact_is_a_branch_error(tmp_path):
    """The no-follow plain reader judges the open descriptor; a second name for the file is not
    the source run's own artifact. Control: the same bytes under one name copy (above)."""
    original = tmp_path / "original.json"
    original.write_bytes(b"{}")
    linked = tmp_path / "linked.json"
    os.link(original, linked)
    with pytest.raises(BranchError):
        _seed._copy_artifact(linked, tmp_path / "dst.json")
