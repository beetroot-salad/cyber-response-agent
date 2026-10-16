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
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests._spec1077 import fixture_run

MiB = 1024 * 1024


def _copy_records(tmp_path):
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    source = fixture_run(tmp_path / fixture_uuid("source")).tables.payloads("l-001", 0)
    target = fixture_run(tmp_path / fixture_uuid("target")).tables.payloads("l-001", 0)
    source.path.parent.mkdir(parents=True)
    return source, target


def test_a_plain_artifact_is_copied_byte_for_byte(tmp_path):
    source, target = _copy_records(tmp_path)
    src = source.path
    src.write_bytes(b'{"a": 1}\r\n\xff')
    dst = target.path
    _seed._copy_artifact(source, target)
    assert dst.read_bytes() == b'{"a": 1}\r\n\xff'


def test_an_artifact_past_the_cap_is_a_branch_error_and_nothing_is_written(tmp_path):
    source, target = _copy_records(tmp_path)
    src = source.path
    with open(src, "wb") as f:
        f.truncate(64 * MiB + 1)
    dst = target.path
    with pytest.raises(BranchError, match="read limit"):
        _seed._copy_artifact(source, target)
    assert not dst.exists()


def test_a_hard_linked_artifact_is_a_branch_error(tmp_path):
    """The no-follow plain reader judges the open descriptor; a second name for the file is not
    the source run's own artifact. Control: the same bytes under one name copy (above)."""
    source, target = _copy_records(tmp_path)
    original = tmp_path / "original.json"
    original.write_bytes(b"{}")
    linked = source.path
    os.link(original, linked)
    with pytest.raises(BranchError):
        _seed._copy_artifact(source, target)
