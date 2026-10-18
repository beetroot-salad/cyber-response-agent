"""Fork snapshot restoration preserves opaque artifacts and refuses unsafe source files."""
from __future__ import annotations

import os

import pytest

from defender.runtime.run_state import RunState
from defender.tests._fork_snapshot_plant import recorded_snapshot
from defender.runtime.branch._spec import BranchError
from defender.tests._spec1077 import fixture_run

MiB = 1024 * 1024


def _copy_records(tmp_path):
    source = fixture_run(tmp_path / "source").tables.payloads("l-001", 0)
    target = fixture_run(tmp_path / "target").tables.payloads("l-001", 0)
    source.path.parent.mkdir(parents=True)
    return source, target


def _restore(source, target):
    source_run = fixture_run(source.path.parents[2])
    target_run = fixture_run(target.path.parents[2])
    snapshot = recorded_snapshot(source_run)
    snapshot.verify(source_run)
    snapshot.restore_files(source_run, target_run, RunState(target_run.run_dir, str(target_run.id)))


def test_a_plain_artifact_is_copied_byte_for_byte(tmp_path):
    source, target = _copy_records(tmp_path)
    src = source.path
    src.write_bytes(b'{"a": 1}\r\n\xff')
    dst = target.path
    _restore(source, target)
    assert dst.read_bytes() == b'{"a": 1}\r\n\xff'


def test_an_artifact_past_the_cap_is_a_branch_error_and_nothing_is_written(tmp_path):
    source, target = _copy_records(tmp_path)
    src = source.path
    with open(src, "wb") as f:
        f.truncate(64 * MiB + 1)
    dst = target.path
    with pytest.raises(BranchError):
        _restore(source, target)
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
        _restore(source, target)
