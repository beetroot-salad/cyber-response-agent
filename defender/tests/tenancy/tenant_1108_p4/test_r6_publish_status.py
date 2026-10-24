"""#1108 P4 round 6 — O-SEE / O-STALE through the real publish child entry (each case was a
wrong-but-green production variant): a launch-time publish records its outcome (a
misconfiguration is visible to `tenant.py check`, a success clears the refusal), a git fetch that
cannot connect is an outage (`stale:transient`), and a busy lock is never recorded as a refusal."""
from __future__ import annotations

import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        yield t


def _status(t):
    from defender.learning.author.version_control import status
    return status.read_status(t.tenant)


def test_r6_a_launch_time_publish_records_a_misconfiguration_and_a_success_clears_it(
        tenant, tmp_path):
    missing = tmp_path / "no-such-dir" / "issuer.json"
    line = B.run_child(tenant, missing)
    assert B.outcome_class(line) == "misconfigured", line
    refused = _status(tenant)
    assert refused and refused.get("refused"), f"a misconfiguration is invisible to check: {refused}"

    merged = tenant.merge(B.MERGE_FILES)
    good = B.write_issuer_config(tmp_path / "operator")
    line = B.run_child(tenant, good)
    assert B.outcome_class(line) == "fresh", line
    published = _status(tenant)
    assert published and published.get("published") == merged, published
    assert "refused" not in published, f"a good publish left the refusal standing: {published}"


def test_r6_a_git_fetch_that_cannot_connect_is_a_transient_outage(tenant, tmp_path):
    tenant.server.close()  # the origin's port now refuses connections
    good = B.write_issuer_config(tmp_path / "operator")
    line = B.run_child(tenant, good)
    assert B.outcome_class(line) == "stale:transient", line
    recorded = _status(tenant)
    assert recorded and recorded.get("kind") == "transient", recorded


def test_r6_a_busy_lock_is_not_recorded_as_a_refusal_and_keeps_the_earlier_record(tenant):
    from defender.learning.author.version_control import LockBusy, status

    status.record_refused(tenant.tenant, RuntimeError("a real refusal"), by="r6")
    before = _status(tenant)
    assert before and before["refused"] == "a real refusal"
    status.record_refused(tenant.tenant, LockBusy("lock busy"), by="r6-later")
    assert _status(tenant) == before
    with pytest.raises(LockBusy):
        with status.recording(tenant.tenant, by="r6-later"):
            raise LockBusy("lock busy")
    assert _status(tenant) == before


def test_r6_batch_reset_keeps_the_lane_folders_a_running_box_has_bound(tenant):
    """The lanes stay across a reset, in place (same inode), even when the batch head holds no
    file under one: a box that bound the lane folder keeps its bind."""
    batch = tenant.open_delivery().start_batch("r6", lanes=("lessons",))
    lane = batch.draft_root / "agent" / "lessons"
    inode = lane.stat().st_ino
    for path in lane.rglob("*"):
        if path.is_file():
            path.unlink()
    batch.commit(batch.change_set(), "empty the lane")
    batch.reset()
    assert lane.is_dir(), "the empty lane folder was dropped by reset"
    assert lane.stat().st_ino == inode, "reset replaced the lane folder (a bound box is stale)"
    (lane / "new.md").write_text("fresh draft\n", encoding="utf-8")
    batch.reset()
    assert lane.stat().st_ino == inode and not (lane / "new.md").exists()
