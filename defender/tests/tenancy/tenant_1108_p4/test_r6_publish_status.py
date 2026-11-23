"""#1108 P4: a batch reset keeps the lane folders a running box has bound, a wrong-but-green production variant.

#1618 retires what this file pinned about the publish child's records for `tenant.py check` (D7: the publish status and
its writers are gone), each with its successor:
- "a launch-time publish records a misconfiguration and a success clears it" (D7, D11: `misconfigured` goes; a tenant
  with no forge wiring is refused lasting, `lifecycle_1214/test_host_entry.py::test_run_start_refuses_an_active_tenant_with_no_forge_wiring`);
- "a git fetch that cannot connect is a transient outage" (its record): the class itself is
  `knowledge_1618/test_refusal_classes_1618.py::test_d11_forgejo_unreachable_is_refused_transient_with_a_reason`;
- "a busy lock is not recorded as a refusal" (K1: no lock, no `LockBusy`; D7: no record).
"""
from __future__ import annotations

import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        yield t


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
    assert lane.stat().st_ino == inode
    assert not (lane / "new.md").exists()
