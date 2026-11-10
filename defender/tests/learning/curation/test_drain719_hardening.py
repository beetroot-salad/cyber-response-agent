"""Drain hardening: a stray outside the corpus must not whitelist itself.

Retired with the file queue (#1278 design r8 Locks: the store's claim is the lane's one lock):
- `test_drain719_locks.py` (deleted whole): rotation and retirement excluded by the append lock, every channel's read
  batch under the append lock, the non-blocking drain lock against a real appender, the declared lock order
  (`drain.LOCK_ORDER`), a bare module invocation beside a live drain skipping its tick, the outer `author_drain` lock
  returning a second drainer at once. There is no append, drain or repo lock any more; two ticks over one tenant are
  excluded by the claim (`tests/tenancy/tenant_1108_p4/test_1278_tick.py`, `tests/learning/store_1278`).
- the retire seam's append-lock wait ending at the configured deadline (`repo_lock_wait_seconds`): no retire seam, no
  append lock, no deadline knob.
"""
from __future__ import annotations

from pathlib import Path

from defender.tests.support.learning.curation import _spec773 as S


def test_a_stray_the_agent_wrote_outside_the_corpus_does_not_whitelist_itself(tmp_path: Path):
    """The guard against writes outside the corpus stays armed across a faulted tick: the stray
    is reset away, and a second tick that writes it again faults again."""
    # Over a batch draft the stray sits in the drain's other lane (the box writes only its
    # lanes): outside this channel's corpus, so the scope gate refuses it.
    sc = S.build_draft_scene(tmp_path, rows=[S.finding_row("a/0", run_id="a")], curator=S.FakeCurator())
    stray = sc.lane.sibling_dir / "scratch.txt"
    sc.curator.writes = {"stray.md": S.lesson("a/0")}
    sc.curator.also = lambda r, b, c: stray.write_text("written outside the corpus\n")

    assert sc.run() == 2
    assert not stray.exists(), "the out-of-corpus write survived the faulted tick"
    assert sc.outcomes == {}

    assert sc.run() == 2, "the second tick authored: the stray was absorbed into the baseline"
    assert not stray.exists()
    assert sc.outcomes == {}
    assert sc.head_files() == []
