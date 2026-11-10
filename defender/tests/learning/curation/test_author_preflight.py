"""Pre-flight gates: the idempotency filter.

The author works on a batch draft, which is clean by construction.

Retired with the file queue (design r8 Locks): `test_lock_refuses_concurrent_run` (the drain role's `TRY_ONCE` lock) and
`test_repo_lock_held_returns_zero` (run_batch exiting cleanly when the shared repo lock is unavailable): there is no drain
or repo lock, the store's claim excludes a second holder
(`tests/tenancy/tenant_1108_p4/test_1278_tick.py::test_locks_a_tick_finding_a_live_batch_of_another_holder_authors_nothing_and_exits_quietly`).
`test_empty_queue_is_noop` is `test_drain719_retire.py::test_an_empty_claim_never_reaches_the_agent_and_decides_nothing`."""
from __future__ import annotations

from dataclasses import replace

from defender.tests.support.learning.curation._author_draft import DraftRepo


def test_idempotency_filter_skips_already_authored(tmp_path):
    # The covering lesson is published in the export commit the draft is built from.
    draft_repo = DraftRepo.over(tmp_path, files={"lessons/preexisting.md": (
        "---\n"
        "name: preexisting\n"
        "description: covers the same pitfall\n"
        "source_finding_ids:\n"
        "  - run-X/0\n"
        "created_at: 2026-05-09T00:00:00+00:00\n"
        "---\n\nbody\n")})
    draft_repo.add("run-X/0")

    invoked = {"called": False}

    def fake_invoke(findings, batch_id, cfg):
        invoked["called"] = True
        return {"committed": [], "consumed_skip": [], "commit_sha": None}

    rc = draft_repo.run(replace(draft_repo.cfg, invoke_agent=fake_invoke))
    assert rc == 0
    assert invoked["called"] is False, "agent must not be invoked when all findings are idempotent"

    assert draft_repo.fate("run-X/0") == ("published", None), "an already-authored finding is published as covered"
    assert draft_repo.lane.landed() == []
