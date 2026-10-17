"""#1255 deferred verification 4 — the FIXTURE-ONLY fork-snapshot planter for hand-planted sources.

A source whose store rows a suite writes directly (`_branch_947.planted_source`,
`_triplet_947.seed_source_session`) was never driven, so production recorded no fork snapshot
for any of its responses, and after #1255 no arm is launched from it (N4). The suites that need
such a source to be BRANCHABLE (state a driven run cannot reach) plant the snapshot here, through
production's own writer (`runtime.branch.SnapshotWriter`), as of the source folder's current
files — the state the hand-planted run "held" at every one of its tool-calling responses.

This builds test inputs; it is not evidence the driver records snapshots. It is never applied to
`_branch_947.legal_source` or a `pre_snapshot=True` source (the N4/C2 fixtures), and no
`test_1255_snapshot_*` module imports it: those observe snapshots only through driven runs.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


def plant_fork_snapshots(store: Any, session_id: str, run_dir: Path) -> None:
    """Record a fork snapshot for every tool-calling MAIN response on `session_id`'s path, each
    describing `run_dir` as it stands now, with a fresh run's counters, review gate and the
    shipped caps."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    from defender.hooks.budget_enforcer import DEFAULT_LIMITS
    from defender.runtime import challenge_gate, session_store
    from defender.runtime.branch import SnapshotWriter
    from defender.runtime.run_state import RunState
    from defender.tests._spec1077 import fixture_run

    bounds = challenge_gate.default_bounds()
    writer = SnapshotWriter(
        store, session_id, run=fixture_run(Path(run_dir)),
        state=RunState(Path(run_dir), Path(run_dir).name), limits=DEFAULT_LIMITS,
        base_request_limit=bounds.base_request_limit, extra_turns=bounds.extra_turns)
    request = 0
    for message in session_store.hydrate(store, session_id, role="analysis"):
        if not isinstance(message, ModelResponse):
            continue
        request += 1
        if any(isinstance(p, ToolCallPart) for p in message.parts):
            writer.record(request, challenge_gate.ReviewState())
            # `record` logs and swallows a fault (a natural run must not die on it); a fixture
            # that planted nothing must say so here, not as "no fork snapshot" downstream.
            assert store.fork_snapshot(session_id, request) is not None, (
                f"the fixture planted no fork snapshot for request {request} of {run_dir}")
