"""Make hand-planted source sessions branchable through the production snapshot writer.

Driven-source snapshot tests do not use this fixture: they verify recording by the driver.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


def plant_fork_snapshots(store: Any, session_id: str, run_dir: Path) -> None:
    """Snapshot the current fixture folder at each tool-calling MAIN response."""
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
