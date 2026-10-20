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
    from defender.runtime import challenge_gate
    from defender.runtime import session_store
    from defender.runtime.branch import SnapshotWriter
    from defender.runtime.run_state import RunState
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

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


def recorded_snapshot(run: Any) -> Any:
    """Capture fixture files through the real writer/store/loader, with fresh run state."""
    import tempfile

    from defender.hooks.budget_enforcer import DEFAULT_LIMITS
    from defender.runtime import challenge_gate
    from defender.runtime.branch import SnapshotWriter
    from defender.runtime.branch._snapshot import load
    from defender.runtime.run_state import RunState
    from defender.tests.support.storage._session_store_705 import store_factory

    with tempfile.TemporaryDirectory() as folder:
        store = store_factory(Path(folder))(run.run_dir.name, run.run_dir)
        try:
            session = store.new_session(agent_id="main")
            bounds = challenge_gate.default_bounds()
            SnapshotWriter(
                store, session, run=run, state=RunState(run.run_dir, str(run.id)),
                limits=DEFAULT_LIMITS, base_request_limit=bounds.base_request_limit,
                extra_turns=bounds.extra_turns).record(1, challenge_gate.ReviewState())
            snapshot = load(store, session, 1)
            assert snapshot is not None, "fixture snapshot was not recorded"
            return snapshot
        finally:
            store.close()
