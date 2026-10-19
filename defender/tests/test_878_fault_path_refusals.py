"""#878 — four reachable faults on the runtime's own fault paths that ended the run with no disposition, and a rollback that closed an fd it no longer owned."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from defender.tests._1255_view import model_path

_DEFENDER = Path(__file__).resolve().parents[1]

from defender.hooks import budget_enforcer  # noqa: E402
from defender.hooks.budget_enforcer import (  # noqa: E402
    DEFAULT_LIMITS,
    tail_exhausted,
)

_LONG_NAME = "n" * 300


# F-15 — a path the read gate ALLOWS raises ENAMETOOLONG out of the `is_file()` probe


def _main_deps(tmp_path: Path):
    from defender.runtime.agent_definition import bind
    from defender.runtime.driver import MAIN_DEF

    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    # No `salt=`: #875 removed the run-scoped delimiter from `bind`/`AgentDeps` entirely —
    # a tool return is framed by `_untrusted.wrap_fresh`, which mints its own.
    return run_dir, bind(MAIN_DEF, run_dir, defender_dir=_DEFENDER)


def test_the_read_gate_allows_the_overlong_basename_it_is_then_asked_to_probe(tmp_path):
    from defender.runtime import permission

    run_dir, deps = _main_deps(tmp_path)
    decision = permission.decide_read(
        run_dir / _LONG_NAME, run_dir=run_dir, defender_dir=_DEFENDER, policy=deps.policy,
    )
    assert decision.allow, "the gate refused the long basename — the probe is no longer reached"


def test_read_file_refuses_an_overlong_basename_instead_of_raising(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools

    run_dir, deps = _main_deps(tmp_path)
    with pytest.raises(ModelRetry) as excinfo:
        tools._gated_read(deps, model_path(run_dir / _LONG_NAME, run_dir=run_dir))
    assert "too long" in str(excinfo.value)


def test_edit_file_refuses_an_overlong_basename_instead_of_raising(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools

    run_dir, deps = _main_deps(tmp_path)
    for old_string in ("", "some anchor"):
        with pytest.raises(ModelRetry) as excinfo:
            tools._tool_edit_file(
                deps, model_path(run_dir / _LONG_NAME, run_dir=run_dir), old_string, "new")
        assert "too long" in str(excinfo.value), \
            f"old_string={old_string!r}: the probe raised instead of drawing a refusal"


def test_a_naive_created_at_does_not_raise_out_of_the_elapsed_check():
    stamp = (datetime.now(UTC) - timedelta(days=1)).replace(tzinfo=None).isoformat()
    assert datetime.fromisoformat(stamp).tzinfo is None, "the seed stamp is not naive"
    naive = {"run_id": "r", "tool_calls": 0, "created_at": stamp}

    assert tail_exhausted(naive, DEFAULT_LIMITS) is True, \
        "a day-old origin is far past the wall-clock cap; a False here means it was not read"


def test_a_naive_origin_is_read_as_utc_not_dropped(tmp_path):
    origin = budget_enforcer._wall_origin({"created_at": "2026-08-13T00:00:00"})
    assert origin is not None, "the naive stamp was dropped instead of read as UTC"
    assert origin.tzinfo is not None
    assert origin.isoformat() == "2026-08-13T00:00:00+00:00"


def _state(tmp_path):
    from defender.runtime.run_state import RunState

    return RunState(tmp_path, "run-878")
