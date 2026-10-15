"""#878 — four reachable faults on the runtime's own fault paths that ended the run with no
disposition, and a rollback that closed an fd it no longer owned.

Every one of them is the same shape as the family #851 named: the refusal that should have been
drawn already exists in the same function, a few lines away, and the fault path walks past it.
So each test here drives the REAL function over the REAL corrupt input and asserts a VERDICT —
a `ModelRetry`, a bool, a returned state — rather than asserting the absence of a traceback,
which any narrowing would satisfy.

F-07 is not here: it is a live-run property (five calls, two rows, three down-messages, and a
run that survives) and it lives with the rest of the breaker's spec, in
`tests/e2e/test_repeat_breaker_807.py::test_load_error_repeat_is_answered_by_the_breaker_not_
the_run_kill`. F-36's amendment lives with `claim_lead`'s other rollback tests, in
`tests/test_record_lead.py`.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]

from defender.hooks import budget_enforcer  # noqa: E402
from defender.hooks.budget_enforcer import (  # noqa: E402
    DEFAULT_LIMITS,
    tail_exhausted,
)
from defender.runtime import circuit_breaker as cb  # noqa: E402

# A basename over NAME_MAX (255 bytes on every filesystem the runs tree is mounted on). The
# parent — the run root — always exists, which is what carries the probe past the clean ENOENT
# `pathlib` swallows and into the ENAMETOOLONG it does not.
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
    """The PREMISE the two tests below rest on, asserted rather than assumed: `decide_read`
    ALLOWS a 300-character basename at the run root.

    MAIN's and GATHER's run-root read shape is `under(run, SEG)` with `SEG = [\\w.@=+-]+`, which
    places no length bound, and `Path.resolve()` does not stat — so the gate says yes and the
    probe four lines below it is the first code to touch the filesystem. If this ever starts
    failing, the two tests below stop testing what they name, because the refusal would be the
    gate's and never the probe's.

    This is also why bounding `SEG` is not the fix: the probe must survive an ALLOWED path
    whatever its shape."""
    from defender.runtime import permission

    run_dir, deps = _main_deps(tmp_path)
    decision = permission.decide_read(
        run_dir / _LONG_NAME, run_dir=run_dir, defender_dir=_DEFENDER, policy=deps.policy,
    )
    assert decision.allow, "the gate refused the long basename — the probe is no longer reached"


def test_read_file_refuses_an_overlong_basename_instead_of_raising(tmp_path):
    """`read_file` over a 300-character basename at MAIN's own run root returns a `ModelRetry`,
    not an `OSError`.

    `_gated_read`'s `p.is_file()` sat outside every `try`, four lines above a read that ALREADY
    maps `OSError` to `ModelRetry`. `os.stat` returns ENAMETOOLONG — errno 36, which is not in
    `pathlib._IGNORED_ERRNOS` (ENOENT/ENOTDIR/EBADF/ELOOP) — so it came back out. The cost was
    the whole run: pydantic_ai's `on_tool_execute_error` chain re-raises, none of
    `_drive_agent`'s five handlers name `OSError`, and `run.py` wraps `asyncio.run(...)` in
    nothing. No disposition, no `report.md`, not even the forced `inconclusive` close.

    The trigger is the defender model itself — MAIN or GATHER naming the path in `read_file` —
    or a prompt-injected gather, since the path is a model-authored string. It discloses
    nothing and bypasses no gate; the gate allowed the path and the file does not exist.

    Mirrors `test_gather_engine_seam.py::test_an_overlong_lead_id_never_reaches_the_claim`, the
    write-side twin of the same defect (#855 F-12)."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools

    run_dir, deps = _main_deps(tmp_path)
    with pytest.raises(ModelRetry) as excinfo:
        tools._gated_read(deps, str(run_dir / _LONG_NAME))
    assert "too long" in str(excinfo.value)


def test_edit_file_refuses_an_overlong_basename_instead_of_raising(tmp_path):
    """The same probe, twice more, in `_tool_edit_file`: one inside a `try` that names only
    `UnicodeDecodeError`, one outside a `try` altogether. Both are now the single guarded probe
    `_gated_read` uses, asked once.

    `write_file` is deliberately NOT exercised: MAIN's `write_allow` names `investigation.md`
    alone, so `decide_write` refuses the long basename before any probe runs. There is no
    defect there and a test would pin the wrong refusal."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools

    run_dir, deps = _main_deps(tmp_path)
    for old_string in ("", "some anchor"):
        with pytest.raises(ModelRetry) as excinfo:
            tools._tool_edit_file(deps, str(run_dir / _LONG_NAME), old_string, "new")
        assert "too long" in str(excinfo.value), \
            f"old_string={old_string!r}: the probe raised instead of drawing a refusal"


# F-17 — an offset-less origin raised out of the enforcement path and ended the run
#
# (#1235: the budget state lives in the run process's memory, so the arms that planted a
# non-dict, undecodable or aliased `budget.json` have no input left to plant. What stays is the
# elapsed check's own arithmetic over a state that carries a naive stamp.)


def test_a_naive_created_at_does_not_raise_out_of_the_elapsed_check():
    """`tail_exhausted` over a state whose `created_at` carries NO OFFSET returns a verdict.

    `_wall_origin` caught only `ValueError` around a bare `datetime.fromisoformat`, and this
    shape does not raise `ValueError` — it returns a NAIVE datetime, and `_elapsed`'s
    `datetime.now(UTC) - origin` then raised `TypeError: can't subtract offset-naive and
    offset-aware datetimes`.

    This is F-17's UNCONDITIONAL path: `lead_zero._budget_account` is documented as not gated on
    `DEFENDER_BUDGET_ENFORCE` (which defaults to False) and is called from `_issue` inside
    the correlation lead's driver, whose only handler catches `BudgetKill` and `RunAborted` — so the
    `TypeError` escaped `_user_prompt`, `run_investigation` and `main` before MAIN's first
    prompt was ever built.

    `open_budget`'s `setdefault` PRESERVES such a stamp rather than replacing it, which is what
    makes the shape survive into enforcement; the second arm asserts exactly that, so the fix
    cannot be mistaken for "the open rewrites it".

    The stamp is derived from NOW rather than written as a literal date: a literal makes the
    "past the cap" arm a fact about the calendar, so the test is a no-op before that date and a
    failure on any machine whose clock has not reached it — a suite that passes because time
    passed is not asserting the narrowing."""
    stamp = (datetime.now(UTC) - timedelta(days=1)).replace(tzinfo=None).isoformat()
    assert datetime.fromisoformat(stamp).tzinfo is None, "the seed stamp is not naive"
    naive = {"run_id": "r", "tool_calls": 0, "created_at": stamp}

    assert tail_exhausted(naive, DEFAULT_LIMITS) is True, \
        "a day-old origin is far past the wall-clock cap; a False here means it was not read"


def test_a_naive_origin_is_read_as_utc_not_dropped(tmp_path):
    """The offset-less stamp is READ, not skipped — `parse_iso_utc` treats it as UTC, which is
    its documented contract and the reason it is the right swap here. A `_wall_origin` that
    merely returned `None` on a naive value would pass the test above by dropping the wall
    clock entirely, silently disabling the tail kill for the whole run."""
    origin = budget_enforcer._wall_origin({"created_at": "2026-08-13T00:00:00"})
    assert origin is not None, "the naive stamp was dropped instead of read as UTC"
    assert origin.tzinfo is not None
    assert origin.isoformat() == "2026-08-13T00:00:00+00:00"


# F-25 — the breaker's verdicts over a healthy state
#
# (#1235: the breaker state lives on the run's `RunState`; the corrupt-nested-shape, non-dict
# and undecodable-bytes arms planted a `circuit_breaker.json` nothing reads any more, and the
# "unreadable state reads as tripped" branch they pinned retired with the file.)


def _state(tmp_path):
    from defender.runtime.run_state import RunState

    return RunState(tmp_path, "run-878")


def test_a_healthy_state_still_reads_and_trips(tmp_path):
    """An ordinary state still counts, still trips at `PER_SYSTEM_FAIL_LIMIT`, and still reports
    a real failure count in `down_message`."""
    state = _state(tmp_path)
    assert cb.is_tripped(state, "elastic") is False
    cb.record_outcome(state, "elastic", 2)
    assert cb.is_tripped(state, "elastic") is False
    cb.record_outcome(state, "elastic", 2)
    assert cb.is_tripped(state, "elastic") is True
    msg = cb.down_message(state, "elastic")
    assert "2 infra failures" in msg
    assert cb.is_tripped(state, "identity") is False, "one system's failures tripped another"


def test_the_run_kill_still_fires_on_a_healthy_state(tmp_path):
    """The other positive control: `RUN_FAIL_KILL_LIMIT` is still reachable. The F-07 fix stops
    ONE class of call from spending it, and that must not have made the kill
    itself unreachable — it is the deliberate abort for a genuinely unreachable environment."""
    state = _state(tmp_path)
    for i in range(cb.RUN_FAIL_KILL_LIMIT - 1):
        cb.record_outcome(state, f"system-{i}", 2)
    with pytest.raises(cb.RunAborted):
        cb.record_outcome(state, "system-last", 2)
