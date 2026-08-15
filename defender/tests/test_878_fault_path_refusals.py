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

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]

from defender.hooks import budget_enforcer  # noqa: E402
from defender.hooks.budget_enforcer import (  # noqa: E402
    DEFAULT_LIMITS,
    open_budget,
    read_budget,
    tail_exhausted,
)
from defender.runtime import circuit_breaker as cb  # noqa: E402

# A basename over NAME_MAX (255 bytes on every filesystem the runs tree is mounted on). The
# parent — the run root — always exists, which is what carries the probe past the clean ENOENT
# `pathlib` swallows and into the ENAMETOOLONG it does not.
_LONG_NAME = "n" * 300


# ---------------------------------------------------------------------------------------
# F-15 — a path the read gate ALLOWS raises ENAMETOOLONG out of the `is_file()` probe
# ---------------------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------------------
# F-17 — a malformed `budget.json` raises out of the enforcement path and ends the run
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("doc", ["[]", "3", '"x"', "null", "[1, 2, 3]"])
def test_read_budget_normalises_a_non_dict_state(tmp_path, doc):
    """`read_budget` returns `{}` for a `budget.json` that parses fine and is not a state.

    `read_json_locked` defends against `JSONDecodeError` alone, so these came back as the state
    itself and `_budget_state_for_enforcement`'s `{**state, …}` raised `TypeError: 'list' object
    is not a mapping`. The named writer is the boxed adapter subprocess: the run root is
    bind-mounted **rw** into the box while the defender tree is mounted readonly, and it is the
    process that handles attacker-influenced payloads. No privilege is gained — this is
    availability, and precisely the DoS lever `docs/runtime-sandbox-design.md` §7 D3 denies."""
    (tmp_path / "budget.json").write_text(doc, encoding="utf-8")
    assert read_budget(tmp_path) == {}


@pytest.mark.parametrize("doc", ["[]", "3", '"x"', "null"])
def test_the_enforcement_path_survives_a_non_dict_budget(tmp_path, doc):
    """The composed path, driven the way `driver._budget_short_circuit` drives it: spread the
    state into a dict, then ask `tail_exhausted`. This is the assertion that would have caught
    F-17(a) — `read_budget`'s return type alone was never the claim."""
    (tmp_path / "budget.json").write_text(doc, encoding="utf-8")
    state = {**read_budget(tmp_path), "started_monotonic": None}
    assert tail_exhausted(state, DEFAULT_LIMITS) is False


@pytest.mark.parametrize("doc", ["[]", "3", '"x"', "null"])
def test_open_budget_starts_over_from_a_non_dict_document(tmp_path, doc):
    """`open_budget` over the same shapes. Its `_mutate` opens with `state.setdefault(...)`, so
    a non-dict raised `AttributeError` from the writer instead — the case the report scoped out
    of F-17 by requiring the corrupt write to land AFTER the open. `update_json_locked` now
    falls back to `default()` for a document it cannot read as state, the same judgement it
    already made for `JSONDecodeError`, so the writer starts over rather than crashing."""
    (tmp_path / "budget.json").write_text(doc, encoding="utf-8")
    state = open_budget(tmp_path, "run-878")
    assert state["run_id"] == "run-878"
    assert state["tool_calls"] == 0
    assert json.loads((tmp_path / "budget.json").read_text(encoding="utf-8"))["run_id"] == "run-878"


def test_a_naive_created_at_does_not_raise_out_of_the_elapsed_check(tmp_path):
    """`tail_exhausted` over a state whose `created_at` carries NO OFFSET returns a verdict.

    `_wall_origin` caught only `ValueError` around a bare `datetime.fromisoformat`, and this
    shape does not raise `ValueError` — it returns a NAIVE datetime, and `_elapsed`'s
    `datetime.now(UTC) - origin` then raised `TypeError: can't subtract offset-naive and
    offset-aware datetimes`.

    This is F-17's UNCONDITIONAL path: `lead_zero._budget_gate` is documented as not gated on
    `DEFENDER_BUDGET_ENFORCE` (which defaults to False) and is called from `_issue` inside
    `resolve_lead_zero`, whose only handler catches `BudgetKill` and `RunAborted` — so the
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
    (tmp_path / "budget.json").write_text(json.dumps(naive), encoding="utf-8")

    assert open_budget(tmp_path, "r")["created_at"] == stamp, \
        "the open replaced the naive stamp — this shape no longer reaches enforcement"
    assert tail_exhausted(read_budget(tmp_path), DEFAULT_LIMITS) is True, \
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


# ---------------------------------------------------------------------------------------
# F-25 — below the top level, no reader or writer of the breaker state validated its shape
# ---------------------------------------------------------------------------------------

#: The four nested shapes, each reproduced against the real module before the fix.
#: `{"systems": 5}` and `{"systems": {"elastic": 7}}` raised `AttributeError` in `is_tripped`;
#: `{"failures": "x"}` raised `TypeError: '>=' not supported between instances of 'str' and
#: 'int'` in the same reader; `{"total_failures": "x"}` passed every reader and raised
#: `TypeError` in the WRITER, and is the only shape that reached `_mutate` on the query path,
#: because no reader touches that key.
_NESTED_SHAPES = [
    pytest.param({"systems": 5}, id="systems-is-a-scalar"),
    pytest.param({"systems": {"elastic": 7}}, id="record-is-a-scalar"),
    pytest.param({"systems": {"elastic": {"failures": "x"}}}, id="failures-is-a-string"),
    pytest.param({"systems": {}, "total_failures": "x"}, id="total-failures-is-a-string"),
]


@pytest.mark.parametrize("doc", _NESTED_SHAPES)
def test_is_tripped_returns_a_verdict_over_a_corrupt_nested_shape(tmp_path, doc):
    """`is_tripped` over each nested shape returns a bool rather than raising.

    It sits OUTSIDE every `try` at both of its call sites — `query_tool`'s breaker check and
    the judge's closed-ticket tool — so the raise passed `_run_gather`'s six named types and
    `_drive_agent`'s five handlers and killed the process.

    The verdict is DOWN, not healthy. `_load`'s §7 D3 rider says a state this module cannot
    read must not read as a healthy, freshly initialised breaker, and it already fails closed on
    a non-dict TOP level; a nested shape is the same rule one level down. Coercing to `{}`
    instead would answer "no system is down" — the fail-open the rider exists to deny — for a
    document whose writer is an out-of-band write into the rw-bound run root."""
    (tmp_path / "circuit_breaker.json").write_text(json.dumps(doc), encoding="utf-8")
    assert cb.is_tripped(tmp_path, "elastic") is True
    assert "UNREADABLE" in cb.down_message(tmp_path, "elastic"), \
        "the state failed closed but the model was told a failure count it does not have"


@pytest.mark.parametrize("doc", _NESTED_SHAPES)
def test_record_outcome_returns_a_verdict_over_a_corrupt_nested_shape(tmp_path, doc):
    """`record_outcome` over the same shapes returns a state rather than raising.

    The writer COERCES where the reader refuses: it cannot fail closed, because it has to leave
    a countable document behind, so a level it cannot read as a counter it starts that counter
    over from — the same thing `default=_blank` already does for the document as a whole. Two
    further failures must therefore still trip the system, which the second arm drives: a
    corrupt state must not become a breaker that can never trip again."""
    path = tmp_path / "circuit_breaker.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    state = cb.record_outcome(tmp_path, "elastic", 2)
    assert isinstance(state, dict)
    assert cb.is_tripped(tmp_path, "elastic") is False, "one failure tripped the breaker"

    cb.record_outcome(tmp_path, "elastic", 2)
    assert cb.is_tripped(tmp_path, "elastic") is True, \
        "the coerced counter never reached PER_SYSTEM_FAIL_LIMIT — the breaker cannot trip"


@pytest.mark.parametrize("doc", ["[]", "3", '"x"', "null"])
def test_record_outcome_survives_a_non_dict_top_level(tmp_path, doc):
    """The TOP-level shapes reach `_mutate` too — before #878 only through F-07's load-error
    branch, which records before the breaker check. `_mutate` cannot repair them in place (it
    mutates the object `update_json_locked` writes back), so the coercion lives at that shared
    seam, and `record_outcome`'s widened `except` is the backstop that honours the rule its own
    comment states: a breaker write must not be the reason the run crashes."""
    (tmp_path / "circuit_breaker.json").write_text(doc, encoding="utf-8")
    assert isinstance(cb.record_outcome(tmp_path, "elastic", 2), dict)
    cb.record_outcome(tmp_path, "elastic", 2)
    assert cb.is_tripped(tmp_path, "elastic") is True


def test_a_healthy_state_still_reads_and_trips(tmp_path):
    """The positive control the shape checks could otherwise break silently: an ordinary,
    well-formed state still counts, still trips at `PER_SYSTEM_FAIL_LIMIT`, and still reports a
    real failure count — not the unreadable message — in `down_message`."""
    assert cb.is_tripped(tmp_path, "elastic") is False
    cb.record_outcome(tmp_path, "elastic", 2)
    assert cb.is_tripped(tmp_path, "elastic") is False
    cb.record_outcome(tmp_path, "elastic", 2)
    assert cb.is_tripped(tmp_path, "elastic") is True
    msg = cb.down_message(tmp_path, "elastic")
    assert "UNREADABLE" not in msg
    assert "2 connectivity/auth failures" in msg
    assert cb.is_tripped(tmp_path, "identity") is False, "one system's failures tripped another"


# ---------------------------------------------------------------------------------------
# The read half of the same seam: UNDECODABLE bytes, and an alias at the state's name
# ---------------------------------------------------------------------------------------

#: A byte the utf-8 decoder cannot start a sequence with. The run root is bind-mounted rw into
#: the box, so "not utf-8" needs no more privilege than "not a dict" does.
_UNDECODABLE = b'\xff\xfe{"systems": {}}'


def test_is_tripped_returns_a_verdict_over_undecodable_bytes(tmp_path):
    """`_load` guarded its `read_text` with `OSError` alone. Reading a text file has a SECOND
    fault class — `UnicodeDecodeError`, a `ValueError` — so non-UTF-8 bytes at the breaker's
    name raised out of `is_tripped`, from the same call sites and past the same handlers as the
    nested shapes above. Same verdict as every other unreadable state: DOWN."""
    (tmp_path / "circuit_breaker.json").write_bytes(_UNDECODABLE)
    assert cb.is_tripped(tmp_path, "elastic") is True
    assert "UNREADABLE" in cb.down_message(tmp_path, "elastic")
    assert isinstance(cb.record_outcome(tmp_path, "elastic", 2), dict)


def test_the_budget_readers_survive_undecodable_bytes(tmp_path):
    """The same fault class on the same seam, both directions. `read_json_locked`'s
    `except OSError` and `update_json_locked`'s bare `f.read()` each let a
    `UnicodeDecodeError` out of a text-mode handle — out of `read_budget` into
    `_budget_state_for_enforcement`, and out of `open_budget` before MAIN's first prompt. It is
    F-17's harm reached one step earlier than the parse the fix narrowed."""
    (tmp_path / "budget.json").write_bytes(_UNDECODABLE)
    assert read_budget(tmp_path) == {}
    assert tail_exhausted({**read_budget(tmp_path), "started_monotonic": None},
                          DEFAULT_LIMITS) is False
    assert open_budget(tmp_path, "run-878")["run_id"] == "run-878"
    assert json.loads((tmp_path / "budget.json").read_text(encoding="utf-8"))["tool_calls"] == 0


def test_read_json_locked_refuses_an_alias_at_the_state_name(tmp_path):
    """A SYMLINK at `budget.json` reads as no state, not as whatever it points at.

    `update_json_locked` goes through `locked_for_rewrite`, which refuses a non-plain target
    before it locks anything (#771 M3), and `circuit_breaker._load` refuses one on its own read
    side. `read_json_locked` — the read half of the same pair — followed it, so the box could
    aim the enforcement path's state read at any file it liked."""
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"run_id": "not-this-run", "tool_calls": 10 ** 6}),
                       encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "budget.json").symlink_to(outside)
    assert read_budget(run_dir) == {}


def test_accounting_failure_state_normalises_corrupt_counters(tmp_path):
    """The counters INSIDE the sidecar, which the seam narrowing does not reach: a string count
    raised `ValueError` out of `int(...)`, and a non-number `first_failure_at` raised `TypeError`
    out of `time.monotonic() - stamp` — both from inside `account_call`'s `except OSError` arm,
    which handles neither."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    sidecar = run_dir.parent / f"{run_dir.name}.accounting_failures.json"
    sidecar.write_text(json.dumps({"consecutive_failures": "x", "first_failure_at": "nope"}),
                       encoding="utf-8")

    assert budget_enforcer.accounting_failure_state(run_dir) == {
        "consecutive_failures": 0, "first_failure_at": None,
    }
    budget_enforcer._record_accounting_failure(run_dir, DEFAULT_LIMITS)
    state = budget_enforcer.accounting_failure_state(run_dir)
    assert state["consecutive_failures"] == 1
    assert isinstance(state["first_failure_at"], float)


def test_the_run_kill_still_fires_on_a_healthy_state(tmp_path):
    """The other positive control: `RUN_FAIL_KILL_LIMIT` is still reachable. The F-07 fix stops
    ONE class of call from spending it, and the coercions here must not have made the kill
    itself unreachable — it is the deliberate abort for a genuinely unreachable environment."""
    for i in range(cb.RUN_FAIL_KILL_LIMIT - 1):
        cb.record_outcome(tmp_path, f"system-{i}", 2)
    with pytest.raises(cb.RunAborted):
        cb.record_outcome(tmp_path, "system-last", 2)
