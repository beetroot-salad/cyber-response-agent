"""The queries table's writer and reader agree on what a row is: params past the nesting limit are refused, never cut."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run

from collections import deque
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import yaml

from defender._io import parse_jsonl_row, read_jsonl_rows
from defender.run_repository import RunPaths
from defender import _query_rules
from defender.scripts.gather_tools.record_query import append_query_row
from defender._query_rules import params_too_deep

LEAD = "l-001"

LIMIT = 32

#: Far past the limit and past where a recursive walk of the value exhausts the interpreter's
#: stack — the depth that tells a bounded refusal from a `RecursionError`.
FAR = 3000

#: The differential's range: the limit, and as far again past it.
DEPTHS = 60


# ── builders ──────────────────────────────────────────────────────────────────────────────


def dict_chain(depth: int) -> Any:
    """A value whose container nesting is exactly `depth` (0 is a scalar), all dicts."""
    value: Any = "leaf"
    for _ in range(depth):
        value = {"k": value}
    return value


def list_chain(depth: int) -> Any:
    value: Any = "leaf"
    for _ in range(depth):
        value = [value]
    return value


def tuple_chain(depth: int) -> Any:
    value: Any = "leaf"
    for _ in range(depth):
        value = (value,)
    return value


def frozenset_chain(depth: int) -> Any:
    value: Any = "leaf"
    for _ in range(depth):
        value = frozenset({value})
    return value


def proxy_chain(depth: int) -> Any:
    """A read-only `Mapping` that is not a `dict` — `_json_safe_walk` counts any `Mapping`."""
    value: Any = "leaf"
    for _ in range(depth):
        value = MappingProxyType({"k": value})
    return value


def mixed_chain(depth: int) -> Any:
    """Every container kind the cleaner walks, in one value: the inner half hashable (tuples
    and frozensets), then one `set` wrapping them, then dicts, lists and read-only mappings.
    A `set` can only hold hashable members, which is what fixes the order."""
    value: Any = "leaf"
    for i in range(depth):
        if i < depth // 2:
            value = (value,) if i % 2 == 0 else frozenset({value})
        elif i == depth // 2:
            value = {value}
        else:
            kind = i % 3
            value = {"k": value} if kind == 0 else [value] if kind == 1 else (
                MappingProxyType({"k": value}))
    return value


def params_of_depth(depth: int, chain: Callable[[int], Any] = dict_chain) -> dict:
    """A params map whose nesting is `depth` WITH THE MAP ITSELF COUNTED — the unit C1 and the
    design use. `{"filt": "leaf"}` is depth 1."""
    assert depth >= 1
    return {"filt": chain(depth - 1)}


# ── the writer, driven the way every production writer drives it ───────────────────────────


def _started(root: Path):  # noqa: ANN202 — a `RunState` (#1235: not imported at module top)
    """A run the writer can be driven on: a run folder and the run's state, started as a run
    start starts it (#1235), since the writer takes each row's seq from the state."""
    from defender.runtime.run_state import RunState

    RunPaths(root).gather_raw.mkdir(parents=True, exist_ok=True)
    return RunState(root, "r1127-nesting")


def _rows(state) -> list[dict]:  # noqa: ANN001
    """This lead's rows as the FILE holds them — what the table's reader returns."""
    return [r for r in read_jsonl_rows(RunPaths(state.run_dir).executed_queries)
            if r.get("lead_id") == LEAD]


def _append(state, params: Any, payload_text: str = "[]") -> dict:  # noqa: ANN001
    return append_query_row(
        state, run=fixture_run(state.run_dir), lead_id=LEAD, system="elastic", verb="query", query_id="elastic.query",
        params=params, raw_command="elastic query", payload_text=payload_text, exit_code=0,
        payload_status="ok", payload_digest="2 bytes", system_key="",
    )


def _lines(state) -> list[str]:  # noqa: ANN001
    """The table's physical lines, read RAW — `read_jsonl_rows` would hide an unreadable one,
    which is exactly the line this suite is about."""
    table = RunPaths(state.run_dir).executed_queries
    if not table.is_file():
        return []
    return [line for line in table.read_text(encoding="utf-8").splitlines() if line.strip()]


def _sidecar(state, seq: int) -> Path:  # noqa: ANN001
    return RunPaths(state.run_dir).payload(LEAD, seq)


def _sidecars(state) -> list[Path]:  # noqa: ANN001
    return sorted(RunPaths(state.run_dir).gather_raw.rglob("*.json"))


# ── the refusal, judged by what was raised ─────────────────────────────────────────────────


def too_deep_error() -> type[BaseException]:
    """`_query_rules.ParamsTooDeep`, resolved when an arm needs it, so a missing name fails
    that arm with a plain message instead of failing every arm at collection."""
    error = getattr(_query_rules, "ParamsTooDeep", None)
    assert isinstance(error, type), "_query_rules.ParamsTooDeep does not exist"
    return error


def raised(fn: Callable[[], Any]) -> Exception | None:
    """What `fn` raised, or `None` if it returned. Captured rather than asserted through
    `pytest.raises`, so a `RecursionError` from a 3000-level walk is reported by its name
    rather than as a thousand-frame traceback, and no deep value reaches pytest's repr."""
    try:
        fn()
    except Exception as e:
        return e
    return None


def assert_refused_as_too_deep(err: Exception | None, what: str) -> None:
    """B's refusal, exactly: raised, not a stack overflow, not an internal error, and the typed
    `ParamsTooDeep`. (`RecursionError` IS a `RuntimeError`, so it is named first.)"""
    assert err is not None, f"{what} was accepted — nothing refused it"
    assert not isinstance(err, RecursionError), \
        f"{what} blew the stack (RecursionError) instead of being refused"
    assert not isinstance(err, RuntimeError), \
        f"{what} was refused as an internal error ({type(err).__name__}), not as ParamsTooDeep"
    assert isinstance(err, too_deep_error()), \
        f"{what} was refused with {type(err).__name__}: {str(err)[:200]}"


def _write_outcome(run, params: Any) -> str:  # noqa: ANN001 — a `RunState` (#1235)
    """Drive the real writer once: "readable" (one line, its reader accepts it), "unreadable"
    (one line, its reader skips it) or "refused" (`ParamsTooDeep`, and nothing written — no
    line, no sidecar). Any other raise fails the arm."""
    before, sidecars = _lines(run), _sidecars(run)
    err = raised(lambda: _append(run, params))
    if err is not None:
        assert_refused_as_too_deep(err, "the writer")
        assert _lines(run) == before, "the writer refused the row but still appended a line"
        assert _sidecars(run) == sidecars, \
            "the writer refused the row but still persisted a payload sidecar"
        return "refused"
    after = _lines(run)
    assert len(after) == len(before) + 1, "the writer returned without appending exactly one line"
    return "readable" if parse_jsonl_row(after[-1]) is not None else "unreadable"


def _cleaner_refuses(params: Any) -> bool:
    """The params cleaner both writers share, asked directly: does it refuse `params`? A
    refusal must be `ParamsTooDeep`; any other raise fails the arm."""
    err = raised(lambda: _query_rules._json_safe_params(params))
    if err is None:
        return False
    assert_refused_as_too_deep(err, "the params cleaner")
    return True


# ── A: one owner for the limit ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("chain", [
    dict_chain, list_chain, tuple_chain, frozenset_chain, proxy_chain, mixed_chain,
], ids=lambda c: c.__name__)
def test_the_predicate_admits_the_limit_and_refuses_one_past_it(chain):
    """The predicate at the boundary, for every container kind `_json_safe_walk` counts. The
    params map itself is level 1."""
    assert params_too_deep(params_of_depth(LIMIT - 1, chain)) is False
    assert params_too_deep(params_of_depth(LIMIT, chain)) is False
    assert params_too_deep(params_of_depth(LIMIT + 1, chain)) is True
    assert params_too_deep(params_of_depth(LIMIT + 50, chain)) is True


def test_a_deep_key_is_written_as_a_readable_row(tmp_path):
    """The positive half of the keys arm, on the writer: the deep-keyed params map is written
    and read back as one row, its key as text. A cleaner that counted keys would refuse it."""
    run = _started(tmp_path)
    params = {"filt": {tuple_chain(LIMIT + 50): "v"}}

    assert _write_outcome(run, params) == "readable"
    rows = _rows(run)
    assert len(rows) == 1
    assert list(rows[0]["params"]["filt"]) == [str(tuple_chain(LIMIT + 50))], \
        "the deep key did not reach the row as text"


# ── cycles and shared references, in process ───────────────────────────────────────────────


def _dict_that_holds_itself() -> dict:
    d: dict = {}
    d["self"] = d
    return d


def _params_holding_a_list_that_holds_itself() -> dict:
    seq: list = []
    seq.append(seq)
    return {"filt": seq}


def _yaml_anchor_cycle() -> Any:
    """C10's shape: an anchor whose body aliases itself. Built with PyYAML's own safe loader,
    which still honours aliases — the repo's manifest loader refuses them (C), but a cyclic
    VALUE can still reach the predicate from any other producer."""
    return yaml.safe_load("p: &a {k: [*a]}")["p"]


CYCLES = [_dict_that_holds_itself, _params_holding_a_list_that_holds_itself, _yaml_anchor_cycle]


@pytest.mark.parametrize("build", CYCLES, ids=lambda b: b.__name__)
def test_a_cyclic_value_is_too_deep_and_the_walk_terminates(build):
    value = build()
    assert _is_cyclic(value), "the fixture is not a cycle, so this arm tests nothing"
    assert params_too_deep(value) is True


@pytest.mark.parametrize("build", CYCLES, ids=lambda b: b.__name__)
def test_the_writer_refuses_a_cyclic_value_as_too_deep_and_writes_nothing(tmp_path, build):
    run = _started(tmp_path)
    value = build()
    assert _is_cyclic(value), "the fixture is not a cycle, so this arm tests nothing"

    assert _write_outcome(run, value) == "refused"
    assert _lines(run) == []
    assert _sidecars(run) == []


def _shared_in_sequences(value: Any) -> dict:
    return {"filt": [value, value, (value, value)]}


def _yaml_anchor_reused() -> Any:
    """An anchor aliased twice — the ordinary YAML way to repeat a block, and no cycle."""
    return yaml.safe_load("a: &h {host: x, tags: [p, q]}\nb: *h\nc: [*h, *h]")


@pytest.mark.parametrize("build", [
    lambda: _shared_under_two_keys({"host": "x"}),
    lambda: _shared_under_two_keys(dict_chain(LIMIT - 1)),
    lambda: _shared_in_sequences({"k": "v"}),
    _yaml_anchor_reused,
], ids=["shared-flat", "shared-at-the-limit", "shared-in-sequences", "yaml-anchor-reused"])
def test_a_value_reached_twice_is_not_a_cycle(build):
    value = build()
    assert not _is_cyclic(value), "the fixture is a cycle, so this arm tests nothing"
    assert params_too_deep(value) is False


def _is_cyclic(value: Any) -> bool:
    stack, seen = [(value, frozenset())], 0
    while stack and seen < 10_000:
        seen += 1
        node, path = stack.pop()
        if id(node) in path:
            return True
        if isinstance(node, dict):
            stack.extend((child, path | {id(node)}) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, path | {id(node)}) for child in node)
    return False


# ── C1 / B: the writer refuses exactly what is past the limit ──────────────────────────────


@pytest.mark.parametrize("depth", [LIMIT - 1, LIMIT])
def test_a_row_at_or_under_the_limit_is_written_verbatim_and_read_back(tmp_path, depth):
    """C1's readable side, and #1117's promise that data writers never cut: the params map is
    written WHOLE — equal to the input, not a repr of a cut — and the reader returns it."""
    run = _started(tmp_path)
    params = params_of_depth(depth)

    row = _append(run, params, payload_text='["ok"]')

    assert row["seq"] == 0
    rows = _rows(run)
    assert len(rows) == 1, f"a depth-{depth} params row was written and then not read back"
    assert rows[0]["params"] == params, "the stored params are not the params the call carried"
    assert list(run.lead_rows(LEAD)) == rows, "the written row is not the row the run's state holds"
    assert _sidecar(run, 0).read_text(encoding="utf-8") == '["ok"]'


@pytest.mark.parametrize("depth", [LIMIT + 1, LIMIT + 2, FAR])
def test_a_row_past_the_limit_is_refused_as_too_deep_before_anything_is_written(tmp_path, depth):
    run = _started(tmp_path)
    params = params_of_depth(depth)

    assert_refused_as_too_deep(
        raised(lambda: _append(run, params, payload_text='["deep"]')),
        f"a depth-{depth} params row")

    assert _lines(run) == [], "the refused row still reached the table"
    assert not _sidecar(run, 0).exists(), \
        "the refused row still persisted its payload sidecar — an orphan the next row overwrites"
    assert _rows(run) == []
    assert list(run.lead_rows(LEAD)) == [], "the refused row still reached the run's state"


# ── the differential: predicate ⇔ cleaner ⇔ written line ───────────────────────────────────


_SHAPES: dict[str, Callable[[int], dict]] = {
    "dict": lambda d: params_of_depth(d, dict_chain),
    "list": lambda d: params_of_depth(d, list_chain),
    "tuple": lambda d: params_of_depth(d, tuple_chain),
    "frozenset": lambda d: params_of_depth(d, frozenset_chain),
    "set-top": lambda d: {"filt": set(frozenset_chain(d - 1))} if d >= 2 else {"filt": "leaf"},
    "mapping": lambda d: params_of_depth(d, proxy_chain),
    "mixed": lambda d: params_of_depth(d, mixed_chain),
    # Depth in the KEY only: the value is two levels whatever `d` is.
    "deep-key": lambda d: {"filt": {tuple_chain(d): "v"}},
    # Not a container the cleaner walks: it is written as its text.
    "deque": lambda d: {"filt": _deque_chain(d)},
    # ONE value reached by two keys — a shared reference, not a cycle. The cleaner writes it
    # twice at the same depth, so it is exactly as deep as one copy.
    "shared": lambda d: _shared_under_two_keys(dict_chain(d - 1)),
}

#: Shapes whose written depth never grows with `d`: nothing may ever be refused.
_NEVER_DEEP = ("deep-key", "deque")


def _shared_under_two_keys(value: Any) -> dict:
    return {"filt": value, "also": value}


def _deque_chain(depth: int) -> Any:
    value: Any = "leaf"
    for _ in range(depth):
        value = deque([value])
    return value


@pytest.mark.parametrize("shape", list(_SHAPES))
def test_the_predicate_the_cleaner_and_the_written_line_agree_at_every_depth(tmp_path, shape):
    build = _SHAPES[shape]
    disagreements = []
    refused_at = set()
    for depth in range(1, DEPTHS + 1):
        params = build(depth)
        predicted_ok = not params_too_deep(params)
        cleaner_ok = not _cleaner_refuses(params)
        outcome = _write_outcome(_started(tmp_path / f"d{depth}"), params)
        if outcome == "refused":
            refused_at.add(depth)
        expected = "readable" if predicted_ok else "refused"
        if (cleaner_ok, outcome) != (predicted_ok, expected):
            disagreements.append((depth, predicted_ok, cleaner_ok, outcome))

    assert disagreements == [], (
        f"{shape}: the predicate, the cleaner and the written line disagree at (depth, "
        f"predicted_ok, cleaner_ok, outcome) {disagreements[:5]}")
    if shape in _NEVER_DEEP:
        assert refused_at == set(), \
            f"{shape} is never deep on disk, yet depths {sorted(refused_at)} were refused"
    else:
        assert refused_at == set(range(LIMIT + 1, DEPTHS + 1)), (
            f"{shape}: {len(refused_at)} depths refused, the first "
            f"{min(refused_at, default=None)}; expected exactly {LIMIT + 1}..{DEPTHS}")


# ── C13: a refusal never costs the next row its seq or its sidecar ─────────────────────────


def test_the_row_after_a_refused_one_takes_the_next_seq_and_overwrites_nothing(tmp_path):
    run = _started(tmp_path)
    first = _append(run, {"native_query": "FROM a"}, payload_text='["first"]')
    first_bytes = _sidecar(run, 0).read_bytes()

    assert_refused_as_too_deep(
        raised(lambda: _append(run, params_of_depth(LIMIT + 1), payload_text='["deep"]')),
        "the one-past-the-limit row")
    assert not _sidecar(run, 1).exists(), \
        "the refused row persisted a sidecar at the seq the next row will be handed"

    second = _append(run, {"native_query": "FROM b"}, payload_text='["second"]')

    assert (first["seq"], second["seq"]) == (0, 1)
    assert [r["seq"] for r in _rows(run)] == [0, 1]
    assert _sidecar(run, 0).read_bytes() == first_bytes, "an earlier sidecar was rewritten"
    assert _sidecar(run, 1).read_text(encoding="utf-8") == '["second"]'
    assert all(parse_jsonl_row(line) is not None for line in _lines(run)), \
        "the table holds a line its own reader skips"
