"""#1127 — the queries table's writer and its reader agree on what a row is.

`read_jsonl_rows` refuses any line nested deeper than `_io.JSON_NESTING_LIMIT` (100), judged on
the bytes. Before #1127 a params map nested 100 deep (the map itself counted as 1) was written
and never read again: `lead_rows` skipped it, `_next_seq` reused its seq, and the next row
overwrote its payload sidecar (C1, C13).

The design (issue #1127, as amended after the review of PR #1139) answers with a REFUSAL, never
a cut:

* A — `record_query.PARAMS_NESTING_LIMIT = 32`, a plain product constant rather than the
  reader's bound less one: far enough under the reader that a line embedding params a few
  levels down (a wire-log record, a ledger row) still reads back. `params_too_deep(value)` stays
  the one public predicate. It walks the Python value the way `_io._json_safe_walk` does — a
  level per `Mapping` or list/tuple/set/frozenset, values not keys — and stops once past the
  limit, so a cyclic value is too deep and the walk terminates.
* B — the cleaner every params writer goes through (`record_query._json_safe_params`, used by
  `append_query_row` and by `ServedCall.row()`) raises the typed `record_query.ParamsTooDeep`, a
  `ValueError`, past the limit — before `append_query_row` persists the seq's payload sidecar,
  and never the `RecursionError` an unbounded walk hits a few thousand levels down.

The arm that matters most is the DIFFERENTIAL: across depths 1..60 and every container kind,
the predicate, the cleaner and the line the writer wrote agree, and they flip at exactly 33. It
is asserted on the line read back off disk, never on the writer's allow/deny alone.

Against HEAD 7ae2c429 (limit 99, a `RuntimeError` backstop, an unbounded cleaner): every arm
at depth 33 is RED because the row is written; the depth-3000 and cyclic-writer arms are RED
with `RecursionError`; the `ParamsTooDeep` type arm is RED because the name does not exist. The
depth-31/32 controls, the predicate's cycle and shared-reference arms and the deep-key arm are
GREEN and must stay so.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import yaml

from defender._io import parse_jsonl_row
from defender._run_paths import RunPaths
from defender.scripts.gather_tools import record_query as rq
from defender.scripts.gather_tools.record_query import append_query_row, lead_rows, params_too_deep

LEAD = "l-001"

#: The deepest params map a row may carry, the map itself counted as 1. SPELLED, not derived
#: from the reader's bound: the amended design makes it a product constant, pinned once below,
#: and every arm here is about that number.
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


def _run_dir(root: Path) -> Path:
    run_dir = root
    RunPaths(run_dir).gather_raw.mkdir(parents=True, exist_ok=True)
    return run_dir


def _append(run_dir: Path, params: Any, payload_text: str = "[]") -> dict:
    return append_query_row(
        run_dir, lead_id=LEAD, system="elastic", verb="query", query_id="elastic.query",
        params=params, raw_command="elastic query", payload_text=payload_text, exit_code=0,
        payload_status="ok", payload_digest="2 bytes", system_key="",
    )


def _lines(run_dir: Path) -> list[str]:
    """The table's physical lines, read RAW — `read_jsonl_rows` would hide an unreadable one,
    which is exactly the line this suite is about."""
    table = RunPaths(run_dir).executed_queries
    if not table.is_file():
        return []
    return [line for line in table.read_text(encoding="utf-8").splitlines() if line.strip()]


def _sidecar(run_dir: Path, seq: int) -> Path:
    return RunPaths(run_dir).payload(LEAD, seq)


def _sidecars(run_dir: Path) -> list[Path]:
    return sorted(RunPaths(run_dir).gather_raw.rglob("*.json"))


# ── the refusal, judged by what was raised ─────────────────────────────────────────────────


def too_deep_error() -> type[BaseException]:
    """`record_query.ParamsTooDeep`, resolved when an arm needs it, so a missing name fails
    that arm with a plain message instead of failing every arm at collection."""
    error = getattr(rq, "ParamsTooDeep", None)
    assert isinstance(error, type), "record_query.ParamsTooDeep does not exist"
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


def _write_outcome(run_dir: Path, params: Any) -> str:
    """Drive the real writer once: "readable" (one line, its reader accepts it), "unreadable"
    (one line, its reader skips it) or "refused" (`ParamsTooDeep`, and nothing written — no
    line, no sidecar). Any other raise fails the arm."""
    before, sidecars = _lines(run_dir), _sidecars(run_dir)
    err = raised(lambda: _append(run_dir, params))
    if err is not None:
        assert_refused_as_too_deep(err, "the writer")
        assert _lines(run_dir) == before, "the writer refused the row but still appended a line"
        assert _sidecars(run_dir) == sidecars, \
            "the writer refused the row but still persisted a payload sidecar"
        return "refused"
    after = _lines(run_dir)
    assert len(after) == len(before) + 1, "the writer returned without appending exactly one line"
    return "readable" if parse_jsonl_row(after[-1]) is not None else "unreadable"


def _cleaner_refuses(params: Any) -> bool:
    """The params cleaner both writers share, asked directly: does it refuse `params`? A
    refusal must be `ParamsTooDeep`; any other raise fails the arm."""
    err = raised(lambda: rq._json_safe_params(params))
    if err is None:
        return False
    assert_refused_as_too_deep(err, "the params cleaner")
    return True


# ── A: one owner for the limit ─────────────────────────────────────────────────────────────


def test_the_params_limit_is_the_product_constant_32():
    """A: `PARAMS_NESTING_LIMIT = 32` — a product constant, no longer the reader's bound less
    one. That it leaves room for the lines that embed params is pinned on the real wire log
    (`e2e/test_1127_deep_params_query_tool.py`)."""
    assert rq.PARAMS_NESTING_LIMIT == LIMIT == 32


def test_params_too_deep_is_a_typed_domain_error_not_a_value_error_or_an_internal_error():
    """B: the refusal is the typed `ParamsTooDeep`, which each caller maps to its own refusal.
    Not a `ValueError`: `ServedCall` cleans its params as it is built, and pydantic wraps a
    `ValueError` raised there into its `ValidationError`, so `except ParamsTooDeep` would miss
    it. Not a `RuntimeError`, which `WorldRegistry._served`'s `except Exception` would re-file
    as a FAULT row carrying the same deep params."""
    error = too_deep_error()
    assert issubclass(error, Exception)
    assert not issubclass(error, ValueError)
    assert not issubclass(error, RuntimeError)


def test_the_refusal_names_the_field_and_the_limit_in_one_sentence():
    """#1127 review: one sentence, owned by the error, naming the field that was too deep — the
    ledger once blamed `params` when `asked_params` was the deep one."""
    err = raised(lambda: rq._json_safe_params({"k": dict_chain(LIMIT)}, field="asked_params"))

    assert isinstance(err, too_deep_error())
    assert getattr(err, "field", None) == "asked_params"
    assert str(err) == (f"asked_params nest deeper than {LIMIT} levels, the most a stored call "
                        "can carry")


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


def test_the_predicate_counts_the_params_map_itself():
    """The off-by-one C1 found: the map is a level. A bare chain of `LIMIT + 1` dicts IS a
    params map nested `LIMIT + 1` deep, and a flat map is depth 1, not 0."""
    assert params_too_deep({}) is False
    assert params_too_deep({"a": 1, "b": "x"}) is False
    assert params_too_deep(dict_chain(LIMIT)) is False
    assert params_too_deep(dict_chain(LIMIT + 1)) is True


def test_the_predicate_walks_values_not_keys():
    """`json_safe` turns every key into text, so a key's own nesting never reaches the row: a
    tuple key nested far past the limit is a short string on disk. The predicate must not count
    it — and the written line proves the row really is shallow."""
    params = {"filt": {tuple_chain(LIMIT + 50): "v", frozenset_chain(LIMIT + 50): "w"}}
    assert params_too_deep(params) is False
    # The complementary condition on the same shape: the same depth moved into the VALUE.
    assert params_too_deep({"filt": {"k": tuple_chain(LIMIT + 50)}}) is True


def test_a_deep_key_is_written_as_a_readable_row(tmp_path):
    """The positive half of the keys arm, on the writer: the deep-keyed params map is written
    and read back as one row, its key as text. A cleaner that counted keys would refuse it."""
    run_dir = _run_dir(tmp_path)
    params = {"filt": {tuple_chain(LIMIT + 50): "v"}}

    assert _write_outcome(run_dir, params) == "readable"
    rows = lead_rows(run_dir, LEAD)
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
    """The walk stops once past the limit, so a cycle terminates and is refused. A cycle has no
    finite depth; answering "shallow" would let it through to a writer. Run in process: a walk
    that did not stop would hang this test, which is the failure."""
    value = build()
    assert _is_cyclic(value), "the fixture is not a cycle, so this arm tests nothing"
    assert params_too_deep(value) is True


@pytest.mark.parametrize("build", CYCLES, ids=lambda b: b.__name__)
def test_the_writer_refuses_a_cyclic_value_as_too_deep_and_writes_nothing(tmp_path, build):
    """B on a cycle: the bounded cleaner refuses it as `ParamsTooDeep` — the cycle is past any
    limit — rather than recursing into `RecursionError`, and nothing reaches the table or the
    payload directory."""
    run_dir = _run_dir(tmp_path)
    value = build()
    assert _is_cyclic(value), "the fixture is not a cycle, so this arm tests nothing"

    assert _write_outcome(run_dir, value) == "refused"
    assert _lines(run_dir) == []
    assert _sidecars(run_dir) == []


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
    """A shared reference is not a cycle: the cleaner writes it once per place it appears, at
    the depth it appears, so it is no deeper than one copy. Paired with the cyclic arm above:
    the predicate must tell "seen before" from "contains itself"."""
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
    run_dir = _run_dir(tmp_path)
    params = params_of_depth(depth)

    row = _append(run_dir, params, payload_text='["ok"]')

    assert row["seq"] == 0
    rows = lead_rows(run_dir, LEAD)
    assert len(rows) == 1, f"a depth-{depth} params row was written and then not read back"
    assert rows[0]["params"] == params, "the stored params are not the params the call carried"
    assert _sidecar(run_dir, 0).read_text(encoding="utf-8") == '["ok"]'


@pytest.mark.parametrize("depth", [LIMIT + 1, LIMIT + 2, FAR])
def test_a_row_past_the_limit_is_refused_as_too_deep_before_anything_is_written(tmp_path, depth):
    """B: `ParamsTooDeep` — exactly, at one past the limit and at a depth where an unbounded
    walk overflows the stack — with no line, and, because the cleaner runs before
    `persist_payload`, no sidecar for the seq the row would have taken."""
    run_dir = _run_dir(tmp_path)
    params = params_of_depth(depth)

    assert_refused_as_too_deep(
        raised(lambda: _append(run_dir, params, payload_text='["deep"]')),
        f"a depth-{depth} params row")

    assert _lines(run_dir) == [], "the refused row still reached the table"
    assert not _sidecar(run_dir, 0).exists(), \
        "the refused row still persisted its payload sidecar — an orphan the next row overwrites"
    assert lead_rows(run_dir, LEAD) == []


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
    """THE DIFFERENTIAL. For every depth 1..60: `params_too_deep(p)` is False exactly when the
    shared cleaner accepts `p` and `append_query_row` writes a line its reader reads back; it
    is True exactly when the cleaner and the writer refuse `p` with `ParamsTooDeep` and nothing
    is written. And the flip is at exactly `LIMIT + 1`.

    Asserted on the written LINE, read back off disk — not on whether the writer allowed the
    call — because the predicate and the cleaner are two copies of one rule, and the only way to
    know they are the same rule is to compare what each says about the same value."""
    build = _SHAPES[shape]
    disagreements = []
    refused_at = set()
    for depth in range(1, DEPTHS + 1):
        params = build(depth)
        predicted_ok = not params_too_deep(params)
        cleaner_ok = not _cleaner_refuses(params)
        outcome = _write_outcome(_run_dir(tmp_path / f"d{depth}"), params)
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
    """C13 on the writer. Were the deep row written unreadable (seq 1, sidecar `1.json`),
    `_next_seq` would hand seq 1 out again and the next row would OVERWRITE that sidecar.
    Refused before `persist_payload`, the deep call leaves no seq and no file behind, and every
    sidecar that exists keeps its bytes."""
    run_dir = _run_dir(tmp_path)
    first = _append(run_dir, {"native_query": "FROM a"}, payload_text='["first"]')
    first_bytes = _sidecar(run_dir, 0).read_bytes()

    assert_refused_as_too_deep(
        raised(lambda: _append(run_dir, params_of_depth(LIMIT + 1), payload_text='["deep"]')),
        "the one-past-the-limit row")
    assert not _sidecar(run_dir, 1).exists(), \
        "the refused row persisted a sidecar at the seq the next row will be handed"

    second = _append(run_dir, {"native_query": "FROM b"}, payload_text='["second"]')

    assert (first["seq"], second["seq"]) == (0, 1)
    assert [r["seq"] for r in lead_rows(run_dir, LEAD)] == [0, 1]
    assert _sidecar(run_dir, 0).read_bytes() == first_bytes, "an earlier sidecar was rewritten"
    assert _sidecar(run_dir, 1).read_text(encoding="utf-8") == '["second"]'
    assert all(parse_jsonl_row(line) is not None for line in _lines(run_dir)), \
        "the table holds a line its own reader skips"
