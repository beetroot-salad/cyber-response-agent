"""#1127 — the queries table's writer and its reader agree on what a row is.

`read_jsonl_rows` refuses any line nested deeper than `_io.JSON_NESTING_LIMIT` (100), judged on
the bytes. A row wraps `params` in one level, so a params map nested 100 deep (the map itself
counted as 1) is written today and never read again: `lead_rows` skips it, `_next_seq` reuses
its seq, and the next row overwrites its payload sidecar (C1, C13).

The design (issue #1127, "Intent + design (discuss-issue, settled)") answers with a REFUSAL,
never a cut:

* M1 — `record_query.PARAMS_NESTING_LIMIT = JSON_NESTING_LIMIT - 1`, and one predicate,
  `params_too_deep(value)`, that walks the Python value the way `_io._json_safe_walk` does: a
  level per `Mapping` or list/tuple/set/frozenset, values not keys, stopping once past the
  limit so a cyclic value terminates.
* M3 — `append_query_row` raises `RuntimeError` when the line it would write fails
  `_io.parse_jsonl_row`, and checks BEFORE `persist_payload`, so a refusal leaves no sidecar.

M1 and M3 are two copies of one rule (a value walk and a byte scan), so the arm that matters
most here is the DIFFERENTIAL: across depths 1..150 and every container kind, the predicate's
answer and the written line's readability must agree. It is asserted on the line the writer
actually wrote, read back off disk, never on the writer's allow/deny alone.

RED today: `PARAMS_NESTING_LIMIT` and `params_too_deep` do not exist (imported inside each
test so one missing name does not mask the writer arms), and `append_query_row` writes the
deep row. The depth-99 and depth-98 arms are the positive controls and pass today.
"""
from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from defender import _yaml
from defender._io import JSON_NESTING_LIMIT, parse_jsonl_row
from defender._run_paths import RunPaths
from defender.scripts.gather_tools.record_query import append_query_row, lead_rows

LEAD = "l-001"

#: The deepest params map a readable row can carry: the row wraps params in one level. Derived
#: from the reader's own bound rather than spelled, so these arms move with the reader; the
#: constant the implementation exports is pinned against it separately.
LIMIT = JSON_NESTING_LIMIT - 1


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


def _append(run_dir: Path, params: dict, payload_text: str = "[]") -> dict:
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


def _write_and_read_back(run_dir: Path, params: dict) -> bool:
    """Drive the real writer once and report whether the line it wrote is a row its reader
    accepts. A refusal counts as "not readable" — and must have written nothing."""
    before = _lines(run_dir)
    try:
        _append(run_dir, params)
    except RuntimeError:
        assert _lines(run_dir) == before, "the writer refused the row but still appended a line"
        return False
    after = _lines(run_dir)
    assert len(after) == len(before) + 1, "the writer returned without appending exactly one line"
    return parse_jsonl_row(after[-1]) is not None


def run_to_completion(fn: Callable[[], Any], *, seconds: float = 10.0) -> Any:
    """Run `fn` and return its result, failing if it does not finish — "terminates" made an
    assertion rather than a hang. A raise inside is re-raised here."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as e:  # noqa: BLE001 — carried back to the test thread
            box["error"] = e

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"did not terminate within {seconds}s"
    if "error" in box:
        raise box["error"]
    return box["value"]


# ── M1: one owner for the limit ────────────────────────────────────────────────────────────


def test_the_params_limit_is_the_readers_bound_less_the_rows_own_level():
    """M1: `PARAMS_NESTING_LIMIT = JSON_NESTING_LIMIT - 1` — derived from the reader's bound,
    because the row (and the ledger row) put `params` directly under the row object."""
    from defender.scripts.gather_tools.record_query import PARAMS_NESTING_LIMIT

    assert PARAMS_NESTING_LIMIT == JSON_NESTING_LIMIT - 1 == 99


@pytest.mark.parametrize("chain", [
    dict_chain, list_chain, tuple_chain, frozenset_chain, proxy_chain, mixed_chain,
], ids=lambda c: c.__name__)
def test_the_predicate_admits_the_limit_and_refuses_one_past_it(chain):
    """M1 at the boundary, for every container kind `_json_safe_walk` counts. The params map
    itself is level 1."""
    from defender.scripts.gather_tools.record_query import params_too_deep

    assert params_too_deep(params_of_depth(LIMIT - 1, chain)) is False
    assert params_too_deep(params_of_depth(LIMIT, chain)) is False
    assert params_too_deep(params_of_depth(LIMIT + 1, chain)) is True
    assert params_too_deep(params_of_depth(LIMIT + 50, chain)) is True


def test_the_predicate_counts_the_params_map_itself():
    """The off-by-one C1 found: the map is a level. A bare chain of `LIMIT + 1` dicts IS a
    params map nested `LIMIT + 1` deep, and a flat map is depth 1, not 0."""
    from defender.scripts.gather_tools.record_query import params_too_deep

    assert params_too_deep({}) is False
    assert params_too_deep({"a": 1, "b": "x"}) is False
    assert params_too_deep(dict_chain(LIMIT)) is False
    assert params_too_deep(dict_chain(LIMIT + 1)) is True


def test_the_predicate_walks_values_not_keys():
    """`json_safe` turns every key into text, so a key's own nesting never reaches the row: a
    tuple key nested far past the limit is a short string on disk. The predicate must not count
    it — and the written line proves the row really is shallow."""
    from defender.scripts.gather_tools.record_query import params_too_deep

    params = {"filt": {tuple_chain(LIMIT + 50): "v", frozenset_chain(LIMIT + 50): "w"}}
    assert params_too_deep(params) is False
    # The complementary condition on the same shape: the same depth moved into the VALUE.
    assert params_too_deep({"filt": {"k": tuple_chain(LIMIT + 50)}}) is True


def test_a_deep_key_is_written_as_a_readable_row(tmp_path):
    """The positive half of the keys arm, on the writer: the deep-keyed params map is written
    and read back as one row. Green today; it stays green only if M3 judges the BYTES."""
    run_dir = _run_dir(tmp_path)
    params = {"filt": {tuple_chain(LIMIT + 50): "v"}}

    assert _write_and_read_back(run_dir, params) is True
    rows = lead_rows(run_dir, LEAD)
    assert len(rows) == 1
    assert list(rows[0]["params"]["filt"]) == [str(tuple_chain(LIMIT + 50))], \
        "the deep key did not reach the row as text"


def _dict_that_holds_itself() -> dict:
    d: dict = {}
    d["self"] = d
    return d


def _params_holding_a_list_that_holds_itself() -> dict:
    seq: list = []
    seq.append(seq)
    return {"filt": seq}


def _yaml_anchor_cycle() -> Any:
    """C10's shape, through the repo's own loader: an anchor whose body aliases itself."""
    return _yaml.safe_load("p: &a {k: [*a]}")["p"]


@pytest.mark.parametrize("build", [
    _dict_that_holds_itself, _params_holding_a_list_that_holds_itself, _yaml_anchor_cycle,
], ids=lambda b: b.__name__)
def test_a_cyclic_value_is_too_deep_and_the_walk_terminates(build):
    """M1: the walk stops once past the limit, so a cycle — which a YAML anchor builds (C10) —
    terminates and is refused. A cycle has no finite depth; answering "shallow" would let it
    through to a writer whose own cleaner recurses on it."""
    from defender.scripts.gather_tools.record_query import params_too_deep

    value = build()
    # The fixture really is cyclic: some container reaches itself again.
    assert _is_cyclic(value), "the fixture is not a cycle, so this arm tests nothing"
    assert run_to_completion(lambda: params_too_deep(value)) is True


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


# ── C1 / M3: the writer refuses exactly what its reader would skip ─────────────────────────


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


@pytest.mark.parametrize("depth", [LIMIT + 1, LIMIT + 2])
def test_a_row_past_the_limit_is_refused_before_anything_is_written(tmp_path, depth):
    """C1's unreadable side, refused (M3): `RuntimeError`, no line, and — because the check runs
    before `persist_payload` — no sidecar for the seq the row would have taken."""
    run_dir = _run_dir(tmp_path)

    with pytest.raises(RuntimeError):
        _append(run_dir, params_of_depth(depth), payload_text='["deep"]')

    assert _lines(run_dir) == [], "the refused row still reached the table"
    assert not _sidecar(run_dir, 0).exists(), \
        "the refused row still persisted its payload sidecar — an orphan the next row overwrites"
    assert lead_rows(run_dir, LEAD) == []


# ── M1 ⇔ M3: the differential ──────────────────────────────────────────────────────────────


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
}


def _deque_chain(depth: int) -> Any:
    value: Any = "leaf"
    for _ in range(depth):
        value = deque([value])
    return value


@pytest.mark.parametrize("shape", list(_SHAPES))
def test_the_predicate_and_the_written_line_agree_at_every_depth(tmp_path, shape):
    """THE DIFFERENTIAL (M1 ⇔ M3). For every depth 1..150: `params_too_deep(p)` is False
    exactly when the line `append_query_row` writes for `p` is a row `parse_jsonl_row` reads
    (a refusal is "not readable").

    Asserted on the written LINE, read back off disk — not on whether the writer allowed the
    call — because the predicate and the writer are two copies of one rule, and the only way
    to know they are the same rule is to compare what each says about the same value."""
    from defender.scripts.gather_tools.record_query import params_too_deep

    build = _SHAPES[shape]
    disagreements = []
    seen_outcomes = set()
    for depth in range(1, 151):
        params = build(depth)
        predicted_ok = not params_too_deep(params)
        readable = _write_and_read_back(_run_dir(tmp_path / f"d{depth}"), params)
        seen_outcomes.add(readable)
        if predicted_ok != readable:
            disagreements.append((depth, predicted_ok, readable))

    assert disagreements == [], (
        f"{shape}: the predicate and the written line disagree at (depth, predicted_ok, "
        f"readable) {disagreements[:5]}")
    if shape in ("deep-key", "deque"):
        assert seen_outcomes == {True}, f"{shape} is never deep on disk, yet a row was refused"
    else:
        assert seen_outcomes == {True, False}, \
            f"{shape} never crossed the limit, so the agreement above is vacuous"


# ── C13: a refusal never costs the next row its seq or its sidecar ─────────────────────────


def test_the_row_after_a_refused_one_takes_the_next_seq_and_overwrites_nothing(tmp_path):
    """C13 on the backstop path. Today the deep row is written (seq 1, sidecar `1.json`), is
    unreadable, so `_next_seq` hands seq 1 out again and the next row OVERWRITES that sidecar.
    Refused before `persist_payload`, the deep call leaves no seq and no file behind, and every
    sidecar that exists keeps its bytes."""
    run_dir = _run_dir(tmp_path)
    first = _append(run_dir, {"native_query": "FROM a"}, payload_text='["first"]')
    first_bytes = _sidecar(run_dir, 0).read_bytes()

    with pytest.raises(RuntimeError):
        _append(run_dir, params_of_depth(LIMIT + 1), payload_text='["deep"]')
    assert not _sidecar(run_dir, 1).exists(), \
        "the refused row persisted a sidecar at the seq the next row will be handed"

    second = _append(run_dir, {"native_query": "FROM b"}, payload_text='["second"]')

    assert (first["seq"], second["seq"]) == (0, 1)
    assert [r["seq"] for r in lead_rows(run_dir, LEAD)] == [0, 1]
    assert _sidecar(run_dir, 0).read_bytes() == first_bytes, "an earlier sidecar was rewritten"
    assert _sidecar(run_dir, 1).read_text(encoding="utf-8") == '["second"]'
    assert all(parse_jsonl_row(line) is not None for line in _lines(run_dir)), \
        "the table holds a line its own reader skips"
