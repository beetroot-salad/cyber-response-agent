"""#1127 on the branch ledger — no ledger row past the params limit is ever built or written.

A ledger row puts `params` (and `asked_params`) directly under the row object, exactly as the
queries table does, and both columns go through the one params cleaner
(`record_query._json_safe_params`). Before #1127 the ledger wrote a params map nested past the
reader's bound anyway, and the served-call path wrote TWO such lines per call (the family `base`
row inside `_base_payload`, then the world's own row), neither of which any reader — `_absorb`,
the episode's comparisons, the judge — would ever see.

The design (issue #1127, as amended after the two reviews of PR #1139):

* the cleaner raises `record_query.ParamsTooDeep` past `PARAMS_NESTING_LIMIT` (32, the map
  counted), bounded — so a params map thousands of levels deep is refused, not a
  `RecursionError` — naming the field that was too deep;
* `ServedCall` cleans `params` and `asked_params` once, AS IT IS BUILT: a call no row could
  carry is never built, so `row()`, both keys and `Ledger.record` cannot fail on depth;
* both doors into `WorldRegistry` — `decide_call` and `_served` — refuse such a call UP FRONT,
  as the ledger's own `LedgerError`, before the grant is decided, the estate adapter runs or
  the call is keyed, and file no row at all. `_served` re-raises it untouched; anything else
  would be caught by its `except Exception` and filed as a FAULT row;
* priming reads a captured row too deep to carry as `unreadable`, so one such row in a source
  run never makes the branch point unprimeable.

Every "nothing was written" assertion reads the file's RAW lines: `read_jsonl_rows` would hide a
line it skips.
"""
from __future__ import annotations

import importlib
import logging
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import parse_jsonl_row, read_jsonl_rows  # noqa: E402
from defender.learning.branch.ledger import (  # noqa: E402
    BASE,
    PASSTHROUGH,
    LedgerError,
    ServedCall,
    payload_text,
    request_key,
)
from defender.scripts.gather_tools.record_query import ParamsTooDeep  # noqa: E402
from defender.tests.test_1127_params_nesting_limit import (  # noqa: E402
    FAR,
    LIMIT,
    raised,
)
from defender.tests.test_1127_params_nesting_limit import dict_chain as chain  # noqa: E402
from defender.tests.test_920_estate_seam import (  # noqa: E402
    CALLS_LOG,
    FAKE_GRANT,
    World,
    adapter_calls,
    fake_estate,
    fresh_ledger,
    run_ctx,
    world_registry,
)

#: The registry module's logger — the only place a FAULT row the ledger then refused would
#: leave a trace (`_record_beside` logs and drops a failed write).
REGISTRY_LOGGER = "defender.learning.branch.estate.registry"


def params_of_depth(depth: int, key: str = "host") -> dict:
    """A params map nested `depth` deep with the map itself counted."""
    return {key: chain(depth - 1)}


def raw_lines(path: Path) -> list[str]:
    """Every non-blank physical line of a ledger file — including the ones its reader drops."""
    if not path.is_file():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def served(params: dict, *, source: str = PASSTHROUGH, world_id: str | None = "w1",
           asked_params: dict | None = None) -> ServedCall:
    return ServedCall(
        system="cmdb", verb="get-host", params=params,
        payload_text=payload_text({"owner": "estate"}), source=source, world_id=world_id,
        asked_params=asked_params,
    )


# ── Ledger.record ──────────────────────────────────────────────────────────────────────────


def assert_ledger_refused(err: Exception | None, what: str) -> None:
    """The ledger's own refusal, exactly — judged on a captured exception so a `RecursionError`
    at depth 3000 is reported by its name rather than as a thousand-frame traceback."""
    assert err is not None, f"{what} was recorded — nothing refused it"
    assert isinstance(err, LedgerError), \
        f"{what} was refused with {type(err).__name__}, not LedgerError: {str(err)[:200]}"


@pytest.mark.parametrize("depth", [LIMIT - 1, LIMIT])
def test_a_ledger_row_at_or_under_the_limit_is_recorded_whole_and_read_back(tmp_path, depth):
    """The positive control: at the limit the row is written, its reader returns it, and the
    params are the params served — whole, never cut (#1117's promise holds on this table too)."""
    path = tmp_path / "served" / "w1.jsonl"
    ledger = fresh_ledger(path)
    params = params_of_depth(depth)

    ledger.record(served(params))

    lines = raw_lines(path)
    assert len(lines) == 1
    assert parse_jsonl_row(lines[0]) is not None, "a row at the limit is unreadable"
    assert [row["params"] for row in read_jsonl_rows(path)] == [params]


def assert_too_deep(err: Exception | None, field: str, what: str) -> None:
    """`ParamsTooDeep` naming `field` — judged on a captured exception so a `RecursionError` at
    depth 3000 is reported by its name rather than as a thousand-frame traceback."""
    assert err is not None, f"{what} was built — nothing refused it"
    assert isinstance(err, ParamsTooDeep), \
        f"{what} was refused with {type(err).__name__}, not ParamsTooDeep: {str(err)[:200]}"
    assert err.field == field, f"{what} was refused naming {err.field!r}, not {field!r}"


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_served_call_past_the_limit_is_never_built(depth):
    """A call whose params no row could carry is refused as it is built, with `ParamsTooDeep`
    naming `params` — so no `ServedCall` that `row()` could fail on ever exists. At one past
    the limit and at a depth an unbounded cleaner cannot walk."""
    assert_too_deep(raised(lambda: served(params_of_depth(depth))), "params",
                    f"a depth-{depth} served call")


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_deep_asked_form_is_refused_naming_the_asked_form(depth):
    """`asked_params` goes through the same cleaner, so a staged call whose ASKED form is too
    deep is refused the same way, the ran form shallow — and the refusal names `asked_params`,
    not `params` (#1127 review: the old message blamed the wrong field)."""
    call = raised(lambda: served({"host": "canary-1"}, asked_params=params_of_depth(depth)))

    assert_too_deep(call, "asked_params", f"a depth-{depth} asked form")


def test_a_served_call_holds_its_params_as_the_row_stores_them():
    """Cleaned once, at construction: the call holds what its row writes (a tuple as a list, a
    non-finite float as its text), and both keys are the keys of the raw call — cleaning twice
    changes nothing."""
    raw = {"hosts": ("a", "b"), "threshold": float("inf")}

    call = served(raw, asked_params={"hosts": ("c",)})

    assert call.params == {"hosts": ["a", "b"], "threshold": "Infinity"}
    assert call.row()["params"] == call.params
    assert call.row()["asked_params"] == {"hosts": ["c"]}
    assert call.key == request_key("cmdb", "get-host", raw)
    assert call.correlation_key == request_key("cmdb", "get-host", {"hosts": ("c",)})


# ── the served-call path: WorldRegistry._served ────────────────────────────────────────────


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_deep_served_call_is_refused_before_the_estate_and_files_nothing(
        tmp_path, caplog, depth):
    """Through the real serving frame. The deep call is refused UP FRONT — the estate adapter
    is never entered — the registry re-raises `LedgerError` UNTOUCHED, and the ledger file
    gains no line at all: no `base` row, no world row, and no FAULT row re-filed with the same
    deep params.

    The adapter check is what tells a refusal at the door from a backstop after the call ran:
    a registry that only turned the ledger's late refusal (or a `RecursionError` from keying
    the call) into `LedgerError` would still have run the call against the estate — a read the
    family then has no record of. The warning check tells a `LedgerError` refusal from any
    other: anything else is caught by `_served`'s `except Exception` and re-filed as a FAULT
    row through `_record_beside`, which the ledger then refuses as well and the registry logs.
    The at-limit control below shows the same adapter IS entered for a call it can record."""
    ledger_path = tmp_path / "ep" / "served" / "w1.jsonl"
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))
    ctx = run_ctx(tmp_path)
    host = chain(depth - 1)
    serve = reg.verbs("cmdb")["get-host"]

    with caplog.at_level(logging.WARNING, logger=REGISTRY_LOGGER):
        err = raised(lambda: serve(ctx, host=host))

    assert_ledger_refused(err, f"a depth-{depth} served call")
    assert adapter_calls(ctx, "get-host") == [], "the estate adapter ran the too-deep call"
    # The fake adapter opens its call log before encoding the call, so a call too deep to
    # encode (depth 3000) still leaves the file behind if the adapter was entered at all.
    assert not (Path(ctx.run_dir) / CALLS_LOG).exists(), \
        "the estate adapter was entered for the too-deep call"
    assert raw_lines(ledger_path) == [], \
        "the deep call left lines in the ledger (a base row, a world row or a FAULT row)"
    assert [r.getMessage()[:200] for r in caplog.records if r.name == REGISTRY_LOGGER] == [], \
        "the registry tried to file a second (FAULT) row for the ledger's own refusal"


def test_a_served_call_at_the_limit_records_both_of_its_rows(tmp_path):
    """The positive control on the same address: at the limit the same call reaches the estate
    adapter once, is served, and leaves its two readable rows — the family's `base` recording
    and the world's own `passthrough` row — each carrying the params whole."""
    ledger_path = tmp_path / "ep" / "served" / "w1.jsonl"
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))
    ctx = run_ctx(tmp_path)
    host = chain(LIMIT - 1)

    payload = reg.verbs("cmdb")["get-host"](ctx, host=host)

    assert payload["host"] == host
    assert [c["params"] for c in adapter_calls(ctx, "get-host")] == [{"host": host}], \
        "the estate adapter was not entered exactly once for a call at the limit"
    lines = raw_lines(ledger_path)
    assert len(lines) == 2
    rows = [parse_jsonl_row(line) for line in lines]
    assert all(row is not None for row in rows), "a row at the limit is unreadable"
    assert [(row["source"], row["world_id"]) for row in rows] == [(BASE, None), (PASSTHROUGH, "w1")]
    assert all(row["params"] == {"host": host} for row in rows)


# ── the other door: WorldRegistry.decide_call ──────────────────────────────────────────────


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_deep_call_to_a_denied_verb_is_refused_before_the_decision_and_files_nothing(
        tmp_path, caplog, depth):
    """#1127 review: `decide_call` files a REFUSED row for a denied verb (and a FAULT row for an
    adapter that cannot load) through `_record_beside`, which logs and drops a write that
    fails. A too-deep call there used to reach the ledger, be refused, and be dropped with a
    warning — the call then read as never asked. It is now refused at the door, as the
    ledger's own `LedgerError`, before the grant is decided: no row is attempted, so none is
    dropped. The control: the same denied call, shallow, files its REFUSED row."""
    ledger_path = tmp_path / "ep" / "served" / "w1.jsonl"
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))

    with caplog.at_level(logging.WARNING, logger=REGISTRY_LOGGER):
        err = raised(lambda: reg.decide_call("elastic", "get-host", {"host": chain(depth - 1)}))

    assert isinstance(err, LedgerError), \
        f"refused with {type(err).__name__}, not LedgerError: {str(err)[:200]}"
    assert "params nest deeper than" in str(err)
    assert raw_lines(ledger_path) == []
    assert [r.getMessage()[:200] for r in caplog.records if r.name == REGISTRY_LOGGER] == [], \
        "a row was attempted for the too-deep call and dropped"

    reg.decide_call("elastic", "get-host", {"host": "canary-1"})
    assert [parse_jsonl_row(line)["source"] for line in raw_lines(ledger_path)] == ["refused"]


# ── priming: a captured row the table reads but no ledger row can carry ───────────────────


@pytest.mark.parametrize("depth", [LIMIT + 1, 99])
def test_a_captured_row_too_deep_to_carry_is_unreadable_and_the_rest_still_primes(
        tmp_path, depth):
    """#1127 review: the queries table reads rows up to its own bound (params 99 deep, the row
    one level more), but a ledger row carries at most 32. A source run holding such a row —
    written before the limit, or planted through the box-writable table — used to abort the
    whole prime with an uncaught `ParamsTooDeep`, on every retry, so that branch point could
    never be branched. It is lost evidence like any other: counted `unreadable`, and the
    shallow call beside it is primed."""
    prime = importlib.import_module("defender.tests.test_947_capture_prime")
    run_dir = prime.source_run(tmp_path)
    deep = params_of_depth(depth)
    prime.append_call(run_dir, prime.call_row("l-001", 0, "cmdb", "get-host", deep), "{}")
    prime.append_call(run_dir, prime.call_row("l-001", 1, "cmdb", "get-host",
                                               {"host": "canary-1"}), '{"owner": "estate"}')
    assert len(read_jsonl_rows(run_dir / "executed_queries.jsonl")) == 2, \
        "the source table cannot read its own deep row, so this arm tests nothing"
    root, base = prime.episode(tmp_path)

    report = prime._prime(run_dir, root)

    assert prime.counts(report) == {"primed": 1, "duplicates": 0, "failed": 0,
                                    "sentinels": 0, "unreadable": 1}
    assert [row["params"] for row in read_jsonl_rows(base)] == [{"host": "canary-1"}]
