"""#1127 on the branch ledger — `Ledger.record` never writes a row past the params limit.

A ledger row puts `params` (and `asked_params`) directly under the row object, exactly as the
queries table does, and both columns go through the one params cleaner
(`record_query._json_safe_params`, via `ServedCall.row()`). Before #1127 the ledger wrote a
params map nested past the reader's bound anyway, and the served-call path wrote TWO such lines
per call (the family `base` row inside `_base_payload`, then the world's own row), neither of
which any reader — `_absorb`, the episode's comparisons, the judge — would ever see.

The design (issue #1127, as amended after the review of PR #1139):

* the cleaner raises `record_query.ParamsTooDeep` past `PARAMS_NESTING_LIMIT` (32, the map
  counted), bounded — so a params map thousands of levels deep is refused, not a
  `RecursionError`;
* `Ledger.record` turns that refusal into `LedgerError` — NOT `RuntimeError` — and appends
  nothing;
* `WorldRegistry._served` re-raises `LedgerError` untouched and files no second row. Anything
  else would be caught by its `except Exception` and re-filed as a FAULT row carrying the same
  deep params, which the ledger refuses in turn and the registry logs.

Every "nothing was written" assertion reads the file's RAW lines: `read_jsonl_rows` would hide a
line it skips.

Against HEAD 7ae2c429 (limit 99): the depth-33 arms are RED because the rows are written; the
depth-3000 arms are RED with `RecursionError` out of the unbounded cleaner (on the `_served`
path, re-filed as a FAULT and logged). The depth-31/32 controls are GREEN.
"""
from __future__ import annotations

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
)
from defender.tests.test_1127_params_nesting_limit import (  # noqa: E402
    FAR,
    LIMIT,
    raised,
)
from defender.tests.test_1127_params_nesting_limit import dict_chain as chain  # noqa: E402
from defender.tests.test_920_estate_seam import (  # noqa: E402
    FAKE_GRANT,
    World,
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


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_ledger_row_past_the_limit_is_refused_with_the_ledgers_own_error(tmp_path, depth):
    """`record` refuses params past the limit with `LedgerError` — the table's own refusal
    type, which the serving frame knows not to re-file — and appends nothing. At one past the
    limit and at a depth an unbounded cleaner cannot walk."""
    path = tmp_path / "served" / "w1.jsonl"
    ledger = fresh_ledger(path)
    call = served(params_of_depth(depth))

    assert_ledger_refused(raised(lambda: ledger.record(call)), f"a depth-{depth} params row")

    assert raw_lines(path) == [], "the refused row still reached the ledger file"


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_deep_asked_form_is_refused_too(tmp_path, depth):
    """`asked_params` sits at the same level as `params` and goes through the same cleaner, so
    a staged call whose ASKED form is too deep is refused the same way, the ran form shallow."""
    path = tmp_path / "served" / "w1.jsonl"
    ledger = fresh_ledger(path)
    call = served({"host": "canary-1"}, asked_params=params_of_depth(depth))

    assert_ledger_refused(raised(lambda: ledger.record(call)), f"a depth-{depth} asked form")

    assert raw_lines(path) == []


def test_a_refused_family_row_leaves_no_memo_hit_behind(tmp_path):
    """The ledger's standing rule — persist first, memoize only on success — must hold for a
    refusal too: a family-tier (`base`) row that was refused must not answer later siblings
    from memory, or a key with no row behind it is served without an adapter call.

    Control on the same ledger: a shallow `base` row IS memoized."""
    path = tmp_path / "served" / "w1.jsonl"
    ledger = fresh_ledger(path)
    deep = params_of_depth(LIMIT + 1)
    shallow = {"host": "canary-1"}

    assert_ledger_refused(
        raised(lambda: ledger.record(served(deep, source=BASE, world_id=None))),
        "the one-past-the-limit base row")
    ledger.record(served(shallow, source=BASE, world_id=None))

    assert ledger.base_payload("cmdb", "get-host", deep) is None, \
        "a refused base row still answers from the family memo"
    assert ledger.base_payload("cmdb", "get-host", shallow) == payload_text({"owner": "estate"})
    assert len(raw_lines(path)) == 1


# ── the served-call path: WorldRegistry._served ────────────────────────────────────────────


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_deep_served_call_surfaces_the_ledgers_refusal_and_files_nothing(
        tmp_path, caplog, depth):
    """Through the real serving frame. The deep call is refused, the registry re-raises
    `LedgerError` UNTOUCHED, and the ledger file gains no line at all — no `base` row, no world
    row, and no FAULT row re-filed with the same deep params.

    The warning check is what tells a `LedgerError` refusal from any other: anything else is
    caught by `_served`'s `except Exception` and re-filed as a FAULT row through
    `_record_beside`, which the ledger then refuses as well and the registry logs. At depth
    3000 an unbounded cleaner raises `RecursionError`, which takes exactly that path."""
    ledger_path = tmp_path / "served.jsonl"
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))
    host = chain(depth - 1)
    serve = reg.verbs("cmdb")["get-host"]

    with caplog.at_level(logging.WARNING, logger=REGISTRY_LOGGER):
        err = raised(lambda: serve(run_ctx(tmp_path), host=host))

    assert_ledger_refused(err, f"a depth-{depth} served call")
    assert raw_lines(ledger_path) == [], \
        "the deep call left lines in the ledger (a base row, a world row or a FAULT row)"
    assert [r.getMessage()[:200] for r in caplog.records if r.name == REGISTRY_LOGGER] == [], \
        "the registry tried to file a second (FAULT) row for the ledger's own refusal"


def test_a_served_call_at_the_limit_records_both_of_its_rows(tmp_path):
    """The positive control on the same address: at the limit the same call is served and
    leaves its two readable rows — the family's `base` recording and the world's own
    `passthrough` row — each carrying the params whole."""
    ledger_path = tmp_path / "served.jsonl"
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))
    host = chain(LIMIT - 1)

    payload = reg.verbs("cmdb")["get-host"](run_ctx(tmp_path), host=host)

    assert payload["host"] == host
    lines = raw_lines(ledger_path)
    assert len(lines) == 2
    rows = [parse_jsonl_row(line) for line in lines]
    assert all(row is not None for row in rows), "a row at the limit is unreadable"
    assert [(row["source"], row["world_id"]) for row in rows] == [(BASE, None), (PASSTHROUGH, "w1")]
    assert all(row["params"] == {"host": host} for row in rows)
