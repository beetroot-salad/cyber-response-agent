"""#1127 M3 on the branch ledger — `Ledger.record` never writes a row its own reader skips.

A ledger row puts `params` (and `asked_params`) directly under the row object, exactly as the
queries table does, so the same bound applies: a params map nested past
`JSON_NESTING_LIMIT - 1` (the map counted) makes a line `read_jsonl_rows` drops. Today the
ledger writes it anyway, and the served-call path writes TWO such lines per call (the family
`base` row inside `_base_payload`, then the world's own row), neither of which any reader —
`_absorb`, the episode's comparisons, the judge — will ever see.

The design (issue #1127, M3, "Branch ledger"):

* `Ledger.record` encodes the row itself, checks it with `_io.parse_jsonl_row`, and raises
  `LedgerError` — NOT `RuntimeError`. `append_jsonl` does its own `json.dumps`, so the check
  cannot live there.
* `WorldRegistry._served` re-raises `LedgerError` untouched and files no second row. A
  `RuntimeError` would instead be caught by its `except Exception` and re-filed as a FAULT row
  carrying the same deep params — a model-visible fault with a circuit-breaker charge.

Every "nothing was written" assertion here reads the file's RAW lines: `read_jsonl_rows`
returns `[]` today precisely because the lines it skips are the defect.

RED today: `record` appends the deep row. The depth-98/99 arms are the positive controls and
pass today. The `_served` arm needs nothing beyond the ledger's own `LedgerError` — the
registry's `except LedgerError: raise` already exists.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import JSON_NESTING_LIMIT, parse_jsonl_row, read_jsonl_rows  # noqa: E402
from defender.learning.branch.ledger import (  # noqa: E402
    BASE,
    PASSTHROUGH,
    LedgerError,
    ServedCall,
    payload_text,
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

#: The deepest params map a readable ledger row can carry (the map counted as 1).
LIMIT = JSON_NESTING_LIMIT - 1

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


@pytest.mark.parametrize("depth", [LIMIT + 1, LIMIT + 40])
def test_a_ledger_row_past_the_limit_is_refused_with_the_ledgers_own_error(tmp_path, depth):
    """M3: `record` refuses a row whose encoded line its reader would skip, with `LedgerError`
    — the table's own refusal type, which the serving frame knows not to re-file — and
    appends nothing."""
    path = tmp_path / "served" / "w1.jsonl"
    ledger = fresh_ledger(path)

    with pytest.raises(LedgerError):
        ledger.record(served(params_of_depth(depth)))

    assert raw_lines(path) == [], "the refused row still reached the ledger file"


def test_a_deep_asked_form_is_refused_too(tmp_path):
    """`asked_params` sits at the same level as `params`, so a staged call whose ASKED form is
    too deep makes the same unreadable line. The check is on the encoded row, not on one
    column."""
    path = tmp_path / "served" / "w1.jsonl"
    ledger = fresh_ledger(path)

    with pytest.raises(LedgerError):
        ledger.record(served({"host": "canary-1"}, asked_params=params_of_depth(LIMIT + 1)))

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

    with pytest.raises(LedgerError):
        ledger.record(served(deep, source=BASE, world_id=None))
    ledger.record(served(shallow, source=BASE, world_id=None))

    assert ledger.base_payload("cmdb", "get-host", deep) is None, \
        "a refused base row still answers from the family memo"
    assert ledger.base_payload("cmdb", "get-host", shallow) == payload_text({"owner": "estate"})
    assert len(raw_lines(path)) == 1


# ── the served-call path: WorldRegistry._served ────────────────────────────────────────────


def test_a_deep_served_call_surfaces_the_ledgers_refusal_and_files_nothing(tmp_path, caplog):
    """Through the real serving frame. The deep call is refused by the ledger, the registry
    re-raises `LedgerError` UNTOUCHED, and the ledger file gains no line at all — no `base`
    row, no world row, and no FAULT row re-filed with the same deep params.

    Today this call writes two lines, both unreadable. The warning check is what tells a
    `LedgerError` backstop from a `RuntimeError` one: the latter is caught by `_served`'s
    `except Exception` and re-filed as a FAULT row through `_record_beside`, which the ledger
    then refuses as well and the registry logs."""
    ledger_path = tmp_path / "served.jsonl"
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))

    with caplog.at_level(logging.WARNING, logger=REGISTRY_LOGGER), \
            pytest.raises(LedgerError):
        reg.verbs("cmdb")["get-host"](run_ctx(tmp_path), host=chain(LIMIT))

    assert raw_lines(ledger_path) == [], \
        "the deep call left lines in the ledger (a base row, a world row or a FAULT row)"
    assert [r for r in caplog.records if r.name == REGISTRY_LOGGER] == [], \
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
