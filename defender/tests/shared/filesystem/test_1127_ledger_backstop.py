"""No ledger row past the params nesting limit is ever built or written."""
from __future__ import annotations

import importlib
import logging
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import parse_jsonl_row, read_jsonl_rows  # noqa: E402
from defender.episodes._episode_paths import LAYOUT, OracleStorePaths  # noqa: E402
from defender.learning.branch.ledger import (  # noqa: E402
    PASSTHROUGH,
    LedgerError,
    ServedCall,
    payload_text,
)
from defender.tests.shared.filesystem.test_1127_params_nesting_limit import (  # noqa: E402
    FAR,
    LIMIT,
    raised,
)
from defender.tests.shared.filesystem.test_1127_params_nesting_limit import dict_chain as chain  # noqa: E402
from defender.tests.learning.branch.test_920_estate_seam import (  # noqa: E402
    CALLS_LOG,
    FAKE_GRANT,
    World,
    adapter_calls,
    control_oracle,
    estate_host,
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


# ── the served-call path: WorldRegistry._served ────────────────────────────────────────────


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_deep_served_call_is_refused_before_the_estate_and_files_nothing(
        tmp_path, caplog, depth):
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


def test_a_served_call_at_the_limit_records_its_row_and_keeps_its_base_read(tmp_path):
    ledger_path = tmp_path / "ep" / "served" / "w1.jsonl"
    host = chain(LIMIT - 1)
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"),
                         **control_oracle(estate_host(host)))
    ctx = run_ctx(tmp_path)

    payload = reg.verbs("cmdb")["get-host"](ctx, host=host)

    assert payload["host"] == host
    assert [c["params"] for c in adapter_calls(ctx, "get-host")] == [{"host": host}], \
        "the estate adapter was not entered exactly once for a call at the limit"
    lines = raw_lines(ledger_path)
    assert len(lines) == 1
    rows = [parse_jsonl_row(line) for line in lines]
    assert all(row is not None for row in rows), "a row at the limit is unreadable"
    assert [(row["source"], row["world_id"]) for row in rows] == [(PASSTHROUGH, "w1")]
    kept = [parse_jsonl_row(line) for line in raw_lines(OracleStorePaths(
        ledger_path.parent / LAYOUT.oracle_dir("w1")).base)]
    assert len(kept) == 1
    assert kept[0] is not None, "the kept base read at the limit is unreadable"
    assert all(row["params"] == {"host": host} for row in rows + kept)


# ── the other door: WorldRegistry.authorize_call ──────────────────────────────────────────────


@pytest.mark.parametrize("depth", [LIMIT + 1, FAR])
def test_a_deep_call_to_a_denied_verb_is_refused_before_the_decision_and_files_nothing(
        tmp_path, caplog, depth):
    ledger_path = tmp_path / "ep" / "served" / "w1.jsonl"
    reg = world_registry(fake_estate(tmp_path), FAKE_GRANT, ledger_path, world=World("w1"))

    with caplog.at_level(logging.WARNING, logger=REGISTRY_LOGGER):
        err = raised(lambda: reg.authorize_call("elastic", "get-host", {"host": chain(depth - 1)}))

    assert isinstance(err, LedgerError), \
        f"refused with {type(err).__name__}, not LedgerError: {str(err)[:200]}"
    assert "params nest deeper than" in str(err)
    assert raw_lines(ledger_path) == []
    assert [r.getMessage()[:200] for r in caplog.records if r.name == REGISTRY_LOGGER] == [], \
        "a row was attempted for the too-deep call and dropped"

    reg.authorize_call("elastic", "get-host", {"host": "canary-1"})
    assert [parse_jsonl_row(line)["source"] for line in raw_lines(ledger_path)] == ["refused"]


# ── priming: a captured row the table reads but no ledger row can carry ───────────────────


@pytest.mark.parametrize("depth", [LIMIT + 1, 99])
def test_a_captured_row_too_deep_to_carry_is_unreadable_and_the_rest_still_primes(
        tmp_path, depth):
    prime = importlib.import_module("defender.tests.learning.branch.test_947_capture_prime")
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
