"""The spend ledger (#1377): one append-only row per model response a run received.

The ledger is the one source of what a run spent. It is written when a response returns, apart from
the conversation (a response with no request after it is never saved there) and from the request
log (a box-writable file). Rows are priced when read, by the caller, from the pricing table."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._read import _check_schema_version

#: The four billed counts a row holds, in column order (`configuration.billed_usage`'s keys).
COUNTS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")


@dataclass(frozen=True)
class SpendRow:
    """One response's spend: the model it reported and the four billed counts."""

    model: str
    usage: dict[str, int]


def record_spend(store: Any, run_id: str, model: str, usage: dict[str, int]) -> None:
    """Append one response's row for `run_id`. Raises whatever the database raises."""
    store.connection.execute(
        "INSERT INTO spend_ledger (run_id, model, input_tokens, output_tokens, "
        "cache_read_input_tokens, cache_creation_input_tokens) VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, model, *(int(usage.get(k, 0)) for k in COUNTS)))


def run_spend(store: Any, run_id: str) -> list[SpendRow]:
    """Every row of `run_id`, in write order, and no other run's. A database without the table, or
    at another schema version, raises `sqlite3.Error` or `UnknownSchemaVersion`."""
    _check_schema_version(store)
    rows = store.connection.execute(
        f"SELECT model, {', '.join(COUNTS)} FROM spend_ledger WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
    return [SpendRow(model=r[0], usage=dict(zip(COUNTS, r[1:], strict=True))) for r in rows]
