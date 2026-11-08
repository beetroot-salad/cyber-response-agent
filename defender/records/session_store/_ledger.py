"""The spend ledger (#1377): one append-only row per model request a run's agent sent.

The ledger is the one source of what a run spent. A row is written when a request ends, apart from
the conversation (a response with no request after it is never saved there) and from the request
log (a box-writable file). A row records the requesting agent, the model it was built to request,
the name the provider reported, the four billed counts and how the request ended (r7 S2a).

`read_ledger` is the one read of a run's rows: it prices each at its requested model's pricing row
(r7 S1, resolved when read), sums them, per agent too, and says whether the ledger is complete (no
unseen request, no unpriced model). `lower_limit` is the one rule that joins that with the host's
own failed-write fact; only the worker adds the run's lifecycle to it."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from defender._agent_role import agent_kind
from defender.configuration import UnknownModel, model_key, usage_cost

from ._read import _check_schema_version

#: The four billed counts a row holds, in column order (`configuration.billed_usage`'s keys).
COUNTS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")

#: How a request ended, as the model-request hook saw it after the retrier (r7 S2a): a response
#: with its counts; refused by the provider before its model ran ($0); or unseen (no response,
#: and not known to be unbilled).
RESPONSE, REFUSED, UNSEEN = "response", "refused", "unseen"
OUTCOMES = (RESPONSE, REFUSED, UNSEEN)


@dataclass(frozen=True)
class SpendRow:
    """One request's row: who sent it, the model it requested, how it ended, and its billed counts."""

    agent_id: str
    requested_model: str
    outcome: str
    usage: dict[str, int]


@dataclass(frozen=True)
class LedgerRead:
    """A run's ledger as one read sees it (#1377 r7 S5).

    `total` is the priced sum; `complete` is false when a row is unseen or requests a model no
    pricing row prices (the sum may be short); `by_agent` is each agent's priced sum, an agent
    whose rows price at $0 included; `requested` is each agent's requested model; `usage` sums
    the four billed counts."""

    total: float
    complete: bool
    by_agent: Mapping[str, float]
    requested: Mapping[str, str] = field(default_factory=dict)
    usage: Mapping[str, int] = field(default_factory=lambda: dict.fromkeys(COUNTS, 0))

    def by_kind(self) -> dict[str, float]:
        """The priced sums by agent kind (main, gather, correlation, review)."""
        out: dict[str, float] = {}
        for agent_id, spent in self.by_agent.items():
            kind = agent_kind(agent_id)
            out[kind] = out.get(kind, 0.0) + spent
        return out

    def price(self, agent_id: str, usage: Any) -> float:
        """`usage` priced at the model `agent_id` requested: the same rule as the ledger's own rows,
        for figures read from elsewhere (the request log). An agent with no row prices at $0."""
        return requested_cost(self.requested.get(agent_id, ""), usage)


def requested_cost(requested_model: str, usage: Any) -> float:
    """`usage` at `requested_model`'s pricing row; $0 for a model no row prices, and for an empty
    name, which is never priced as some default (r7.1 D)."""
    return usage_cost(requested_model, usage) if priced(requested_model) else 0.0


def priced(requested_model: str) -> bool:
    """Whether a pricing row prices `requested_model` (an empty name is not priced)."""
    if not requested_model:
        return False
    try:
        model_key(requested_model)
    except UnknownModel:
        return False
    return True


def lower_limit(*, complete: bool, spend_write_failed: bool) -> bool:
    """Whether a ledger total is "at least": the read was not `complete`, or the host knows a spend
    write failed. The run file and the run page both mark their total by this; the worker adds
    the run's lifecycle (r7.1 S5)."""
    return spend_write_failed or not complete


def record_spend(store: Any, run_id: str, *, agent_id: str, requested_model: str, outcome: str,
                 reported_model: str | None, usage: dict[str, int]) -> None:
    """Append one request's row for `run_id`. Raises whatever the database raises."""
    if outcome not in OUTCOMES:
        raise ValueError(f"{outcome!r} is not a request outcome {OUTCOMES}")
    store.connection.execute(
        "INSERT INTO spend_ledger (run_id, agent_id, requested_model, reported_model, outcome, "
        f"{', '.join(COUNTS)}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, agent_id, requested_model, reported_model, outcome, *(int(usage.get(k, 0)) for k in COUNTS)))


def run_spend(store: Any, run_id: str) -> list[SpendRow]:
    """Every row of `run_id`, in write order, and no other run's. A database without the table, or
    at another schema version, raises `sqlite3.Error` or `UnknownSchemaVersion`."""
    _check_schema_version(store)
    rows = store.connection.execute(
        f"SELECT agent_id, requested_model, outcome, {', '.join(COUNTS)} FROM spend_ledger "  # noqa: S608
        "WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
    return [SpendRow(agent_id=r[0], requested_model=r[1], outcome=r[2], usage=dict(zip(COUNTS, r[3:], strict=True)))
            for r in rows]


def read_ledger(store: Any, run_id: str) -> LedgerRead:
    """The one read of `run_id`'s ledger (#1377 r7 S5). Raises as `run_spend` does, and
    `ValueError` for a row whose agent id is not a run-side agent's or whose outcome is unknown:
    such a ledger is unreadable, never counted as MAIN's."""
    total, complete = 0.0, True
    by_agent: dict[str, float] = {}
    requested: dict[str, str] = {}
    billed: list[dict[str, int]] = []
    for row in run_spend(store, run_id):
        agent_kind(row.agent_id)
        if row.outcome not in OUTCOMES:
            raise ValueError(f"a ledger row of {row.agent_id!r} has the unknown outcome {row.outcome!r}")
        requested.setdefault(row.agent_id, row.requested_model)
        spent = 0.0
        # A request whose end was never seen, or any row at a model no pricing row prices
        # (r7 S2b, r7.1 D), leaves the sum possibly short.
        if row.outcome == UNSEEN or not priced(row.requested_model):
            complete = False
        if row.outcome == RESPONSE:
            spent = requested_cost(row.requested_model, row.usage)
            billed.append(row.usage)
        by_agent[row.agent_id] = by_agent.get(row.agent_id, 0.0) + spent
        total += spent
    usage = {k: sum(int(u.get(k, 0)) for u in billed) for k in COUNTS}
    return LedgerRead(total=total, complete=complete, by_agent=by_agent, requested=requested, usage=usage)
