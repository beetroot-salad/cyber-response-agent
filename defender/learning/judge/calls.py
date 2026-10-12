"""One run's two call records, joined by the host-written call id (A2, A12), and the one
definition of a BLOCKED CALL (A2, A14).

The served ledger (`served/<token>.<X>.jsonl`, the host's) owns what was served or blocked; the
query table (`worlds/<X>/executed_queries.jsonl`) owns call order and the pre-branch rows. The
two are joined on the call id both carry — exactly, never on `(system, verb, params)`:

* a table row whose id names this run is the run's own call; its ledger partner is the ledger
  row carrying the same id (none: the call is UNSERVED);
* a table row carrying no id of this run is INHERITED (pre-branch, seeded from the source): the
  shared baseline, never paired, never unserved;
* a ledger row whose id is in no table row is UNMAPPED.

A blocked call is a ledger `refused`/`fault` row, a table row whose ledger partner is one, the
inherited pre-branch `∅.denied` row present identically in every readable run's table (J3), or
a pre-flight `not_replayable` entry. Every reader that asks "was this blocked" — the resolver's
gap-only rule, the found gaps, a named gap's key — asks `is_blocked_ledger_row` /
`is_blocked_table_row` here; none re-derives it. An outage (`real-error`) is served, not
blocked.

The id's spelling (`<world token>/<n>`) is the runtime writer's (query tool and registry, A12);
`call_id_names_run` is the one place the judge reads it, so when the writer exports its own
parser this function is re-pointed at it and nothing else changes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from defender._query_rules import DENIED_QUERY_ID
from defender.learning.branch.ledger import FAULT, REFUSED
from defender.learning.judge.family import mapping_key

#: The field both call records carry the host-written id under (A12).
CALL_ID = "call_id"

#: The ledger decisions that mean the call was blocked before or at the system (A2). An outage
#: (`real-error`) is not here: the investigator was served the error.
BLOCKED_SOURCES = frozenset({REFUSED, FAULT})


def call_id_names_run(call_id: Any, token: str) -> bool:
    """Does `call_id` name a call of the run whose world token is `token`? The id is
    `<token>/<n>`: the run, then the call."""
    if not isinstance(call_id, str):
        return False
    run, sep, call = call_id.rpartition("/")
    return bool(sep) and run == token and bool(call)


def is_inherited(table_row: Mapping[str, Any], token: str) -> bool:
    """A table row carrying no id of this run: a pre-branch row the run inherited (A12)."""
    return not call_id_names_run(table_row.get(CALL_ID), token)


def ledger_partner(table_row: Mapping[str, Any], ledger_rows: Sequence[Mapping[str, Any]],
                   token: str) -> Mapping[str, Any] | None:
    """The ledger row joined to `table_row` by its call id, or `None` (inherited, or unserved).

    The one join of the two call records (A12; the id itself is `record_query.next_call_id`'s):
    every reader pairing a table row with what it was served asks this, never a
    `(system, verb, params)` match."""
    call_id = table_row.get(CALL_ID)
    if not call_id_names_run(call_id, token):
        return None
    for row in ledger_rows:
        if row.get(CALL_ID) == call_id:
            return row
    return None


def is_blocked_ledger_row(row: Mapping[str, Any]) -> bool:
    """Is this served-ledger row a blocked call (A2): `refused` or `fault`?"""
    return row.get("source") in BLOCKED_SOURCES


def inherited_denial_key(table_row: Mapping[str, Any], token: str) -> str | None:
    """J3's candidate key: an inherited `∅.denied` row's canonical request key, else `None`."""
    if table_row.get("query_id") != DENIED_QUERY_ID or not is_inherited(table_row, token):
        return None
    return mapping_key(table_row)


def inherited_denials(tables: Iterable[tuple[str, Sequence[Mapping[str, Any]]]]) -> frozenset[str]:
    """The request keys of J3's rows: inherited `∅.denied` rows present in EVERY readable run's
    table (`(token, rows)` pairs, the control's included). Fewer than two tables decide
    nothing (A12): the empty set."""
    per_table = [{key for row in rows if (key := inherited_denial_key(row, token)) is not None}
                 for token, rows in tables]
    if len(per_table) < 2:
        return frozenset()
    return frozenset(set.intersection(*per_table))


def is_blocked_table_row(table_row: Mapping[str, Any], ledger_rows: Sequence[Mapping[str, Any]],
                         token: str, *, j3: frozenset[str]) -> bool:
    """Is this query-table row a blocked call (A14)? Its own call whose ledger partner is
    blocked, or J3's inherited denial. A table `∅.` row counts only through one of those two:
    a reject (exit 64) or a repeat the guard refused is the investigator's own conduct."""
    partner = ledger_partner(table_row, ledger_rows, token)
    if partner is not None:
        return is_blocked_ledger_row(partner)
    return inherited_denial_key(table_row, token) in j3


def blocked_call_key(run: str, row: Mapping[str, Any]) -> tuple[str, str]:
    """A blocked call's identity (A2's key): its run and its canonical `(system, verb, params)`.
    The key a found gap is listed under and a named gap is matched across draws by (A7)."""
    return run, mapping_key(row)


def key_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """The `(system, verb, params)` columns of a call row, as a gap entry writes them."""
    params = row.get("params")
    return {"system": row.get("system"), "verb": row.get("verb"),
            "params": dict(params) if isinstance(params, Mapping) else {}}


#: The run a found gap of the family as a whole names: J3's inherited denial, present in every
#: run, and a call pre-flight could not replay.
FAMILY_RUN = "family"


def found_gaps(runs: Iterable[tuple[str, str, Sequence[Mapping[str, Any]],
                                    Sequence[Mapping[str, Any]]]], *, j3: frozenset[str],
               not_replayable: Iterable[Any] = ()) -> list[dict[str, Any]]:
    """The user record's found gaps (A2), computed by code, never by the model: every blocked
    call of every run `(label, token, table rows, ledger rows)`, once per key with its count;
    J3's inherited denial and pre-flight's `not_replayable` calls once each under the family's
    run (`FAMILY_RUN`). An inherited table row is J3's or nothing; a run's own calls are read
    off its ledger (a table row's blocked state is its partner's)."""
    counts: dict[tuple[str, str], int] = {}
    rows: dict[tuple[str, str], Mapping[str, Any]] = {}
    for label, token, table_rows, ledger_rows in runs:
        for row in ledger_rows:
            if is_blocked_ledger_row(row):
                key = blocked_call_key(label, row)
                counts[key] = counts.get(key, 0) + 1
                rows.setdefault(key, row)
        for row in table_rows:
            denial = inherited_denial_key(row, token)
            if denial is not None and denial in j3:
                key = (FAMILY_RUN, denial)
                counts[key] = counts.get(key, 0) + 1
                rows.setdefault(key, row)
    for entry in not_replayable:
        if isinstance(entry, Mapping) and isinstance(entry.get("system"), str):
            key = blocked_call_key(FAMILY_RUN, entry)
            counts[key] = counts.get(key, 0) + 1
            rows.setdefault(key, entry)
    return [{"run": key[0], **key_fields(rows[key]), "count": counts[key]} for key in counts]


__all__ = [
    "BLOCKED_SOURCES", "CALL_ID", "FAMILY_RUN", "blocked_call_key", "found_gaps", "call_id_names_run", "inherited_denial_key",
    "inherited_denials", "is_blocked_ledger_row", "is_blocked_table_row", "is_inherited",
    "key_fields", "ledger_partner",
]
