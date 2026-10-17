"""One run's two call records, joined by the host-written call id (A2, A12), and the one
definition of a BLOCKED CALL (A2, A14).

The served ledger (`served/<token>.<X>.jsonl`, the host's) owns what was served or blocked; the
query table (`worlds/<X>/executed_queries.jsonl`) owns call order and the pre-branch rows. The
two are joined on the call id — exactly, never on `(system, verb, params)`. The ledger row
carries the id; the table row does not (#1255 G4: the model reads that table), and the id a
table row is joined by is its run's host-only call join's for the row's `(lead_id, seq)`
(`family.read_query_table` hands each row back carrying it under `CALL_ID`):

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

import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from defender._episode_paths import LAYOUT
from defender._io import Bound
from defender._query_rules import DENIED_QUERY_ID
from defender.learning.branch.ledger import FAULT, REFUSED
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.family import mapping_key
from defender.runtime.branch._family import episode_token_for, world_token_for

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


def inherited_denial_rows(tables: Iterable[tuple[str, Sequence[Mapping[str, Any]]]],
                          ) -> dict[str, tuple[int, Mapping[str, Any]]]:
    """J3's rows (A12, A14), by request key: inherited `∅.denied` rows present in EVERY table
    of `tables` (`(token, rows)` pairs, the control's included), each with how many times it
    stands in every one of them (the smallest count over the tables: the identical prefix the
    seed copied) and its first row in the first table. Fewer than two tables decide nothing:
    the empty mapping."""
    per_table: list[tuple[dict[str, int], dict[str, Mapping[str, Any]]]] = []
    for token, rows in tables:
        counts: dict[str, int] = {}
        first: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            key = inherited_denial_key(row, token)
            if key is not None:
                counts[key] = counts.get(key, 0) + 1
                first.setdefault(key, row)
        per_table.append((counts, first))
    if len(per_table) < 2:
        return {}
    shared = set.intersection(*(set(counts) for counts, _first in per_table))
    return {key: (min(counts[key] for counts, _first in per_table), per_table[0][1][key])
            for key in sorted(shared)}


def inherited_denials(tables: Iterable[tuple[str, Sequence[Mapping[str, Any]]]]) -> frozenset[str]:
    """The request keys of J3's rows (`inherited_denial_rows`)."""
    return frozenset(inherited_denial_rows(tables))


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
#: run, and a call pre-flight could not replay. A named gap resting on J3's row carries it too.
FAMILY_RUN = "family"

#: The field a found-gap entry names an unread census input under, with its cause (NA04).
UNREAD = "unread"


def _call_tally(entries: dict[tuple[str, str], tuple[int, Mapping[str, Any]]],
            key: tuple[str, str], row: Mapping[str, Any], n: int = 1) -> None:
    count, first = entries.get(key, (0, row))
    entries[key] = (count + n, first)


def _present_tables(bound: Bound, manifest: Mapping[str, Any], *, episode_token: str,
                    ) -> tuple[list[tuple[str, str, list[dict[str, Any]]]], list[str]]:
    """Every manifest world's query table that reads whole, as `(label, token, rows)` in
    manifest order (control first), and why each other present one could not be read. A world
    with no table at all (not archived) is in neither list."""
    from defender.learning.judge.family import control_world, non_control_worlds, read_query_table

    tables: list[tuple[str, str, list[dict[str, Any]]]] = []
    unread: list[str] = []
    for world in [control_world(dict(manifest)), *non_control_worlds(dict(manifest))]:
        label = world["world_id"]
        try:
            rows = read_query_table(bound, label)
        except JudgeRefused as refused:
            unread.append(str(refused))
            continue
        if rows is not None:
            tables.append((label, world_token_for(episode_token, label), rows))
    return tables, unread


def inherited_prefix_outliers(tables: Sequence[tuple[str, str, Sequence[Mapping[str, Any]]]],
                              ) -> dict[str, str]:
    """The tables whose inherited rows (A12: every row carrying no id of its run, in order)
    differ from the others', by label, each with its refusal (A21). Every sibling's table
    inherits the same pre-branch rows from the one source, so a table whose copy differs (a
    row missing, added or altered — a box can rewrite its own run's table) is a failed read.
    The copy a strict majority of the tables share is the family's; with no strict majority
    (two tables that disagree, say) no copy can be told from its edit, so every table whose
    copy is not unanimous is refused. `tables` is `(label, token, rows)`."""
    copies = {label: json.dumps([dict(r) for r in rows if is_inherited(r, token)],
                                sort_keys=True, default=str)
              for label, token, rows in tables}
    if len(set(copies.values())) <= 1:
        return {}
    top, n = Counter(copies.values()).most_common(1)[0]
    family_copy = top if 2 * n > len(copies) else None
    return {label: (f"world {label!r}: {LAYOUT.world(label).executed_queries} holds inherited "
                    "(pre-branch) rows that differ from the other readable query tables' — "
                    "every sibling inherits the same rows from the one source, so this table "
                    "was edited after its run")
            for label, copy in copies.items() if copy != family_copy}


def readable_tables(bound: Bound, manifest: Mapping[str, Any], *, episode_token: str,
                    ) -> tuple[list[tuple[str, list[dict[str, Any]]]], list[str]]:
    """Every manifest world's query table that reads well-formed — whole, and with the
    inherited rows the family's tables share (`inherited_prefix_outliers`) — as `(token, rows)`
    pairs in manifest order (control first), and why each other present one could not be read.
    A world with no table at all (not archived) is in neither list. The tables J3's rows are
    identified over (A12: "every readable run's table")."""
    tables, unread = _present_tables(bound, manifest, episode_token=episode_token)
    outliers = inherited_prefix_outliers(tables)
    return ([(token, rows) for label, token, rows in tables if label not in outliers],
            [*unread, *outliers.values()])


def table_refusals(bound: Bound, manifest: Mapping[str, Any], *, episode_token: str,
                   ) -> dict[str, str]:
    """The worlds whose query table reads whole but whose inherited rows differ from the
    family's (`inherited_prefix_outliers`), by label: failed reads the usability read cannot
    see from one run alone (A21)."""
    return inherited_prefix_outliers(_present_tables(bound, manifest,
                                                     episode_token=episode_token)[0])


def found_gaps(bound: Bound, manifest: Mapping[str, Any], *,
               not_replayable: Iterable[Any] = ()) -> list[dict[str, Any]]:
    """The user record's found gaps (A2), computed by code from the archive, never by the
    model, on every pass that read the manifest (graded or stamped).

    @owns unread — a found-gap entry `{run, unread}` naming a census input that could not be
    read and why (NA04); the page shows it beside the listed entries.

    Every manifest world's served ledger, the control's and every failed, cut-short, excluded
    or not-archived world's included, is read on its own (`family.read_served_ledger`, whatever
    that run's query table holds): each blocked row (`refused`/`fault`) is listed once per key
    `(run, system, verb, params)` with its count. A ledger that cannot be read is one entry
    under its run naming the cause; it costs no other run its entries. Then the family's own
    entries under `FAMILY_RUN`: J3's inherited denials, identified over every readable query
    table (`readable_tables`) and counted as often as each table holds the row — or, with fewer
    than two readable tables, one entry naming that unread — and pre-flight's `not_replayable`
    calls. Entries come in manifest order, control first, then the family's."""
    from defender.learning.judge.family import (
        control_world, episode_id_of, non_control_worlds, read_served_ledger)

    token = episode_token_for(episode_id_of(dict(manifest)))
    out: list[dict[str, Any]] = []
    for world in [control_world(dict(manifest)), *non_control_worlds(dict(manifest))]:
        label = world["world_id"]
        try:
            ledger = read_served_ledger(bound, label, episode_token=token)
        except JudgeRefused as refused:
            out.append({"run": label, UNREAD: str(refused)})
            continue
        entries: dict[tuple[str, str], tuple[int, Mapping[str, Any]]] = {}
        for row in ledger:
            if is_blocked_ledger_row(row):
                _call_tally(entries, blocked_call_key(label, row), row)
        out += [{"run": key[0], **key_fields(first), "count": count}
                for key, (count, first) in entries.items()]
    family: dict[tuple[str, str], tuple[int, Mapping[str, Any]]] = {}
    tables, unread_tables = readable_tables(bound, manifest, episode_token=token)
    if len(tables) < 2:
        why = "; ".join(unread_tables) or (
            "no run's table is archived" if not tables else "no other run's table is archived")
        out.append({"run": FAMILY_RUN, UNREAD: (
            f"the inherited pre-branch denial is identified across two or more readable query "
            f"tables, and {len(tables)} could be read ({why})")})
    for key, (count, first) in inherited_denial_rows(tables).items():
        _call_tally(family, (FAMILY_RUN, key), first, count)
    for entry in not_replayable:
        if isinstance(entry, Mapping) and isinstance(entry.get("system"), str):
            _call_tally(family, blocked_call_key(FAMILY_RUN, entry), entry)
    out += [{"run": FAMILY_RUN, **key_fields(first), "count": count}
            for (count, first) in family.values()]
    return out


__all__ = [
    "BLOCKED_SOURCES", "CALL_ID", "FAMILY_RUN", "UNREAD", "blocked_call_key", "call_id_names_run",
    "found_gaps", "inherited_denial_key", "inherited_denial_rows", "inherited_denials",
    "inherited_prefix_outliers", "is_blocked_ledger_row", "is_blocked_table_row", "is_inherited",
    "key_fields", "ledger_partner", "readable_tables", "table_refusals",
]
