"""Archived query records and their served-ledger joins."""
from __future__ import annotations

from collections.abc import Mapping




from typing import Any


from pathlib import PurePath

from defender._io import Bound



from defender._text import unwritable_value


from defender.episodes._episode_paths import LAYOUT, WORLD_LEAVES

from defender.learning.branch.ledger import (
    normalized_source,
    request_key,
)

from defender.learning.judge._errors import JudgeRefused

from defender.learning.lead_repository import row_seq











def mapping_key(mapping: Mapping[str, Any]) -> str:
    """The canonical `(system, verb, params)` key of any mapping carrying those three.

    Shared by every reader that dedups served ledger rows by call."""
    params = mapping.get("params")
    return request_key(str(mapping.get("system") or ""), str(mapping.get("verb") or ""),
                       dict(params) if isinstance(params, Mapping) else {})




def read_call_join(bound: Bound, world_id: str) -> dict[tuple[str, int], str]:
    """World `world_id`'s archived call join (#1255 G4/G6): each row the run itself wrote, by its
    `(lead_id, seq)`, mapped to the call's host-written id. An absent join is no rows of the
    run's own (a world whose investigator asked nothing). `JudgeRefused` naming the file and
    the refusal for a read the no-follow reader refuses, a torn line, a malformed line or two
    lines for one `(lead_id, seq)`.

    @owns call_join read — the one read of `worlds/<X>/call_join.jsonl`; its writer is
    `record_query.append_query_row` (`CALL_JOIN_COLUMNS`)."""
    name = LAYOUT.world(world_id).call_join
    rows, torn, read = bound.read_jsonl(name)
    if read.absent:
        return {}
    if read.refusal is not None:
        raise JudgeRefused(f"world {world_id!r}: {read.refusal}")
    if torn:
        raise JudgeRefused(f"world {world_id!r}: {name} holds {torn} line(s) that do not parse "
                           "as a row")
    join: dict[tuple[str, int], str] = {}
    for index, row in enumerate(rows):
        lead, seq, call_id = row.get("lead_id"), row.get("seq"), row.get("call_id")
        if (not isinstance(lead, str) or not isinstance(seq, int) or isinstance(seq, bool)
                or not isinstance(call_id, str)):
            raise JudgeRefused(f"world {world_id!r}: {name} row {index} is not a (lead_id, seq) "
                               f"-> call id line ({row!r})")
        if (lead, seq) in join:
            raise JudgeRefused(f"world {world_id!r}: {name} joins ({lead!r}, {seq}) twice "
                               f"(row {index})")
        join[(lead, seq)] = call_id
    return join




def read_query_table(bound: Bound, world_id: str) -> list[dict[str, Any]] | None:
    """World `world_id`'s archived query table, every line a row joined to its call id; `None`
    when nothing is at the name (a world not archived); `JudgeRefused` naming the file and the
    refusal (a link, a FIFO, a directory, an oversize file, a torn line, or malformed call
    fields)."""
    table = _admitted_query_table(bound, world_id)
    if table is None:
        return None
    join = read_call_join(bound, world_id)
    return [_joined_row(row, join) for row in table]




def _admitted_query_table(bound: Bound, world_id: str) -> list[dict[str, Any]] | None:
    """World `world_id`'s archived query table read whole and admitted (`read_query_table`'s
    refusals), unjoined; `None` when nothing is at the name."""
    from defender.learning.judge.calls import CALL_ID

    table_name = LAYOUT.world(world_id).executed_queries
    table, torn_table, table_read = bound.read_jsonl(table_name)
    if table_read.absent:
        return None
    if table_read.refusal is not None:
        raise JudgeRefused(f"world {world_id!r}: {table_read.refusal}")
    if torn_table:
        raise JudgeRefused(f"world {world_id!r}: {table_name} holds {torn_table} line(s) that do "
                           "not parse as a row")
    _refuse_unwritable(table, label=world_id, name=table_name)
    for index, row in enumerate(table):
        for column in ("lead_id", "system", "verb", "query_id"):
            if not isinstance(row.get(column), str):
                raise JudgeRefused(
                    f"world {world_id!r}: {table_name} row {index} has malformed {column} "
                    f"({row.get(column)!r}); expected str")
    for index, row in enumerate(table):
        if CALL_ID in row:
            raise JudgeRefused(
                f"world {world_id!r}: {table_name} row {index} carries a {CALL_ID} column, which "
                "no query-table writer writes since #1255 (the id lives in the host-only "
                f"{WORLD_LEAVES.call_join}) — an archive from before #1255, or a planted column")
    return table




def _joined_row(row: dict[str, Any], join: Mapping[tuple[str, int], str]) -> dict[str, Any]:
    """`row` carrying the call id `join` records for its `(lead_id, seq)`, if any."""
    from defender.learning.judge.calls import CALL_ID

    own = dict(row)
    call_id = join.get((row["lead_id"], row_seq(row)))
    if call_id is not None:
        own[CALL_ID] = call_id
    return own




def read_served_ledger(bound: Bound, world_id: str) -> list[dict[str, Any]]:
    """World `world_id`'s served ledger read whole and required well-formed (A3, A12), or
    `JudgeRefused` naming the file and the refusal: every line parses, every row carries a
    decision word, names this run (`world_id`) and carries a call id of this run. An absent
    ledger is no rows. The ledger half of `read_call_records`, and the found gaps' one read of
    a run's ledger (A2), which reads it whatever that run's query table holds."""
    from defender.learning.judge.calls import CALL_ID, call_id_names_run

    token = world_id
    ledger_name = world_ledger_name(world_id)
    ledger, torn_ledger, ledger_read = bound.read_jsonl(ledger_name)
    if ledger_read.refusal is not None:
        raise JudgeRefused(f"world {world_id!r}: {ledger_read.refusal}")
    if torn_ledger:
        raise JudgeRefused(f"world {world_id!r}: {ledger_name} holds {torn_ledger} line(s) that "
                           "do not parse as a row")
    for i, row in enumerate(ledger):
        if normalized_source(row.get("source")) is None:
            raise JudgeRefused(f"world {world_id!r}: {ledger_name} row {i} carries no decision "
                               f"word ({row.get('source')!r})")
        if row.get("world_id") != token:
            raise JudgeRefused(f"world {world_id!r}: {ledger_name} row {i} names another run "
                               f"({row.get('world_id')!r}), not {token!r}")
        if not call_id_names_run(row.get(CALL_ID), token):
            raise JudgeRefused(f"world {world_id!r}: {ledger_name} row {i} carries no {CALL_ID} "
                               f"of this run ({row.get(CALL_ID)!r})")
    _refuse_unwritable(ledger, label=world_id, name=ledger_name)
    return ledger




def read_call_records(
    bound: Bound, world_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """One run's two call records — its query table and its served ledger — read whole through
    the bounded no-follow reader and required well-formed (A3, A12), or `JudgeRefused` naming
    the file and the refusal."""
    from defender.learning.judge.calls import CALL_ID, call_id_names_run

    token = world_id
    table_name = LAYOUT.world(world_id).executed_queries
    table = read_query_table(bound, world_id) or []
    ledger = read_served_ledger(bound, world_id)
    ledger_name = world_ledger_name(world_id)
    own: dict[str, dict[str, Any]] = {}
    for i, row in enumerate(table):
        call_id = row.get(CALL_ID)
        if not isinstance(call_id, str) or not call_id_names_run(call_id, token):
            continue
        if call_id in own:
            raise JudgeRefused(f"world {world_id!r}: {table_name} rows share the call id "
                               f"{call_id!r} (row {i})")
        own[call_id] = row
    for i, row in enumerate(ledger):
        partner = own.get(row[CALL_ID])
        if partner is not None and mapping_key(partner) != mapping_key(row):
            raise JudgeRefused(f"world {world_id!r}: {ledger_name} row {i} and the {table_name} "
                               f"row its {CALL_ID} {row[CALL_ID]!r} joins name different calls")
    return table, ledger




def world_ledger_name(world_id: str) -> str:
    """The relative name of a world's served ledger, shared by every reader and refusal."""
    return str(LAYOUT.served_world(world_id))




def _refuse_unwritable(rows: list[dict[str, Any]], *, label: str, name: str | PurePath) -> None:
    """Refuse a record holding a value no record can carry (`_text.unwritable_value`: a lone
    surrogate, a non-finite number), naming the file, the row and the cause (A3, well-formed):
    such a row would fail the pass later, at a canonical key or a write, far from its file."""
    for i, row in enumerate(rows):
        bad = unwritable_value(row)
        if bad is not None:
            raise JudgeRefused(f"world {label!r}: {name} row {i} carries {bad}, which no "
                               "record can carry")
