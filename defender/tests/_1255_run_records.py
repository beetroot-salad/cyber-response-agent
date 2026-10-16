"""#1255 — the records a run folder holds, by name (P3). Defines no tests.

The run folder is the tree the box mounts read-write. P3 keeps arm-only facts and host
bookkeeping (the query join, an arm's lineage) "where no box mount reaches", so whether the
folder holds such a record is checked STRUCTURALLY: every file in it is one of a run's records,
by name. A shape is not a name. Contract-repair findings F2-Q and F2-P3b (#1255 adversary,
pass 2) kept the query join in `wire_logs/call_join.jsonl` and an arm's lineage in
`wire_logs/lineage.jsonl`, both zlib-compressed past the encoded scan, and the shape
`wire_logs/*.jsonl` admitted both (the lexical-where-structural deck entry from PR #1090).

What a run folder may hold (`unlisted` reports everything else):

  * the root records, as LITERALS (`run_repository._layout`'s record names at base 4b3628ed):
    the stamp, the documents and logs the model reads, the host's observability streams and
    the box sentinel. Literal, not read off the layout, because P3 moves the stamp out of the
    run folder and its accessor may go with it;
  * the case input and the wire logs, composed by the layout's own NAMED accessors:
    `RUN_LAYOUT.alert` and `.alert_record` (what `alert_input_shape` admits), `.wire_log`, and
    `.review_trace(role)` for each of the review gate's roles (`challenge_gate.REVIEW_ROLES`).
    Never matched by a wildcard and never by enumerating the layout: a name the implementation
    adds to the layout is not admitted until it is listed here and argued in review;
  * the review gate's numbered records, `review_record.<turn>.json` — the one shape left: the
    layout composes it from a turn number, so a run may hold any count of them;
  * per query-table row, keyed by the row: its lead's claim (`gather_raw/<lead>.lead.json`)
    and summary (`gather_summaries/<lead>.md`), and the payload it names when that is in the
    layout's payload shape under the row's own lead (`gather_raw/<lead>/<n>.json`) — a row
    cannot vouch for a file of any other name.

Learning-role records (`lead_author/`, a lead-author trace under `wire_logs/`) are out of
#1255's scope (rev 5, C12) and never land in the folders these tests read.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

#: The root records a run writes, by name.
ROOT_RECORDS = frozenset({
    "provenance.json", "investigation.md", "report.md", "executed_queries.jsonl",
    "source_refs.yaml", "tool_trace.jsonl", "policy_denials.jsonl", "lessons_loaded.jsonl",
    "runtime.html", ".box-sentinel"})
#: The review gate's numbered records: the one admitted shape (see the module docstring).
REVIEW_RECORD = re.compile(r"review_record\.[0-9]+\.json")
#: Files a run never writes, in the places F-Q1, F2-Q and F2-P3b hid host bookkeeping: the
#: positive control every listing is checked against.
PLANTED = ("gather_raw/.calls", ".query_join.jsonl", "gather_raw/l-001/.join.json",
           "wire_logs/call_join.jsonl", "wire_logs/lineage.jsonl", "alert_input/lineage.json")


def named_records() -> frozenset[str]:
    """Every run-folder record admitted by name: `ROOT_RECORDS`, and the case input and wire
    logs as the layout's named accessors compose them."""
    from defender.run_repository import RUN_LAYOUT
    from defender.runtime.challenge_gate import REVIEW_ROLES

    composed = {RUN_LAYOUT.alert, RUN_LAYOUT.alert_record, RUN_LAYOUT.wire_log,
                *(RUN_LAYOUT.review_trace(role) for role in REVIEW_ROLES)}
    return ROOT_RECORDS | {p.as_posix() for p in composed}


def _row_keyed(rows: Iterable[Mapping[str, Any]]) -> set[str]:
    keyed: set[str] = set()
    for row in rows:
        lead, payload = row.get("lead_id"), row.get("payload_path")
        if not isinstance(lead, str) or not lead:
            continue
        keyed |= {f"gather_raw/{lead}.lead.json", f"gather_summaries/{lead}.md"}
        if isinstance(payload, str) and re.fullmatch(
                rf"gather_raw/{re.escape(lead)}/[0-9]+\.json", payload):
            keyed.add(payload)
    return keyed


def unlisted(rel_paths: Iterable[str], rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """The run-folder files (relative POSIX paths) that are none of the records a run holds,
    given the run's query-table `rows`: anything else is a new file in the box's own mount — a
    new channel (O5), and where host-only bookkeeping such as the query join or an arm's
    lineage would hide (P3)."""
    named = named_records() | _row_keyed(rows)
    return sorted(rel for rel in rel_paths
                  if rel not in named and not REVIEW_RECORD.fullmatch(rel))


def folder_files(run_dir: Path) -> list[str]:
    """Every file under `run_dir`, as a relative POSIX path."""
    return sorted(p.relative_to(run_dir).as_posix() for p in Path(run_dir).rglob("*")
                  if p.is_file())


def table_rows(run_dir: Path) -> list[dict]:
    """The run's query table read off disk (no table is no rows)."""
    from defender._io import read_jsonl_rows

    return read_jsonl_rows(Path(run_dir) / "executed_queries.jsonl")


def assert_only_run_records(run_dir: Path, where: str,
                            rows: list[dict] | None = None) -> None:
    """Every file under `run_dir` is one of the records a run holds (`unlisted`; `rows`, the
    run's query table, read off the folder when left out). Positive control on the same
    listing: it does flag each of `PLANTED` beside the folder's own files, so an empty answer
    is the folder's."""
    rel_paths = folder_files(run_dir)
    rows = table_rows(run_dir) if rows is None else rows
    assert rel_paths, f"fixture: {where} left no files"
    missed = set(PLANTED) - set(unlisted([*rel_paths, *PLANTED], rows))
    assert not missed, f"positive control: the listing does not flag a planted record: {missed}"
    extra = unlisted(rel_paths, rows)
    assert not extra, (
        f"{where}: the run folder (the box's own mount) holds files that are none of a run's "
        f"records — host bookkeeping such as the query join, and an arm's lineage, belong "
        f"outside it (P3): {extra}")
