"""Check run-folder records by explicit names and query-row keys, never broad bookkeeping wildcards."""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

ROOT_RECORDS = frozenset({
    "provenance.json", "investigation.md", "report.md", "executed_queries.jsonl",
    "source_refs.yaml", "tool_trace.jsonl", "policy_denials.jsonl", "lessons_loaded.jsonl",
    "runtime.html", ".box-sentinel"})
REVIEW_RECORD = re.compile(r"review_record\.[0-9]+\.json")
PLANTED = ("gather_raw/.calls", ".query_join.jsonl", "gather_raw/l-001/.join.json",
           "wire_logs/call_join.jsonl", "wire_logs/lineage.jsonl", "alert_input/lineage.json")


def named_records() -> frozenset[str]:
    """Compose explicit record names using only the declared layout accessors."""
    from defender.records import RUN_LAYOUT
    from defender.investigation.challenge_gate import REVIEW_ROLES

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
    """Return files outside explicit record names, numbered reviews, and query-row-keyed evidence."""
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


def assert_only_run_records(run_dir: Path, where: str, rows: list[dict]) -> None:
    """Reject unlisted files and confirm that planted bookkeeping names are detected."""
    rel_paths = folder_files(run_dir)
    assert rel_paths, f"fixture: {where} left no files"
    missed = set(PLANTED) - set(unlisted([*rel_paths, *PLANTED], rows))
    assert not missed, f"positive control: the listing does not flag a planted record: {missed}"
    extra = unlisted(rel_paths, rows)
    assert not extra, (
        f"{where}: the run folder (the box's own mount) holds files that are none of a run's "
        f"records — host bookkeeping such as the query join, and an arm's lineage, belong "
        f"outside it (P3): {extra}")
