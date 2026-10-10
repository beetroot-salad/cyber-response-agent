"""The runs repository (#1105): the one owner of run-folder layout, the run handle, the
tenant-scoped repository (`Tenant.runs_repository()`, PR 2) and the episode -> runs record.
This module is its door.

The door serves the public surface lazily (PEP 562 `__getattr__`): reading a name imports the
one submodule that defines it, and nothing else. That is load-bearing twice over (R4-6):

- in-box code imports layout names with no third-party package installed, and the handle
  (through `_tenant`) needs pydantic, so a layout name must load `_layout` alone;
- the handle imports `_report`, `_artifact_schema` and `_episode_paths`, each of which imports
  layout names from here, so an eager door would import itself in a cycle.

A failed first import propagates and is retried on the next read (NF-13): nothing is cached
until a submodule has imported. `__all__`, the names declared under `TYPE_CHECKING` (so mypy
types each as its real object, R4-30) and the names `__getattr__` serves are one set, pinned
by a test. Every submodule is `_`-prefixed: outside the package and its owner modules
(`_episode_paths`, `_episode_handle`, `_tenant`), production code imports from this door only.
"""
from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from defender.run_repository._layout import (
        WIRE_LOG_DIR, WIRE_LOG, PROVENANCE, GATE_METADATA_KEY, ALERT, REPORT, INVESTIGATION,
        EXECUTED_QUERIES, SOURCE_REFS, RAW_MARKER, GATHER_SUMMARIES_DIRNAME, LEAD_AUTHOR_DIRNAME,
        TICKET_READS_MARKER, LEAD_CLAIM_SUFFIX, REVIEW_RECORD_PREFIX, TRACE_SUFFIX,
        REVIEW_TRACE_SUFFIX, JSONL_EXT, AGENT_TRACE_SUFFIX, AGENT_FRAMED_TRACE_SUFFIX,
        SERVED_PREFIX, PAYLOAD_SUFFIX, SESSION_DB_SUFFIX, TOOL_TRACE, POLICY_DENIALS, BUDGET,
        CIRCUIT_BREAKER, LESSONS_LOADED, SESSION_POINTER, RUNTIME_HTML, BOX_SENTINEL,
        RUN_END_SIDECAR_SUFFIX, SCRUB_VERDICT_SUFFIX, ACCOUNTING_FAILURES_SUFFIX,
        TICKET_WRITE_SUFFIX, ORACLE_HELD_SUFFIX,
        SESSIONS_DIRNAME, RunLayout, RUN_LAYOUT, WireLogNames, WIRE_LOG_NAMES,
        RunPaths, SessionPaths, LEAD_ID_BODY, LEAD_ID_RE, GATHER_RAW_SHAPE, CASE_ANSWER_KEY_NAMES,
        is_case_answer_key, gather_summaries_shape, artifact_file, plain_file, artifact_dir,
        resolve_run_bundle, contained_payload,
    )
    from defender.run_repository._handle import (
        Run, RunRecord, ArchivedWorld, RecordHandle, case_ref,
    )
    from defender.run_repository._id import (
        RunId,
    )
    from defender.run_repository._lookup import (
        RunsRepository, EpisodeRuns, Listed, RunAddress,
    )
    from defender.run_repository._record import (
        record_episode_runs, episode_runs, sibling_run_ids, episode_sibling_ids,
    )
    from defender.run_repository._errors import (
        RunRefused, RunAbsent,
    )
    from defender.run_repository._held import (
        hold_runs_folder, run_name_fault,
    )

#: Each public name and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys((
        "WIRE_LOG_DIR", "WIRE_LOG", "PROVENANCE", "GATE_METADATA_KEY", "ALERT", "REPORT",
        "INVESTIGATION", "EXECUTED_QUERIES", "SOURCE_REFS", "RAW_MARKER",
        "GATHER_SUMMARIES_DIRNAME", "LEAD_AUTHOR_DIRNAME", "TICKET_READS_MARKER",
        "LEAD_CLAIM_SUFFIX", "REVIEW_RECORD_PREFIX", "TRACE_SUFFIX", "REVIEW_TRACE_SUFFIX",
        "JSONL_EXT", "AGENT_TRACE_SUFFIX", "AGENT_FRAMED_TRACE_SUFFIX", "SERVED_PREFIX",
        "PAYLOAD_SUFFIX", "SESSION_DB_SUFFIX", "TOOL_TRACE", "POLICY_DENIALS", "BUDGET",
        "CIRCUIT_BREAKER", "LESSONS_LOADED", "SESSION_POINTER", "RUNTIME_HTML", "BOX_SENTINEL",
        "RUN_END_SIDECAR_SUFFIX", "SCRUB_VERDICT_SUFFIX", "ACCOUNTING_FAILURES_SUFFIX",
        "TICKET_WRITE_SUFFIX", "ORACLE_HELD_SUFFIX",
        "SESSIONS_DIRNAME", "RunLayout", "RUN_LAYOUT", "WireLogNames",
        "WIRE_LOG_NAMES", "RunPaths", "SessionPaths", "LEAD_ID_BODY", "LEAD_ID_RE",
        "GATHER_RAW_SHAPE", "CASE_ANSWER_KEY_NAMES", "is_case_answer_key",
        "gather_summaries_shape", "artifact_file", "plain_file", "artifact_dir",
        "resolve_run_bundle", "contained_payload",
    ), "_layout"),
    **dict.fromkeys(("Run", "RunRecord", "ArchivedWorld", "RecordHandle", "case_ref",), "_handle"),
    **dict.fromkeys(("RunId",), "_id"),
    **dict.fromkeys(("RunsRepository", "EpisodeRuns", "Listed", "RunAddress",), "_lookup"),
    **dict.fromkeys(("record_episode_runs", "episode_runs", "sibling_run_ids", "episode_sibling_ids",), "_record"),
    **dict.fromkeys(("RunRefused", "RunAbsent",), "_errors"),
    **dict.fromkeys(("hold_runs_folder", "run_name_fault",), "_held"),
}

__all__ = [
    "WIRE_LOG_DIR", "WIRE_LOG", "PROVENANCE", "GATE_METADATA_KEY", "ALERT", "REPORT",
    "INVESTIGATION", "EXECUTED_QUERIES", "SOURCE_REFS", "RAW_MARKER", "GATHER_SUMMARIES_DIRNAME",
    "LEAD_AUTHOR_DIRNAME", "TICKET_READS_MARKER", "LEAD_CLAIM_SUFFIX", "REVIEW_RECORD_PREFIX",
    "TRACE_SUFFIX", "REVIEW_TRACE_SUFFIX", "JSONL_EXT", "AGENT_TRACE_SUFFIX",
    "AGENT_FRAMED_TRACE_SUFFIX", "SERVED_PREFIX", "PAYLOAD_SUFFIX", "SESSION_DB_SUFFIX",
    "TOOL_TRACE", "POLICY_DENIALS", "BUDGET", "CIRCUIT_BREAKER", "LESSONS_LOADED",
    "SESSION_POINTER", "RUNTIME_HTML", "BOX_SENTINEL", "RUN_END_SIDECAR_SUFFIX",
    "SCRUB_VERDICT_SUFFIX", "ACCOUNTING_FAILURES_SUFFIX", "TICKET_WRITE_SUFFIX",
    "ORACLE_HELD_SUFFIX",
    "SESSIONS_DIRNAME", "RunLayout", "RUN_LAYOUT", "WireLogNames", "WIRE_LOG_NAMES", "RunPaths",
    "SessionPaths", "LEAD_ID_BODY", "LEAD_ID_RE", "GATHER_RAW_SHAPE", "CASE_ANSWER_KEY_NAMES",
    "is_case_answer_key", "gather_summaries_shape", "artifact_file", "plain_file", "artifact_dir",
    "resolve_run_bundle", "contained_payload", "Run", "RunRecord", "ArchivedWorld",
    "RecordHandle", "case_ref", "RunId", "RunsRepository", "EpisodeRuns", "Listed", "RunAddress",
    "record_episode_runs", "episode_runs", "sibling_run_ids", "episode_sibling_ids", "RunRefused",
    "RunAbsent", "hold_runs_folder", "run_name_fault",
]


def __getattr__(name: str) -> Any:  # lint-dup: ok — a PEP 562 module hook, a name Python fixes; runtime/permission's serves its own package
    home = _HOMES.get(name)
    if home is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(f"{__name__}.{home}"), name)
    globals()[name] = value
    return value
