"""Investigation input, artifact schemas, provenance, report records, and the runs repository
(#1105): the one owner of run-folder layout, the run handle, the tenant-scoped repository
(`Tenant.runs_repository()`, PR 2), whose episode view owns the arm roster (#1187). This module is
the runs repository's door, served lazily (`defender.lazy_door`); record formats have their own,
`defender.records.formats`."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.records._layout import (
        WIRE_LOG_DIR, WIRE_LOG, PROVENANCE, GATE_METADATA_KEY, ALERT, ALERT_INPUT_DIRNAME, ALERT_RECORD, REPORT, INVESTIGATION,
        EXECUTED_QUERIES, SOURCE_REFS, RAW_MARKER, GATHER_SUMMARIES_DIRNAME, LEAD_AUTHOR_DIRNAME,
        TICKET_READS_MARKER, LEAD_CLAIM_SUFFIX, REVIEW_RECORD_PREFIX, TRACE_SUFFIX,
        REVIEW_TRACE_SUFFIX, JSONL_EXT, AGENT_TRACE_SUFFIX, AGENT_FRAMED_TRACE_SUFFIX,
        SERVED_PREFIX, PAYLOAD_SUFFIX, SESSION_DB_SUFFIX, TOOL_TRACE, POLICY_DENIALS,
        LESSONS_LOADED, RUNTIME_HTML, BOX_SENTINEL,
        RUN_END_SIDECAR_SUFFIX, SCRUB_VERDICT_SUFFIX, ACCOUNTING_FAILURES_SUFFIX,
        TICKET_WRITE_SUFFIX, SESSION_POINTER_SUFFIX,
        SESSIONS_DIRNAME, RunLayout, RUN_LAYOUT, WireLogNames, WIRE_LOG_NAMES,
        RunPaths, SessionPaths, LEAD_ID_BODY, LEAD_ID_RE, GATHER_RAW_SHAPE, CASE_ANSWER_KEY_NAMES,
        is_case_answer_key, gather_summaries_shape, alert_input_shape, artifact_file, plain_file, artifact_dir,
        contained_payload,
    )
    from defender.records._handle import (
        Run, RunRecord, ArchivedWorld, RecordHandle, case_ref, case_ref_of_digest,
    )
    from defender.records._id import (
        RunId,
    )
    from defender.records._lookup import (
        RunsRepository, EpisodeRuns, Listed, RunAddress, check_arm_roster_capacity,
    )
    from defender.records._errors import (
        RunRefused, RunAbsent, RunUnreachable,
    )
    from defender.records._held import (
        RecordTenant, hold_runs_folder, run_name_fault, sidecar_names,
    )

#: Each public name and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys((
        "WIRE_LOG_DIR", "WIRE_LOG", "PROVENANCE", "GATE_METADATA_KEY", "ALERT", "ALERT_INPUT_DIRNAME", "ALERT_RECORD", "REPORT",
        "INVESTIGATION", "EXECUTED_QUERIES", "SOURCE_REFS", "RAW_MARKER",
        "GATHER_SUMMARIES_DIRNAME", "LEAD_AUTHOR_DIRNAME", "TICKET_READS_MARKER",
        "LEAD_CLAIM_SUFFIX", "REVIEW_RECORD_PREFIX", "TRACE_SUFFIX", "REVIEW_TRACE_SUFFIX",
        "JSONL_EXT", "AGENT_TRACE_SUFFIX", "AGENT_FRAMED_TRACE_SUFFIX", "SERVED_PREFIX",
        "PAYLOAD_SUFFIX", "SESSION_DB_SUFFIX", "TOOL_TRACE", "POLICY_DENIALS",
        "LESSONS_LOADED", "RUNTIME_HTML", "BOX_SENTINEL",
        "RUN_END_SIDECAR_SUFFIX", "SCRUB_VERDICT_SUFFIX", "ACCOUNTING_FAILURES_SUFFIX",
        "TICKET_WRITE_SUFFIX", "SESSION_POINTER_SUFFIX",
        "SESSIONS_DIRNAME", "RunLayout", "RUN_LAYOUT", "WireLogNames",
        "WIRE_LOG_NAMES", "RunPaths", "SessionPaths", "LEAD_ID_BODY", "LEAD_ID_RE",
        "GATHER_RAW_SHAPE", "CASE_ANSWER_KEY_NAMES", "is_case_answer_key",
        "gather_summaries_shape", "alert_input_shape", "artifact_file", "plain_file", "artifact_dir",
        "contained_payload",
    ), "_layout"),
    **dict.fromkeys(("Run", "RunRecord", "ArchivedWorld", "RecordHandle", "case_ref", "case_ref_of_digest",), "_handle"),
    **dict.fromkeys(("RunId",), "_id"),
    **dict.fromkeys(("RunsRepository", "EpisodeRuns", "Listed", "RunAddress",
                     "check_arm_roster_capacity",), "_lookup"),
    **dict.fromkeys(("RunRefused", "RunAbsent", "RunUnreachable",), "_errors"),
    **dict.fromkeys(("RecordTenant", "hold_runs_folder", "run_name_fault", "sidecar_names",), "_held"),
}

__all__ = [
    "WIRE_LOG_DIR", "WIRE_LOG", "PROVENANCE", "GATE_METADATA_KEY", "ALERT", "ALERT_INPUT_DIRNAME", "ALERT_RECORD", "REPORT",
    "INVESTIGATION", "EXECUTED_QUERIES", "SOURCE_REFS", "RAW_MARKER", "GATHER_SUMMARIES_DIRNAME",
    "LEAD_AUTHOR_DIRNAME", "TICKET_READS_MARKER", "LEAD_CLAIM_SUFFIX", "REVIEW_RECORD_PREFIX",
    "TRACE_SUFFIX", "REVIEW_TRACE_SUFFIX", "JSONL_EXT", "AGENT_TRACE_SUFFIX",
    "AGENT_FRAMED_TRACE_SUFFIX", "SERVED_PREFIX", "PAYLOAD_SUFFIX", "SESSION_DB_SUFFIX",
    "TOOL_TRACE", "POLICY_DENIALS", "LESSONS_LOADED",
    "RUNTIME_HTML", "BOX_SENTINEL", "RUN_END_SIDECAR_SUFFIX",
    "SCRUB_VERDICT_SUFFIX", "ACCOUNTING_FAILURES_SUFFIX", "TICKET_WRITE_SUFFIX",
    "SESSION_POINTER_SUFFIX",
    "SESSIONS_DIRNAME", "RunLayout", "RUN_LAYOUT", "WireLogNames", "WIRE_LOG_NAMES", "RunPaths",
    "SessionPaths", "LEAD_ID_BODY", "LEAD_ID_RE", "GATHER_RAW_SHAPE", "CASE_ANSWER_KEY_NAMES",
    "is_case_answer_key", "gather_summaries_shape", "alert_input_shape", "artifact_file", "plain_file", "artifact_dir",
    "contained_payload", "Run", "RunRecord", "ArchivedWorld",
    "RecordHandle", "case_ref", "case_ref_of_digest", "RunId", "RunsRepository", "EpisodeRuns", "Listed", "RunAddress",
    "check_arm_roster_capacity", "RunRefused", "RunAbsent", "RunUnreachable", "RecordTenant", "hold_runs_folder",
    "run_name_fault", "sidecar_names",
]


__getattr__ = lazy_door(globals(), _HOMES)
