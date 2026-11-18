"""The investigation's closing record (#1534): one row per closed run in its lineage's session
database, written by the close and read through one lookup.

`records` owns the record's words: the column and entry vocabularies and bounds (`_vocab`), the
one treatment of model text (`_treat.treat`), the record and entry types with one line renderer
per entry (`_record`), and the lookup with its three outcomes (`_lookup`). The table itself and
its write are the session store's (`session_store.write_closing_record`). The episode-view route
(`_episode.for_world`) reads an episode world's record through its arm."""
from __future__ import annotations

from ._episode import for_world, roster_fault
from ._lookup import (
    ARM_REFUSED, COMMITTED_WITHOUT_RECORD, DATABASE_MISSING, FAULT_KINDS, FAULT_WORDING, LEGACY_LINK,
    POINTER_UNREADABLE, RECORDED_BEFORE_1534, ROSTER_GONE, ROW_INVALID, SCHEMA_VERSION_KIND,
    STORE_UNREADABLE, TABLE, CouldNotLook, Lookup, NeverClosed, Record, encode_entries, fault, for_run, for_run_dir,
    read_database,
)
from ._record import (
    BaselineEntry, CeilingEntry, ClosingRecord, baseline_line, baseline_line_of, baseline_lines_length,
    canonical_instant, ceiling_line, ceiling_line_of, ceiling_lines_length, entry_lines,
)
from ._treat import DOTS, treat
from ._vocab import (
    ANCHOR_ID_BOUND, ANCHOR_KINDS, BASELINE_LINES_BOUND, CAP_BOUND, CAUSE_CEILING_EXAMINED,
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, CAUSE_NOT_REVIEWED, CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_REVIEW_INCOMPLETE, CAUSE_SENTENCES, CAUSE_STORY_SETTLED, CAUSE_TURN_BUDGET_SPENT, CAUSES,
    CEILING_COUNT_CAP, CEILING_LINES_BOUND, CEILING_NOTHING_TO_TRY, CEILING_QUERY_EMPTY,
    CEILING_QUERY_FAILED, CEILING_STATES, ELLIPSIS, FAILURE_KINDS, FORCED_INCONCLUSIVE, GROUNDING_KINDS,
    LEAD_BOUND, NOTE_BOUND, OPENERS, OUTCOMES, REASONING_BOUND, RESULT_BOUND, STAGE_ERROR, STANDS,
    SUMMARY_BOUND, TIMEOUT, UNREADABLE, grounding_acceptable,
)

__all__ = [
    "ANCHOR_ID_BOUND", "ANCHOR_KINDS", "ARM_REFUSED", "BASELINE_LINES_BOUND", "CAP_BOUND", "CAUSES",
    "CAUSE_CEILING_EXAMINED", "CAUSE_EVIDENCE_CANNOT_DISCRIMINATE", "CAUSE_NOTHING_LEFT_TO_ASK",
    "CAUSE_NOT_REVIEWED", "CAUSE_REVIEW_INCOMPLETE", "CAUSE_SENTENCES", "CAUSE_STORY_SETTLED",
    "CAUSE_TURN_BUDGET_SPENT", "CEILING_COUNT_CAP", "CEILING_LINES_BOUND", "CEILING_NOTHING_TO_TRY",
    "CEILING_QUERY_EMPTY", "CEILING_QUERY_FAILED", "CEILING_STATES", "COMMITTED_WITHOUT_RECORD",
    "DATABASE_MISSING", "DOTS", "ELLIPSIS", "FAILURE_KINDS", "FAULT_KINDS", "FAULT_WORDING",
    "FORCED_INCONCLUSIVE", "GROUNDING_KINDS", "LEAD_BOUND", "LEGACY_LINK", "NOTE_BOUND", "OPENERS",
    "OUTCOMES", "POINTER_UNREADABLE", "REASONING_BOUND", "RECORDED_BEFORE_1534", "RESULT_BOUND",
    "ROSTER_GONE", "ROW_INVALID", "SCHEMA_VERSION_KIND", "STAGE_ERROR", "STANDS", "STORE_UNREADABLE",
    "SUMMARY_BOUND", "TABLE", "TIMEOUT", "UNREADABLE", "BaselineEntry", "CeilingEntry", "ClosingRecord",
    "CouldNotLook", "Lookup", "NeverClosed", "Record", "baseline_line", "baseline_line_of", "baseline_lines_length",
    "canonical_instant", "ceiling_line", "ceiling_line_of", "ceiling_lines_length", "encode_entries", "entry_lines", "fault",
    "for_run", "for_run_dir", "for_world", "grounding_acceptable", "read_database", "roster_fault", "treat",
]
