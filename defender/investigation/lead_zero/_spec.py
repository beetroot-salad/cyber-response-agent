"""Lead-0 vocabulary: the correlation lead's id, provenance and endings. Imports none of its siblings."""
from __future__ import annotations


L3 = "l-00c"
RESERVED_LEAD_IDS = (L3,)
CORRELATION_REQUEST_LIMIT = 8


PROVENANCE_KEY = "provenance"
HARNESS_PROVENANCE = "harness"

#: The heading of the one correlation section in MAIN's opening message (A4, M1). It names the
#: reserved id; the outcome (the lead's framed summary, or one ending's sentence) sits under it.
CORRELATION_HEADING = f"## Correlation lead ({L3})"

#: A2's closed list of the lead's own endings, in the order the classifier tries them.
ENDING_WITHHELD = "withheld"
ENDING_DISPATCH_RAISED = "dispatch_raised"
ENDING_CLAIM_COLLIDED = "claim_collided"
ENDING_CLAIM_FAILED = "claim_failed"
ENDING_REQUEST_LIMIT = "request_limit"
ENDING_TRIPPED_BREAKER = "tripped_breaker"
ENDING_EMPTY_OUTPUT = "empty_output"
ENDING_EVERY_CALL_FAILED = "every_call_failed"
ENDING_TIMED_OUT = "timed_out"
#: #1256 O-6: the lead's system was down from run start (not configured, or its adapter broken),
#: so the lead ended before its claim and its gather count, as the withheld ending does. One
#: ending for every start-time cause; its sentence names the cause.
ENDING_DOWN_AT_START = "down_at_start"
#: #1256 O-5b: a call of the lead raised `ConfigFault` its system's start check did not catch,
#: so the system went down as not configured while the lead ran. Never the breaker's ending: the
#: escaped fault is not charged (DP3, DP4).
ENDING_DOWN_MID_LEAD = "down_mid_lead"

#: The run-level end the correlation lead's own deadline names on its session
#: (`session_store.TRUNCATED_BY_TIMED_OUT`).
