#!/usr/bin/env python3

from __future__ import annotations

import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS

LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")

_ADAPTER_RE = re.compile(r"(?:^|/)(\w+)_adapter\.py$")
_NON_ADAPTER = frozenset({"invlang"})

# The model-visible view of a captured payload lives in `payload_view.py` (#832) — this module
# records the query, that one renders its result. They were one file while the view was a
# key-name guess made inline; splitting them is what let the view become a testable unit with
# its own budget arithmetic, and it keeps the repeat guards below free of it.


def derive_system(inner: list[str]) -> str | None:
    for tok in inner:
        if tok.startswith("defender-") and "/" not in tok and "=" not in tok:
            name = tok[len("defender-"):]
            if name and name not in _NON_ADAPTER:
                return name
        if "=" in tok:
            continue
        m = _ADAPTER_RE.search(tok)
        if m:
            name = m.group(1).replace("_", "-")
            if name not in _NON_ADAPTER:
                return name
    return None


def payload_digest(stdout: str, stderr: str, exit_code: int) -> str:
    if exit_code != 0:
        return f"exit={exit_code}; {stderr.strip()[:160]}"
    lines = stdout.count("\n") + 1 if stdout.strip() else 0
    return f"{len(stdout)} bytes, {lines} line(s)"


def _request_key(system: Any, verb: Any, params: Any) -> str:
    return json.dumps(
        [system, verb, params if isinstance(params, dict) else {}],
        sort_keys=True, default=str,
    )


def _json_safe_params(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, dict):
        return {k: _json_safe_params(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe_params(v) for v in value]
    return value


def lead_rows(run_dir: Path, lead: str) -> list[dict]:
    """This lead's rows off `{run_dir}/executed_queries.jsonl`, in file order.

    The one read+filter loop `_next_seq`, `repeat_note` and `repeat_trip` all key off — torn
    or unparseable lines are already dropped by `read_jsonl_rows`, and any `OSError` (a
    missing table, a chmod-000 file) reads as zero prior rows rather than propagating: no
    existing reader of this table is the one that starts crashing the query tool.
    """
    try:
        rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    except OSError:
        return []
    return [r for r in rows if isinstance(r, dict) and r.get("lead_id") == lead]


def repeat_note(
    run_dir: Path, lead: str, *, seq: int, system: str, verb: str,
    params: dict, payload_digest: str, exit_code: int = 0,
) -> str | None:
    """Name the earlier call in this lead that this one repeats, if any.

    A repeat is invisible from inside the turn loop. The payload is persisted under a fresh
    `{seq}.json` every call, and `build_truncated_view` embeds that path three times, so two
    executions of the same query differ by one integer in three places and read as new
    evidence. Nothing else in the loop compares a result to the one before it. Both branches
    below are statements of fact about rows already in the table — no refusal, no advice the
    caller has to accept — because the failure this addresses is a caller that has stopped
    producing reasoning, and only a changed observation reaches one.

    `exit_code` is THIS call's, and selects the wording only — never whether a note fires
    (#826 item 3). The comparison itself is unchanged and needs no exit code of its own: for a
    failed call `payload_digest` is already `_record`'s `exit={code}; {detail}` form, so two
    failures match each other and can never match a success's `N bytes, M line(s)`. What the
    failing caller must not be told is that its request "returned the same payload" — it
    returned no payload at all, and the fact that matched is the identical ERROR.
    """
    key = _request_key(system, verb, params)
    repeat_seq: int | None = None
    same_payload: int | None = None
    for rec in lead_rows(run_dir, lead):
        # Excludes ABOVE_GUARD_QUERY_ID rows so this scans the SAME counted domain repeat_trip
        # does (`test_repeat_key_is_the_shipped_request_key`: the two readers may name a
        # different row from the matching set, but the set itself is one answer) — a row a
        # call answered above the guard's own placement never reached the backend and its
        # digest is an error string, not a payload.
        if rec.get("query_id") == ABOVE_GUARD_QUERY_ID:
            continue
        prior = rec.get("seq")
        if not isinstance(prior, int) or prior >= seq:
            continue
        payload_matches = rec.get("payload_digest") == payload_digest
        # REPEAT requires BOTH conditions on the SAME row: `same_request`/`same_payload`
        # used to be tracked as two independent "earliest match" scans, which could name two
        # DIFFERENT prior rows and then assert a compound fact about only one of them.
        if (
            repeat_seq is None and payload_matches
            and _request_key(rec.get("system"), rec.get("verb"), rec.get("params")) == key
        ):
            repeat_seq = prior
        if same_payload is None and payload_matches:
            same_payload = prior
    if repeat_seq is not None and exit_code != 0:
        return (
            f"[record_query] REPEAT — this is the same request you ran at seq {repeat_seq}, "
            f"and it failed the same way, character for character. It will keep failing this "
            f"way however many times you send it; the result is structural, not a transient "
            f"to retry through. Change the approach, not the retry count."
        )
    if repeat_seq is not None:
        return (
            f"[record_query] REPEAT — this is the same request you ran at seq {repeat_seq}, "
            f"and it returned the same payload byte for byte. It will keep returning this "
            f"payload however many times you send it; the result is structural, not a "
            f"transient to retry through. Change the approach, not the retry count."
        )
    if same_payload is not None and exit_code != 0:
        # Deliberately says nothing about WHERE the call was turned back. This arm fires for
        # every non-zero exit, and the classes differ: exit 64 is a usage refusal that never
        # reached the system, while exit 1 is the system's own answer to a query it did parse.
        # An earlier wording asserted the first for both, which told a lead facing a genuine
        # syntax error that rewording the query could not help — the one thing that would.
        return (
            f"[record_query] NO-OP — your request differs from seq {same_payload} but failed "
            f"with the identical error, so the change did not reach whatever rejected it. "
            f"Read the error text itself before varying the request again: it names the cause, "
            f"and a variation that leaves that cause standing will return it again."
        )
    if same_payload is not None:
        return (
            f"[record_query] NO-OP — your request differs from seq {same_payload} but the "
            f"payload is byte-identical, so the change did not move the result set at all. "
            f"Before varying it again, check the clause you added is a form this system "
            f"actually applies: a filter the query language silently ignores narrows nothing "
            f"and reports no error."
        )
    return None


def _next_seq(run_dir: Path, lead: str) -> int:
    return len(lead_rows(run_dir, lead))


# --------------------------------------------------------------------------------------- #
# The repeat circuit breaker (#807 ask (1)).
#
# `repeat_trip` is the predicate: a lead that issues the SAME request (`lead_id`, `system`,
# `verb`, canonical `params`) `REPEAT_THRESHOLD` times has stopped producing reasoning, and the
# third identical call is refused before it reaches the backend rather than earning a third
# identical corrective note. The count is derived per call from `lead_rows` — no new persisted
# state — and the domain is exactly the rows the guard itself could have refused (§ the
# suite's module docstring): a row a call answered ABOVE the guard's placement in
# `QueryCapture.wrap_tool_execute` is never an occurrence, live or on replay.
# --------------------------------------------------------------------------------------- #

REPEAT_THRESHOLD = 3

REPEAT_ESCAPE = (
    "Sending this exact request again will not produce a different answer. Move on with "
    "what this lead has already captured, or change what you are asking for."
)
# Deliberately avoids the word "complete": `_run_gather`'s `except GatherDeadEnd` branch
# appends the fixed `INCOMPLETE_IDIOM` ("Treat this lead as incomplete...") right after this
# string in the message handed to main, and the two must not read as opposed dispositions.

ABOVE_GUARD_QUERY_ID = "∅.above-repeat-guard"
"""The sentinel `query_id` for the three rows written ABOVE the guard's own placement in
`QueryCapture.wrap_tool_execute` — `wrap_tool_validate`'s rejection row, and both of
`_grant_check`'s row-writing branches (the adapter-load-error row and the non-`GRANTED`/
unresolvable row). No call that reaches the guard could ever HAVE such a row itself refused, so
counting one toward a later trip would let the replay oracle report a trip no live run can
produce. P-a found no discriminator among the twelve frozen row keys between such a row and a
validated one, so this value is deliberately reserved — `resolve_query_id` refuses to return it
(or an unscreened traversal string) even when a model supplies one verbatim as `query_id` — and
lives inside the existing twelve keys rather than adding a thirteenth."""


@dataclass(frozen=True)
class RepeatTrip:
    """One trip of the repeat guard: the earliest matching row's seq, and this call's
    1-based occurrence number (`== threshold` at a trip)."""

    first_seq: int | None
    occurrence: int


class GatherDeadEnd(Exception):
    """A lead-level dead end: the request the guard just refused (`reason`), and a fixed,
    system-agnostic sentence handing the decision to main (`escape`). Raised out of
    `QueryCapture.wrap_tool_execute`; caught at `_run_gather` beside `UsageLimitExceeded` so it
    stays contained to the one lead."""

    def __init__(self, reason: str, escape: str):
        # Both args go through `super().__init__` (not just `reason`) so `.args` round-trips
        # through `cls(*self.args)` — the reconstruction `pickle`/`copy.deepcopy` use — instead
        # of raising "missing 1 required positional argument: 'escape'".
        super().__init__(reason, escape)
        self.reason = reason
        self.escape = escape


def _trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any, threshold: int,
    in_domain,
) -> RepeatTrip | None:
    """The ONE counting loop both guards drive, over the domain `in_domain` selects.

    Identity and arithmetic are shared deliberately: two guards that counted the same
    `(lead_id, system, verb, canonical(params))` by two hand-written loops would be one
    normalisation fix away from disagreeing about what a repeat is, at two placements, with
    only the DOMAIN ever meant to differ between them."""
    key = _request_key(system, verb, _json_safe_params(params))
    matches = [
        r for r in rows
        if isinstance(r, dict) and r.get("lead_id") == lead and in_domain(r)
        and _request_key(r.get("system"), r.get("verb"), r.get("params")) == key
    ]
    occurrence = len(matches) + 1
    if occurrence < threshold:
        return None
    seqs = [m["seq"] for m in matches if isinstance(m.get("seq"), int)]
    return RepeatTrip(first_seq=min(seqs) if seqs else None, occurrence=occurrence)


def repeat_trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any,
    threshold: int = REPEAT_THRESHOLD,
) -> RepeatTrip | None:
    """`None` below `threshold` occurrences of this request in `rows`, else the `RepeatTrip`
    naming the earliest matching row's seq. `params` is the LIVE call's params — normalised to
    the stored form (`_json_safe_params`, then `_request_key`) before keying, so this is
    literally the same predicate the shipped `repeat_note` and a replay over a recorded table
    both drive. `rows` need not be pre-filtered to `lead`; the identity is `(lead_id, system,
    verb, canonical(params))`, checked here."""
    return _trip(
        rows, lead, system=system, verb=verb, params=params, threshold=threshold,
        in_domain=lambda r: r.get("query_id") != ABOVE_GUARD_QUERY_ID,
    )


def rejection_trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any,
    threshold: int = REPEAT_THRESHOLD,
) -> RepeatTrip | None:
    """The COMPANION guard's predicate (#826 item 4) — `repeat_trip` over the complementary
    domain: the rejections that never reached `wrap_tool_execute`'s placement at all.

    A repeat loop the pydantic ARGUMENT SCHEMA turns back, or one an unresolvable verb turns
    back at the grant check, is invisible to `repeat_trip` by construction — its rows carry
    `ABOVE_GUARD_QUERY_ID` precisely so they cannot count there. Nothing else bounded such a
    loop except `DEFAULT_TOOL_RETRIES = 10`, whose exhaustion raised `UnexpectedModelBehavior`
    and reached main as the same "Treat this lead as incomplete" idiom with no repeat named and
    no trip row: a second, silent terminator. This is the guard for that class, and it is
    deliberately a SECOND one rather than a widening of the first — the two count disjoint
    domains, so neither can report a trip the other's placement could have prevented, and each
    still agrees with a replay over its own domain.

    THE DOMAIN IS NARROWER THAN `ABOVE_GUARD_QUERY_ID` ALONE, by `error_class`: an above-guard
    row is in it only when it is `agent-fixable`. The third above-guard writer is
    `_grant_check`'s adapter-load-error branch, whose rows are `infra` (exit 2) and whose
    repeat is ALREADY owned end to end by `circuit_breaker` — two failures mark the system down
    and the third call is answered by the down-message. Counting those here would give one
    shape two owners and convert an infra outage into a lead-level dead end, so this guard
    never sees them. Both fields are among the twelve frozen row keys; no thirteenth is
    needed, and the same filter is what a replay over a recorded table applies."""
    return _trip(
        rows, lead, system=system, verb=verb, params=params, threshold=threshold,
        in_domain=lambda r: (
            r.get("query_id") == ABOVE_GUARD_QUERY_ID
            and r.get("error_class") == AGENT_FIXABLE_ERROR_CLASS
        ),
    )


def _ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def repeat_trip_detail(trip: RepeatTrip) -> str:
    """The trip row's own detail — short enough to survive `_record`'s 160-char truncation,
    and distinguishable from an ordinary parameter refusal (`trip_row_detail_names_the_
    repetition`): it names the repetition and the earliest seq it repeats."""
    return f"refused: repeat of request already issued at seq {trip.first_seq} ({_ordinal(trip.occurrence)} occurrence)"  # noqa: E501


def rejection_trip_detail(trip: RepeatTrip, rejection: str = "") -> str:
    """`repeat_trip_detail`'s counterpart for the companion guard's trip row. Says "turned
    back", not "issued": the calls it counts never reached a system of record, and a downstream
    reader that could not tell the two apart would report a lead as having queried something it
    never queried.

    `rejection` is the error THIS call produced, kept as a tail because the companion guard's
    trip row is not a row of its own: unlike `wrap_tool_execute`, where the refused request
    never got to fail and the trip row records only the refusal, here one row is both the
    rejection record and the trip row. Replacing the detail outright would have made the
    append-only table permanently forget why the last call was malformed. The trip phrase
    leads, so it survives `_record`'s 160-character digest truncation whole and the tail is
    what gets cut."""
    detail = f"refused: repeat of request already turned back at seq {trip.first_seq} ({_ordinal(trip.occurrence)} occurrence)"  # noqa: E501
    return f"{detail}; rejected: {rejection}" if rejection else detail


def rejection_dead_end_reason(system: str, verb: str, trip: RepeatTrip) -> str:
    """`dead_end_reason`'s counterpart, and deliberately WITHOUT its executed-query count: a
    request that never got past the argument schema or the grant check executed nothing at this
    key, and the honest thing to tell main is what was rejected and that re-sending it is not a
    route through. Never the model-authored `params` text, for `dead_end_reason`'s reason — an
    unbounded fragment must not cross into main's context on a refusal path."""
    # `system`/`verb` are the RAW arguments at the schema placement and coarsen to `""` when
    # the call did not supply them as strings at all — so the pair can be empty, and
    # "the request ( )" would name nothing. Say that instead of rendering a blank.
    target = f"{system} {verb}".strip() or "system/verb unreadable in the call's own arguments"
    return (
        f"the request ({target}) was rejected before it ran and repeats the one already "
        f"turned back at seq {trip.first_seq}; it has now been rejected "
        f"{trip.occurrence} times for the same reason. The rejection is structural, not a "
        "transient to retry through."
    )


def dead_end_reason(system: str, verb: str, trip: RepeatTrip, executed: int) -> str:
    """The string `GatherDeadEnd.reason` carries: this trip's own repeated request (`system`,
    `verb`, the earliest seq), that the cause is structural rather than a transient to retry
    through, and how many queries this lead EXECUTED before the stop — widened deliberately
    beyond O2's literal oracle, which names only the request and the cause. `executed` is the
    count of exit-0 rows, not the row count: a lead whose prior calls were all refused (by
    `_screen`, say) executed zero of them, and counting the refusals would tell main "this lead
    found things" when it never got anywhere — exactly the distinction this widening exists to
    draw. Never the model-authored `params` text: an unbounded fragment must not cross into
    main's context on a refusal path."""
    plural = "query" if executed == 1 else "queries"
    return (
        f"the request ({system} {verb}) repeats the one already issued at seq {trip.first_seq}; "
        f"this lead executed {executed} {plural} before this repeat. The result is structural, "
        "not a transient to retry through."
    )


