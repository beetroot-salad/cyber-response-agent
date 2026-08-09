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

from defender._env import env_int
from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths

LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")

_ADAPTER_RE = re.compile(r"(?:^|/)(\w+)_adapter\.py$")
_NON_ADAPTER = frozenset({"invlang"})

def _passthrough_max_bytes() -> int:
    return env_int("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", 65536)


PASSTHROUGH_SAMPLE_COUNT = 3
_SAMPLE_MAX_CHARS = 600
_RECORD_KEYS = ("hits", "results", "events", "records", "data", "rows")


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


def _find_records(stdout: str):
    try:
        obj = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in _RECORD_KEYS:
            if isinstance(obj.get(key), list):
                return obj[key]
        lists = [v for v in obj.values() if isinstance(v, list)]
        if lists:
            return max(lists, key=len)
    return None


def _is_event_payload(stdout: str) -> bool:
    try:
        obj = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return False
    if isinstance(obj, list):
        return True
    if isinstance(obj, dict):
        return any(isinstance(obj.get(k), list) for k in _RECORD_KEYS)
    return False


def _envelope_total(stdout: str) -> int | None:
    try:
        obj = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(obj, dict) and isinstance(obj.get("total"), int) and not isinstance(
        obj.get("total"), bool
    ):
        return obj["total"]
    return None


_TIME_KEYS = ("@timestamp", "timestamp")


def _record_time(rec: Any) -> str | None:
    if not isinstance(rec, dict):
        return None
    src = rec["_source"] if isinstance(rec.get("_source"), dict) else rec
    for key in _TIME_KEYS:
        if isinstance((v := src.get(key)), str) and v:
            return v
    return None


def returned_span(records: list) -> tuple[str, str] | None:
    """The time range the returned docs actually cover.

    A capped payload is a *slice*, and which slice depends on the adapter's sort — for the
    SIEM's `query` verb that is `@timestamp` descending, so a window bracketing an alert hands
    back the window's newest N and the alert's own events can sit entirely outside them. The
    envelope reports `total` and `returned` but never *which* docs these are, so a lead that
    asked for ±15m around a pivot and got the last six minutes has no way to tell. Stating the
    span costs nothing and is a fact about the payload, not advice about what to do next.
    """
    stamps = sorted(t for rec in records if (t := _record_time(rec)) is not None)
    return (stamps[0], stamps[-1]) if stamps else None


def build_truncated_view(stdout: str, payload_rel: str | None, run_dir: Path) -> str:
    size = len(stdout)
    records = _find_records(stdout)
    total = _envelope_total(stdout)
    sampled = records is not None and total is not None and total > len(records)
    lines: list[str] = []
    if records is not None:
        shown = min(len(records), PASSTHROUGH_SAMPLE_COUNT)
        if sampled:
            assert total is not None  # `sampled` is only True when `total is not None`
            lines.append(
                f"[record_query] {total} total matches (EXACT, from the envelope). "
                f"This payload is a {len(records)}-doc SAMPLE (returned-doc cap), "
                f"{size} bytes — showing the first {shown} for field shape. COUNTS "
                f"come from `total` (to count a subset, re-query with the narrowing "
                f"filter and read its `total`); NEVER count the sample — its length "
                f"is the cap, not a count."
            )
            if (span := returned_span(records)) is not None:
                lines.append(
                    f"[record_query] those {len(records)} docs span {span[0]} … {span[1]} "
                    f"— ONE slice of the {total}, not a spread across your window. The "
                    f"other {total - len(records)} lie outside that span and no `limit` "
                    f"reaches them: narrow the window onto the pivot you care about, or "
                    f"compute the answer server-side with an aggregating query."
                )
        else:
            lines.append(
                f"[record_query] {len(records)} records, {size} bytes — showing the "
                f"first {shown} as a FIELD-SHAPE sample (to write your filters). Do NOT "
                f"count these or read values off them; compute over the full payload on disk."
            )
        for idx, rec in enumerate(records[:PASSTHROUGH_SAMPLE_COUNT]):
            sample = json.dumps(rec, default=str)
            if len(sample) > _SAMPLE_MAX_CHARS:
                sample = sample[:_SAMPLE_MAX_CHARS] + "…"
            lines.append(f"sample[{idx}]: {sample}")
    else:
        lines.append(f"[record_query] {size} bytes — pass-through truncated")
        lines.append(stdout[:_SAMPLE_MAX_CHARS * PASSTHROUGH_SAMPLE_COUNT] + "…")
    if payload_rel:
        abs_payload = run_dir / payload_rel
        if sampled:
            lines.append(f"sample payload (≤ cap, field shape only): {abs_payload}")
            lines.append(
                "→ COUNTS come from a query envelope's `total`, not this file: to count "
                "a subset, re-query with the narrowing filter and read its `total`. Use "
                "the on-disk sample only to read field shape, e.g. (the viewers read "
                "STDIN — pipe the file in, don't pass it as an operand):\n"
                f"  cat {abs_payload} | head -40"
            )
        else:
            lines.append(f"full payload: {abs_payload}")
            lines.append(
                "→ compute every value over the full payload on disk (defender-sql, grep); "
                "never count or read answers off the samples above. The reducers read STDIN "
                "— pipe the file in, don't pass it as an operand, e.g.:\n"
                f"  cat {abs_payload} | defender-sql 'SELECT count(*) FROM data'"
            )
    return "\n".join(lines) + "\n"


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
    params: dict, payload_digest: str,
) -> str | None:
    """Name the earlier call in this lead that this one repeats, if any.

    A repeat is invisible from inside the turn loop. The payload is persisted under a fresh
    `{seq}.json` every call, and `build_truncated_view` embeds that path three times, so two
    executions of the same query differ by one integer in three places and read as new
    evidence. Nothing else in the loop compares a result to the one before it. Both branches
    below are statements of fact about rows already in the table — no refusal, no advice the
    caller has to accept — because the failure this addresses is a caller that has stopped
    producing reasoning, and only a changed observation reaches one.
    """
    key = _request_key(system, verb, params)
    same_request: int | None = None
    same_payload: int | None = None
    for rec in lead_rows(run_dir, lead):
        prior = rec.get("seq")
        if not isinstance(prior, int) or prior >= seq:
            continue
        if same_payload is None and rec.get("payload_digest") == payload_digest:
            same_payload = prior
        if same_request is None and _request_key(
            rec.get("system"), rec.get("verb"), rec.get("params")
        ) == key:
            same_request = prior
    if same_request is not None and same_payload is not None:
        return (
            f"[record_query] REPEAT — this is the same request you ran at seq {same_request}, "
            f"and it returned the same payload byte for byte. It will keep returning this "
            f"payload however many times you send it; the result is structural, not a "
            f"transient to retry through. Change the approach, not the retry count."
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
    "Sending this exact request again will not produce a different answer. Either treat this "
    "lead as complete with what you already have, or change what you are asking for."
)

ABOVE_GUARD_QUERY_ID = "∅.above-repeat-guard"
"""The sentinel `query_id` for the three rows written ABOVE the guard's own placement in
`QueryCapture.wrap_tool_execute` — `wrap_tool_validate`'s rejection row, and both of
`_grant_check`'s row-writing branches (the adapter-load-error row and the non-`GRANTED`/
unresolvable row). No call that reaches the guard could ever HAVE such a row itself refused, so
counting one toward a later trip would let the replay oracle report a trip no live run can
produce. P-a found no discriminator among the twelve frozen row keys between such a row and a
validated one, so this value is deliberately reserved — never the model-supplied or derived
`{system}.{verb}` form `resolve_query_id` would otherwise produce — and lives inside the
existing twelve keys rather than adding a thirteenth."""


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
        super().__init__(reason)
        self.reason = reason
        self.escape = escape


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
    key = _request_key(system, verb, _json_safe_params(params))
    matches = [
        r for r in rows
        if isinstance(r, dict) and r.get("lead_id") == lead
        and r.get("query_id") != ABOVE_GUARD_QUERY_ID
        and _request_key(r.get("system"), r.get("verb"), r.get("params")) == key
    ]
    occurrence = len(matches) + 1
    if occurrence < threshold:
        return None
    seqs = [m["seq"] for m in matches if isinstance(m.get("seq"), int)]
    return RepeatTrip(first_seq=min(seqs) if seqs else None, occurrence=occurrence)


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


