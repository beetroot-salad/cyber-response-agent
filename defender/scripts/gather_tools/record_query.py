#!/usr/bin/env python3

from __future__ import annotations

import json
import math
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._env import env_int
from defender._io import guarded_mkdir, read_jsonl_rows, write_guarded
from defender._run_paths import RunPaths
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS, error_class_for_exit

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


def _time_sort_key(ts: str) -> tuple[int, Any]:
    """A chronological sort key for one `@timestamp` string, falling open to string order.

    Plain string order breaks the moment two stamps in the same second carry different
    fractional-second precision: `"...11:59:00Z"` sorts AFTER `"...11:59:00.500Z"` because
    `.` (0x2E) is below `Z` (0x5A) in ASCII, even though 00Z is the earlier instant — inverting
    `returned_span`'s reported start/end. Parsed timestamps sort first (chronologically);
    anything unparseable sorts after, by its raw string, rather than raising on a field this
    function was never handed a schema for.
    """
    try:
        return (0, datetime.fromisoformat(ts.replace("Z", "+00:00")))
    except ValueError:
        return (1, ts)


def returned_span(records: list) -> tuple[str, str] | None:
    """The time range the returned docs actually cover.

    A capped payload is a *slice*, and which slice depends on the adapter's sort — for the
    SIEM's `query` verb that is `@timestamp`, newest-first unless the call asked for `sort:
    "asc"`, so a window bracketing an alert hands back the window's newest N by default and
    the alert's own events can sit entirely outside them. The envelope reports `total` and
    `returned` but never *which* docs these are, so a lead that asked for ±15m around a pivot
    and got the last six minutes has no way to tell. Stating the span costs nothing and is a
    fact about the payload, not advice about what to do next.
    """
    stamps = [t for rec in records if (t := _record_time(rec)) is not None]
    if not stamps:
        return None
    stamps.sort(key=_time_sort_key)
    return (stamps[0], stamps[-1])


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


def persist_payload(run_dir: Path, lead_id: str, seq: int, text: str) -> str | None:
    """The payload sidecar at `gather_raw/{lead_id}/{seq}.json`, best-effort.

    Moved here from `query_tool` (#823) so the two writers of the queries table persist their
    by-ref payload through one function rather than two copies. `ValueError` as well as
    `OSError`: `guarded_mkdir` raises it for a target outside the tree the anchor names, which
    a `lead_id` carrying path separators or `..` produces. Best-effort persistence must not
    become the run's crash.

    The sidecar must EXIST even when empty: `lead_extraction.extract_from_joined` skips any row
    whose `raw_ref` is not a file (lead_extraction.py:60), so a row written without one is
    dropped from the offline loop entirely rather than merely arriving thin."""
    lead_dir = RunPaths(run_dir).gather_raw / lead_id
    payload_path = lead_dir / f"{seq}.json"
    try:
        guarded_mkdir(lead_dir, base=run_dir)
        write_guarded(payload_path, text)
    except (OSError, ValueError):
        return None
    return str(payload_path.relative_to(run_dir))


def append_query_row(  # noqa: PLR0913 — one parameter per ROW COLUMN the caller must decide
    run_dir: Path, *, lead_id: str, system: str, verb: str, query_id: str, params: dict,
    raw_command: str, payload_text: str, exit_code: int, payload_status: str,
    payload_digest: str,
) -> dict:
    """THE append to the queries table: allocate this lead's next seq, persist the payload
    sidecar, assemble the twelve frozen keys, append one line.

    Extracted from `QueryCapture._record` (#823 fork F1) because the gather bash lane became a
    second writer and a second copy of this would be a third place for the row shape to drift
    — `lint_duplicate_helpers` is the check that would have caught it. `error_class` is
    DERIVED here from `exit_code` rather than accepted from the caller: a writer that could
    disagree with `error_class_for_exit` is exactly the divergence the offline loop's
    `agent-fixable` filter cannot see.

    ATOMICITY IS BY THREAD-CONFINEMENT, not by a lock, and the distinction matters because the
    two callers guard differently: `_record` still holds `QueryCapture._seq_lock` around this
    call, the bash lane holds nothing. What actually keeps `(lead_id, seq)` unique is that this
    function contains no `await`, so no caller on the event loop thread can interleave with it
    — and `_tool_bash` is synchronous, so it runs on that thread too.

    That is a CONTRACT, not an accident: moving the bash tool off-thread (an
    `asyncio.to_thread(_tool_bash, …)` at its registration site, tempting because the lane can
    block for `_BASH_TIMEOUT_S`) breaks it, because two threads would each compute
    `_next_seq` and collide — the exact defect the mechanical gate's R2 demand was raised
    about, and one that loses a payload sidecar silently since both writers are best-effort
    about persistence. Anything that makes either writer concurrent needs a real cross-writer
    lock here first."""
    seq = _next_seq(run_dir, lead_id)
    payload_rel = persist_payload(run_dir, lead_id, seq, payload_text)
    row = {
        "lead_id": lead_id,
        "seq": seq,
        "system": system,
        "verb": verb,
        "query_id": query_id,
        "params": _json_safe_params(dict(params)),
        "raw_command": raw_command,
        "payload_path": payload_rel,
        "exit_code": exit_code,
        "error_class": error_class_for_exit(exit_code),
        "payload_status": payload_status,
        "payload_digest": payload_digest,
    }
    write_guarded(RunPaths(run_dir).executed_queries, json.dumps(row) + "\n", mode="append")
    return row


def _payload_key(operand: Path, base: Path) -> tuple[str, int] | None:
    """The `(lead_id, seq)` a `gather_raw/{lead}/{seq}.json` operand names, or `None` for any
    path that is not one — outside the tree, at the wrong depth, wrong suffix, unparseable
    seq. Every rejection is a `continue` at the caller, so they are one answer here."""
    try:
        rel = Path(operand).resolve().relative_to(base)
    except (ValueError, OSError):
        return None
    if len(rel.parts) != 2 or rel.suffix != ".json":
        return None
    try:
        return (rel.parts[0], int(rel.stem))
    except ValueError:
        return None


def system_for_payload_operands(run_dir: Path, operands: Iterable[Path]) -> str:
    """The system a reducer's failure belongs to: the system of the PAYLOAD it read.

    #823's M2, and the reason `derive_system` is not used for this. `derive_system` parses the
    argv, and a reducer argv names the reducer — `defender-sql` yields the system `"sql"`,
    `defender-jq` yields `"jq"`, and a pitfall row carrying either makes
    `_build_pitfalls_handoffs` emit `defender/skills/sql/execution.md` and invite the curator
    to create a system directory for a system that does not exist (the phantom class closed
    for `h-*` in #821/#828).

    The payload path carries the answer instead: `gather_raw/{lead}/{seq}.json` joins straight
    back to the row that wrote it, whose `system` was set by a real dispatch. Keyed on the
    PAYLOAD's own lead, not the reading lead — the system is a property of the bytes, so a
    cross-lead read still attributes correctly.

    `""` when no operand resolves to a run payload, which is the honest answer and not a
    guess: `collect_general_failures` skips a systemless row at its existing guard
    (lead_extraction.py:100).

    The operands are keyed FIRST and the table read only if one of them is a payload path, so
    the common `defender-sql` call that opens no run payload costs no read at all — and the
    read that does happen is the second of two on this path (`append_query_row`'s `_next_seq`
    is the other), not the third."""
    try:
        base = RunPaths(run_dir).gather_raw.resolve()
    except OSError:
        return ""
    keys = [k for operand in operands if (k := _payload_key(operand, base)) is not None]
    if not keys:
        return ""
    try:
        rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    except OSError:
        return ""
    wanted = set(keys)
    by_key = {
        (r.get("lead_id"), r.get("seq")): r
        for r in rows
        if isinstance(r, dict) and (r.get("lead_id"), r.get("seq")) in wanted
    }
    for key in keys:
        row = by_key.get(key)
        if row is None:
            continue
        system = str(row.get("system") or "").strip()
        if system:
            return system
    return ""


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

RESERVED_QUERY_ID_PREFIX = "∅."
"""The prefix every writer-only sentinel `query_id` carries, and the ONE screen that keeps a
model from spelling one.

`∅` is chosen because it fails `draft_synthesis._SAFE_ID_SEGMENT`, so the offline routers
partition a sentinel row by construction rather than by a learned case. That property is
useless if a model can claim the identity: a `query_id` the model supplies verbatim would let
it stamp the repeat guard's own refusal record onto a query that was never refused, or route an
arbitrary failing query into the pitfalls residue with unbounded model-authored `params` —
past the `SHIM_COMMAND_MAX_CHARS` bound that exists for exactly that reach.

`resolve_query_id` therefore refuses the whole prefix rather than one literal at a time, so a
fourth sentinel is reserved the day it is defined instead of the day someone remembers."""


def is_reserved_query_id(value: str) -> bool:
    return value.startswith(RESERVED_QUERY_ID_PREFIX)


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

BASH_SHIM_QUERY_ID = "∅.bash-shim"
"""The sentinel `query_id` for a FAILED reducer-shim row from the gather bash lane (#823 M1).

Shares `ABOVE_GUARD_QUERY_ID`'s `∅.` prefix because it needs the same property, for a different
reader: `∅` fails `draft_synthesis._SAFE_ID_SEGMENT`, so `_draft_candidate_segments` returns
`None` and the row falls past `synthesize_drafts`; it is not a catalog id, so `build_handoff`
does not claim it either. What is left is `collect_general_failures` — the pitfalls residue,
which is where a reducer mistake belongs, because `skills/{system}/execution.md` is the file
the gather subagent reads before coining its next query.

The routing is therefore BY CONSTRUCTION: no collector learned a new case and none was edited.
A descriptive id would have been the trap — `{system}.defender-sql-unnest` passes the
safe-segment match, so every failed reduce would have been minted as a candidate catalog
template."""

REPEAT_TRIP_QUERY_ID = "∅.repeat-trip"
"""The sentinel `query_id` for the repeat guard's own trip row (#823 M3).

A DISTINCT literal from `ABOVE_GUARD_QUERY_ID`, and the distinction is load-bearing:
`repeat_trip`'s counted domain keys on that value alone and MUST NOT widen to include this one.
`test_trip_row_is_itself_an_occurrence_on_replay` (#807) pins that a trip row counts toward a
later check of the same key, so that a replay of a recorded table keeps matching the live run it
replays. This constant changes what the row is CALLED — which only the offline router reads —
never what the guard COUNTS.

Before it, the trip row carried `resolve_query_id(...)`, the model's own coined id, and
misrouted in both directions: a coined id was minted as a `_draft/` template proposing the very
query the guard had just refused, and a catalog id was handed to the lead-author as a failure of
that template. Neither reached the curator, which is the one reader that could act on it."""

SHIM_COMMAND_MAX_CHARS = 2000
"""The bound on a shim row's recorded command (#823, the security dive).

`payload_digest` has always been capped at 160 chars, but `params` was not, and
`draft_synthesis._structured_call` yaml-dumps `params` whole into the `executed_query` the
curator's prompt receives — from where the agent can echo it into a committed `execution.md`.
The command is model-authored text, so it is the one field of a shim row an attacker-influenced
turn chooses freely. 2000 is far above any real reduce (the footer's own suggestion is ~60
chars) and far below anything that could crowd a prompt."""


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


