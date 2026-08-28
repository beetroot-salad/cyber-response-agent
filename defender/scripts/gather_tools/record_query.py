#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._io import guarded_mkdir, read_jsonl_rows, write_guarded
from defender._run_paths import LEAD_ID_RE, RunPaths  # noqa: F401 — re-export: `tools_gather` imports the pre-dispatch gate from here
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS, error_class_for_exit

_ADAPTER_RE = re.compile(r"(?:^|/)(\w+)_adapter\.py$")
_NON_ADAPTER = frozenset({"invlang"})

# The model-visible view of a captured payload lives in `payload_view.py` — this module records
# the query, that one renders its result.


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
    """The row's HUMAN-READABLE display string — prose for the offline readers, never an
    identity.

    On a success it is a serialized LENGTH (both writers pass `json.dumps(payload,
    default=str)`, which escapes control characters, so `lines` is always 1). Equal-length
    payloads share a digest, so it must NOT stand alone for a payload comparison —
    `_result_identity` reads it beside `payload_sha256`. On a FAILURE it is the discriminating
    half instead: every failed row hashes the same empty payload, so only the error text
    separates two of them."""
    if exit_code != 0:
        return f"exit={exit_code}; {stderr.strip()[:160]}"
    lines = stdout.count("\n") + 1 if stdout.strip() else 0
    return f"{len(stdout)} bytes, {lines} line(s)"


def payload_sha256(payload_text: str) -> str:
    """The row's CONTENT identity: `sha256` of the exact text persisted to the sidecar.

    Its own column beside `payload_digest` because only one of the two may drift: the digest is
    prose a curator reads and truncates (`lead_extraction` cuts it at 200 chars), the hash is
    what `repeat_note` asserts byte identity from.

    `surrogatepass`, NOT the `replace` the transports decode vendor bytes with: `replace` maps
    every unencodable codepoint to the SAME U+FFFD, so two distinct payloads would collide and
    `repeat_note` would call them byte-identical. Moot while `ensure_ascii` is on at both
    writers; `surrogatepass` keeps it true the day that changes."""
    return hashlib.sha256(payload_text.encode("utf-8", errors="surrogatepass")).hexdigest()


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
    """This lead's rows off `{run_dir}/executed_queries.jsonl`, in file order — the one
    read+filter loop `_next_seq`, `repeat_note` and `repeat_trip` all key off. `OSError`
    (missing table, chmod-000 file) reads as zero prior rows rather than propagating: reading
    this table must never be what starts crashing the query tool.
    """
    try:
        rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    except OSError:
        return []
    return [r for r in rows if isinstance(r, dict) and r.get("lead_id") == lead]


def persist_payload(run_dir: Path, lead_id: str, seq: int, text: str) -> str | None:
    """The payload sidecar at `gather_raw/{lead_id}/{seq}.json`, best-effort.

    `ValueError` as well as `OSError`: `guarded_mkdir` raises it for a target outside the tree
    the anchor names, which a `lead_id` carrying path separators or `..` produces.

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
    sidecar, assemble the thirteen frozen keys, append one line.

    THE one writer for both callers (`QueryCapture._record` and the gather bash lane), so the row
    shape has a single place to drift. `error_class` is DERIVED here from `exit_code` rather than
    accepted from the caller: a writer that could disagree with `error_class_for_exit` is exactly
    the divergence the offline loop's `agent-fixable` filter cannot see.

    ATOMICITY IS BY THREAD-CONFINEMENT, not by a lock — the two callers guard differently
    (`_record` holds `QueryCapture._seq_lock`, the bash lane holds nothing). What keeps
    `(lead_id, seq)` unique is that this function contains no `await`, so nothing on the event
    loop thread can interleave with it, and `_tool_bash` is synchronous so it runs there too.

    That is a CONTRACT: moving the bash tool off-thread (tempting, since the lane can block for
    `_BASH_TIMEOUT_S`) makes two threads compute `_next_seq` and collide, silently losing a
    payload sidecar since both writers are best-effort about persistence. Making either writer
    concurrent needs a real cross-writer lock here first."""
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
        # DERIVED here, like `error_class`: a caller-supplied hash could disagree with the bytes
        # just persisted, which is the divergence this column exists to close.
        "payload_sha256": payload_sha256(payload_text),
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

    NOT `derive_system`, which parses the argv — and a reducer argv names the reducer, so
    `defender-sql` yields the system `"sql"`. A pitfall row carrying that makes
    `_build_pitfalls_handoffs` emit `defender/skills/sql/execution.md` and invite the curator to
    create a system directory for a system that does not exist.

    The payload path carries the answer instead: `gather_raw/{lead}/{seq}.json` joins straight
    back to the row that wrote it, whose `system` was set by a real dispatch. Keyed on the
    PAYLOAD's own lead, not the reading lead — the system is a property of the bytes, so a
    cross-lead read still attributes correctly.

    `""` when no operand resolves to a run payload, which is honest rather than a guess. It
    does not decide whether the row is collected: `collect_general_failures` admits a
    `BASH_SHIM_QUERY_ID` row on its sentinel id and normalizes `system` to `""` there, because
    a `defender-sql` mistake belongs to the reducer surface however the reduce was attributed.

    Operands are keyed FIRST and the table read only if one of them is a payload path, so the
    common `defender-sql` call that opens no run payload costs no read at all."""
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


def _result_identity(digest: Any, sha256: Any) -> tuple[str, str] | None:
    """What two calls must SHARE for their RESULTS to be the same fact — or `None` when a row
    evidences no such fact and can therefore match nothing.

    BOTH halves, each discriminating for a different kind of row:

      - for a FAILURE the digest carries the error (`exit={code}; {detail}`) and the hash is
        the same empty-payload hash every failed row has, both writers persisting `""`.
      - for a SUCCESS the hash carries the content and the digest is only a serialized LENGTH.
        Keying on the digest alone produces false byte-identical verdicts at scale, because
        fixed-schema enumeration yields same-length payloads by construction — a `fim-checksum`
        of `/etc/passwd` and one of `/etc/shadow` are both 160 bytes.

    Deliberately blind to `exit_code`: the exit code selects the note's WORDING and never whether
    a note fires, so a caller passing the wrong one must get the wrong prose, not silence.

    A row carrying no `payload_sha256` yields `None` and matches nothing — the note asserts byte
    identity, and a row that cannot evidence it must produce no note rather than a plausible one.
    """
    return (str(digest), str(sha256)) if sha256 else None


def repeat_note(  # noqa: PLR0913 — one parameter per ROW FIELD the comparison reads: the request identity (system/verb/params), the result identity (digest + hash), and this call's own seq/exit
    run_dir: Path, lead: str, *, seq: int, system: str, verb: str,
    params: dict, payload_digest: str, payload_sha256: str, exit_code: int = 0,
) -> str | None:
    """Name the earlier call in this lead that this one repeats, if any.

    A repeat is otherwise invisible from inside the turn loop: the payload is persisted under a
    fresh `{seq}.json` every call and the view embeds that path in its footer, so two executions
    of the same query differ by one integer and read as new evidence. Every branch below states a
    fact about rows already in the table — no refusal, no advice — because only a changed
    observation reaches a caller that has stopped producing reasoning.

    `exit_code` is THIS call's and selects the wording only, never whether a note fires. The
    comparison needs none of its own: a failed call's digest is the `exit={code}; {detail}` form,
    so two failures match each other and can never match a success's `N bytes, M line(s)`. The
    wording matters because a failing caller must not be told its request "returned the same
    payload" — it returned no payload at all, and what matched is the identical ERROR.
    """
    key = _request_key(system, verb, params)
    identity = _result_identity(payload_digest, payload_sha256)
    repeat_seq: int | None = None
    same_payload: int | None = None
    for rec in lead_rows(run_dir, lead):
        # Excludes ABOVE_GUARD_QUERY_ID rows so this scans the SAME counted domain `repeat_trip`
        # does — such a row never reached the backend, and its digest is an error, not a payload.
        if rec.get("query_id") == ABOVE_GUARD_QUERY_ID:
            continue
        prior = rec.get("seq")
        if not isinstance(prior, int) or prior >= seq:
            continue
        payload_matches = identity is not None and identity == _result_identity(
            rec.get("payload_digest"), rec.get("payload_sha256"),
        )
        # REPEAT requires BOTH conditions on the SAME row. Tracking request-match and
        # payload-match as two independent "earliest match" scans names two DIFFERENT prior rows
        # and then asserts a compound fact about only one of them.
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
        # Deliberately says nothing about WHERE the call was turned back: this arm fires for
        # every non-zero exit, and the classes differ — exit 64 is a usage refusal that never
        # reached the system, exit 1 is the system's own answer to a query it did parse.
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


# The repeat circuit breaker.
#
# `repeat_trip` is the predicate: a lead that issues the SAME request (`lead_id`, `system`,
# `verb`, canonical `params`) `REPEAT_THRESHOLD` times has stopped producing reasoning, and the
# third identical call is refused before it reaches the backend. The count is derived per call
# from `lead_rows` — no new persisted state — over exactly the rows the guard itself could have
# refused: a row answered ABOVE the guard's placement in `QueryCapture.wrap_tool_execute` is
# never an occurrence, live or on replay.

REPEAT_THRESHOLD = 3

REPEAT_ESCAPE = (
    "Sending this exact request again will not produce a different answer. Move on with "
    "what this lead has already captured, or change what you are asking for."
)
# Deliberately avoids the word "complete": `_run_gather`'s `except GatherDeadEnd` branch appends
# the fixed `INCOMPLETE_IDIOM` right after this string in the message handed to main, and the two
# must not read as opposed dispositions.

RESERVED_QUERY_ID_PREFIX = "∅."
"""The prefix every writer-only sentinel `query_id` carries, and the ONE screen that keeps a
model from spelling one.

`∅` fails `draft_synthesis._SAFE_ID_SEGMENT`, so the offline routers partition a sentinel row
by construction rather than by a learned case — a property that is useless if a model can claim
the identity. A verbatim `query_id` would let it stamp the repeat guard's refusal record onto a
query that was never refused, or route an arbitrary failing query into the pitfalls residue
with unbounded model-authored `params`, past the `SHIM_COMMAND_MAX_CHARS` bound that exists for
exactly that reach.

`resolve_query_id` refuses the whole prefix rather than one literal at a time, so a fourth
sentinel is reserved the day it is defined instead of the day someone remembers."""


def is_reserved_query_id(value: str) -> bool:
    return value.startswith(RESERVED_QUERY_ID_PREFIX)


ABOVE_GUARD_QUERY_ID = "∅.above-repeat-guard"
"""The sentinel `query_id` for the three rows written ABOVE the guard's own placement in
`QueryCapture.wrap_tool_execute` — `wrap_tool_validate`'s rejection row, and both of
`_grant_check`'s row-writing branches (adapter-load error, non-`GRANTED`/unresolvable).

No call that reaches the guard could ever HAVE such a row refused, so counting one toward a
later trip would let the replay oracle report a trip no live run can produce. Nothing in the
frozen row keys discriminates such a row from a validated one, hence a reserved value —
refused by `resolve_query_id` even when a model supplies it verbatim — inside the existing
key set rather than a new key of its own."""

BASH_SHIM_QUERY_ID = "∅.bash-shim"
"""The sentinel `query_id` for a FAILED reducer-shim row from the gather bash lane.

Shares the `∅.` prefix for the same property `ABOVE_GUARD_QUERY_ID` needs, serving a different
reader: `∅` fails `draft_synthesis._SAFE_ID_SEGMENT`, so `_draft_candidate_segments` returns
`None` and the row falls past `synthesize_drafts`; it is not a catalog id, so `build_handoff`
does not claim it either. What is left is `collect_general_failures` — the pitfalls residue,
where a reducer mistake belongs. The surface it is taught on is
`skills/gather/defender-sql.md`, the file the gather subagent reads before it writes the SQL,
not the `skills/{system}/execution.md` of whichever system's payload it opened.

The routing is BY CONSTRUCTION, not a learned case. A descriptive id would be the trap:
`{system}.defender-sql-unnest` passes the safe-segment match, so every failed reduce would be
minted as a candidate catalog template."""

REPEAT_TRIP_QUERY_ID = "∅.repeat-trip"
"""The sentinel `query_id` for the repeat guard's own trip row.

A DISTINCT literal from `ABOVE_GUARD_QUERY_ID`, and the distinction is load-bearing:
`repeat_trip`'s counted domain keys on that value alone and MUST NOT widen to include this one.
A trip row must keep counting toward a later check of the same key, so that a replay of a
recorded table keeps matching the live run it replays. This constant changes what the row is
CALLED — which only the offline router reads — never what the guard COUNTS.

Naming the row with the model's coined id instead misroutes it in both directions: a coined id
is minted as a `_draft/` template proposing the very query the guard just refused, and a
catalog id reaches the lead-author as a failure of that template. Neither reaches the curator,
the one reader that could act on it."""

SHIM_COMMAND_MAX_CHARS = 2000
"""The bound on a shim row's recorded command.

`payload_digest` is capped at 160 chars but `params` is not, and
`draft_synthesis._structured_call` yaml-dumps `params` whole into the `executed_query` the
curator's prompt receives — from where the agent can echo it into a committed `execution.md`.
The command is model-authored text, so it is the one field of a shim row an attacker-influenced
turn chooses freely. 2000 is far above any real reduce (~60 chars) and far below anything that
could crowd a prompt."""


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
        # BOTH args go through `super().__init__` so `.args` round-trips through
        # `cls(*self.args)` — the reconstruction `pickle`/`copy.deepcopy` use.
        super().__init__(reason, escape)
        self.reason = reason
        self.escape = escape


def _trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any, threshold: int,
    in_domain,
) -> RepeatTrip | None:
    """The ONE counting loop both guards drive, over the domain `in_domain` selects. Two
    hand-written loops over the same `(lead_id, system, verb, canonical(params))` would be one
    normalisation fix away from disagreeing about what a repeat is; only the DOMAIN is ever
    meant to differ."""
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
    naming the earliest matching row's seq. `params` is the LIVE call's, normalised to the stored
    form before keying, so this is the same predicate `repeat_note` and a replay over a recorded
    table both drive. `rows` need not be pre-filtered to `lead` — the identity `(lead_id, system,
    verb, canonical(params))` is checked here."""
    return _trip(
        rows, lead, system=system, verb=verb, params=params, threshold=threshold,
        in_domain=lambda r: r.get("query_id") != ABOVE_GUARD_QUERY_ID,
    )


def rejection_trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any,
    threshold: int = REPEAT_THRESHOLD,
) -> RepeatTrip | None:
    """The COMPANION guard's predicate — `repeat_trip` over the complementary domain: the
    rejections that never reached `wrap_tool_execute`'s placement at all.

    A repeat loop the pydantic ARGUMENT SCHEMA turns back, or one an unresolvable verb turns back
    at the grant check, is invisible to `repeat_trip` by construction — its rows carry
    `ABOVE_GUARD_QUERY_ID` precisely so they cannot count there. Deliberately a SECOND guard
    rather than a widening of the first: the two count disjoint domains, so neither can report a
    trip the other's placement could have prevented.

    THE DOMAIN IS NARROWER THAN `ABOVE_GUARD_QUERY_ID` ALONE, by `error_class`: an above-guard
    row counts only when it is `agent-fixable`. `_grant_check`'s adapter-load-error rows are
    `infra` (exit 2) and their repeat is ALREADY owned end to end by `circuit_breaker` — two
    failures mark the system down and the third call gets the down-message. Counting them here
    would give one shape two owners and turn an infra outage into a lead-level dead end."""
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
    """The trip row's own detail — short enough to survive `_record`'s 160-char truncation, and
    distinguishable from an ordinary parameter refusal by naming the repetition and the earliest
    seq it repeats."""
    return f"refused: repeat of request already issued at seq {trip.first_seq} ({_ordinal(trip.occurrence)} occurrence)"  # noqa: E501


def rejection_trip_detail(trip: RepeatTrip, rejection: str = "") -> str:
    """`repeat_trip_detail`'s counterpart for the companion guard's trip row. Says "turned
    back", not "issued": the calls it counts never reached a system of record, and a reader that
    could not tell the two apart would report a lead as having queried something it never did.

    `rejection` is the error THIS call produced, kept as a tail because here one row is both the
    rejection record and the trip row — replacing the detail outright would make the append-only
    table permanently forget why the last call was malformed. The trip phrase leads, so it
    survives `_record`'s 160-character digest truncation whole and the tail is what gets cut."""
    detail = f"refused: repeat of request already turned back at seq {trip.first_seq} ({_ordinal(trip.occurrence)} occurrence)"  # noqa: E501
    return f"{detail}; rejected: {rejection}" if rejection else detail


def rejection_dead_end_reason(system: str, verb: str, trip: RepeatTrip) -> str:
    """`dead_end_reason`'s counterpart, deliberately WITHOUT its executed-query count: a request
    that never got past the argument schema or the grant check executed nothing at this key.
    Never the model-authored `params` text — an unbounded fragment must not cross into main's
    context on a refusal path."""
    # `system`/`verb` are the RAW arguments at the schema placement and coarsen to `""` when the
    # call did not supply them as strings, so the pair can be empty. Say that, not "( )".
    target = f"{system} {verb}".strip() or "system/verb unreadable in the call's own arguments"
    return (
        f"the request ({target}) was rejected before it ran and repeats the one already "
        f"turned back at seq {trip.first_seq}; it has now been rejected "
        f"{trip.occurrence} times for the same reason. The rejection is structural, not a "
        "transient to retry through."
    )


def dead_end_reason(system: str, verb: str, trip: RepeatTrip, executed: int) -> str:
    """The string `GatherDeadEnd.reason` carries: this trip's repeated request, that the cause is
    structural, and how many queries this lead EXECUTED before the stop.

    `executed` is the count of exit-0 rows, NOT the row count: a lead whose prior calls were all
    refused executed zero of them, and counting the refusals would tell main "this lead found
    things" when it never got anywhere. Never the model-authored `params` text — an unbounded
    fragment must not cross into main's context on a refusal path."""
    plural = "query" if executed == 1 else "queries"
    return (
        f"the request ({system} {verb}) repeats the one already issued at seq {trip.first_seq}; "
        f"this lead executed {executed} {plural} before this repeat. The result is structural, "
        "not a transient to retry through."
    )


