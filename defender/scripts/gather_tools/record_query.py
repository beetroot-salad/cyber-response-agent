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
    """The row's HUMAN-READABLE display string — prose for the offline readers
    (`lead_extraction`, `lead_repository`, the lead-author's prompt), never an identity.

    On a success it is a serialized LENGTH and says so: both writers hand it
    `json.dumps(payload, default=str)`, which escapes control characters, so the text holds no
    raw newline and `lines` is always 1. Two different payloads of equal length produce the
    same digest, which is why it no longer STANDS ALONE for a payload comparison (#877 F-9):
    `_result_identity` reads it beside `payload_sha256`, and the hash is what carries a
    success's content. On a FAILURE it is still the discriminating half — every failed row
    hashes the same empty payload, so the error text is the only thing that separates two of
    them."""
    if exit_code != 0:
        return f"exit={exit_code}; {stderr.strip()[:160]}"
    lines = stdout.count("\n") + 1 if stdout.strip() else 0
    return f"{len(stdout)} bytes, {lines} line(s)"


def payload_sha256(payload_text: str) -> str:
    """The row's CONTENT identity: `sha256` of the exact text persisted to the sidecar.

    Its own column beside `payload_digest` rather than a longer digest string, because the two
    answer different questions and only one of them may drift: the digest is prose a curator
    reads and truncates (`lead_extraction` cuts it at 200 chars), the hash is what
    `repeat_note` asserts byte identity from.

    `surrogatepass`, and NOT the `replace` the transports decode vendor bytes with: this is the
    one field whose whole contract is that different bytes hash differently, and `replace` maps
    every unencodable codepoint to the SAME U+FFFD — two distinct payloads would collide and
    `repeat_note` would tell the lead they are byte-identical. Today the question is moot, and
    the docstring says so rather than inventing a hazard: both writers hand this
    `json.dumps(payload, default=str)` with `ensure_ascii` on, so the text is pure ASCII and
    nothing can fail to encode. `surrogatepass` is what keeps that true the day it stops being
    (#834's compact encoding would turn `ensure_ascii` off) — it round-trips a lone surrogate
    instead of raising out of the recorder or folding it into a shared character."""
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
    sidecar, assemble the thirteen frozen keys, append one line.

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
        # DERIVED here, like `error_class`, and for the same reason: a writer that could hand
        # in a hash disagreeing with the bytes it just persisted is exactly the divergence the
        # column exists to close. It is the hash of the text written to the sidecar above.
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
    guess. Since #870 M5′ that answer no longer decides whether the row is collected: a
    `BASH_SHIM_QUERY_ID` row is admitted by `collect_general_failures` on its sentinel id and
    has its `system` normalized to `""` there anyway, because a `defender-sql` mistake belongs
    to the reducer surface however the reduce happened to be attributed.

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


def _result_identity(digest: Any, sha256: Any) -> tuple[str, str] | None:
    """What two calls must SHARE for their RESULTS to be the same fact — or `None` when a row
    evidences no such fact and can therefore match nothing.

    BOTH halves, and each is the discriminating one for a different kind of row:

      - for a FAILURE the digest carries the error (`exit={code}; {detail}`) and the hash is
        the same empty-payload hash every failed row has, both writers persisting `""`. The
        error text is what repeats, and it is what separates two failures.
      - for a SUCCESS the hash carries the payload's content and the digest is `f"{len(text)}
        bytes, 1 line(s)"` — a serialized LENGTH (`json.dumps` escapes every newline, so the
        line count is always 1). Keying on the digest alone is #877 F-9: measured over the
        recorded runs it read 55 false byte-identical verdicts against 41 true ones, because
        fixed-schema enumeration produces same-length payloads by construction — a
        `fim-checksum` of `/etc/passwd` and one of `/etc/shadow` are both 160 bytes, and the
        lead was told the checksum of shadow was the checksum of passwd.

    Neither half is read as a KIND, and this function is deliberately blind to `exit_code`:
    #826 item 3 pins that the exit code selects the note's wording and never whether a note
    fires, so a caller passing the wrong one must get the wrong prose, not silence.

    A row carrying no `payload_sha256` — a table written before the column existed — yields
    `None` and matches nothing. The note asserts byte identity; a row that cannot evidence it
    must produce no note rather than a plausible one.
    """
    return (str(digest), str(sha256)) if sha256 else None


def repeat_note(  # noqa: PLR0913 — one parameter per ROW FIELD the comparison reads: the request identity (system/verb/params), the result identity (digest + hash), and this call's own seq/exit
    run_dir: Path, lead: str, *, seq: int, system: str, verb: str,
    params: dict, payload_digest: str, payload_sha256: str, exit_code: int = 0,
) -> str | None:
    """Name the earlier call in this lead that this one repeats, if any.

    A repeat is invisible from inside the turn loop. The payload is persisted under a fresh
    `{seq}.json` every call, and the payload view embeds that path in its footer, so two
    executions of the same query differ by one integer and read as new
    evidence. Nothing else in the loop compares a result to the one before it. Both branches
    below are statements of fact about rows already in the table — no refusal, no advice the
    caller has to accept — because the failure this addresses is a caller that has stopped
    producing reasoning, and only a changed observation reaches one.

    `exit_code` is THIS call's, and selects the wording only — never whether a note fires
    (#826 item 3). The comparison itself needs no exit code of its own: a failed call's digest
    is `_record`'s `exit={code}; {detail}` form, so two failures match each other and can never
    match a success's `N bytes, M line(s)` — and since #877 F-9 the digest is checked together
    with the payload's content hash (`_result_identity`), which is what makes "byte-identical"
    a claim the row can actually stand behind. What the failing caller must not be told is that
    its request "returned the same payload" — it returned no payload at all, and the fact that
    matched is the identical ERROR.
    """
    key = _request_key(system, verb, params)
    identity = _result_identity(payload_digest, payload_sha256)
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
        payload_matches = identity is not None and identity == _result_identity(
            rec.get("payload_digest"), rec.get("payload_sha256"),
        )
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
produce. P-a found no discriminator among the frozen row keys between such a row and a
validated one, so this value is deliberately reserved — `resolve_query_id` refuses to return it
(or an unscreened traversal string) even when a model supplies one verbatim as `query_id` — and
lives inside the existing key set rather than adding one of its own."""

BASH_SHIM_QUERY_ID = "∅.bash-shim"
"""The sentinel `query_id` for a FAILED reducer-shim row from the gather bash lane (#823 M1).

Shares `ABOVE_GUARD_QUERY_ID`'s `∅.` prefix because it needs the same property, for a different
reader: `∅` fails `draft_synthesis._SAFE_ID_SEGMENT`, so `_draft_candidate_segments` returns
`None` and the row falls past `synthesize_drafts`; it is not a catalog id, so `build_handoff`
does not claim it either. What is left is `collect_general_failures` — the pitfalls residue,
which is where a reducer mistake belongs. Since #870 the surface it is taught on is
`skills/gather/defender-sql.md`, the file the gather subagent reads before it writes the SQL,
rather than the `skills/{system}/execution.md` of whichever system's payload it opened.

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
    never sees them. Both fields are among the frozen row keys; no key of the guard's own is
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


