#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import re
import shlex
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._io import (
    JsonTooDeep,
    guarded_mkdir,
    json_nesting_depth,
    json_safe,
    read_jsonl_rows,
    write_guarded,
)
from defender._model import model
from defender._run_paths import LEAD_ID_RE, RunPaths  # noqa: F401 — re-export: `tools_gather` imports the pre-dispatch gate from here
from defender._text import as_int, as_str, is_content_less
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS, error_class_for_exit

_ADAPTER_RE = re.compile(r"(?:^|/)(\w+)_adapter\.py$")
_NON_ADAPTER = frozenset({"invlang"})

# The model-visible view of a captured payload lives in `payload_view.py`.


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
    """The row's human-readable display string — prose for offline readers, never an identity.

    On success it is a serialized length, so equal-length payloads share it; `_result_identity`
    pairs it with `payload_sha256`. On failure it is the discriminating half, since every failed
    row hashes the same empty payload — except for above-guard rejections whose `system` was
    coarsened away: those record host text only, so two rejections naming different undeclared
    systems share both this string and the hash. That is safe because `repeat_note` skips every
    `ABOVE_GUARD_QUERY_ID` row and `collect_general_failures` drops systemless rows before
    `pitfall_key` merges on the digest. For unreadable-system rejections (`system_key == ""`)
    the two strings are unrecoverable from the table."""
    if exit_code != 0:
        return f"exit={exit_code}; {stderr.strip()[:160]}"
    lines = stdout.count("\n") + 1 if stdout.strip() else 0
    return f"{len(stdout)} bytes, {lines} line(s)"


def _sha256_hex(text: str) -> str:
    """`sha256` under the encoding both hash columns share.

    `surrogatepass`, not `replace`: `replace` maps every unencodable codepoint to U+FFFD, so
    distinct strings would collide — fatal for both `payload_sha256` (byte identity for
    `repeat_note`) and `system_fingerprint` (telling ghosts apart)."""
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def payload_sha256(payload_text: str) -> str:
    """The row's content identity: `sha256` of the exact text persisted to the sidecar.

    Separate from `payload_digest` because the digest is prose that readers truncate, while
    this is what `repeat_note` asserts byte identity from."""
    return _sha256_hex(payload_text)


def names_something_readable(raw_system: Any) -> bool:
    """Does `raw_system` name anything a reader could tell apart from an empty argument?

    Public because this module's repeat grouping and `query_tool._undeclared_target`'s
    dead-end wording must agree: a group the guard folds is a group the message describes.

    Uses `_text.is_content_less` rather than `.strip()` (which leaves zero-width and format
    codepoints standing, each minting its own digest while rendering as empty) or
    `str.isprintable()` (which depends on the interpreter's Unicode database, so the answer
    could change across Python versions, and calls private-use glyphs unreadable). A non-`str`
    is unreadable rather than a raise: both callers run inside a rejection handler.

    Not closed: assigned, visible-category characters that render blank in most fonts
    (U+3164, U+2800, U+115F/U+1160, a lone variation selector) count as readable and mint their
    own identity. "Renders blank" is a font property, not a string property; the containment is
    `rejection_budget_trip`, which counts rejections regardless of identity."""
    return isinstance(raw_system, str) and not is_content_less(raw_system)


def system_fingerprint(raw_system: Any, recorded_system: str) -> str:
    """@owns system_key — the row's `system_key` column: the only value derived from a
    model-authored system string allowed to leave the writer's frame.

    `""` when the row already separates the call: a declared system (`recorded_system` carries
    it) or a system with nothing readable in it (all such calls are one repeat group).

    `raw_system` is coerced via `names_something_readable` rather than trusted, because both
    above-guard callers run inside a rejection handler that would not catch a raise here.

    Otherwise the full-width `sha256` of the raw string. Truncating buys nothing: a system name
    is low-entropy either way, and `verb`, `params` and `raw_command` on the same row already
    store unbounded model text verbatim. `sha256` rather than `hash()` so a replay agrees with
    the run that wrote the table. Kept out of `system` because the digest is name-shaped and
    `system` feeds corpus paths; only the guard's `_trip` reads this column.

    Never minted for a declared name: `recorded_system` is `""` exactly when the registry's
    fixed roster does not declare `raw_system`."""
    if recorded_system or not names_something_readable(raw_system):
        return ""
    return _sha256_hex(raw_system)


def _request_key(system: Any, verb: Any, params: Any) -> str:
    # Cleaned here, not by each caller, so live params and a stored row's key alike.
    call = [system, verb, params if isinstance(params, dict) else {}]
    return json.dumps(json_safe(call, non_finite="text"), sort_keys=True)


#: The deepest a call's params may nest, the params map itself counting as one level. A
#: product bound, not derived from any reader: no real query nests near it, and it sits far
#: enough under `JSON_NESTING_LIMIT` that every record embedding a call's arguments stays
#: readable — the query row and the branch ledger one level down, the gather wire log several.
PARAMS_NESTING_LIMIT = 32


class ParamsTooDeep(Exception):
    """`field` nests past `PARAMS_NESTING_LIMIT`; nothing was stored. Every refusal of a
    too-deep call says it in this sentence, naming the field.

    An `Exception`, not a `ValueError`: `ServedCall` cleans its params as it is built, and
    pydantic would wrap a `ValueError` raised there into its own `ValidationError` (`_model`)."""

    def __init__(self, field: str = "params") -> None:
        self.field = field
        super().__init__(
            f"{field} nest deeper than {PARAMS_NESTING_LIMIT} levels, the most a stored call "
            "can carry")


def _json_safe_params(value: Any, *, field: str = "params") -> Any:
    """@owns PARAMS_NESTING_LIMIT — params as every table stores them, or `ParamsTooDeep`
    naming `field`.

    Text for a non-finite float: the record is what a reader diagnoses a query from, and a
    `threshold` of infinity is not a missing one. The same rule `_request_key` keys by.

    Refuses rather than cuts: a cut value would key differently from its live call. The walk
    stops at the limit, so no params can exhaust the stack here or anywhere downstream."""
    try:
        return json_safe(value, non_finite="text",
                         max_depth=PARAMS_NESTING_LIMIT, deeper="refuse")
    except JsonTooDeep:
        raise ParamsTooDeep(field) from None


def params_too_deep(value: Any) -> bool:
    """Would `value`, stored as a call's params, be refused as too deep?

    Asks the storing step itself, so no check can disagree with what the writers refuse."""
    try:
        _json_safe_params(value)
    except ParamsTooDeep:
        return True
    return False


def call_args_too_deep(args: Any) -> bool:
    """Would any argument of a model's call, stored as params, be refused as too deep?

    `args` is the call's whole argument object, as text or decoded. Text is judged on its
    bytes, because text too deep for `json.loads` decodes to nothing and would look shallow;
    the argument object sits one level above each argument, hence the `+ 1`."""
    if isinstance(args, str):
        return json_nesting_depth(args) > PARAMS_NESTING_LIMIT + 1
    return isinstance(args, Mapping) and any(params_too_deep(v) for v in args.values())


def lead_rows(run_dir: Path, lead: str) -> list[dict]:
    """This lead's rows from `executed_queries.jsonl`, in file order. `OSError` reads as zero
    rows: reading this table must never crash the query tool."""
    try:
        rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    except OSError:
        return []
    return [r for r in rows if isinstance(r, dict) and r.get("lead_id") == lead]


def payload_status(exit_code: int, payload: Any) -> str:
    """The `payload_status` column's rule — `error` / `empty` / `ok` — for a decoded payload.

    Shared by both row writers so they cannot drift; the offline loop reads it to tell a query
    that found nothing from one that failed. Not derived in `append_query_row`, which only sees
    the payload's text (`None` and `"null"` are the same bytes)."""
    if exit_code != 0:
        return "error"
    if payload is None:
        return "empty"
    if isinstance(payload, (dict, list, tuple, set, str)) and len(payload) == 0:
        return "empty"
    return "ok"


def raw_command(system: str, verb: str, params: dict) -> str:
    """The `raw_command` column: the call as one shell-quoted line (shared by both writers)."""
    return shlex.join([system, verb, *(f"{k}={v}" for k, v in params.items())])


def persist_payload(run_dir: Path, lead_id: str, seq: int, text: str) -> str | None:
    """Write the payload sidecar at `gather_raw/{lead_id}/{seq}.json`, best-effort; returns its
    run-dir-relative path or `None`.

    Catches `ValueError` too: `guarded_mkdir` raises it when a `lead_id` with separators or
    `..` escapes the tree. The sidecar must exist even when empty, because
    `lead_extraction.extract_from_joined` drops any row whose `raw_ref` is not a file."""
    owner = RunPaths(run_dir)
    try:
        payload_path = owner.payload(lead_id, seq)
        guarded_mkdir(payload_path.parent, base=run_dir)
        write_guarded(payload_path, text)
    except (OSError, ValueError):
        return None
    return owner.payload_relpath(lead_id, seq)


#: The queries row's column set, in writer order. `append_query_row` refuses to write a row
#: whose keys differ, `lead_repository.QueryRow` projects exactly these (`payload_path` as
#: `raw_ref`), and a test asserts the frozen key set equals it — so a new column cannot reach
#: the writer without reaching the readers.
QUERY_ROW_COLUMNS: tuple[str, ...] = (
    "lead_id",
    "seq",
    "system",
    "verb",
    "query_id",
    "params",
    "raw_command",
    "payload_path",
    "exit_code",
    "error_class",
    "payload_status",
    "payload_digest",
    "payload_sha256",
    "system_key",
)


def append_query_row(  # noqa: PLR0913 — one parameter per ROW COLUMN the caller must decide
    run_dir: Path, *, lead_id: str, system: str, verb: str, query_id: str, params: dict,
    raw_command: str, payload_text: str, exit_code: int, payload_status: str,
    payload_digest: str, system_key: str,
) -> dict:
    """@owns QUERY_ROW_COLUMNS — the single append to the queries table: allocate the lead's
    next seq, persist the payload sidecar, and append one row in `QUERY_ROW_COLUMNS` order.

    Every writer goes through here. A row whose keys or order differ from the declaration is a
    `RuntimeError` at the first write. Params past `PARAMS_NESTING_LIMIT` are `ParamsTooDeep`
    before anything is written, so every row is one its reader can read back. `error_class`
    and `payload_sha256` are derived here so a caller cannot disagree with them.

    `system_key` is required: `""` is a real answer, so a default would hide a writer that
    should have fingerprinted. It cannot be derived here because the string it fingerprints is
    absent from the row.

    Atomicity is by thread confinement, not a lock: this function contains no `await`, and the
    synchronous bash tool also runs on the event loop thread, so `(lead_id, seq)` stays unique.
    Moving either writer off-thread would let two threads compute the same `_next_seq` and lose
    a payload sidecar; add a cross-writer lock first."""
    # First, so too-deep params are refused before a seq is taken or a sidecar written.
    stored_params = _json_safe_params(dict(params))
    seq = _next_seq(run_dir, lead_id)
    payload_rel = persist_payload(run_dir, lead_id, seq, payload_text)
    row: dict[str, Any] = {
        "lead_id": lead_id,
        "seq": seq,
        "system": system,
        "verb": verb,
        "query_id": query_id,
        "params": stored_params,
        "raw_command": raw_command,
        "payload_path": payload_rel,
        "exit_code": exit_code,
        "error_class": error_class_for_exit(exit_code),
        "payload_status": payload_status,
        "payload_digest": payload_digest,
        # Derived here so it cannot disagree with the bytes just persisted.
        "payload_sha256": payload_sha256(payload_text),
        # Passed in: the raw string it fingerprints must not be on the row.
        "system_key": system_key,
    }
    # Compared as a tuple: the on-disk key order is part of the contract.
    if tuple(row) != QUERY_ROW_COLUMNS:
        raise RuntimeError(
            "internal: append_query_row's row disagrees with QUERY_ROW_COLUMNS: "
            f"{tuple(row)} != {QUERY_ROW_COLUMNS}"
        )
    write_guarded(RunPaths(run_dir).executed_queries, json.dumps(row) + "\n", mode="append")
    return row


def _payload_key(operand: Path, base: Path) -> tuple[str, int] | None:
    """The `(lead_id, seq)` a `gather_raw/{lead}/{seq}.json` operand names, or `None`."""
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
    """The system a reducer's failure belongs to: the system of the payload it read.

    Not `derive_system`, which would yield `"sql"` from a `defender-sql` argv and send the
    curator to a skill directory for a system that does not exist. The payload path joins back
    to the row that wrote it, keyed on the payload's own lead so cross-lead reads attribute
    correctly. `""` when no operand is a run payload; the table is read only if one is."""
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
    """What two calls must share for their results to be the same fact, or `None` when the row
    cannot evidence one (no `payload_sha256`) and so must match nothing.

    Both halves: for a failure the digest carries the error and the hash is the shared
    empty-payload hash; for a success the hash carries the content and the digest is only a
    length (fixed-schema enumerations often produce same-length payloads). Blind to
    `exit_code`, which only selects the note's wording.
    """
    return (str(digest), str(sha256)) if sha256 else None


def repeat_note(  # noqa: PLR0913 — one parameter per row field the comparison reads
    run_dir: Path, lead: str, *, seq: int, system: str, verb: str,
    params: dict, payload_digest: str, payload_sha256: str, exit_code: int = 0,
) -> str | None:
    """Name the earlier call in this lead that this one repeats, if any.

    Each payload is persisted under a fresh `{seq}.json`, so without this note two executions
    of the same query read as new evidence. The note states facts about prior rows only — no
    refusal, no advice. `exit_code` selects the wording (a failed call returned no payload, so
    it must not be told it "returned the same payload"); failures and successes never match
    each other because their digests have different shapes.
    """
    key = _request_key(system, verb, params)
    identity = _result_identity(payload_digest, payload_sha256)
    repeat_seq: int | None = None
    same_payload: int | None = None
    for rec in lead_rows(run_dir, lead):
        # Same counted domain as `repeat_trip`: these rows never reached the backend.
        if rec.get("query_id") in ABOVE_PLACEMENT_QUERY_IDS:
            continue
        prior = rec.get("seq")
        if not isinstance(prior, int) or prior >= seq:
            continue
        payload_matches = identity is not None and identity == _result_identity(
            rec.get("payload_digest"), rec.get("payload_sha256"),
        )
        # A repeat needs both matches on the same row.
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
        # Says nothing about where the call was rejected: exit 64 never reached the system,
        # exit 1 is the system's own answer.
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


# The repeat circuit breaker: a lead issuing the same request (`lead_id`, `system`, `verb`,
# canonical `params`, `system_key`) `REPEAT_THRESHOLD` times has stopped reasoning, and that
# call is refused before it reaches the backend. The count is derived per call from
# `lead_rows`, excluding rows written above the guard's placement in
# `QueryCapture.wrap_tool_execute`, so live runs and replays agree.

REPEAT_THRESHOLD = 3

REPEAT_ESCAPE = (
    "Sending this exact request again will not produce a different answer. Move on with "
    "what this lead has already captured, or change what you are asking for."
)
# Avoids the word "complete": `tools_gather._dead_end_notice` appends `INCOMPLETE_IDIOM` right
# after this string, and the two must not read as opposed dispositions.

# The per-lead rejection budget. `rejection_trip` only bounds rejections of the same request,
# and a lead can mint unboundedly many distinct ones (see `names_something_readable`). The
# framework's per-tool retry count does not bound them either: `ToolManager.for_run_step`
# drops it — at the pydantic-ai 1.107 floor on any step where `query` did not fail, from 2.x
# only on a successful `query` — so a lead can keep buying more rejections. This is an
# aggregate, identity-blind bound over `in_rejection_domain`, recovered from existing rows.
#
# Its own literal rather than derived from `REPEAT_THRESHOLD`: it is sized from the archive
# (no lead in 320 wrote more than 2 above-guard agent-fixable rows).
#
# Invariant, pinned by a test rather than here (to avoid importing the agent-build layer):
# `REJECTION_BUDGET < driver.DEFAULT_TOOL_RETRIES`, so the host's sentence reaches main instead
# of pydantic-ai's error text.
#
# Not covered:
#   - The framework counts every failed `query` step, this only above-guard rows. A lead mixing
#     below-guard `_screen` refusals with ghosts can still hit the framework's limit first
#     (e.g. six refusals then five ghosts stamps `retry-exhausted`).
#   - The correlation lead runs under `CORRELATION_REQUEST_LIMIT = 8`, where 6 is 75% of the
#     allowance (vs 15% of `GATHER_REQUEST_LIMIT = 40`). Resizing or exempting it is for the
#     owner of ORIENT's correlation section.
#   - Both `_tripped_message` returns answer with a plain tool result and write no row, and
#     `_grant_check`'s `∅.denied` rows are excluded from both predicates, so a lead looping on
#     a policy-denied verb is bounded only by `GATHER_REQUEST_LIMIT`.

REJECTION_BUDGET = 6

REJECTION_BUDGET_ESCAPE = (
    "Further requests of that shape will be turned back the same way. Move on with what "
    "this lead has already captured."
)
# Avoids "complete" for the reason `REPEAT_ESCAPE` does. Distinct from it because the escape is
# the only part of the dead-end message that tells main which kind of stop this was.

RESERVED_QUERY_ID_PREFIX = "∅."
"""The prefix every writer-only sentinel `query_id` carries; `resolve_query_id` refuses it.

`∅` fails `draft_synthesis._SAFE_ID_SEGMENT`, so the offline routers partition sentinel rows by
construction. A model able to spell one could stamp a refusal record onto an unrefused query, or
route arbitrary failures with unbounded `params` into the pitfalls residue past
`SHIM_COMMAND_MAX_CHARS`. The whole prefix is refused so new sentinels are covered."""


def is_reserved_query_id(value: str) -> bool:
    return value.startswith(RESERVED_QUERY_ID_PREFIX)


ABOVE_GUARD_QUERY_ID = "∅.above-repeat-guard"
"""Sentinel `query_id` for rows written above the guard's placement in
`QueryCapture.wrap_tool_execute`: `wrap_tool_validate`'s rejection row and `_grant_check`'s
adapter-load-error and non-`GRANTED` rows.

No call that reaches the guard could have such a row refused, so counting them would let a
replay report a trip no live run can produce."""

BASH_SHIM_QUERY_ID = "∅.bash-shim"
"""Sentinel `query_id` for a failed reducer-shim row from the gather bash lane.

`∅` fails `draft_synthesis._SAFE_ID_SEGMENT` and is no catalog id, so the row reaches only
`collect_general_failures` — the pitfalls residue, taught via `skills/gather/defender-sql.md`.
A descriptive id like `{system}.defender-sql-unnest` would pass the safe-segment match and mint
every failed reduce as a candidate catalog template."""

DENIED_QUERY_ID = "∅.denied"
"""Sentinel `query_id` for a call the grant check refused (a verb withheld from the role).

The offline judge grades leads, so a lead whose only activity was a denied verb needs a row to
be found by. Like the other sentinels it stays out of the learning loop: `lead_repository`
splits it onto `JoinedLead.sentinels` and each router partitions on `is_sentinel`. The denial
audit record in `policy_denials.jsonl` is still written first.

Distinct from `ABOVE_GUARD_QUERY_ID` because the judge reports it as `kind=denied` and its
`error_class` is `DENIED_ERROR_CLASS`. It is written above the guard's placement, so it is in
`ABOVE_PLACEMENT_QUERY_IDS`; `in_rejection_domain` excludes it by construction."""

REPEAT_TRIP_QUERY_ID = "∅.repeat-trip"
"""Sentinel `query_id` for the repeat guard's own trip row.

Must not join `ABOVE_PLACEMENT_QUERY_IDS`: a trip row keeps counting toward later checks of the
same key so replays match the live run. The id only changes offline routing. The model's own id
would misroute it: a coined id becomes a `_draft/` template for the refused query, a catalog id
reaches the lead-author as a template failure, and neither reaches the curator."""

#: Sentinel ids of rows written above `wrap_tool_execute`'s guard placement, which
#: `repeat_trip` and `repeat_note` must not count. Excludes `REPEAT_TRIP_QUERY_ID` (trip rows
#: keep counting) and `BASH_SHIM_QUERY_ID` (the bash lane has no guard placement).
ABOVE_PLACEMENT_QUERY_IDS = frozenset({ABOVE_GUARD_QUERY_ID, DENIED_QUERY_ID})

SHIM_COMMAND_MAX_CHARS = 2000
"""The bound on a shim row's recorded command.

`params` is uncapped and `draft_synthesis._structured_call` dumps it whole into the curator's
prompt, from where it can reach a committed `execution.md`. The command is the one field of a
shim row an attacker-influenced turn chooses freely. 2000 is far above a real reduce (~60
chars) and far below anything that could crowd a prompt."""


@model(frozen=True)
class RepeatTrip:
    """One trip of the repeat guard: the earliest matching row's seq, and this call's
    1-based occurrence number (`== threshold` at a trip)."""

    first_seq: int | None
    occurrence: int


@model(frozen=True, kw_only=True)
class RejectionBudgetTrip:
    """One trip of the per-lead rejection budget: this call's 1-based `occurrence` among the
    lead's above-guard agent-fixable rejections, and the `budget` it reached.

    Integers only, so no model-authored string can travel into
    `rejection_budget_dead_end_reason` and on into main's context. Not a `RepeatTrip`: there is
    no `first_seq`, and the dispatchers tell the guards apart by type. Keyword-only because
    `occurrence` and `budget` coincide at an ordinary stop, so a transposition would only show
    when parallel calls push `occurrence` past `budget`."""

    occurrence: int
    budget: int


class GatherDeadEnd(Exception):
    """A lead-level dead end: the refused request (`reason`) and a fixed, system-agnostic
    sentence handing the decision to main (`escape`).

    Raised by the guards inside the query tool and caught by the tool's own hooks, which record
    both on the lead's `LeadStop`, answer the call with `reason` as a failed tool result, and
    let the model's next turn be its summary. Only deps without a stop record see it raised.
    `reason` becomes the header of the lead's message in main's context, so it may carry nothing
    model-authored."""

    def __init__(self, reason: str, escape: str):
        # Both args go to `super().__init__` so `pickle`/`copy.deepcopy` can rebuild it.
        super().__init__(reason, escape)
        self.reason = reason
        self.escape = escape


def _trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any, threshold: int,
    in_domain, system_key: Any,
) -> RepeatTrip | None:
    """The counting loop both guards drive over the domain `in_domain` selects, so they cannot
    disagree about what a repeat is.

    `system_key` is coerced through `as_str` on both sides: older rows and hand-built fixtures
    lack the column and a replayed live call passes `None`, and both must read as `""` or the
    rejection loop stops being bounded. `system_key` extends the identity to separate calls
    naming different undeclared systems, whose `system` is `""`. Required here so no guard can
    silently skip it.

    The cheap `system_key` compare runs before the per-row `json.dumps`, which matters for
    `rejection_trip` where many rows differ by system key."""
    key_request = _request_key(system, verb, params)
    key_system = as_str(system_key)
    matches = [
        r for r in rows
        if isinstance(r, dict) and r.get("lead_id") == lead and in_domain(r)
        and as_str(r.get("system_key")) == key_system
        and _request_key(r.get("system"), r.get("verb"), r.get("params")) == key_request
    ]
    occurrence = len(matches) + 1
    if occurrence < threshold:
        return None
    # `as_int`, not `isinstance(_, int)`: the table is box-writable, and a planted `"seq": true`
    # passes `isinstance` but fails strict `RepeatTrip.first_seq` validation.
    seqs = [seq for m in matches if (seq := as_int(m.get("seq"))) is not None]
    return RepeatTrip(first_seq=min(seqs) if seqs else None, occurrence=occurrence)


def repeat_trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any,
    threshold: int = REPEAT_THRESHOLD, system_key: Any = "",
) -> RepeatTrip | None:
    """`None` below `threshold` occurrences of this request in `rows`, else the `RepeatTrip`
    naming the earliest matching row's seq. `params` is the live call's, normalised to the
    stored form, so live and replayed checks agree. `rows` need not be pre-filtered to `lead`.

    `system_key` defaults to `""` because every row in this domain reached the backend under a
    declared system."""
    return _trip(
        rows, lead, system=system, verb=verb, params=params, threshold=threshold,
        system_key=system_key,
        in_domain=lambda r: r.get("query_id") not in ABOVE_PLACEMENT_QUERY_IDS,
    )


def in_rejection_domain(row: Any) -> bool:
    """The above-guard rejection domain: rows refused above `wrap_tool_execute`'s guard for
    something the model itself can fix.

    Shared by `rejection_trip`, `rejection_budget_trip` and the offline replay oracle; separate
    copies would split the guards in silence while every fixture stayed green. Narrower than
    `ABOVE_GUARD_QUERY_ID` by `error_class`: adapter-load errors are `infra` and already owned
    by `circuit_breaker`, so counting them would turn an outage into a lead-level dead end. A
    non-`dict` is out of the domain rather than a raise."""
    return (
        isinstance(row, dict)
        and row.get("query_id") == ABOVE_GUARD_QUERY_ID
        and row.get("error_class") == AGENT_FIXABLE_ERROR_CLASS
    )


def rejection_trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any, system_key: Any,
    threshold: int = REPEAT_THRESHOLD,
) -> RepeatTrip | None:
    """The companion guard: `repeat_trip` over the rejections that never reached
    `wrap_tool_execute`'s placement (argument-schema failures, unresolvable verbs at the grant
    check), which `repeat_trip` cannot see. The two domains are disjoint, so neither can report
    a trip the other's placement could have prevented. The domain is `in_rejection_domain`.

    `system_key` carries the identity the row cannot: an undeclared system is recorded as
    `""`, so without it three rejections naming three different systems would trip. Required
    here (unlike `repeat_trip`) because omitting it would silently key every ghost alike.

    `rejection_budget_trip` also counts this domain, identity-blind. The two are checked in
    order with distinct sentences, so a lead ended here did repeat itself, and the row's detail
    says which guard fired."""
    return _trip(
        rows, lead, system=system, verb=verb, params=params, threshold=threshold,
        system_key=system_key,
        in_domain=in_rejection_domain,
    )


def rejection_budget_trip(
    rows: list[dict], lead: str, *, budget: int = REJECTION_BUDGET,
) -> RejectionBudgetTrip | None:
    """`None` while this call is below the lead's `budget`-th above-guard rejection, else the
    trip. The guarded call counts: `budget - 1` prior rows trip.

    The domain is exactly `rejection_trip`'s (`in_rejection_domain`). Widening it by
    `error_class` would turn adapter outages into dead ends; widening it to below-guard
    parameter refusals would end healthy leads (30 of 320 archived leads have 4+, tails up to
    98).

    Identity-blind: it reads none of `system`, `verb`, `params` or `system_key`, since those
    are exactly what an attacker-influenced turn chooses freely. Counts over the lead's
    lifetime, since the framework's counter is what gets reset.

    The guarded call's rejection row is written whether or not it trips, so a recorded table
    holds exactly `budget` matching rows at a trip and replays reach the same verdict. `>=`
    because `query` is not `sequential`: parallel calls can read a stale count and arrive past
    the budget, and the stop must still land."""
    count = sum(
        1 for r in rows
        if in_rejection_domain(r) and r.get("lead_id") == lead
    )
    occurrence = count + 1
    if occurrence < budget:
        return None
    return RejectionBudgetTrip(occurrence=occurrence, budget=budget)


def _ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def repeat_trip_detail(trip: RepeatTrip) -> str:
    """The trip row's detail, short enough to survive `_record`'s 160-char truncation."""
    return f"refused: repeat of request already issued at seq {trip.first_seq} ({_ordinal(trip.occurrence)} occurrence)"  # noqa: E501


def _with_rejection_tail(detail: str, rejection: str) -> str:
    """Join an above-guard trip row's leading phrase with the guarded call's own error, so both
    guards' rows share one grammar for offline readers."""
    return f"{detail}; rejected: {rejection}" if rejection else detail


def rejection_trip_detail(trip: RepeatTrip, rejection: str = "") -> str:
    """`repeat_trip_detail`'s counterpart for the companion guard. Says "turned back", not
    "issued": these calls never reached a system of record.

    `rejection` is this call's own error, kept as a tail because the row is both the rejection
    record and the trip row; replacing the detail outright would make the append-only table
    permanently forget why the last call was malformed. The trip phrase leads so the 160-char
    truncation cuts the tail."""
    detail = f"refused: repeat of request already turned back at seq {trip.first_seq} ({_ordinal(trip.occurrence)} occurrence)"  # noqa: E501
    return _with_rejection_tail(detail, rejection)


def rejection_dead_end_reason(system: str, verb: str, trip: RepeatTrip) -> str:
    """`dead_end_reason`'s counterpart, without an executed-query count: a request rejected
    before it ran executed nothing. Never includes model-authored `params`."""
    # `system`/`verb` coarsen to `""` when not supplied as strings, so the pair can be empty.
    # `names_something_readable` rather than `.strip()` so this agrees with
    # `_undeclared_target` and a zero-width verb cannot produce "the request (​)".
    pair = f"{system} {verb}".strip()
    target = pair if names_something_readable(pair) else (
        "system/verb unreadable in the call's own arguments")
    return (
        f"the request ({target}) was rejected before it ran and repeats the one already "
        f"turned back at seq {trip.first_seq}; it has now been rejected "
        f"{trip.occurrence} times for the same reason. The rejection is structural, not a "
        "transient to retry through."
    )


def rejection_budget_dead_end_reason(trip: RejectionBudgetTrip) -> str:
    """`GatherDeadEnd.reason` for a budget stop.

    Takes no target or verb: the count is over the lead, not one request, and both callers hold
    raw model strings at this point — an unused parameter would be one edit from being used.
    Describes the rejected requests by category only. Reports `occurrence`, not `budget`,
    because parallel calls can push the count past the allowance."""
    return (
        f"{trip.occurrence} requests in this lead were rejected before they ran — each named "
        "a system the run does not declare, a verb it does not have, or arguments the tool "
        "could not read. That is the lead's whole allowance for such requests; the rejections "
        "are structural, not transients to retry through."
    )


def rejection_detail(trip: RepeatTrip | RejectionBudgetTrip, rejection: str = "") -> str:
    """The single producer of an above-guard trip row's `detail`, which is how every reader of
    the queries table tells which guard stopped a lead.

    No column may carry this: the trip row must stay an ordinary `ABOVE_GUARD_QUERY_ID` /
    `agent-fixable` row so it keeps counting and replays reproduce the run. The leading phrase
    is the discriminator. A budget stop ends a lead on calls that all differed, so it must never
    claim a repeat; the repeat branch delegates to `rejection_trip_detail`. `rejection` is kept
    as a tail for the same reason as there."""
    if type(trip) is RepeatTrip:
        return rejection_trip_detail(trip, rejection)
    if not isinstance(trip, RejectionBudgetTrip):
        # Total, not an `else`: a third guard's trip must not be silently described as a
        # budget stop. The branch above uses `type(trip) is` so a `RepeatTrip` subclass lands
        # here instead of being described as a repeat.
        raise TypeError(f"no above-guard detail for {type(trip).__name__}")
    detail = (
        f"refused: {_ordinal(trip.occurrence)} request in this lead rejected before it ran "
        f"(budget {trip.budget})"
    )
    return _with_rejection_tail(detail, rejection)


def rejection_dead_end(
    trip: RepeatTrip | RejectionBudgetTrip, *, target: str, verb: str,
) -> GatherDeadEnd:
    """The single producer of the above-guard `GatherDeadEnd` for both placements and both
    guards, so a placement cannot pair a budget stop with the repeat guard's escape.

    `target` and `verb` are discarded on the budget branch: the budget stop's contract is that
    no byte of the model's arguments reaches main. Keyword-only because the two placements name
    these mirrored `str`s differently, and a transposition would type-check silently."""
    if type(trip) is RepeatTrip:
        return GatherDeadEnd(
            reason=rejection_dead_end_reason(target, verb, trip),
            escape=REPEAT_ESCAPE,
        )
    if not isinstance(trip, RejectionBudgetTrip):
        # Total, as in `rejection_detail`; here a `RepeatTrip` subclass taking the repeat
        # branch would also echo the model's own arguments into main's context.
        raise TypeError(f"no above-guard dead end for {type(trip).__name__}")
    return GatherDeadEnd(
        reason=rejection_budget_dead_end_reason(trip),
        escape=REJECTION_BUDGET_ESCAPE,
    )


def dead_end_reason(system: str, verb: str, trip: RepeatTrip, executed: int) -> str:
    """`GatherDeadEnd.reason` for a repeat stop: the repeated request, that the cause is
    structural, and how many queries the lead executed.

    `executed` counts exit-0 rows only, so a lead whose calls were all refused is not reported
    as having found things. Never includes model-authored `params`: this harness-authored
    header reaches main's context."""
    plural = "query" if executed == 1 else "queries"
    return (
        f"the request ({system} {verb}) repeats the one already issued at seq {trip.first_seq}; "
        f"this lead executed {executed} {plural} before this repeat. The result is structural, "
        "not a transient to retry through."
    )


#: Characters a `query_id` may not carry: path shapes (traversal out of the directory it names
#: a file in) and render shapes (a newline or `#` would forge markdown structure in the offline
#: collectors' documents).
_QID_FORBIDDEN = ("/", "\\", "..", "\x00", "\n", "\r", "#")

#: The part after the first `.` in a coined `query_id`. No dots: `'system.foo.bar'` would give
#: `draft_synthesis._draft_candidate_segments` a second unvalidated path component.
_KEBAB_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]*\Z")


def resolve_query_id(system: str, verb: str, model_query_id: str | None) -> str:
    """The `query_id` a call is recorded under: the model's `{system}.{kebab-name}` when well
    formed for `system`, else `{system}.{verb}`. Here rather than in the tool so pydantic-ai-free
    callers apply the same rule."""
    # A model-supplied reserved `∅.` id must not reach a real row: the repeat-trip record sits
    # above `_screen`, so nothing else screens it.
    if (
        model_query_id
        and not is_reserved_query_id(model_query_id)
        and not any(t in model_query_id for t in _QID_FORBIDDEN)
    ):
        # The prefix must equal the dispatched system exactly (no case folding or NFC).
        prefix, sep, remainder = model_query_id.partition(".")
        if sep and prefix == system and remainder and _KEBAB_SEGMENT.match(remainder):
            return model_query_id
    return f"{system}.{verb}" if verb else f"{system}.ad-hoc"
