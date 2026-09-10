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
from defender._text import as_str, is_content_less
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
    separates two of them — WITH ONE CLASS EXCEPTED since #1016. An above-guard rejection whose
    `system` the host coarsened away records HOST material, and both placements collapse: the
    grant check writes one literal, and the schema placement renders a model-chosen field name
    as the placeholder `argument`. Two rejections naming two different undeclared systems now
    share this string as well as their payload hash.

    THE ABOVE-GUARD EXCLUSION is what keeps that safe — not this column and not `system_key`.
    `_result_identity`'s only consumer is `repeat_note`, which skips every
    `ABOVE_GUARD_QUERY_ID` row, so no collapsed pair is ever compared, and
    `collect_general_failures` drops a systemless row before `pitfall_key` merges on the digest.
    `system_key` separates two READABLE ghosts for the companion guard alone, and only in the
    raw table: it is `""` for the whole N5 group and `lead_repository.QueryRow` does not project
    it. For that group there is no fallback at all — two rejections naming two different
    invisible strings are byte-identical in every column, and neither string is recoverable.
    That is #855 and #1016's trade, not an oversight, but a reader sent to the raw table for
    that class would be sent to a surface that cannot answer."""
    if exit_code != 0:
        return f"exit={exit_code}; {stderr.strip()[:160]}"
    lines = stdout.count("\n") + 1 if stdout.strip() else 0
    return f"{len(stdout)} bytes, {lines} line(s)"


def _sha256_hex(text: str) -> str:
    """`sha256` over `text` under the ONE encoding contract both hash columns share.

    `surrogatepass`, NOT the `replace` the transports decode vendor bytes with: `replace` maps
    every unencodable codepoint to the SAME U+FFFD, so two distinct strings collide — which is
    the one thing neither of the two callers may allow, `payload_sha256` because `repeat_note`
    reads byte identity off it and `system_fingerprint` because telling two ghosts apart is the
    whole of what it is for. One home, so a change to the contract cannot reach one and not the
    other."""
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def payload_sha256(payload_text: str) -> str:
    """The row's CONTENT identity: `sha256` of the exact text persisted to the sidecar.

    Its own column beside `payload_digest` because only one of the two may drift: the digest is
    prose a curator reads and truncates (`lead_extraction` cuts it at 200 chars), the hash is
    what `repeat_note` asserts byte identity from.

    `surrogatepass`, NOT the `replace` the transports decode vendor bytes with: `replace` maps
    every unencodable codepoint to the SAME U+FFFD, so two distinct payloads would collide and
    `repeat_note` would call them byte-identical. Moot while `ensure_ascii` is on at both
    writers; `surrogatepass` keeps it true the day that changes."""
    return _sha256_hex(payload_text)


def names_something_readable(raw_system: Any) -> bool:
    """Does `raw_system` name anything a reader could tell apart from an empty argument?

    PUBLIC because it is asked at two seams that must never disagree: this module's N5 class
    (which calls of no readable system are ONE repeat group) and `query_tool._undeclared_target`
    (whether the dead-end message may say "an undeclared system" or must say the arguments were
    unreadable). A group the guard FOLDS is a group the message DESCRIBES, so two spellings of
    the question let the sentence MAIN receives be decided by whichever member of the group
    landed last — the "the coarsening may not make the dead end LIE" property, lost to turn
    order.

    NOT `raw_system.strip()`, which is the same question asked of `str.isspace` alone and gets
    it wrong in the direction that matters: `.strip()` folds the SPACES but leaves every
    zero-width and format codepoint standing (U+200B, U+200C/D, U+2060, U+FEFF, U+00AD, the C0
    controls), so each of them, and each of their unbounded concatenations, would mint a digest
    of its own while rendering as exactly the empty argument beside it.

    THE ANSWER IS `_text.is_content_less`, NEGATED, and not a third spelling of it. That module
    exists for this question over model-produced text, argues the `.strip()` case in the same
    words, and pins the category set `{Cc, Cf, Cs}` — which is what makes this predicate a
    fixed function of the string rather than of the interpreter. `str.isprintable()` is the
    spelling to avoid here: it reads Cn off the RUNNING interpreter's UCD, so an unassigned
    codepoint folds into the N5 group today and mints a digest of its own after a Python
    upgrade — the same across-processes disagreement `system_fingerprint` pins `sha256` over
    `hash()` to prevent, one function earlier. It also answers Co (private use) as unreadable,
    which would tell MAIN a call naming a glyph the reader can see was "unreadable".

    A non-`str` is UNREADABLE rather than a raise, for the reason `system_fingerprint` coerces:
    both seams that ask this run inside a rejection handler with no `try` of their own.

    WHAT THIS DOES NOT CLOSE, stated so the next reader does not have to rediscover it: a
    character that is ASSIGNED and in a visible category but renders blank in most fonts —
    U+3164 HANGUL FILLER (Lo), U+2800 BRAILLE PATTERN BLANK (So), U+115F/U+1160, a lone
    variation selector (Mn) — is readable here and mints a digest of its own, so those still
    supply an unbounded family of identities that print as nothing. That is deliberate rather
    than overlooked: they are real characters, "renders blank" is a property of the FONT and
    not of the string, and a predicate that guessed at it would be neither stable nor
    explainable. The containment for a lead that spends identities is a bound on the NUMBER of
    above-guard rejections, not a cleverer notion of emptiness — and since #1015 that bound
    exists: `rejection_budget_trip` counts this predicate's whole output identity-blind, so
    every member of the family above costs the same one rejection as a visible name."""
    return isinstance(raw_system, str) and not is_content_less(raw_system)


def system_fingerprint(raw_system: Any, recorded_system: str) -> str:
    """@owns system_key — the row's `system_key` column, and the ONLY value derived from a
    model-authored system string that is allowed to leave the writer's frame.

    `""` is "this row's identity needs no fingerprint", and it is the answer in both cases
    where the row already separates the call by itself: a DECLARED system (`recorded_system`
    is the model's own string, so `_request_key` discriminates on it already) and a system
    argument with nothing readable in it (`_text.as_str` coarsens a non-string to `""` at the
    schema placement, and "no readable system at all" is ONE mistake — two such calls stay
    one repeat group; `names_something_readable` decides which strings are in it).

    `raw_system` is COERCED rather than trusted, like every other value on this path
    (`_text.as_str`, `_as_dict`) — the coercion is `names_something_readable`'s,
    so the two seams cannot disagree about what a non-`str` means. Both ABOVE-GUARD call sites
    run inside a rejection handler that has no `try` of its own, so a raise here would replace
    the rejection — no row for the guard to count, and the fault unwinds past the lead's own
    catch. (`lead_zero._record_manual_row` is the third caller and is not in a handler; it
    passes a host constant, so it can only ever be answered `""`.)

    Otherwise: `sha256` over the raw string, at FULL width, exactly as `payload_sha256` spends
    it on the neighbouring column of the same row. It is not truncated, and an earlier draft
    that truncated it to 16 was carrying two reasons that do not survive being asked for
    evidence — "harder to reverse" (a system name is low-entropy, so it is dictionary-open at
    any width) and "a smaller channel out of a table the gather agent can read" (the agent
    AUTHORED the string, and `verb`, `params` and `raw_command` on this same row store
    unbounded model text verbatim). The repo's other truncations are all identifiers a person
    reads or types; this one is compared machine-to-machine inside `_trip` and displayed
    nowhere, so the readability that buys them their width buys this nothing.

    `sha256` itself IS pinned, and against `hash()`, whose per-process salt would make a
    replay over a recorded table disagree with the run that wrote it.

    The digest is name-shaped at either width — `is_system_name` accepts a 64-character hex
    run as readily as a 16-character one — which is why it lives in its own column instead of
    being folded into `system`: the corpus-path consumer reads `system`, and nothing reads
    this."""
    if recorded_system or not names_something_readable(raw_system):
        return ""
    return _sha256_hex(raw_system)


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
    payload_digest: str, system_key: str,
) -> dict:
    """THE append to the queries table: allocate this lead's next seq, persist the payload
    sidecar, assemble the fourteen frozen keys, append one line.

    THE one writer for both callers (`QueryCapture._record` and the gather bash lane), so the row
    shape has a single place to drift. `error_class` is DERIVED here from `exit_code` rather than
    accepted from the caller: a writer that could disagree with `error_class_for_exit` is exactly
    the divergence the offline loop's `agent-fixable` filter cannot see.

    `system_key` is REQUIRED and not defaulted, like every other column the caller decides:
    `""` is a real answer here (this row's `system` already identifies the call), so a default
    would let a writer that OUGHT to fingerprint silently skip it and be indistinguishable from
    one that correctly has nothing to fingerprint. Unlike `error_class` and `payload_sha256`
    it cannot be derived here — the string it fingerprints is by design absent from the row.

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
        # #871: the rejection guard's identity for a row whose `system` was coarsened to `""`.
        # PASSED IN rather than derived, because the raw string it fingerprints is exactly what
        # this row must not carry — `system_fingerprint` owns the value, and only the two
        # above-guard placements that mint one still hold the string to give it.
        "system_key": system_key,
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
# `verb`, canonical `params`, and since #871 `system_key`) `REPEAT_THRESHOLD` times has stopped
# producing reasoning, and the third identical call is refused before it reaches the backend.
# The count is derived per call from `lead_rows` — no new persisted state — over exactly the
# rows the guard itself could have refused: a row answered ABOVE the guard's placement in
# `QueryCapture.wrap_tool_execute` is never an occurrence, live or on replay. `system_key` is
# `""` on every row in THIS guard's domain, so the fifth element changes nothing here; it is
# the companion guard (`rejection_trip`) whose rows carry it.

REPEAT_THRESHOLD = 3

REPEAT_ESCAPE = (
    "Sending this exact request again will not produce a different answer. Move on with "
    "what this lead has already captured, or change what you are asking for."
)
# Deliberately avoids the word "complete": `_run_gather`'s `except GatherDeadEnd` branch appends
# the fixed `INCOMPLETE_IDIOM` right after this string in the message handed to main, and the two
# must not read as opposed dispositions.

# The per-lead rejection budget (#1015).
#
# `rejection_trip` bounds the above-guard loop BY IDENTITY: three rejections of the SAME
# request end the lead. Nothing bounded a lead whose rejections all DIFFER, and the family of
# ways to differ is unbounded — `names_something_readable` is deliberately blind to assigned
# but font-blank codepoints (its docstring names #1015 as the containment), so a fresh
# undeclared name per turn walks past the guard forever. Worse, the FRAMEWORK's own ceiling
# does not contain it either: `ToolManager.for_run_step` DROPS `query`'s accumulated retry
# count, so a lead that stops failing for a turn buys `DEFAULT_TOOL_RETRIES` more rejections,
# indefinitely, and spends its whole request budget on them.
#
# EXACTLY WHEN IT DROPS IS A VERSION FACT, and `defender/pyproject.toml` floors the dependency
# without pinning it (`pydantic-ai-slim>=1.107`), so BOTH rules ship:
#   - at the 1.107 floor, `for_run_step` rebuilds `retries` from `failed_tools` ALONE
#     (`retries = {name: prev + 1 for name in self.failed_tools}`), so the count is dropped on
#     every step where `query` did not FAIL — a bash reduce, a `list_verbs`, or a text-only
#     turn resets it, no successful query required;
#   - from 2.x, the rebuild carries a count forward unless its tool is in `succeeded_tools`,
#     so the drop requires an actual SUCCESSFUL `query`.
# Neither rule contains the loop, and the weaker one (the floor's) is what makes the loop
# cheapest to sustain — so every argument below holds under both, and the margin paragraph's
# worked example is the shape that keeps `query` failing on CONSECUTIVE steps, which is the
# only shape that reaches the framework's arm under EITHER rule. Do not restate one of the two
# as "the" rule; the installed version decides which is running.
#
# So the containment is an AGGREGATE bound, identity-blind, over exactly `rejection_trip`'s
# domain — the one filter both placements already load their rows for. NO NEW STATE and no new
# column: the count is recovered from the rows the guard itself wrote.
#
# ITS OWN LITERAL, not derived from `REPEAT_THRESHOLD`: the two answer different questions
# (this one is sized by the archive — no lead in 42 runs / 320 leads wrote more than 2
# above-guard agent-fixable rows) and one edit must not move both.
#
# INVARIANT, pinned by `test_1015_rejection_budget_predicate` rather than enforced here:
# `REJECTION_BUDGET < driver.DEFAULT_TOOL_RETRIES`. At or above the framework's per-tool
# ceiling the framework raises first and main is handed pydantic-ai's text and a documentation
# URL instead of the host's own sentence — the same race `challenge_gate.Bounds.__post_init__`
# keeps its turn bound strictly below. The check lives in a test and not in an import because
# this module is the low-level recorder every gather path already imports, and reaching up to
# the agent-build layer for a constant would tie the two together for one assertion.
#
# WHAT THE MARGIN DOES NOT COVER, stated because the inequality alone reads as if it did: the
# framework counts every FAILED STEP for the tool NAME, and this budget counts only above-guard
# rows. A lead that MIXES the two — below-guard `_screen` parameter refusals among the ghosts —
# reaches eleven failed `query` steps before its sixth above-guard rejection and ends on
# `UnexpectedModelBehavior` after all, with the framework's text in main's context. Executed:
# six below-guard refusals then five ghosts, no successful call between them, stamps
# `retry-exhausted`. Closing that means either widening this domain (which C13's census
# forbids at this bound) or keeping the framework's own text out of `_run_gather`'s degrade
# arms; neither is #1015's, and the claim above holds only for a lead whose `query` failures
# are all above-guard rows.
#
# NOR IS 40 THE ONLY REQUEST LIMIT THIS BOUND SITS UNDER. #1015 sized 6 against main's gather
# limit (`GATHER_REQUEST_LIMIT = 40`) and against the retry ceiling, but the harness-authored
# CORRELATION lead runs the same `_run_gather`, hence the same `QueryCapture` and the same
# budget, under `lead_zero._spec.CORRELATION_REQUEST_LIMIT = 8` — so this constant is 15% of a
# model-dispatched lead's allowance and 75% of that one's. A dead end was already reachable
# there (the repeat guard's, at three identical rejections), so this widens an existing door
# rather than opening one. The stop is REACHABLE and was reproduced: six schema-rejected turns
# on `l-00c` write six in-domain rows, stamp `dead-end` on that session and hand the
# correlation section the budget summary. No arm drives it today — but not because the arms
# CANNOT: `test_repeat_breaker_807._replay_rejections` reads every lead's rows with no reserved
# filter, and `test_808_correlation_lead` already asserts `l-00c`'s terminator (it drives
# SUCCESSFUL calls, so it reaches the request limit rather than this guard). An arm is
# affordable; it is the SIZE that is not this issue's to settle. Resizing, or exempting that
# lead, is a decision for whoever owns the correlation section of ORIENT — recorded here
# because the number cannot be re-derived from the census alone.
#
# NOR IS IT THE ONLY WAY A LEAD SPENDS ITS REQUESTS ON REFUSALS: `_grant_check`'s DENIED branch
# and both `_tripped_message` returns answer ABOVE this guard with a plain tool RESULT and no
# queries-table row at all, so they are invisible to both predicates AND reset the framework's
# per-tool counter. A lead looping on a policy-denied verb is bounded only by
# `GATHER_REQUEST_LIMIT`. Also not #1015's, and also not closed by this constant.

REJECTION_BUDGET = 6

REJECTION_BUDGET_ESCAPE = (
    "Further requests of that shape will be turned back the same way. Move on with what "
    "this lead has already captured."
)
# Avoids the word "complete" for the reason `REPEAT_ESCAPE` does: `_run_gather`'s dead-end
# branch appends the fixed `INCOMPLETE_IDIOM` right after this string, and the two must not
# read as opposed dispositions. DISTINCT from `REPEAT_ESCAPE` — the escape is the only part of
# the dead-end message that says what kind of stop this was, and one shared sentence would
# leave main unable to tell "you are repeating yourself" from "you have spent the allowance".

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


@dataclass(frozen=True, kw_only=True)
class RejectionBudgetTrip:
    """One trip of the per-lead rejection budget: this call's 1-based `occurrence` among the
    lead's above-guard agent-fixable rejections, and the `budget` it reached.

    INTEGERS ONLY, and that is half of why the budget stop cannot leak (#1015 S1). The other
    half is `_run_gather`'s dead-end arm, which composes main's summary from `reason` and
    `escape` alone. A `str` field here — the ghost's name, its fingerprint, a params fragment —
    would put a model-authored, unbounded string one attribute access away from
    `rejection_budget_dead_end_reason`, which is the #855 leak channel. There is no field for
    one to travel in, so no future edit of the sentence can spend it.

    Deliberately NOT a `RepeatTrip` with a different threshold: `first_seq` is meaningless here
    (the budget names no one earlier request), and the two dispatchers below tell the guards
    apart by TYPE. A shared type would make that a flag, and a flag read wrongly would hand
    main the other guard's sentence.

    KEYWORD-ONLY, for the reason `rejection_dead_end`'s two `str`s are: `occurrence` and
    `budget` are two adjacent same-typed fields derived from the same call, and a transposition
    is INVISIBLE at an ordinary stop because the two coincide there. It shows up only in the
    one case the field exists to describe — the parallel calls the `>=` rule admits, where
    `occurrence > budget` — and there it makes `rejection_budget_dead_end_reason` report the
    allowance instead of the rejections that happened, which is exactly what that function's
    docstring says it must never do."""

    occurrence: int
    budget: int


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
    in_domain, system_key: Any,
) -> RepeatTrip | None:
    """The ONE counting loop both guards drive, over the domain `in_domain` selects. Two
    hand-written loops over the same `(lead_id, system, verb, canonical(params))` would be one
    normalisation fix away from disagreeing about what a repeat is; only the DOMAIN is ever
    meant to differ.

    BOTH SIDES ARE COERCED THROUGH `as_str`, and that is load-bearing rather than defensive:
    every row recorded before #871 added the column, and every hand-built fixture row that
    lists the keys literally, has no `system_key` at all — while a live call reconstructed
    from such a row (which is exactly what #807's replay oracle does) passes `None`. Read
    either as anything but `""` and each of those rows stops matching the next one, silently
    un-bounding the rejection loop #826 item 4 closed.

    `system_key` EXTENDS that identity rather than replacing any of it (#871): it is `""` for
    every call whose `system` names itself, so it changes nothing for the first guard, and it
    is what separates two calls that named two different UNDECLARED systems — which the row's
    own `system` cannot do, because it deliberately holds `""` for both. REQUIRED and not
    defaulted here, for the reason `append_query_row` gives the column: a guard that could
    silently skip the key would key every call alike, which is the pre-#871 defect.

    The KEY HALF IS COMPARED FIRST, and that is a cost decision, not a semantic one: the pair
    is an `and`, so either order selects the same rows, but `_request_key` is a `json.dumps`
    per row and `as_str` is an `isinstance`. #871 is precisely the change that fills a
    lead with rows whose cheap half already differs (one per distinct undeclared system), so
    the expensive half is the one that must not run on them. The saving is `rejection_trip`'s
    ALONE — every row in `repeat_trip`'s domain stores `""` and every one of its callers means
    `""`, so there the cheap half never short-circuits and is pure added compare."""
    key_request = _request_key(system, verb, _json_safe_params(params))
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
    seqs = [m["seq"] for m in matches if isinstance(m.get("seq"), int)]
    return RepeatTrip(first_seq=min(seqs) if seqs else None, occurrence=occurrence)


def repeat_trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any,
    threshold: int = REPEAT_THRESHOLD, system_key: Any = "",
) -> RepeatTrip | None:
    """`None` below `threshold` occurrences of this request in `rows`, else the `RepeatTrip`
    naming the earliest matching row's seq. `params` is the LIVE call's, normalised to the stored
    form before keying, so this is the same predicate `repeat_note` and a replay over a recorded
    table both drive. `rows` need not be pre-filtered to `lead` — the identity `(lead_id, system,
    verb, canonical(params), system_key)` is checked here.

    Its callers pass no `system_key` and behave exactly as they did before #871: a row this
    guard counts reached the backend, so its `system` is a system the run declared and its
    `system_key` is `""` on both sides of the comparison."""
    return _trip(
        rows, lead, system=system, verb=verb, params=params, threshold=threshold,
        system_key=system_key,
        in_domain=lambda r: r.get("query_id") != ABOVE_GUARD_QUERY_ID,
    )


def in_rejection_domain(row: Any) -> bool:
    """THE above-guard rejection domain, in ONE place: a row this lead's calls were refused at
    ABOVE `wrap_tool_execute`'s guard, for something the model itself can fix.

    PUBLIC and shared because THREE readers ask it and their agreement is load-bearing:
    `rejection_trip` counts this population by identity, `rejection_budget_trip` counts it
    blind to identity, and #807's replay oracle asks it again offline to reproduce a stop. Both
    predicates' docstrings assert the domains are identical — spelled three times, that
    identity was asserted by nothing, and widening one copy (a second sentinel `query_id`, a
    second error class) would split the guards in silence while every fixture stayed green.

    NARROWER THAN `ABOVE_GUARD_QUERY_ID` ALONE, by `error_class`: `_grant_check`'s
    adapter-load-error rows are `infra` (exit 2) and their repeat is ALREADY owned end to end
    by `circuit_breaker`, so counting them here would give one shape two owners and turn an
    infra outage into a lead-level dead end.

    A non-`dict` is OUT of the domain rather than a raise, for the reason `lead_rows` swallows
    `OSError`: a torn or hand-built table must not be what starts crashing the query tool."""
    return (
        isinstance(row, dict)
        and row.get("query_id") == ABOVE_GUARD_QUERY_ID
        and row.get("error_class") == AGENT_FIXABLE_ERROR_CLASS
    )


def rejection_trip(
    rows: list[dict], lead: str, *, system: Any, verb: Any, params: Any, system_key: Any,
    threshold: int = REPEAT_THRESHOLD,
) -> RepeatTrip | None:
    """The COMPANION guard's predicate — `repeat_trip` over the complementary domain: the
    rejections that never reached `wrap_tool_execute`'s placement at all.

    A repeat loop the pydantic ARGUMENT SCHEMA turns back, or one an unresolvable verb turns back
    at the grant check, is invisible to `repeat_trip` by construction — its rows carry
    `ABOVE_GUARD_QUERY_ID` precisely so they cannot count there. Deliberately a SECOND guard
    rather than a widening of the first: the two count disjoint domains, so neither can report a
    trip the other's placement could have prevented.

    THE DOMAIN IS `in_rejection_domain`, spent rather than restated — narrower than
    `ABOVE_GUARD_QUERY_ID` alone, by `error_class`, for the reason that predicate gives.

    `system_key` (#871) is the identity half the ROW cannot carry: above the guard a
    model-named undeclared system is coarsened to `""` before it is recorded, so without it
    three rejections naming three different phantoms key the same and the third ends a lead
    the guard promised never to end for calls that DIFFER. The caller computes it with
    `system_fingerprint`, from the raw string it still holds.

    REQUIRED here and not defaulted, unlike `repeat_trip`'s — this is the one predicate whose
    rows carry a real fingerprint, so a caller that omitted the keyword would silently get the
    pre-#871 identity back: every ghost keying alike, no exception, no type error, and a guard
    that can never trip on any recorded ghost table. `repeat_trip` keeps its default because
    `""` is what every row in ITS domain stores and what every one of its callers means.

    SINCE #1015 THIS IS NOT THE ONLY GUARD ON THESE ROWS. `rejection_budget_trip` counts the
    same domain identity-blind, and a lead can now end on a call that differs from every one
    before it — for SPENDING, never for repeating. That does not weaken the promise this
    predicate keeps: the two are asked in order and each has its own sentence, so a lead ended
    here is still one that repeated itself, and the row's own detail says which guard it
    was."""
    return _trip(
        rows, lead, system=system, verb=verb, params=params, threshold=threshold,
        system_key=system_key,
        in_domain=in_rejection_domain,
    )


def rejection_budget_trip(
    rows: list[dict], lead: str, *, budget: int = REJECTION_BUDGET,
) -> RejectionBudgetTrip | None:
    """`None` while this call is below the lead's `budget`-th above-guard rejection, else the
    `RejectionBudgetTrip` for the call being guarded (#1015). The guarded call COUNTS: a table
    already holding `budget - 1` such rows trips, because this call is the `budget`-th.

    THE DOMAIN IS EXACTLY `rejection_trip`'S, and not by restatement — both spend
    `in_rejection_domain`, so the identity of domains that is the whole design is a shared
    call rather than two copies. Wider by `error_class` and an adapter outage becomes a
    lead-level dead end on rows `circuit_breaker` already owns end to end. Wider than
    `ABOVE_GUARD_QUERY_ID` and it swallows the below-guard parameter refusals, which run 4+ per
    lead in 30 of 320 archived leads (tails of 30, 71 and 98) — those are a model iterating on
    a REAL system's parameters under specific coaching, and a bound of 6 over them would end
    healthy leads.

    IDENTITY-BLIND, which is the ONE way it differs from `rejection_trip` and the reason it is
    a second predicate rather than another `threshold` on the first: it reads no `system`, no
    `verb`, no `params`, no `system_key`. Those are exactly the fields an attacker-influenced
    turn chooses freely, so any of them in the count is a knob for evading it. It does not go
    through `_trip` for the same reason — `_trip` IS the identity rule, shared so the two
    guards can never disagree about what a repeat is, and this predicate has no identity to
    agree about.

    NOTHING REFILLS IT. The count is over the lead's LIFETIME rows, and that is the defect it
    answers: the framework's own per-tool counter is DROPPED whenever the lead stops failing
    for a turn (the module comment above gives the two version-dependent rules for exactly
    when), which is precisely what un-bounds the loop. A lead that recovered and then thrashes
    again still ends at `budget`.

    ACCUMULATE BEFORE STOP, the shape `rejection_trip` has: the guarded call's own rejection
    row is written whether or not it trips, so `occurrence = count + 1` and a recorded table
    holds exactly `budget` matching rows at a trip. A replay over that table reaches the same
    verdict at the same row — which is what makes the stop recoverable offline.

    `>=` rather than `==`: the `query` tool is not declared `sequential`, so two calls in one
    model step can both read a stale count and the second can arrive past the budget. The stop
    then lands within the step rather than at the exact B-th row, and it must still land."""
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
    """The trip row's own detail — short enough to survive `_record`'s 160-char truncation, and
    distinguishable from an ordinary parameter refusal by naming the repetition and the earliest
    seq it repeats."""
    return f"refused: repeat of request already issued at seq {trip.first_seq} ({_ordinal(trip.occurrence)} occurrence)"  # noqa: E501


def _with_rejection_tail(detail: str, rejection: str) -> str:
    """THE join between an above-guard trip row's leading PHRASE and the error the guarded call
    itself produced — one home, so the leading phrase is the only thing that differs between the
    two guards' rows.

    Spelled once per branch instead, one edit to the separator (or to what an empty tail does)
    reaches whichever branch the author had open, and the append-only table then holds two
    grammars for one field: an offline reader splitting on `"; rejected: "` would parse the
    repeat guard's rows and the budget's differently, which is exactly the divergence
    `rejection_detail`'s single-producer discipline exists to prevent."""
    return f"{detail}; rejected: {rejection}" if rejection else detail


def rejection_trip_detail(trip: RepeatTrip, rejection: str = "") -> str:
    """`repeat_trip_detail`'s counterpart for the companion guard's trip row. Says "turned
    back", not "issued": the calls it counts never reached a system of record, and a reader that
    could not tell the two apart would report a lead as having queried something it never did.

    `rejection` is the error THIS call produced, kept as a tail because here one row is both the
    rejection record and the trip row — replacing the detail outright would make the append-only
    table permanently forget why the last call was malformed. The trip phrase leads, so it
    survives `_record`'s 160-character digest truncation whole and the tail is what gets cut."""
    detail = f"refused: repeat of request already turned back at seq {trip.first_seq} ({_ordinal(trip.occurrence)} occurrence)"  # noqa: E501
    return _with_rejection_tail(detail, rejection)


def rejection_dead_end_reason(system: str, verb: str, trip: RepeatTrip) -> str:
    """`dead_end_reason`'s counterpart, deliberately WITHOUT its executed-query count: a request
    that never got past the argument schema or the grant check executed nothing at this key.
    Never the model-authored `params` text — an unbounded fragment must not cross into main's
    context on a refusal path."""
    # `system`/`verb` are the RAW arguments at the schema placement and coarsen to `""` when the
    # call did not supply them as strings, so the pair can be empty. Say that, not "( )".
    #
    # `names_something_readable`, NOT `.strip()` — THE SAME predicate `_undeclared_target` uses
    # to decide the system half. `.strip()` here is what made the two disagree: a verb of one
    # zero-width codepoint is `.strip()`-truthy, so an empty system beside it kept this
    # fallback from firing and MAIN was handed literally "the request ()" — the "( )" this
    # branch exists to prevent, with an unbounded invisible model string inside the parens.
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
    """The string `GatherDeadEnd.reason` carries for a BUDGET stop (#1015).

    TAKES NO TARGET AND NO VERB, and the absent parameters are the point rather than an
    economy: the count is over the LEAD, not over a request, so there is no one request to
    name — and both placements that reach this function are holding a raw model string at the
    moment they call it (`wrap_tool_validate`'s pre-validation arguments, `_grant_check`'s
    unresolved system). `rejection_dead_end_reason` next door takes a target because its
    sentence is ABOUT one specific repeated request; this one would only be able to spend a
    string, never to need it. A parameter it did not use would be one edit from being used.

    Says WHAT was wrong with the requests in categories, not in the model's own words: the
    three above-guard shapes are an undeclared system, an absent verb, and arguments the
    schema could not read. That is enough for the lead to know why without a byte of what it
    asked for crossing back.

    The count is `occurrence`, NOT `budget`. They coincide on an ordinary stop and the design
    admits they need not — parallel calls in one step can push the occurrence past the
    allowance — and a sentence reporting the allowance would then tell main a number of
    rejections that did not happen."""
    return (
        f"{trip.occurrence} requests in this lead were rejected before they ran — each named "
        "a system the run does not declare, a verb it does not have, or arguments the tool "
        "could not read. That is the lead's whole allowance for such requests; the rejections "
        "are structural, not transients to retry through."
    )


def rejection_detail(trip: RepeatTrip | RejectionBudgetTrip, rejection: str = "") -> str:
    """THE ONE PRODUCER of an above-guard trip row's `detail` — the shipped form of "which
    guard stopped this lead", for every reader of the queries table.

    NO NEW COLUMN carries this, and none may: the trip row must stay an ordinary
    `ABOVE_GUARD_QUERY_ID` / `agent-fixable` row so it keeps counting, which is what lets a
    replay reproduce the run that wrote it. So the leading PHRASE is the whole discriminator,
    which is why it needs a single producer even though no field was added — both above-guard
    placements call this rather than each choosing a sentence per trip type, and the offline
    readers key on what it wrote. A second placement composing its own would be a second,
    silently diverging answer to a question the table can only be asked one way.

    The two branches must not be confusable, and that is #871's owner's promise (O2): the
    repeat guard ends a lead only for a call that REPEATS one before it, so a budget stop —
    which ends a lead for SPENDING, on calls that all differed — must never say "turned back
    at seq". The repeat branch is DELEGATED to `rejection_trip_detail` rather than restated
    here: that sentence already has an owner and a copy would drift from it.

    `rejection` is the tail for the same reason it is one there: this row is both the rejection
    record and the trip record, and replacing the detail outright would make the append-only
    table permanently forget why the last call was malformed. The budget phrase leads, so it
    survives `_record`'s 160-character digest cut whole and the tail is what gets eaten."""
    if type(trip) is RepeatTrip:
        return rejection_trip_detail(trip, rejection)
    if not isinstance(trip, RejectionBudgetTrip):
        # TOTAL, not an `else`. A third guard's trip falling through here would be described to
        # every reader of the table as a budget stop — silently, which is the one failure a
        # single producer exists to prevent.
        #
        # `type(trip) is`, not `isinstance`, on the branch above, and that is what makes this
        # check total: the natural way to add a third guard is to SUBCLASS `RepeatTrip` for its
        # `occurrence`/`first_seq`, and under `isinstance` such a trip takes the repeat branch
        # — no raise, and the table is told the lead repeated a request it never issued.
        raise TypeError(f"no above-guard detail for {type(trip).__name__}")
    detail = (
        f"refused: {_ordinal(trip.occurrence)} request in this lead rejected before it ran "
        f"(budget {trip.budget})"
    )
    return _with_rejection_tail(detail, rejection)


def rejection_dead_end(
    trip: RepeatTrip | RejectionBudgetTrip, *, target: str, verb: str,
) -> GatherDeadEnd:
    """THE ONE PRODUCER of the above-guard `GatherDeadEnd` pair — the reason and escape main's
    summary is composed from, for both placements and both guards.

    ONE dispatcher instead of a type switch at each placement, for the reason `_coarsen`
    exists one file over: the two placements read mirrored argument surfaces and have already
    had a `(raw, recorded)` pair transposed between them once. A budget branch spelled twice is
    a budget branch that can be spelled once with the repeat guard's escape, and the failure is
    silent — main simply receives the wrong explanation of why its lead stopped.

    `target` and `verb` are DISCARDED on the budget branch, not merely unspent: they are the
    model's own arguments (already coarsened by `_undeclared_target`, but derived from them),
    and the budget stop's contract is that no byte of them crosses into main's context. The
    repeat branch spends both, which is why they are still parameters at all.

    BOTH ARE KEYWORD-ONLY, for the reason `_undeclared_target` one file over is: they are two
    adjacent `str`s derived from the same call, spelled at two placements whose local names for
    them are mirrored, and only one of them may be echoed. A transposition at either placement
    type-checks, raises nothing, and puts "the request (query an undeclared system)" in main's
    context — caught only by an arm that drives THAT placement to the threshold."""
    if type(trip) is RepeatTrip:
        return GatherDeadEnd(
            reason=rejection_dead_end_reason(target, verb, trip),
            escape=REPEAT_ESCAPE,
        )
    if not isinstance(trip, RejectionBudgetTrip):
        # TOTAL, for the reason `rejection_detail`'s twin is: a third guard falling through to
        # the budget's sentence and escape is main receiving the wrong explanation, silently.
        # `type(trip) is` above for that twin's reason too — and here the subclass case is
        # worse, because the repeat branch SPENDS `target` and `verb`, so a third guard that
        # inherited from `RepeatTrip` would echo the model's own arguments into main's context.
        raise TypeError(f"no above-guard dead end for {type(trip).__name__}")
    return GatherDeadEnd(
        reason=rejection_budget_dead_end_reason(trip),
        escape=REJECTION_BUDGET_ESCAPE,
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


