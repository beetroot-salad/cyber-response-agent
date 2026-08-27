"""Harness-executed lead-0.

Before MAIN's first ORIENT turn, the runtime resolves the alert's ancestor documents (item 1)
and dispatches one tightly-bounded correlation gather lead (item 3), both writing into the
run's leads/queries tables under the reserved ids ``l-000``/``l-00c`` so the learning loop and
the review gate cite them like any model-dispatched lead.

This module owns every backend call, run-dir write and dispatch those two items add;
``orient.py`` stays a pure text-assembler that calls ``resolve_lead_zero`` and formats the
returned block as one more ORIENT section.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender._io import read_jsonl_rows, read_text_soft
from defender._run_paths import RunPaths
from defender._untrusted import wrap_fresh
from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    BudgetKill,
    read_budget,
    tail_exhausted,
    update_budget_locked,
)
from defender.hooks.record_lead import ALREADY_CLAIMED, CLAIMED, claim_lead
from defender.runtime import circuit_breaker
from defender.runtime.verb_grant import GrantError, VerbGrant
from defender.runtime.verbs import VerbContext

# ─── the names this spec mints on the production side ───────────────────────────────────
L0 = "l-000"
L3 = "l-00c"
RESERVED_LEAD_IDS = (L0, L3)
CORRELATION_REQUEST_LIMIT = 8

#: Item 3's grant, at module scope so it is the SINGLE authored home for the vendor name on the
#: correlation path. `CORRELATION_SYSTEM` derives from it rather than being spelled again in
#: `GatherRequest` and the `:L findings` row, so the dispatched system cannot drift away from
#: the grant that actually confines the lead: the grant is the authority (it is what `decide`
#: consults), and `system` is only ever a rendering/routing key.
CORRELATION_GRANT = VerbGrant(
    role="lead-zero-correlation",
    entries=(("elastic", "alerts", "r"), ("elastic", "health-check", "r")),
)

#: The catalog template item 3's contract names outright. The grant admits exactly one query
#: verb (`alerts`), and every other elastic template binds `esql` or `query` — so without this
#: template grant ∩ catalog is empty and the dispatch renders `_INDEX_NONE_GRANTED`, leaving a
#: lead to spend its whole budget discovering why nothing is runnable.
CORRELATION_TEMPLATE = "elastic.correlate-alerts-by-entity"


def _sole_system(grant: VerbGrant) -> str:
    """The one system a single-system grant reaches. Raises rather than picking, because a
    two-system correlation grant is an authoring change whose dispatched-system choice must be
    made deliberately (it selects the template index's on-target tier and the prompt-cache
    lane), not silently resolved by `sorted(...)[0]` at run time."""
    systems = sorted(grant.systems)
    if len(systems) != 1:
        raise GrantError(
            f"the correlation grant for role {grant.role!r} reaches {len(systems)} systems "
            f"({systems}) — `system` is derived from it and only a single-system grant "
            "determines one. Name the dispatched system explicitly if this is intended."
        )
    return systems[0]


CORRELATION_SYSTEM = _sole_system(CORRELATION_GRANT)

#: Item 1's OWN system, and deliberately not `CORRELATION_SYSTEM`. Every backend call item 1
#: issues names this string directly — `_capture_issue`'s `args`, `_record_manual_row`'s row +
#: `query_id` + `raw_command`, `_breaker_failures`' per-system state read, `_CallLedger.call`'s
#: registry lookup — so its `:L findings` row must be labelled from the SAME anchor. Labelling
#: it from the correlation grant's derived system looks like a dedup while the two are the same
#: string, and mislabels item 1's row the moment `CORRELATION_GRANT` names a different vendor.
ITEM1_SYSTEM = "elastic"

PROVENANCE_KEY = "provenance"
HARNESS_PROVENANCE = "harness"

LEAD_ZERO_HEADING = "## Alert ancestors"

STATUS_FAILED = "failed"
STATUS_EMPTY = "succeeded-empty"
STATUS_TRUNCATED = "succeeded-truncated"
#: Every requested ancestor document resolved. Derived from `saw_success` / `docs` /
#: `requested`; `prepare_correlation_lead`'s gate reads it as "item 1 resolved documents".
STATUS_RESOLVED = "succeeded-resolved"

UNAVAILABLE = "_(unavailable:"
SHORTFALL = "_(incomplete:"
ELIDED = "_(elided:"

#: The per-document `message` rendering budget. Any value that keeps the block materially
#: smaller than a large payload will do; the exact number is not load-bearing.
MESSAGE_CHAR_BUDGET = 4000

ALERT_ID_FIELD = "kibana.alert.uuid"
GROUP_ID_FIELD = "kibana.alert.group.id"
BUILDING_BLOCK_FIELD = "kibana.alert.building_block_type"

ITEM1_GOAL = (
    "Resolve this alert's ancestor documents (the constituent events of its EQL sequence, "
    "or the ancestor_events batch) so MAIN has their timestamp/message/structured fields at "
    "ORIENT without spending a lead or a gather round on it."
)
ITEM1_WHAT_TO_SUMMARIZE = [
    "each resolved ancestor document's timestamp, message and structured fields",
]

_ANY_RUN_TAG = re.compile(r"</?run-[0-9a-zA-Z]*-[a-z-]+>")
#: A markdown code-fence run. Neutralized because item 1's rendered block is interpolated into
#: item 3's goal, which `tools_gather._gather_prompt` emits INSIDE a fenced block: a fence run
#: in an attacker-authored `message` (a captured command line, a shell transcript) closes that
#: fence early, so the harness's own `what_to_summarize` block renders as free prose the lead
#: reads as document content.
_FENCE_RUN = re.compile(r"`{3,}")


# ─── the return contract (F1) ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LeadZeroResult:
    """Item 1's result: `text` is its rendered block — already sanitized, elided and wrapped —
    and it is also what item 3's contract carries, so the correlation lead reads the same bytes
    MAIN reads at ORIENT and picks its own correlation axes off them.

    Deliberately NO extracted-entity field. A fixed `host.name`/`user.name`/`source.ip` triple
    fits exactly one class of alert source (host-level auth logs) and produces noise on any
    source that carries its entities elsewhere: a container-runtime source names every alert
    with the shared host the runtime runs on, nests the real actor under a vendor-specific
    namespace, and has no source address at all. Which entities matter is a property of the
    alert, not of a schema — and choosing what to filter on is what every other gather lead
    already does."""

    text: str
    status: str


# ─── small sync/async bridge ─────────────────────────────────────────────────────────────

def _run_sync(coro: Any) -> Any:
    """Run an async coroutine from a SYNCHRONOUS caller, whether or not an event loop is
    already running on this thread. `resolve_lead_zero` is a synchronous entry point called
    both from bare pytest functions (no loop) and from inside `run_investigation` (already
    inside one) — the latter cannot call `asyncio.run()` directly, so the coroutine goes to a
    fresh thread with its own loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


# ─── sanitizing wrap-delimiter shapes (K1 round 2 + F4) ─────────────────────────────────

def _sanitize(text: Any) -> str:
    """Neutralize any `<run-…-…>`-shaped delimiter, and any markdown code-fence run, in
    externally-sourced content before it is INTERPOLATED into text that crosses an agent
    boundary unframed.

    The fence half is unconditional: a ``` run ends the fenced block whichever consumer put the
    text inside one.

    The DELIMITER half is NOT about the untrusted frame — `wrap_fresh` mints this section's
    delimiter after the body is assembled and re-mints on collision, so no content can close
    the frame that wraps it. It is about item 3's contract: the correlation lead's GOAL is free
    prose built from those same attacker-derived values and handed to the gather subagent as a
    dispatch argument, inside no frame at all, so no re-mint covers it.

    DEFANGED, NEVER DELETED: the evidence has to survive in a form the reader can still see, or
    the sanitizer passes by destroying what it was protecting."""
    if not isinstance(text, str):
        text = str(text)
    text = _ANY_RUN_TAG.sub(lambda m: m.group(0).replace("<", "‹").replace(">", "›"), text)
    return _FENCE_RUN.sub(lambda m: "ˋ" * len(m.group(0)), text)


# ─── deps for routing through the real QueryCapture (K7/d10) ────────────────────────────

@dataclass(frozen=True)
class _CaptureDeps:
    run_dir: Path
    defender_dir: Path
    run_id: str
    lead_id: str
    box: Any = None
    budget_started_monotonic: float = 0.0


def _rows_for(run_dir: Path, lead_id: str) -> list[dict]:
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead_id]


def _last_row_seq(run_dir: Path, lead_id: str) -> int:
    """The queries-table `seq` the LAST call under `lead_id` wrote — the payload sidecar a
    document resolved by that call is elided against.

    Item 1 issues several calls and one batched call returns many documents, so a document's
    POSITION in the rendered block is not its payload's seq: printing the position points four
    documents off one fetch at `gather_raw/l-000/{0..3}.json`, files no writer produced. `-1`
    when no row exists (a screened call, or a table write that could not land)."""
    rows = _rows_for(run_dir, lead_id)
    seq = rows[-1].get("seq") if rows else None
    return seq if isinstance(seq, int) else -1


async def _capture_issue(
    capture: Any, deps: _CaptureDeps, verb: str, params: dict, env: dict,
) -> tuple[dict | None, str]:
    """Issue ONE call through the REAL `QueryCapture.wrap_tool_execute` — the model's own
    routing, so all eight screens (grant, breaker, repeat-guard, traversal, param validation,
    self-ticket, confine_index, guard_outbound) run as they do for a model-dispatched query.

    Returns `(envelope_or_None, raw_result_text)`. `None` covers both "screened" (breaker trip,
    repeat trip, grant denial — no row written at all) and "attempted but failed" (a row IS
    written, with a nonzero exit code)."""
    before = len(_rows_for(deps.run_dir, deps.lead_id))
    call = SimpleNamespace(tool_name="query")
    args = {"system": ITEM1_SYSTEM, "verb": verb, "params": params}
    # Stash the in-memory result as `handler` produces it, so a later write failure (below) can
    # recover it WITHOUT re-issuing the same backend call. `wrap_tool_execute` runs `handler`
    # at most once per call.
    captured: list[Any] = []

    async def handler(_args: dict) -> Any:
        fn = capture._registry.verbs(ITEM1_SYSTEM)[verb]
        vctx = VerbContext(defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=env)
        result = await asyncio.to_thread(fn, vctx, **params)
        captured.append(result)
        return result

    ctx = SimpleNamespace(deps=deps)
    try:
        text = await capture.wrap_tool_execute(ctx, call=call, args=args, handler=handler)
    except (OSError, ValueError):
        # RENDER FROM THE IN-MEMORY RESULT: a queries-table write that cannot land (a directory
        # squatting the table's own name) must cost the run its evidence ROW, never its
        # evidence, and never a second real backend call for the same logical fetch —
        # `captured` holds whatever `handler` returned before `_record`'s write raised.
        envelope = captured[0] if captured else None
        return (envelope if isinstance(envelope, dict) else None), ""
    after = _rows_for(deps.run_dir, deps.lead_id)
    if len(after) <= before:
        return None, text
    row = after[-1]
    if row.get("exit_code") != 0:
        return None, text
    payload_path = row.get("payload_path")
    if not isinstance(payload_path, str):
        # A successful call (exit_code == 0) whose sidecar payload failed to PERSIST leaves
        # `payload_path` None; fall back to the in-memory result this call already produced
        # rather than crashing on `Path(...) / None`.
        envelope = captured[0] if captured else None
        return (envelope if isinstance(envelope, dict) else None), text
    try:
        data = json.loads((deps.run_dir / payload_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, text
    if not isinstance(data, dict):
        return None, text
    return data, text


#: The capped path's default exit code for an UNMAPPED fault. Mirrors
#: `query_tool.DEFAULT_FAULT_EXIT` rather than importing it: that constant is an internal
#: detail of the model-facing capture, not a shared contract.
_UNMAPPED_FAULT_EXIT = 2


def _record_manual_row(
    deps: _CaptureDeps, verb: str, params: dict, payload: Any, *, exit_code: int,
) -> None:
    """Write a queries-table row with the SAME thirteen-key shape `QueryCapture._record` writes
    — including `error_class`/`payload_status` DERIVED the same way
    (`circuit_breaker.error_class_for_exit`, `query_tool._payload_status`'s rule) rather than
    hardcoded, since a hardcoded `error_class="infra"` mis-files an agent-fixable capped-path
    fault out of `collect_general_failures`' pitfalls curation.

    Deliberately WITHOUT feeding `circuit_breaker.record_outcome`: that is what lets item 1's
    calls past its first recorded failure keep running without pushing the breaker's per-system
    counter over the trip boundary on lead-0's behalf. The cap bounds RECORDED failures, not
    calls."""
    import shlex

    from defender._io import guarded_mkdir, write_guarded
    from defender.runtime.circuit_breaker import error_class_for_exit
    from defender.scripts.gather_tools.record_query import (
        _json_safe_params,
        _next_seq,
        payload_digest,
        payload_sha256,
    )

    seq = _next_seq(deps.run_dir, deps.lead_id)
    lead_dir = RunPaths(deps.run_dir).gather_raw / deps.lead_id
    payload_name = f"gather_raw/{deps.lead_id}/{seq}.json"
    payload_rel: str | None = payload_name
    text = json.dumps(payload, default=str) if exit_code == 0 else ""
    try:
        guarded_mkdir(lead_dir, base=deps.run_dir)
        write_guarded(deps.run_dir / payload_name, text)
    except (OSError, ValueError):
        payload_rel = None
    if exit_code != 0:
        payload_status = "error"
    elif payload is None or (isinstance(payload, (dict, list, tuple, set, str)) and len(payload) == 0):
        payload_status = "empty"
    else:
        payload_status = "ok"
    row = {
        "lead_id": deps.lead_id, "seq": seq, "system": ITEM1_SYSTEM, "verb": verb,
        "query_id": f"{ITEM1_SYSTEM}.{verb}", "params": _json_safe_params(dict(params)),
        "raw_command": shlex.join(
            [ITEM1_SYSTEM, verb, *(f"{k}={v}" for k, v in params.items())]
        ),
        "payload_path": payload_rel, "exit_code": exit_code,
        "error_class": error_class_for_exit(exit_code),
        "payload_status": payload_status,
        "payload_digest": (
            payload_digest(text, "", 0) if exit_code == 0 else f"exit={exit_code}; capped"
        ),
        # Over the SAME text the sidecar above holds — the content identity `repeat_note` keys
        # byte-identity on. Derived rather than defaulted, so this second writer's rows can
        # never read as "no payload evidence" beside `_record`'s.
        "payload_sha256": payload_sha256(text),
    }
    write_guarded(RunPaths(deps.run_dir).executed_queries, json.dumps(row) + "\n", mode="append")


def _breaker_failures(run_dir: Path) -> int:
    path = Path(run_dir) / "circuit_breaker.json"
    if not path.is_file():
        return 0
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    # `3`, `"x"` and `[…]` are all valid JSON and none is a breaker state (the "parsed fine,
    # wrong shape" case `circuit_breaker._load` guards too). Without these isinstance checks a
    # corrupted or planted `circuit_breaker.json` raises `AttributeError`/`ValueError` here,
    # uncaught, degrading item 1's WHOLE resolution instead of just this one state read.
    if not isinstance(state, dict):
        return 0
    systems = state.get("systems")
    if not isinstance(systems, dict):
        return 0
    sysrec = systems.get(ITEM1_SYSTEM)
    if not isinstance(sysrec, dict):
        return 0
    try:
        return int(sysrec.get("failures", 0) or 0)
    except (TypeError, ValueError):
        return 0


class _CallLedger:
    """Tracks item 1's OWN contribution to the elastic per-system breaker across a resolution,
    so a second (and later) infra failure can still be ISSUED without being RECORDED past the
    cap."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.capped = False

    async def call(self, capture, deps, verb, params, env):
        from defender.scripts.adapters.faults import AdapterFault

        before = _breaker_failures(self.run_dir)
        if self.capped:
            # Past the cap: issue the call directly (bypassing QueryCapture's own automatic
            # `record_outcome`), still writing a queries-table row of the same shape.
            try:
                fn = capture._registry.verbs(ITEM1_SYSTEM)[verb]
                vctx = VerbContext(defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=env)
                envelope = await asyncio.to_thread(fn, vctx, **params)
                _record_manual_row(deps, verb, params, envelope, exit_code=0)
                return envelope, ""
            except (circuit_breaker.RunAborted, asyncio.CancelledError,
                    KeyboardInterrupt, GeneratorExit):
                # Cancellation/control-flow signals must propagate, not be absorbed as "a
                # capped call's own fault": swallowing `CancelledError` breaks task
                # cancellation, and `KeyboardInterrupt`/`GeneratorExit` are never a query's
                # fault to begin with.
                raise
            except AdapterFault as e:
                # A MAPPED fault keeps its own exit code/class (matching
                # `QueryCapture._record`'s `except AdapterFault` arm) instead of being filed
                # as `error_class="infra"`.
                _record_manual_row(deps, verb, params, None, exit_code=e.exit_code)
                return None, ""
            except BaseException:  # noqa: BLE001 — an unmapped capped-call fault must not raise
                _record_manual_row(deps, verb, params, None, exit_code=_UNMAPPED_FAULT_EXIT)
                return None, ""
        envelope, text = await _capture_issue(capture, deps, verb, params, env)
        after = _breaker_failures(self.run_dir)
        if after > before:
            self.capped = True
        return envelope, text


def _build_deps(run_dir: Path, defender_dir: Path, run_id: str, lead_id: str) -> _CaptureDeps:
    return _CaptureDeps(
        run_dir=run_dir, defender_dir=defender_dir, run_id=run_id, lead_id=lead_id,
    )


# ─── budget chaining (K23) ────────────────────────────────────────────────────────────

def _budget_gate(run_dir: Path, limits: dict) -> None:
    """Unconditional, not gated on `DEFENDER_BUDGET_ENFORCE`: lead-0 is harness pre-turn work,
    and its wall-clock discipline is not a product toggle the way the model's tool refusals
    are."""
    state = read_budget(run_dir)
    if tail_exhausted(state, limits):
        raise BudgetKill("lead-0's own call refused: the run's budget tail is exhausted")


def _budget_account(run_dir: Path, run_id: str, tool_name: str, limits: dict) -> None:
    import contextlib

    with contextlib.suppress(Exception):  # accounting must never break the run
        update_budget_locked(run_dir, run_id, tool_name, limits=limits)


# ─── item 1 rendering ─────────────────────────────────────────────────────────────────

def _elide(value: Any, lead_id: str, seq: int) -> str:
    """Bound ONE rendered leaf, with a pointer to the payload that holds it whole.

    `seq` is the QUERIES-TABLE seq of the call that returned the document (`_last_row_seq`),
    never the document's position in the block — those are different numbers. A negative `seq`
    means the call wrote no row at all (screened, or the table write failed), and the note then
    says so rather than naming a payload that was never persisted."""
    if not isinstance(value, str) or len(value) <= MESSAGE_CHAR_BUDGET:
        return value if isinstance(value, str) else str(value)
    where = (
        f", full text at gather_raw/{lead_id}/{seq}.json"
        if seq >= 0 else ", and the call that returned it persisted no payload"
    )
    return f"{value[:MESSAGE_CHAR_BUDGET]}\n{ELIDED} {len(value)} chars{where})"


def _flatten_doc(doc: dict) -> dict[str, Any]:
    """A document's leaves, keyed by their DOTTED ECS path.

    The adapter hands `_source` back UNMODIFIED, and real ECS `_source` is NESTED
    (`{"host": {"name": …}}`, with per-source namespaces two or three levels deeper) while the
    alerting namespace arrives as flat dotted keys. Rendering the top level alone prints a
    nested document as one line per top-level object holding a PYTHON DICT REPR — `host:
    {'name': 'ws-1'}` — which is not a field name anything can be queried on. This block is
    the correlation lead's whole entity evidence and it is asked to name the field each entity
    came from, so a repr is not good enough."""
    out: dict[str, Any] = {}

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict) and node:
            for k, v in node.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                walk(v, key)
        elif isinstance(node, list) and any(isinstance(x, dict) for x in node):
            # An ARRAY OF OBJECTS is the same defect one level down, and not exotic: every
            # Kibana alert document carries `kibana.alert.ancestors`, and on the group-id path
            # the documents this block renders ARE alert documents. Indexed (`…ancestors.0.id`)
            # so two elements' same-named leaves stay distinguishable; an array of SCALARS
            # stays whole, since `['a', 'b']` already reads as the multi-valued field it is.
            for i, item in enumerate(node):
                walk(item, f"{prefix}.{i}" if prefix else str(i))
        elif prefix:
            out[prefix] = node

    walk(doc, "")
    return out


def _render_doc(doc: dict, lead_id: str, seq: int) -> str:
    flat = _flatten_doc(doc)
    lines = []
    ts = flat.get("@timestamp")
    if ts:
        lines.append(f"- @timestamp: {_sanitize(ts)}")
    for key in sorted(flat):
        if key in ("@timestamp", "message"):
            continue
        # A null leaf is DROPPED, not rendered: `_sanitize(None)` is the literal string
        # `"None"`, and this block is what the correlation lead picks its axes off —
        # `host.name: None` reads as a bindable value and invites `host.name:"None"`, a
        # predicate that matches nothing and reports as a real zero. An absent field and a null
        # one are the same thing to the index anyway.
        if flat[key] is None:
            continue
        # The field NAME as well as its value: an attacker-influenced document whose KEY
        # carries a `<run-…-…>`-shaped delimiter would otherwise end the untrusted frame early.
        #
        # EVERY leaf is elided, not just `message`: flattening makes every leaf of every
        # namespace its own line, and a captured command line or a rule's stored query is
        # exactly as unbounded as a message.
        lines.append(f"  {_sanitize(key)}: {_sanitize(_elide(flat[key], lead_id, seq))}")
    if flat.get("message") is not None:
        lines.append(f"  message: {_sanitize(_elide(flat['message'], lead_id, seq))}")
    return "\n".join(lines)


def _sort_chrono(docs: list[tuple[dict, int]]) -> list[tuple[dict, int]]:
    """Chronological by each document's own `@timestamp`. Each entry is `(doc, seq)` — the
    queries-table seq of the call that returned it, which the elision pointer names."""
    def key(entry: tuple[dict, int]) -> str:
        return str(entry[0].get("@timestamp") or "")
    return sorted(docs, key=key)


def _unavailable(reason: str) -> str:
    """The reason is SANITIZED: `_unavailable(f"{e!r}")` interpolates the repr of an exception
    whose message can carry attacker-influenced text, and the note lands INSIDE the untrusted
    frame with everything else."""
    return f"{UNAVAILABLE} {_sanitize(reason)})"


# ─── item 1: ancestor resolution ─────────────────────────────────────────────────────

_DS_RE = re.compile(r"^\.ds-(?P<name>.+)-[^-]+-\d{4}\.\d{2}\.\d{2}-\d+$")


def _map_backing_index(index: str) -> str:
    """An open, bounded rewrite from a concrete `.ds-<name>-<namespace>-<date>-<generation>`
    backing index to the datastream pattern it belongs to, never a hardcoded substring table.
    A no-match passes the string through UNCHANGED so `confine_index`'s gate refuses it."""
    if not isinstance(index, str):
        return index
    m = _DS_RE.match(index)
    if not m:
        return index
    return f"{m.group('name')}-*"


async def _fetch_batched(ancestors: list[dict], issue) -> tuple[list[tuple[dict, int]], int, bool]:
    """Batch ancestor ids by MAPPED backing index — one call per distinct index, never one per
    ancestor. Returns `(docs, requested_count, truncated_any)` where each doc is paired with
    the queries-table `seq` of the call that returned it (the elision pointer's target).
    `issue` is the caller's budget-gated, success-tracking call wrapper: it returns
    `(envelope, seq)` and is told whether this call could produce an ancestor at all."""
    by_index: dict[str, list[str]] = {}
    for a in ancestors:
        aid = a.get("id")
        idx = a.get("index")
        if not isinstance(aid, str) or not aid.strip():
            continue
        if not isinstance(idx, str) or not idx.strip():
            continue
        mapped = _map_backing_index(idx)
        by_index.setdefault(mapped, []).append(aid)

    if not by_index:
        return [], 0, False

    docs: list[tuple[dict, int]] = []
    truncated_any = False
    for mapped_index, ids in sorted(by_index.items()):
        predicate = " OR ".join(f'"{i}"' for i in ids)
        params = {"native_query": f"_id: ({predicate})", "limit": 20,
                  "index": mapped_index, "sort": "desc"}
        envelope, seq = await issue("query", params, ancestor=True)
        if envelope is None:
            continue
        docs.extend((h, seq) for h in (envelope.get("hits") or []))
        truncated_any = truncated_any or bool(envelope.get("truncated"))
    return docs, sum(len(v) for v in by_index.values()), truncated_any


async def _resolve_item1(  # noqa: C901, PLR0912, PLR0915 — item 1's own branch/call census: the shell fetch, the group/fallback branch, the empty/no-group fallback, per-call budget gating — see the module docstring
    *, run_dir: Path, defender_dir: Path, run_id: str, alert: dict,
    capture: Any, env: dict, limits: dict,
) -> tuple[str, str]:
    from defender.scripts.adapters.elastic_adapter import load_config

    deps = _build_deps(run_dir, defender_dir, run_id, L0)
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L0, "goal": ITEM1_GOAL,
        "what_to_summarize": ITEM1_WHAT_TO_SUMMARIZE, "provenance": HARNESS_PROVENANCE,
    })
    if claimed != CLAIMED:
        # Someone else already owns L0 (a planted collision): degrade rather than issue backend
        # calls or append a second, inconsistent `:L findings` row under an id this call does
        # not own. Mirrors `prepare_correlation_lead`'s L3 collision arm.
        #
        # `!= CLAIMED` and not `== ALREADY_CLAIMED`: a claim that could not be WRITTEN leaves
        # this frame owning exactly as little as a collision does, and the harness has no more
        # right than the model to run a lead with no leads row.
        return (_unavailable(
            f"{L0} is already claimed by something else on this run dir"
            if claimed == ALREADY_CLAIMED else f"{L0}'s leads row could not be claimed"
        ), STATUS_FAILED)
    _declare_l_finding(run_dir, L0, "ancestor resolution", ITEM1_SYSTEM)

    alert_id = alert.get("alert_id")
    signal_index = alert.get("signal_index")
    if not isinstance(signal_index, str) or not signal_index.strip():
        try:
            cfg = load_config(VerbContext(defender_dir=defender_dir, run_dir=run_dir, env=env))
            signal_index = cfg["ELASTIC_ALERTS_INDEX"]
        except Exception:  # noqa: BLE001 — degrade the whole item, never the run
            return (_unavailable("could not resolve this alert's signal_index"),
                    STATUS_FAILED)

    ancestor_events = alert.get("ancestor_events") or []
    if not isinstance(ancestor_events, list):
        ancestor_events = []

    ledger = _CallLedger(run_dir)
    issued_any = False
    answered_any = False
    # COUNTS, not booleans: one batched call per distinct backing index means "an ancestor call
    # answered" and "the ancestor calls answered" are different facts, and the rendering arms
    # below need both.
    ancestor_issued = 0
    ancestor_answered = 0

    async def _issue(verb: str, params: dict, *, ancestor: bool) -> tuple[dict | None, int]:
        """`ancestor=False` marks a call that CANNOT produce an ancestor document — item 1's
        opening by-`alert_id` fetch of the alert's own shell.

        The discriminator matters because the shell fetch answers on every alert with a
        resolvable `alert_id`: a single success flag set from every call is therefore always
        true, `STATUS_FAILED` becomes unreachable however the ancestor calls ended, and an
        outage on them renders as `_(unavailable: … found nothing)` — an absence of ancestors,
        which is triage evidence, asserted over a backend that never answered.

        `ancestor` has NO DEFAULT deliberately: a call site added later that forgets it must
        not silently read as an ancestor call.

        `answered_any` is tracked beside it because "no ancestor call was made" is not by
        itself a resolved absence: when the shell fetch is the ONLY call and it failed, the
        group-id branch was never reachable, so nothing was established."""
        nonlocal issued_any, answered_any, ancestor_issued, ancestor_answered
        issued_any = True
        if ancestor:
            ancestor_issued += 1
        _budget_gate(run_dir, limits)
        envelope, _text = await ledger.call(capture, deps, verb, params, env)
        _budget_account(run_dir, run_id, "query", limits)
        if envelope is not None:
            answered_any = True
            if ancestor:
                ancestor_answered += 1
        # The seq is read AFTER the call, off the row it just wrote: a document's elision
        # pointer must name the payload of the fetch that returned it, not its own position.
        return envelope, _last_row_seq(run_dir, L0)

    shell: dict | None = None
    if isinstance(alert_id, str) and alert_id.strip():
        shell_envelope, _ = await _issue("alerts", {
            "native_query": f'{ALERT_ID_FIELD}:"{alert_id}"', "limit": 1,
            "index": signal_index, "sort": "desc",
        }, ancestor=False)
        if isinstance(shell_envelope, dict):
            hits = shell_envelope.get("hits") or []
            shell = hits[0] if hits else None

    group_id = shell.get(GROUP_ID_FIELD) if isinstance(shell, dict) else None
    docs: list[tuple[dict, int]] = []
    requested = len(ancestor_events)
    truncated = False

    if isinstance(group_id, str) and group_id.strip():
        envelope, group_seq = await _issue("alerts", {
            "native_query": f'{GROUP_ID_FIELD}:"{group_id}"', "limit": 20,
            "index": signal_index, "sort": "desc",
        }, ancestor=True)
        hits = [h for h in ((envelope or {}).get("hits") or []) if h.get(BUILDING_BLOCK_FIELD)]
        if hits:
            docs = [(h, group_seq) for h in hits]
            requested = max(requested, len(hits))
            truncated = bool((envelope or {}).get("truncated"))
        else:
            # No group, or a group resolving to zero building blocks: fall back.
            docs, requested2, truncated = await _fetch_batched(ancestor_events, _issue)
            requested = max(requested, requested2)
    else:
        docs, requested2, truncated = await _fetch_batched(ancestor_events, _issue)
        requested = max(requested, requested2)

    if not issued_any:
        return (_unavailable("no usable ancestor identifier or alert id survived — no "
                              "fetch was issued"), STATUS_EMPTY)

    docs = _sort_chrono(docs)

    # One call per DISTINCT MAPPED BACKING INDEX means a resolution can have both an ancestor
    # call that answered and one that faulted. Gating the absence sentence below on "at least
    # one answered" makes an alert whose ancestors span two indices — the first matching
    # nothing, the second faulting — render "the resolution reached the backend and found
    # nothing": a resolved absence claimed over an index that never answered.
    ancestor_failed = ancestor_issued - ancestor_answered

    body_lines = []
    if docs:
        for doc, seq in docs:
            body_lines.append(_render_doc(doc, L0, seq))
    elif ancestor_issued and not ancestor_answered:
        # Not "every backend call this resolution attempted failed": the shell fetch answered,
        # and only the calls that could have produced an ancestor did not.
        body_lines.append(_unavailable(
            "every backend call that could have resolved an ancestor failed"))
    elif not answered_any:
        # No ancestor call was ISSUED and the only call this resolution made — the shell fetch
        # whose group id decides whether an ancestor branch exists at all — failed. Nothing
        # answered, so the group branch was never reachable and no absence was established;
        # without this arm the run renders `_(unavailable: … found nothing)`, a false claim
        # over a silent backend.
        body_lines.append(_unavailable("every backend call this resolution attempted failed"))
    elif ancestor_failed:
        # SOME answered and some did not, and nothing came back from the ones that did: the
        # absence holds only over the indices actually reached, never over the alert.
        body_lines.append(_unavailable(
            f"{ancestor_failed} of {ancestor_issued} ancestor fetches failed; the rest "
            "reached the backend and found nothing"))
    else:
        # Every ancestor call this resolution issued answered, and none matched — or the alert
        # declared no usable ancestor and its shell answered with no group id, so there was no
        # ancestor call to make. Both are a resolved absence, which is what this sentence says.
        body_lines.append(_unavailable("the resolution reached the backend and found nothing"))

    if docs and ancestor_failed:
        # The docs-present half of the same distinction. The count note below reads as "the
        # backend did not have them"; this one says the other thing that can be true at the
        # same time, and the two compose.
        body_lines.append(
            f"{SHORTFALL} {ancestor_failed} of {ancestor_issued} ancestor fetches failed — "
            "the documents above are what the rest returned)"
        )

    if requested and (len(docs) < requested or truncated):
        body_lines.append(
            f"{SHORTFALL} resolved {len(docs)} of {requested} requested ancestor "
            "document(s))"
        )

    text = "\n\n".join(body_lines)

    # FAILED when no call that could have contributed answered. `ancestor_issued` guards the
    # ancestor half so an alert with nothing to ask for stays EMPTY: a resolution that issued
    # no ancestor call has no failed call to report. The `answered_any` half keeps a resolution
    # whose SHELL FETCH was its only call, and failed, out of EMPTY — it asked nothing further
    # because the answer that would have told it what to ask never came.
    #
    # A PARTIAL ancestor failure stays EMPTY/TRUNCATED rather than earning a fifth status: the
    # over-claim it could produce is in what MAIN is TOLD, which the arms above now say, while
    # the status has exactly two consumers — the dispatch gate, which refuses FAILED and EMPTY
    # alike, and `_user_prompt`, which forwards it. Moving a partial failure to FAILED would
    # discard the documents the calls that DID answer returned.
    if not ancestor_answered and (ancestor_issued or not answered_any):
        status = STATUS_FAILED
    elif not docs:
        status = STATUS_EMPTY
    elif requested and (len(docs) < requested or truncated):
        status = STATUS_TRUNCATED
    else:
        status = STATUS_RESOLVED

    return text, status


# ─── item 3: the correlation lead's harness-authored contract ───────────────────────────

def _correlation_contract(alert: dict, ancestor_block: str) -> tuple[str, list[str]] | None:
    """The contract carries item 1's RESOLVED DOCUMENTS and the lead chooses the correlation
    axes off them.

    What gates the dispatch is item 1 resolving documents, which `prepare_correlation_lead`'s
    status check already decides — there is no entity-emptiness arm here. `GatherRequest`
    carries `goal` and `what_to_summarize` and nothing else, so handing over a harness-extracted
    entity triple instead would ask the lead to correlate on entities it had never seen."""
    ts = alert.get("alert_timestamp")
    if not isinstance(ts, str) or not ts.strip():
        return None
    try:
        from datetime import datetime
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None

    goal = (
        "Correlate ANY signature of alert already on the SOC's radar for THIS alert's key "
        f"entities over a bounded window around {_sanitize(ts)}.\n\n"
        "The alert's resolved ancestor documents follow. Read them first and judge which "
        "entities actually discriminate this alert — the ones that would pick it out of the "
        "environment's traffic rather than match everything in it. A container id, a process "
        "name, a destination host named inside a command line, a file path, a user, a source "
        "IP are all candidates; which of them matter is a property of THIS alert, not a fixed "
        "list. Prefer an entity that is specific to the activity over one every document in "
        "the environment carries: a host name that names the shared VPS every containerized "
        "alert reports from selects the whole environment and measures nothing.\n\n"
        f"{ancestor_block}\n\n"
        "Search the alerts index ONLY (this is a correlation over prior alerts, not raw "
        "telemetry). Do not narrow to this alert's own rule. The documents above may NAME that "
        "rule — on a sequence alert they are themselves alert documents, carrying "
        "`kibana.alert.rule.*` — and it is still not an axis to bind: a different rule firing "
        "on the same entity is exactly the related behaviour this lead exists to surface, and "
        "narrowing to the signature that already fired is the one result guaranteed to teach "
        "nothing. Bind "
        f"`{CORRELATION_TEMPLATE}` — read it first: it is named by your grant-filtered template "
        "index, and it carries the window params and the substitutable entity filter this "
        "contract needs. Each count is the result envelope's `total`, which the `hits` cap does "
        "not bound — a `truncated` result still carries a complete count."
    )
    # Two COUNT dimensions, each answerable by ONE `alerts` call, plus a third line that is not
    # a count. A fourth — "whether any correlated alert is already benign-explained" — is
    # deliberately absent: `kibana.alert.workflow_status` is `"open"` on every alert this
    # environment produces, and the systems that could carry a benign explanation (`ticket`,
    # `change-mgmt`) are outside this lead's grant, so it has exactly one possible answer.
    #
    # "across any rule", not "same-signature": the goal says do NOT narrow to this alert's own
    # rule, and a per-rule breakdown over the 8 installed rules is 8-16 `alerts` calls against a
    # request limit of 8 — the one verb that could group-by in a single call (`esql`) is exactly
    # what this lead's grant withholds for index confinement.
    #
    # Each dimension names its ENTITY SCOPE, and as SCOPED/UNSCOPED rather than
    # "on-host"/"fleet-wide". Read literally, "alerts fleet-wide" counts every alert the
    # environment emitted — a number about the SOC, not this alert — and the host-centric
    # spelling collapses on any source whose alerts all report the same shared host: the
    # on-host count degenerates to "every alert this source emitted" and the fleet-wide one has
    # nothing left to bind. Scoped/unscoped asks for the same two measurements without naming
    # which field carries them.
    #
    # The third line exists because the lead CHOOSES what the first two are counted over: a
    # number whose predicate MAIN cannot see is not a measurement MAIN can weigh, and the prose
    # summary is the only thing that reaches it.
    what = [
        "the count of alerts in the window scoped to the entities you judged central — one "
        "call, across any rule (the envelope's `total`)",
        "the count for those same entities UNSCOPED — the same window with the narrowing "
        "predicate dropped, across any rule (the envelope's `total`)",
        "which entities you correlated on, the field each came from, and why you judged them "
        "the discriminating ones for this alert",
    ]
    return goal, what


async def dispatch_correlation(  # noqa: C901, PLR0913 — item 3's own dispatch: the narrowed registry, the session/terminator wiring, the pre-claimed seam call — one composition frame
    *, run_dir: Path, defender_dir: Path, run_id: str,
    goal: str, what_to_summarize: list[str], verbs: Any, limits: dict,
    make_model: Any, logger: Any, box: Any, store: Any = None,
    budget_started_monotonic: float = 0.0,
) -> str | None:
    """The ASYNC half of item 3: dispatch the real gather subagent for `l-00c`, reusing the
    shared terminator/bookkeeping seam (`tools_gather._run_gather`) with `pre_claimed=True` —
    `prepare_correlation_lead` already claimed the leads row synchronously, before MAIN's first
    turn."""
    from .agent_definition import bind
    from .agent_role import GATHER_AGENT_ID_PREFIX
    from .driver import GATHER_DEF, build_gather_agent
    from .tools import GatherDeps
    from .tools_gather import GatherRequest, _run_gather

    # A thin re-grant wrapper: same verb resolution, a narrower grant object — so `esql` (never
    # `confine_index`'d) is denied at the grant check rather than reaching a transport.
    from .verbs import VerbRegistry

    class _Narrowed(VerbRegistry):
        def __init__(self, inner):
            super().__init__(CORRELATION_GRANT)
            self._inner = inner

        def systems(self):
            return self._inner.systems()

        def verbs(self, system):
            return self._inner.verbs(system)

        def _cold_verb_names(self, system):
            return self._inner._cold_verb_names(system)

    registry = _Narrowed(verbs)

    # The SAME spelling `_run_gather` derives for the agent id it hands `gather_factory` and
    # `stamp_terminator`. Spelled as a literal here, the session this frame opens and the one
    # those two callbacks key would drift apart the moment the prefix moved, with nothing to
    # catch it — the store would carry an orphan row.
    agent_id = f"{GATHER_AGENT_ID_PREFIX}{L3}"
    gather_session_id: str | None = None
    if store is not None:
        gather_session_id = store.new_session(agent_id=agent_id)

    def gather_factory(_agent_id: str, system: str, request_limit: int):
        from .driver import _gather_extra_capabilities

        extra: list = []
        if store is not None and gather_session_id is not None:
            # `request_limit` arrives from `_run_gather` — the value it is about to enforce —
            # rather than being read again from `CORRELATION_REQUEST_LIMIT` here: the recorder
            # withholds the doomed round by comparing against it, so it must not measure a
            # ceiling this dispatch did not receive.
            extra = _gather_extra_capabilities(
                store, gather_session_id, _agent_id, request_limit=request_limit,
            )
        return build_gather_agent(
            defender_dir, logger, _agent_id, make_model, registry, limits,
            extra_capabilities=extra, session_id=gather_session_id,
            # Same per-system cache-key convention as the model-dispatched path
            # (`driver.py::_build_gather`).
            #
            # KNOWN MISMATCH, not fixed here: this key is shared with MAIN's own gather leads
            # on the same system, and the prefix behind it is NOT the same text — the template
            # index is grant-filtered, so this role renders one template where role `gather`
            # renders fourteen. One lane, two prefixes. The fix is to key on role as well as
            # system; that changes `driver.py`'s convention too, so it is not made here.
            cache_key=f"{GATHER_AGENT_ID_PREFIX}{system}",
        )

    def stamp_terminator(_agent_id: str, reason: str) -> None:
        if store is None or gather_session_id is None:
            return
        try:
            store.set_truncated_by(gather_session_id, reason)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            print(f"[run.py] correlation lead truncated_by write skipped: {e!r}")

    gbase = bind(GATHER_DEF, run_dir, defender_dir=defender_dir, box=box)
    assert isinstance(gbase, GatherDeps)
    # Thread the RUN's own budget-clock origin through, the way `_run_gather`'s model-dispatched
    # path does. Otherwise `bind`'s `AgentDeps` default (`default_factory=time.monotonic`)
    # stamps a FRESH origin whenever this coroutine happens to start, and under
    # `DEFENDER_BUDGET_ENFORCE` the correlation lead's wall-clock enforcement measures elapsed
    # time from its own start rather than the run's true remaining budget.
    gdeps = replace(
        gbase, run_id=run_id, lead_id=L3, budget_started_monotonic=budget_started_monotonic,
    )

    request = GatherRequest(L3, CORRELATION_SYSTEM, goal, tuple(what_to_summarize))
    try:
        return await _run_gather(
            gdeps, gather_factory, CORRELATION_REQUEST_LIMIT, request, CORRELATION_GRANT,
            stamp_terminator, pre_claimed=True,
        )
    except (BudgetKill, circuit_breaker.RunAborted):
        raise
    except Exception as e:  # noqa: BLE001 — item 3's own dispatch must never break the run
        print(f"[run.py] correlation lead dispatch failed ({e!r}); skipping its summary",
              file=sys.stderr)
        return None


def _declare_l_finding(run_dir: Path, lead_id: str, name: str, system: str) -> None:
    """The HARNESS writes lead-0's declaring `:L findings` row into `investigation.md` before
    MAIN's first turn: with no such row, `invlang_validate` refuses any citation of the
    reserved id as an "undeclared lead".

    `system` is the CALLER's, not a module constant: this frame serves both reserved ids and
    they do not share an authority for it — item 1's is the literal its own backend calls name
    (`ITEM1_SYSTEM`), item 3's is derived from the grant that confines it
    (`CORRELATION_SYSTEM`). They are the same string today; a shared constant would silently
    mislabel one of the two rows the moment they stop being.

    THE SEED IS VALIDATED LIKE ANY OTHER APPEND (#964). This writer runs before MAIN's first
    turn and reaches `write_guarded` directly — it is not a tool call, so there is no
    `permission.decide_write` in front of it — which made it the one writer of this document
    that no schema had seen. Harmless in fact (one block, one row, so it cannot form the
    within-block duplicate the validator refuses) and load-bearing anyway: the invariant every
    other gate is designed against is "a committed investigation parses", and an ungated
    writer makes that true only of the verbs the MODEL calls. It is checked here rather than
    routed through the permission gate because that gate answers WHO MAY WRITE WHERE from a
    policy and a role, and this frame has neither — what it needs is the content schema, which
    `validate_artifact` is the neutral leaf for.

    A SEED THAT FAILS IS NOT WRITTEN, and the id stays undeclared. That is the deliberate half
    (the issue asks for a decision, not just a check). Writing it anyway would rebuild the
    bypass under a new name — the whole point is that no unvalidated bytes reach this
    document. Skipping costs a reserved id that MAIN may then cite, and the validator answers
    that citation with `undeclared lead` — a refusal MAIN reads, can act on, and can clear by
    declaring the lead itself. So the failure is loud, actionable and recoverable, where a
    laundered write is none of the three. The likely reason for a failure is a document that
    was ALREADY malformed when this frame read it, in which case the seed is the messenger and
    the refusal names the real fault.

    Best-effort is preserved in both directions: a refusal prints and returns, and never
    raises into a run that has not started."""
    from defender._artifact_schema import INVESTIGATION_NAME, validate_artifact
    from defender._io import write_guarded

    path = RunPaths(run_dir).investigation
    block = (
        f"## lead-0 ({lead_id}) — harness-authored, declared before the investigation begins\n\n"
        "```invlang\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        f"{lead_id}|0|{name}|||{system}|n/a\n"
        "```\n\n"
    )
    try:
        # `None` for an absent file, matching what `permission.decide_write` passes as the
        # append-only baseline — `""` would claim an empty document was committed.
        existing = path.read_text(encoding="utf-8") if path.is_file() else None
        proposed = block if existing is None else existing + block
        reason = validate_artifact(INVESTIGATION_NAME, proposed, existing)
        if reason is not None:
            print(
                f"[lead_zero] refused to declare {lead_id} in investigation.md — the document "
                f"would not pass validation, so nothing was written and the id stays "
                f"undeclared: {reason}"
            )
            return
        write_guarded(path, proposed)
    except (OSError, ValueError) as e:  # noqa: BLE001 — best-effort; never breaks the run
        print(f"[lead_zero] could not declare {lead_id} in investigation.md: {e!r}")


def prepare_correlation_lead(
    run_dir: Path, alert: dict, ancestor_block: str, status: str,
) -> tuple[str, list[str]] | None:
    """The SYNCHRONOUS half of item 3: gate on the resolution status (dispatches on RESOLVED
    and TRUNCATED, never on FAILED/EMPTY), build the harness-authored contract, and claim
    `l-00c`'s leads row BEFORE MAIN's first turn. Returns `(goal, what_to_summarize)` when item
    3 should actually dispatch, else `None`.

    The gate is "item 1 resolved at least one ancestor DOCUMENT" — nothing downstream turns a
    dispatch away for yielding no host/user/source-ip, which would exclude every alert source
    carrying its entities outside those three fields.

    `ancestor_block` is item 1's rendered block as `LeadZeroResult.text` carries it — already
    sanitized, elided and wrapped — so the lead reads the same bytes MAIN reads at ORIENT."""
    if status not in (STATUS_RESOLVED, STATUS_TRUNCATED):
        return None
    contract = _correlation_contract(alert, ancestor_block)
    if contract is None:
        return None
    goal, what = contract
    claimed = claim_lead({
        "run_dir": str(run_dir), "lead_id": L3, "goal": goal,
        "what_to_summarize": what, "provenance": HARNESS_PROVENANCE,
    })
    if claimed != CLAIMED:
        # Someone else already owns this id (a planted collision), or the row could not be
        # written at all — either way this frame owns nothing, so it dispatches nothing and
        # touches the id no further.
        return None
    _declare_l_finding(run_dir, L3, "correlation lead", CORRELATION_SYSTEM)
    return goal, what


# ─── the wrap + section assembly ─────────────────────────────────────────────────────

def _render_section(body: str) -> str:
    """`LeadZeroResult.text`: item 1's rendered block IN ITS ENTIRETY inside ONE
    `wrap_fresh(text, "untrusted")` frame — nothing outside it. The ORIENT heading is a
    separate, TRUSTED line `render_orient_section` prepends; it is not part of the entry
    point's own return value."""
    return wrap_fresh(body, "untrusted")


def render_orient_section(result: LeadZeroResult, run_dir: Path | None = None) -> str:
    """The ORIENT-time section text: the trusted heading (naming the reserved ids MAIN must not
    reuse) followed by item 1's whole untrusted frame, unmodified.

    `run_dir` is what lets the heading tell the truth about `L0`. The harness seeds that lead's
    declaring `:L findings` row before this renders, and that seed can decline to write — it
    validates the document first and refuses rather than laundering unvalidated bytes past the
    gate (#964). "Already claimed; do not reuse them" is then a TRAP, and a tight one: MAIN is
    told the id is claimed, cites it, and is refused with `undeclared lead` — for which the
    only repair is to write the very `:L findings` row it reads "do not reuse" as forbidding.
    So when the row is not on the page, say so and say what to do.

    DERIVED FROM THE DOCUMENT, not from a flag the seed sets. Same rule the repair window
    obeys: the answer is a property of the bytes on disk, so it cannot go stale, cannot
    disagree with the file, and is right about a row that went missing some other way. Passed
    `None`, the extra line is simply omitted — the heading is exactly what it was. Both
    production call sites pass a real dir, INCLUDING the degraded arm: a `BudgetKill` or
    `RunAborted` mid-resolution is the case in which the seed most likely never ran at all, so
    an arm that silently dropped the run dir would omit the escape line on precisely the runs
    that need it. `None` is for a caller that genuinely has no run dir — the tests that drive
    this function directly.

    `L3` gets no such line: it is dispatched AFTER this renders and conditionally, so an absent
    row there is the ordinary case and not a fault. Its citation is covered by the validator's
    own refusal, which names the harness-reserved case in its repair text."""
    heading = (
        f"{LEAD_ZERO_HEADING} (resolved by the harness before your first turn — reserved "
        f"lead ids {L0} (this resolution) and {L3} (a correlation lead dispatched off it, "
        "if any) are already claimed; do not attach new work to them"
    )
    if run_dir is not None and not _is_declared(run_dir, L0):
        heading += (
            f". NOTE: {L0}'s declaring `:L findings` row is NOT in investigation.md — the "
            f"harness could not write it. If you cite {L0}, declare it yourself in a `:L "
            f"findings` block first; that is not reuse"
        )
    return heading + ")\n\n" + result.text


def _is_declared(run_dir: Path, lead_id: str) -> bool:
    """Is `lead_id`'s declaring `:L findings` row on the page right now?

    Answered through the real parser rather than a substring search: the id appears in prose
    and in a `:R` row's first cell too, and a heading that promised a declaration on the
    strength of either would be wrong in exactly the case it exists to catch.

    DECLARED MEANS WHAT THE VALIDATOR MEANS BY IT — a `:L findings` row carrying a NAME. The
    projector opens a lead bucket for any id it meets, so a bare `:R` reference already puts
    `{"id": lead_id}` in `findings`; keying on the id alone would answer True for exactly the
    citation `_check_lead_refs` is about to refuse as `undeclared lead`, and the heading would
    then withhold the escape line on the one document that needs it. `_check_lead_refs`
    separates the two the same way (`if isinstance(f.get("id"), str) and f.get("name")`), and
    the two readings have to agree or the prompt contradicts the refusal.

    FAILS OPEN — an unreadable or unparseable document returns True, so the extra line is
    omitted. This is prompt text, not a gate: a document nothing can parse is a fault the
    write gate and the close both refuse on their own terms, and guessing "not declared" here
    would bolt a confusing instruction onto a run whose real problem is elsewhere."""
    from defender.skills.invlang.parser import parse_dense_companion

    path = RunPaths(run_dir).investigation
    if not path.is_file():
        return False
    try:
        companion, _warnings = parse_dense_companion(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — prompt prose must not decide a run's fate
        print(f"[lead_zero] could not check whether {lead_id} is declared: {e!r}")
        return True
    return any(
        f.get("id") == lead_id and f.get("name")
        for f in companion.get("findings", [])
    )


# ─── the entry point (F1) ─────────────────────────────────────────────────────────────

def resolve_lead_zero(
    *, run_dir: Path, defender_dir: Path, alert_path: Path, verbs: Any,
    limits: dict = DEFAULT_LIMITS, run_id: str | None = None,
) -> LeadZeroResult:
    run_dir = Path(run_dir)
    defender_dir = Path(defender_dir)
    resolved_run_id = run_id or run_dir.name

    if verbs is None:
        unavailable_text = _render_section(
            _unavailable("no verb registry was injected into this run"))
        return LeadZeroResult(text=unavailable_text, status=STATUS_FAILED)

    alert_text, err = read_text_soft(Path(alert_path))
    if alert_text is None:
        body = _unavailable(f"could not read the alert: {err}")
        return LeadZeroResult(text=_render_section(body), status=STATUS_FAILED)
    try:
        alert = json.loads(alert_text)
    except (ValueError, TypeError) as e:
        body = _unavailable(f"the alert is not valid JSON: {e!r}")
        return LeadZeroResult(text=_render_section(body), status=STATUS_FAILED)
    if not isinstance(alert, dict):
        body = _unavailable("the alert is not a JSON object")
        return LeadZeroResult(text=_render_section(body), status=STATUS_FAILED)

    from defender import run_common
    from .query_tool import QueryCapture

    try:
        env = run_common.run_env(defender_dir, run_dir)
    except Exception:  # noqa: BLE001 — orientation-adjacent work must never break the run
        env = {}

    capture = QueryCapture(verbs, "gather")

    async def _go():
        try:
            return await _resolve_item1(
                run_dir=run_dir, defender_dir=defender_dir, run_id=resolved_run_id,
                alert=alert, capture=capture, env=env, limits=limits,
            )
        except (BudgetKill, circuit_breaker.RunAborted, asyncio.CancelledError,
                KeyboardInterrupt, GeneratorExit):
            # Cancellation/control-flow signals must propagate rather than degrade into a plain
            # "item 1 failed" result: swallowing `CancelledError` here breaks task cancellation
            # semantics for whatever is running this coroutine.
            raise
        except BaseException as e:  # noqa: BLE001 — item 1's own faults degrade, never raise
            return _unavailable(f"{e!r}"), STATUS_FAILED

    body, status = _run_sync(_go())
    return LeadZeroResult(text=_render_section(body), status=status)


__all__ = [
    "CORRELATION_GRANT",
    "CORRELATION_REQUEST_LIMIT",
    "CORRELATION_SYSTEM",
    "CORRELATION_TEMPLATE",
    "ELIDED",
    "HARNESS_PROVENANCE",
    "ITEM1_SYSTEM",
    "L0",
    "L3",
    "LEAD_ZERO_HEADING",
    "PROVENANCE_KEY",
    "RESERVED_LEAD_IDS",
    "SHORTFALL",
    "STATUS_EMPTY",
    "STATUS_FAILED",
    "STATUS_RESOLVED",
    "STATUS_TRUNCATED",
    "UNAVAILABLE",
    "LeadZeroResult",
    "dispatch_correlation",
    "prepare_correlation_lead",
    "resolve_lead_zero",
]
