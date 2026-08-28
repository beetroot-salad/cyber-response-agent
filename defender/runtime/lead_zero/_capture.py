"""Harness-executed lead-0.

Before MAIN's first ORIENT turn, the runtime resolves the alert's ancestor documents (item 1)
and dispatches one tightly-bounded correlation gather lead (item 3), both writing into the
run's leads/queries tables under the reserved ids ``l-000``/``l-00c`` so the learning loop and
the review gate cite them like any model-dispatched lead.

This module owns every backend call, run-dir write and dispatch those two items add;
``orient.py`` stays a pure text-assembler that calls ``resolve_lead_zero`` and formats the
returned block as one more ORIENT section.

Issuing a turn-zero call, and recording what came back.

The budget gate, the per-run call ledger, and the declaring `:L findings` row a harness
lead must own before it may write anything. Split out of `lead_zero.py` at 1215 lines.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths
from defender.hooks.budget_enforcer import (
    BudgetKill,
    read_budget,
    tail_exhausted,
    update_budget_locked,
)
from defender.runtime import circuit_breaker
from defender.runtime.verbs import VerbContext
from ._spec import ITEM1_SYSTEM, _ANY_RUN_TAG, _FENCE_RUN


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


# small sync/async bridge

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


# sanitizing wrap-delimiter shapes (K1 round 2 + F4)

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


# deps for routing through the real QueryCapture (K7/d10)

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


# budget chaining (K23)

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
