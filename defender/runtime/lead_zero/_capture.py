"""Lead-0: issuing a turn-zero call and recording what came back.

The budget gate, the per-run call ledger, and the declaring `:L findings` row a harness
lead must own before it may write anything.
"""
from __future__ import annotations

import asyncio
import json
import logging
from defender._model import model
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any

from pydantic import SkipValidation

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

_logger = logging.getLogger(__name__)


@model(frozen=True)
class LeadZeroResult:
    """Item 1's result. `text` is the rendered block (sanitized, elided, wrapped); item 3's
    contract carries the same bytes so the correlation lead picks its own axes off them.

    No extracted-entity field: a fixed host/user/source-ip triple fits only host-level auth
    sources and is noise elsewhere (e.g. container sources that all report one shared host)."""

    text: str
    status: str


def _run_sync(coro: Any) -> Any:
    """Run a coroutine from a synchronous caller, whether or not a loop is already running
    on this thread (if one is, it runs on a fresh thread with its own loop).

    The thread runs in a copy of the caller's context so log lines keep the run id and
    tenant."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    import contextvars

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(contextvars.copy_context().run, asyncio.run, coro).result()


def _sanitize(text: Any) -> str:
    """Defang `<run-…-…>`-shaped delimiters and markdown fence runs in external content
    before it is interpolated into text that crosses an agent boundary.

    The delimiter half matters for item 3's goal, which is handed to the gather subagent
    unframed (the ORIENT frame re-mints its own delimiter on collision). Characters are
    replaced, never deleted, so the evidence stays visible."""
    if not isinstance(text, str):
        text = str(text)
    text = _ANY_RUN_TAG.sub(lambda m: m.group(0).replace("<", "‹").replace(">", "›"), text)
    return _FENCE_RUN.sub(lambda m: "ˋ" * len(m.group(0)), text)


@model(frozen=True)
class _CaptureDeps:
    run_dir: Path
    defender_dir: Path
    run_id: str
    lead_id: str
    box: Any = None
    budget_started_monotonic: float = 0.0
    #: The run's tenant record (#1107) — what item 1's verb context hands the adapter. `None`
    #: only for a caller with no run (a direct test of the recorder); a verb built over it is
    #: refused by `VerbContext`.
    tenant: Annotated[Any, SkipValidation] = None


def _rows_for(run_dir: Path, lead_id: str) -> list[dict]:
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead_id]


def _last_row_seq(run_dir: Path, lead_id: str) -> int:
    """The queries-table `seq` of the last call under `lead_id`, which documents from that
    call are elided against (a document's position in the block is not its payload's seq).
    `-1` when no row exists."""
    rows = _rows_for(run_dir, lead_id)
    seq = rows[-1].get("seq") if rows else None
    return seq if isinstance(seq, int) else -1


async def _capture_issue(
    capture: Any, deps: _CaptureDeps, verb: str, params: dict, env: dict,
) -> tuple[dict | None, str]:
    """Issue one call through the real `QueryCapture.wrap_tool_execute`, so every screen runs
    as for a model-dispatched query.

    Returns `(envelope_or_None, raw_result_text)`; `None` covers both a screened call and one
    that was attempted but failed."""
    before = len(_rows_for(deps.run_dir, deps.lead_id))
    call = SimpleNamespace(tool_name="query")
    args = {"system": ITEM1_SYSTEM, "verb": verb, "params": params}
    # Kept so a later write failure can recover the result without re-issuing the call.
    captured: list[Any] = []

    async def handler(_args: dict) -> Any:
        fn = capture._registry.verbs(ITEM1_SYSTEM)[verb]
        vctx = VerbContext(defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=env,
                           tenant=_tenant_of(deps))
        result = await asyncio.to_thread(fn, vctx, **params)
        captured.append(result)
        return result

    ctx = SimpleNamespace(deps=deps)
    try:
        text = await capture.wrap_tool_execute(ctx, call=call, args=args, handler=handler)
    except (OSError, ValueError):
        # A queries-table write that cannot land costs the evidence row, not the evidence,
        # and must not trigger a second backend call.
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
        # The sidecar payload failed to persist; use the in-memory result.
        envelope = captured[0] if captured else None
        return (envelope if isinstance(envelope, dict) else None), text
    try:
        data = json.loads((deps.run_dir / payload_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, text
    if not isinstance(data, dict):
        return None, text
    return data, text


#: The capped path's exit code for an unmapped fault. Mirrors `query_tool.DEFAULT_FAULT_EXIT`
#: without importing it, since that is internal to the model-facing capture.
_UNMAPPED_FAULT_EXIT = 2


def _record_manual_row(
    deps: _CaptureDeps, verb: str, params: dict, payload: Any, *, exit_code: int,
) -> None:
    """Write a queries-table row through `record_query.append_query_row`, the shared row
    constructor, so the columns always match `QUERY_ROW_COLUMNS`. Derived columns come from
    the column owner's helpers; only the display digest and `system` are decided here.

    Does not feed `circuit_breaker.record_outcome`, so capped calls keep running without
    pushing the breaker over its trip boundary on lead-0's behalf."""
    from defender.scripts.gather_tools.record_query import (
        append_query_row,
        payload_digest,
        payload_status,
        raw_command,
        system_fingerprint,
    )

    text = json.dumps(payload, default=str) if exit_code == 0 else ""
    append_query_row(
        deps.run_dir,
        lead_id=deps.lead_id,
        system=ITEM1_SYSTEM,
        verb=verb,
        query_id=f"{ITEM1_SYSTEM}.{verb}",
        params=params,
        raw_command=raw_command(ITEM1_SYSTEM, verb, params),
        payload_text=text,
        exit_code=exit_code,
        payload_status=payload_status(exit_code, payload),
        payload_digest=(
            payload_digest(text, "", 0) if exit_code == 0 else f"exit={exit_code}; capped"
        ),
        # No model-authored system name on this path (`raw_system` is `""`); the system is
        # the host's own constant.
        system_key=system_fingerprint("", ITEM1_SYSTEM),
    )


def _breaker_failures(run_dir: Path) -> int:
    # Read through the breaker's own reader (bounded, nesting-guarded, shape-checked, #1174
    # O10). Unusable state must degrade only this read, not item 1's whole resolution.
    state = circuit_breaker._load(run_dir)
    if state.get("_unreadable"):
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
    """Tracks item 1's contribution to the per-system breaker, so later infra failures can
    still be issued without being recorded past the cap."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.capped = False

    async def call(self, capture, deps, verb, params, env):
        from defender.scripts.adapters.faults import AdapterFault

        before = _breaker_failures(self.run_dir)
        if self.capped:
            # Past the cap: bypass QueryCapture's `record_outcome`, still writing a row.
            try:
                fn = capture._registry.verbs(ITEM1_SYSTEM)[verb]
                vctx = VerbContext(defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=env,
                                   tenant=_tenant_of(deps))
                envelope = await asyncio.to_thread(fn, vctx, **params)
                _record_manual_row(deps, verb, params, envelope, exit_code=0)
                return envelope, ""
            except (circuit_breaker.RunAborted, asyncio.CancelledError,
                    KeyboardInterrupt, GeneratorExit):
                # Control-flow signals propagate; they are never the query's fault.
                raise
            except AdapterFault as e:
                # A mapped fault keeps its own exit code, as in `QueryCapture._record`.
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


def _tenant_of(deps: Any) -> Any:
    """The run's tenant record a lead-0 verb is handed — refused, not guessed, when the deps were
    built without one (#1106: there is no checkout copy to fall back to)."""
    tenant = getattr(deps, "tenant", None)
    if tenant is None:
        raise TypeError("lead-0's verb context needs the run's tenant record")
    return tenant


def _build_deps(
    run_dir: Path, defender_dir: Path, run_id: str, lead_id: str, tenant: Any,
) -> _CaptureDeps:
    return _CaptureDeps(
        run_dir=run_dir, defender_dir=defender_dir, run_id=run_id, lead_id=lead_id,
        tenant=tenant,
    )


def _budget_gate(run_dir: Path, limits: dict) -> None:
    """Not gated on `DEFENDER_BUDGET_ENFORCE`: lead-0 is harness work, not a model tool
    refusal."""
    state = read_budget(run_dir)
    if tail_exhausted(state, limits):
        raise BudgetKill("lead-0's own call refused: the run's budget tail is exhausted")


def _budget_account(run_dir: Path, run_id: str, tool_name: str, limits: dict) -> None:
    import contextlib

    with contextlib.suppress(Exception):  # accounting must never break the run
        update_budget_locked(run_dir, run_id, tool_name, limits=limits)


def _declare_l_finding(run_dir: Path, lead_id: str, name: str, system: str) -> None:
    """Write lead-0's declaring `:L findings` row into `investigation.md` before MAIN's first
    turn; without it, a citation of the reserved id is refused as an undeclared lead.

    `system` comes from the caller because the two reserved ids get it from different
    authorities (item 1's constant, item 3's dispatch), which can diverge.

    This write bypasses `permission.decide_write`, so the content schema is applied here via
    `validate_artifact`, keeping "a committed investigation parses" true. A seed that fails
    validation is not written: the id stays undeclared and MAIN gets a recoverable
    `undeclared lead` refusal instead of unvalidated bytes. Best-effort: never raises."""
    from defender._artifact_schema import validate_artifact
    from defender._run_paths import RUN_LAYOUT
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
        # `None`, not `""`, for an absent file, matching `permission.decide_write`'s baseline.
        existing = path.read_text(encoding="utf-8") if path.is_file() else None
        proposed = block if existing is None else existing + block
        reason = validate_artifact(RUN_LAYOUT.investigation.name, proposed, existing)
        if reason is not None:
            _logger.warning(
                f"refused to declare {lead_id} in investigation.md — the document "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
                f"would not pass validation, so nothing was written and the id stays "
                f"undeclared: {reason}"
            )
            return
        write_guarded(path, proposed)
    except (OSError, ValueError) as e:  # noqa: BLE001 — best-effort; never breaks the run
        _logger.warning(f"could not declare {lead_id} in investigation.md: {e!r}")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
