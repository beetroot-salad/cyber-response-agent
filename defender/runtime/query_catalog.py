"""The model-facing query catalog and capability descriptions."""
from __future__ import annotations

import asyncio

import inspect

import json

import logging

from collections.abc import Mapping


from typing import Any


from pydantic_ai import RunContext


from pydantic_ai.exceptions import (
    ApprovalRequired,
    CallDeferred,
    ModelRetry,
    SkipToolExecution,
    ToolRetryError,
)


from defender.knowledge._knowledge import CHECKOUT_KNOWLEDGE

from defender.hooks.budget_enforcer import BudgetKill










from defender.runtime import circuit_breaker
from defender.runtime import system_status
from defender.runtime.run_end import CallRecordWriteFailed
from defender.runtime.verbs import GRANTED, ServingAbort, _ann_name, _resolved_hints, SYSTEM_MAX_LEN, is_system_name, model_facing_params


_logger = logging.getLogger(__name__)



CONTROL_FLOW_EXCEPTIONS: tuple[type[BaseException], ...] = (
    circuit_breaker.RunAborted,
    ModelRetry,
    SkipToolExecution,
    CallDeferred,
    ApprovalRequired,
    ToolRetryError,
    # A served verb that gave up on its world (#1224): the sibling ends, nothing is filed.
    ServingAbort,
    CallRecordWriteFailed,
)




#: What a param renders as when its annotation could not be resolved. `_resolved_hints` then
#: returns `{}` for the whole verb and `validate_params` type-checks nothing, so printing the
#: annotation would promise a check that is not made.
UNENFORCED_TYPE = "type unenforced"



#: The grant-first answer: absent and withheld systems read the same, so discovery neither
#: imports an ungranted adapter nor becomes an oracle over the on-disk roster. Listing the
#: reachable systems discloses nothing new (the dispatch prompt lists them) and fixes typos.
_LIST_VERBS_UNREACHABLE = (
    "`{system}` — your grant reaches no verb on any system by that name, so there is nothing "
    "here you may run and no surface to show you.{roster} Measure this lead against a system "
    "you do hold, or say so in your summary rather than reporting a measurement you could not "
    "take."
)



_LIST_VERBS_UNKNOWN_SYSTEM = (
    "`{system}` — no adapter is registered under that name, so no verb surface can be derived "
    "for it. The Dispatch block at the end of your prompt names the system you were dispatched "
    "to; confirm it there and call this again with that name."
)



#: Where a system's skill sits, as the model-facing notes below name it (`defender.knowledge._knowledge`).
_SKILLS_REL = CHECKOUT_KNOWLEDGE.skills_rel



#: Reached only for a name that passed `_adapter_path_under`'s checks, so interpolating it into
#: a path is safe. `execution.md` holds only value constraints and pitfalls, not verbs.
_LIST_VERBS_UNLOADABLE = (
    "`{system}` — UNAVAILABLE: its adapter could not be loaded ({err}). No verb surface can be "
    "derived for it right now, and no file carries a copy — the verb roster and its params are "
    "read from the live signatures and nowhere else. "
    f"`{_SKILLS_REL}{{system}}/execution.md` still states this system's value constraints and "
    "recorded pitfalls; report the failure in your summary rather than guessing a verb or a "
    "param name."
)



#: The adapter loaded but its surface could not be derived (e.g. a grant/declaration class
#: disagreement out of `decide`): a defender-side fault the lead cannot route around.
_LIST_VERBS_UNDERIVABLE = (
    "`{system}` — UNAVAILABLE: its verb surface could not be derived ({err}). That is a "
    "defender-side fault, not something your call can fix, and no file carries a copy of the "
    f"surface. `{_SKILLS_REL}{{system}}/execution.md` still states this system's value "
    "constraints and recorded pitfalls; report the failure in your summary rather than guessing "
    "a verb or a param name."
)



#: A missing or malformed `VERBS` table (read as `{}`): a broken adapter, not a withheld grant.
_LIST_VERBS_NO_VERBS = (
    "`{system}` — UNAVAILABLE: its adapter declares no verbs at all, so no verb surface can be "
    "derived for it, and no file carries a copy. "
    f"`{_SKILLS_REL}{{system}}/execution.md` still states this system's value constraints and "
    "recorded pitfalls; report the failure in your summary rather than guessing a verb or a "
    "param name."
)



#: Every declared verb is withheld from this role; distinct from a broken adapter, which calls
#: for the opposite response.
_LIST_VERBS_NONE_GRANTED = (
    "`{system}` — its adapter declares verbs, but your grant admits none of them. This is not "
    "an empty system and not a read failure: there is nothing here you may run. Measure this "
    "lead against a system you do hold, or say so in your summary rather than reporting a "
    "measurement you could not take."
)



_LIST_VERBS_HEADER = (
    "`{system}` — the {count} verb(s) your grant admits, read from the adapter's live "
    "signatures. Copy a line and bind the values in place of each `<…>`:\n"
)



_LIST_VERBS_LEGEND = (
    "\nParams bind **by name**; there are no flags and no positional args. Types are literal "
    "JSON: a number is a number (`20`, never `\"20\"`), a boolean is `true`/`false` (never "
    "`\"false\"`, which is truthy and would have meant the opposite). A param whose descriptor "
    "carries a `default` is OPTIONAL — drop it to take that default; every other param is "
    "REQUIRED.\n"
    "\nAdd `query_id=\"{system}.<id>\"` to the call — a catalog template's id when you reused "
    "one, or a coined `{system}.<descriptive-kebab>` when none fit.\n"
)



#: Quotes the marker as a prefix: a param with a default renders `<type unenforced, default …>`.
_LIST_VERBS_UNENFORCED_NOTE = (
    "\nA descriptor opening `<{marker}` marks a param whose declared annotation could not be "
    "resolved, so the boundary does NOT type-check it — a wrong-typed value there reaches the "
    "adapter instead of being refused. Bind it to the value constraint this system's "
    "`execution.md` states, and treat a surprising answer as suspect rather than as data.\n"
)




def _json_default(value: Any) -> str:
    """A param default in JSON spelling (`null`/`true`), never `repr`'s, so a copied call is valid."""
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return json.dumps(repr(value))




def _rendered_param(param: inspect.Parameter, hints: Mapping[str, Any]) -> str:
    """One declared param as a `"name": <descriptor>` entry of a `params={…}` body."""
    inner = _ann_name(hints[param.name]) if param.name in hints else UNENFORCED_TYPE
    if param.default is not inspect.Parameter.empty:
        inner = f"{inner}, default {_json_default(param.default)}"
    return f'"{param.name}": <{inner}>'




def _echoed_system(system: str) -> str:
    """The `system` string a degradation message may interpolate.

    A well-formed name is echoed verbatim. Anything else is a bounded `repr` with backticks
    removed, so it cannot forge markdown structure or close the backticked span early.
    """
    if is_system_name(system):
        return system
    return repr(system[:SYSTEM_MAX_LEN]).replace("`", "")




#: What every guarded read below re-raises rather than degrading: framework control flow plus
#: process kills.
_RERAISE: tuple[type[BaseException], ...] = (
    *CONTROL_FLOW_EXCEPTIONS,
    BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError,
)




def _registry_declares(registry: Any, system: str) -> bool:
    """Does the registry list `system`? `systems()` never raises, so there is no "cannot say"."""
    return system in registry.systems()




def _granted_systems(registry: Any) -> tuple[str, ...]:
    """The systems this role's grant reaches, or `()` when the registry cannot say."""
    try:
        return tuple(sorted(registry.grant.systems))
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — a registry that cannot name its grant reaches nothing
        # Logged because the lead sees only an empty grant, indistinguishable from a real one.
        _logger.warning(f"verb registry could not name its grant "
                        f"({type(e).__name__}: {e}); list_verbs will answer 'no system reached'")
        return ()




def _list_verbs_declared(
    registry: Any, system: str, shown: str,
) -> tuple[Mapping[str, Any], str | None]:
    """`(declared_verbs, degradation)`: the registry's table for `system`, or the message to
    answer instead. Never both, and never an exception out of the tool."""
    try:
        declared = registry.verbs(system)
    except KeyError as e:
        # `KeyError` means either "no such adapter" or an import-time `KeyError` in the adapter
        # (e.g. `os.environ[...]`); the system list tells them apart. The key is the diagnosis.
        if _registry_declares(registry, system):
            return {}, _LIST_VERBS_UNLOADABLE.format(system=shown, err=f"KeyError: {e}")
        return {}, _LIST_VERBS_UNKNOWN_SYSTEM.format(system=shown)
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — an adapter that will not import is a degradation
        return {}, _LIST_VERBS_UNLOADABLE.format(system=shown, err=f"{type(e).__name__}: {e}")
    if not declared:
        # `{}` here is a broken adapter (no usable `VERBS`), not a withheld grant.
        return {}, _LIST_VERBS_NO_VERBS.format(system=shown)
    return declared, None




def _list_verbs_line(
    registry: Any, system: str, verb: Any, shown: str,
) -> tuple[tuple[str, bool] | None, str | None]:
    """`((rendered_call, any_param_unenforced), degradation)` for one verb — `(None, None)`
    when the grant withholds it.

    Decision and render are guarded together: both can raise on a broken adapter, and an
    exception out of a discovery tool would end the lead's turn.
    """
    try:
        decision = registry.decide(system, verb)
        if decision.outcome != GRANTED or decision.fn is None:
            return None, None
        # `model_facing_params`: wrapper-only params are refused, so they are not published.
        params = model_facing_params(decision.fn)
        hints = _resolved_hints(decision.fn)
        rendered = ", ".join(_rendered_param(p, hints) for p in params.values())
        # `shown`, not raw `system`: the line the lead copies must not carry an unescaped name.
        line = f'query(system="{shown}", verb="{verb}", params={{{rendered}}})'
        return (line, any(name not in hints for name in params)), None
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — a surface that cannot be derived degrades loud
        return None, _LIST_VERBS_UNDERIVABLE.format(
            system=shown, err=f"{shown}.{verb}: {type(e).__name__}: {e}",
        )




#: A granted system that is down for the run (#1256 O-3): its cause, and what to do instead.
_LIST_VERBS_DOWN = (
    "`{system}` — DOWN for this run ({cause}). No verb of it runs in this run, so there is no "
    "surface to show you and nothing to call. Do not query or dispatch it: measure this lead "
    "against a system that is up, and name the missing evidence in your summary — it is a "
    "visibility gap, not a result."
)




def _tool_list_verbs(registry: Any, system: str, down: system_status.Down | None = None) -> str:
    """`system`'s granted verbs and their declared params, derived at call time.

    Uses the same readers `validate_params` enforces with, and filters through
    `registry.decide`, so what is published is what `query` admits. The system-level grant
    check runs first because `decide` would import the adapter; a granted system that is down
    for the run (`down`, its cause) answers that instead of a surface no call could use.

    Nothing is persisted (no row, breaker, or repeat guard): it reads our own adapter
    signatures, so the output is first-party and carries no untrusted frame.
    """
    shown = _echoed_system(system)
    # Grant first, before anything resolves an adapter.
    reachable = _granted_systems(registry)
    if system not in reachable:
        roster = f" The systems your grant reaches: {', '.join(reachable)}." if reachable else ""
        return _LIST_VERBS_UNREACHABLE.format(system=shown, roster=roster)
    if down is not None:
        return _LIST_VERBS_DOWN.format(system=shown, cause=system_status.cause_text(down))

    declared, degradation = _list_verbs_declared(registry, system, shown)
    if degradation is not None:
        return degradation

    lines: list[str] = []
    any_unenforced = False
    # `key=str` so a broken adapter's mixed key types cannot raise here; non-string keys are
    # then withheld by the grant filter.
    for verb in sorted(declared, key=str):
        rendered, failure = _list_verbs_line(registry, system, verb, shown)
        if failure is not None:
            return failure
        if rendered is None:
            continue
        line, unenforced = rendered
        any_unenforced = any_unenforced or unenforced
        lines.append(line)

    if not lines:
        return _LIST_VERBS_NONE_GRANTED.format(system=shown)

    out = (
        _LIST_VERBS_HEADER.format(system=shown, count=len(lines))
        + "\n" + "\n".join(f"    {line}" for line in lines) + "\n"
        + _LIST_VERBS_LEGEND.format(system=shown)
    )
    if any_unenforced:
        out += _LIST_VERBS_UNENFORCED_NOTE.format(marker=UNENFORCED_TYPE)
    return out




def register_list_verbs_tool(agent, registry) -> None:

    @agent.tool
    async def list_verbs(ctx: RunContext[Any], system: str) -> str:
        """The verbs one system of record declares and the params each one binds — read from
        the adapter's live signatures, filtered to what your grant admits. Call it before you
        coin a query no template covers: it is the same surface the `query` tool enforces, so
        a param it names is a param that will bind and one it omits will be refused. `system`
        is the system you were dispatched to (the Dispatch block names it); call it again for
        another system if this lead crosses one. It runs nothing against the system of record
        and is not recorded as a query."""
        # The run's one question (#1256): is this system down? Deps no run started (an agent
        # built on its own) hold no state, and nothing is down for them.
        state = getattr(ctx.deps, "run_state", None)
        down = system_status.down_cause(state, system) if state is not None else None
        # Off the event loop: the first call imports the adapter module, which would otherwise
        # stall sibling leads.
        return await asyncio.to_thread(_tool_list_verbs, registry, system, down)
