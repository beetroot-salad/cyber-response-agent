"""Executable spec for #900 — `list_verbs`, gather's verb/param discovery tool.

The only complete, accurate statement of a verb's param surface a gather lead reliably meets
today is a REJECTION: `validate_params` (`runtime/verbs.py:196`) names the declared set from
inside `_screen`, one failed call after the model guessed. Every published surface is
hand-authored prose (`skills/*/execution.md`'s `## Verbs` blocks), the pointer in
`skills/gather/SKILL.md:104` names a catalog that carries no params at all, and the generated
`verb-roster.md` is a build-time audit artifact no model reads. Hand-authored prose drifts:
#900's C3 measured one live drift already (`ticket.list-tickets` declares four params, its
`execution.md` documents three and asserts the fourth away).

The replacement is a discovery tool, sibling to `query`, that derives its answer at call time
from THE SAME TWO FUNCTIONS the enforcer uses — `declared_params` and `_resolved_hints` — so
publication and enforcement cannot disagree:

    register_list_verbs_tool(agent, registry)      # defender/runtime/query_tool.py
    list_verbs(ctx, system: str) -> str            # `system` is REQUIRED
    ToolSet.list_verbs: bool = False               # GATHER_DEF.tools sets it; the judge does not

What each test pins (the obligation ids are #900's):

  O1  agreement with the enforcer — the reported params ARE `model_facing_params(fn)`, i.e.
      `declared_params` minus the `@verb(wrapper_only=…)` set a first-party wrapper reserves;
      every name it publishes is accepted by `validate_params` and a name it withholds is
      refused; its required/optional split and its defaults round-trip through the same
      function. `ticket`'s `require_closed` is the live reserved param: the judge's tool
      hard-codes it and keeps it off its own schema, and gather — which shares the verb — must
      neither see nor bind it, because the pin only NARROWS and would silently drop the open
      siblings a lead is dispatched to correlate.
  O3  no over-promising on types — `_resolved_hints` SWALLOWS an unresolvable annotation
      (`verbs.py:166-170`) and `validate_params` then accepts ANY value for that param, so a
      param whose annotation does not resolve must be published as type-UNENFORCED. No shipped
      adapter triggers this (0 of 44 declared params over 28 granted verbs), so the case is
      driven by a SYNTHETIC verb through the registry injection seam.
  O4  degrade loudly, per system — `registry.verbs("nope-not-a-system")` raises a bare
      `KeyError` and a broken adapter's import error propagates; neither may crash the lead's
      turn, and neither may come back as the empty string, which reads as "this system has no
      verbs".
  O5  grant filtering — the tool never names a `(system, verb)` the caller's grant withholds.

Plus the property that keeps the tool OUT of the run's evidence record: a `list_verbs` call
writes no `executed_queries.jsonl` row, persists no payload, and neither trips nor feeds the
repeat guard (`test_query_tool_611.py:771` is the precedent, for `template_search`).

THE RENDERING THIS SPEC FIXES. The answer is rendered in the `query(...)` grammar the
`execution.md` files already use, so a lead can copy a line into a `query` call:

    query(system="host-state", verb="authorized-keys", params={"host": <str>, "user": <str, default root>})

The tests parse only what they must, and this is the whole of it:
  - one `query(system="…", verb="…", params={…})` call per published verb, `{}` when it
    declares none;
  - inside `params={…}`, each param is a `"name":`-keyed entry, and everything between that
    colon and the next key (or the closing brace) is that param's DESCRIPTOR;
  - a descriptor names its param's type by the python spelling `_ann_name`/`validate_params`
    already use in their own error text (`str`, `int`, `bool`, …) — and names NO type when the
    annotation does not resolve, which is the whole of O3;
  - a descriptor publishes a default when — and only when — the param declares one, plus the
    default's own value; either spelling discharges it (the word `default`, or a python
    `= value` tail), because what must be legible is the required/optional split, not a word.

Nothing else about the wording is pinned; the loud-degradation tests match a vocabulary
alternation rather than a fixed sentence.

None of the target symbols exist at HEAD — `query_tool.register_list_verbs_tool`, the
registered `list_verbs` tool, `ToolSet(list_verbs=…)` — so every test reds on its own missing
symbol while every import in this module resolves against HEAD, so the harness collects and
proves itself.
"""
from __future__ import annotations

import asyncio
import inspect
import re
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union, get_args, get_origin

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent, RunContext  # noqa: E402
from pydantic_ai.exceptions import ModelRetry  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender.agents import AGENTS  # noqa: E402
from defender.runtime import query_tool  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import ToolSet, bind, effective_tools_for  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    GRANTED,
    SYSTEM_RE,
    ModuleVerbRegistry,
    VerbContext,
    VerbRegistry,
    _resolved_hints,
    declared_params,
    declared_verb_names,
    model_facing_params,
    validate_params,
    wrapper_only_params,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

if TYPE_CHECKING:
    # Imported ONLY for the type checker, which is exactly how an unresolvable annotation
    # reaches a shipped adapter: the name is never bound at runtime, so `typing.get_type_hints`
    # raises NameError and `_resolved_hints` swallows it into `{}` (O3 / #900 B2). Nothing else
    # in this module uses it — it annotates the synthetic verb below and nothing more.
    from collections.abc import Sequence as _WindowSpec

pytestmark = pytest.mark.e2e

_ADAPTERS = DEFENDER / "scripts" / "adapters"
LEAD = "l-001"

#: The systems the shipped gather grant reaches. Read off the grant rather than restated, so a
#: new system in `GATHER_PAIRS` is covered by this suite the day it lands.
_GRANT_SYSTEMS = tuple(sorted(GATHER_DEF.verb_grant.systems))

#: Verbs the adapters DECLARE and gather's grant WITHHOLDS (`driver.py:375-377` names the first
#: two outright; the three `ticket` ones are the judge's closed-ticket surface). Each is checked
#: to be really declared before it is asserted absent, so the test cannot pass by the verb
#: having been deleted.
_WITHHELD = (
    ("cmdb", "list-roles"),
    ("identity", "list-authorized-hosts"),
    ("ticket", "get-ticket"),
    ("ticket", "case-opened-at"),
    ("ticket", "key-pattern"),
)

#: Words that make a degradation LOUD. A broad alternation rather than a sentence: O4 demands
#: the failure be legible and NAMED, not that it be spelled one way. Deliberately generous —
#: what discriminates is the company it keeps in each O4 test (the system is named, no verb is
#: published, and the three conditions do not share one message).
_LOUD = re.compile(
    r"unknown|unavailable|unresolvable|could not|cannot|can't|failed|no such|not registered|"
    r"no adapter|does not|doesn't|error|missing|no verb|none of",
    re.I,
)

#: One published verb, in the `query(...)` grammar `skills/*/execution.md` already uses. The
#: params body is brace-free by construction (a type is `str`/`int`/`str | None`, never a
#: literal dict), so the inner `[^{}]*` is exact rather than lazy. A trailing argument after
#: `params={…}` — a `query_id=` the lead is meant to fill in — is allowed and ignored.
_CALL_RE = re.compile(
    r"""query\(\s*system\s*=\s*["'](?P<system>[^"']*)["']\s*,\s*"""
    r"""verb\s*=\s*["'](?P<verb>[^"']*)["']\s*,\s*"""
    r"""params\s*=\s*\{(?P<params>[^{}]*)\}[^)]*\)""",
    re.S,
)
_KEY_RE = re.compile(r"""["'](?P<name>[A-Za-z_][A-Za-z0-9_]*)["']\s*:""")

#: A real system / verb name. A rendering may carry a `query(system="x", verb="<verb>",
#: params={...})` TEMPLATE line alongside the per-verb ones; a placeholder is not a published
#: verb, and this is what tells them apart.
#:
#: THE shared pattern rather than a local copy of it (#914): a verb name is held to the same
#: alphabet as a system name — the tree has no separate verb pattern — so a copy here would be
#: a second place to edit and a place for this suite to drift from what it is checking.
_NAME_RE = SYSTEM_RE

#: The type spellings a descriptor may claim, and a value of the WRONG type for each. A claim
#: is only honest if `validate_params` refuses the mismatch (O3).
_MISMATCH: dict[str, Any] = {
    "bool": "yes", "int": "20", "float": "x", "str": 123, "list": "x", "dict": "x",
}




def _parse(out: str) -> dict[tuple[str, str], dict[str, str]]:
    """`{(system, verb): {param: descriptor}}` — the whole of this spec's rendering contract."""
    calls: dict[tuple[str, str], dict[str, str]] = {}
    for m in _CALL_RE.finditer(out):
        if not (_NAME_RE.match(m.group("system")) and _NAME_RE.match(m.group("verb"))):
            continue
        body = m.group("params")
        keys = list(_KEY_RE.finditer(body))
        params: dict[str, str] = {}
        for i, key in enumerate(keys):
            end = keys[i + 1].start() if i + 1 < len(keys) else len(body)
            params[key.group("name")] = body[key.end():end].strip().rstrip(",").strip()
        calls[(m.group("system"), m.group("verb"))] = params
    return calls


def _reports_default(descriptor: str) -> bool:
    """Does this descriptor publish a DEFAULT? Either spelling counts — the word `default` or a
    python `= value` tail — because the demand is that the required/optional split be legible
    and that the value be there, not that one word be used."""
    return bool(re.search(r"\bdefaults?\b|=", descriptor, re.I))


def _type_claim(descriptor: str) -> str | None:
    """The concrete type a descriptor CLAIMS, or None for a descriptor that claims none."""
    for token in _MISMATCH:
        if re.search(rf"\b{token}\b", descriptor):
            return token
    return None


def _spelled(hint: Any) -> str:
    """The python spelling of a resolved annotation — `str | None` publishes as `str`, the
    same base `validate_params`' own "takes str" message names."""
    origin = get_origin(hint)
    if origin is Union or origin is types.UnionType:
        args = [a for a in get_args(hint) if a is not type(None)]
        return _spelled(args[0]) if args else "None"
    return getattr(hint, "__name__", None) or str(hint)


def _accepted_value(hint: Any) -> Any:
    """A value `validate_params` accepts for `hint` — synthesized from the REAL resolved hint,
    never from the tool's claim, so the round-trip below tests the tool rather than itself."""
    if hint is None or hint is Any:
        return "x"
    origin = get_origin(hint)
    if origin is Union or origin is types.UnionType:
        args = [a for a in get_args(hint) if a is not type(None)]
        return _accepted_value(args[0]) if args else None
    if hint is bool:
        return True
    if hint is int:
        return 1
    if hint is float:
        return 1.0
    if origin is list or hint is list:
        return []
    if origin is dict or hint is dict:
        return {}
    return "x"


def _binding(fn: Any, names: Any) -> dict[str, Any]:
    hints = _resolved_hints(fn)
    return {name: _accepted_value(hints.get(name)) for name in names}


def _registry() -> ModuleVerbRegistry:
    """The PRODUCTION registry under gather's own grant — the shipped surface O1/O5 are about."""
    return ModuleVerbRegistry(_ADAPTERS, GATHER_DEF.verb_grant)


def _granted(registry: VerbRegistry, system: str) -> dict[str, Any]:
    """`{verb: fn}` for what the grant admits — the oracle O5's filter must reproduce."""
    return {
        verb: registry.decide(system, verb).fn
        for verb in sorted(registry.verbs(system))
        if registry.decide(system, verb).outcome == GRANTED
    }


class _ScopedVerbs(VerbRegistry):
    """An injected registry whose GRANT the scenario authors, and whose systems may FAIL.

    `FakeVerbs` cannot serve either half: it self-grants every verb in its own table (so no
    withheld verb is expressible) and its `verbs()` cannot fail. Both are exactly what O4 and
    O5 are about. Same seam, same shape — dumb data handed to `register_tools`, never a
    monkeypatched module attribute. A system mapped to an EXCEPTION raises it from `verbs()`,
    which is what a broken adapter module does at `_load_adapter_module`; an unmapped system
    raises the bare `KeyError` `ModuleVerbRegistry.verbs` raises (#900 B3).
    """

    def __init__(self, table: dict[str, Any], grant: VerbGrant):
        super().__init__(grant)
        self._table = dict(table)

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def verbs(self, system: str):
        entry = self._table[system]
        if isinstance(entry, BaseException):
            raise entry
        return entry


def _agent(registry: VerbRegistry):
    """A gather agent built through the REAL registration seam: `GATHER_DEF.tools` decides what
    is registered (never a synthetic ToolSet, which stays green while the DEF drifts), and the
    registry is the injected value the tool must read."""
    model = FunctionModel(lambda messages, info: ModelResponse(parts=[TextPart(content="x")]))
    agent = Agent(model, deps_type=runtime_tools.AgentDeps)
    runtime_tools.register_tools(agent, GATHER_DEF.tools, registry)
    return agent


def _deps(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return bind(GATHER_DEF, run_dir)


def _ask(registry: VerbRegistry, system: str, tmp_path: Path) -> str:
    """Drive the REAL registered `list_verbs` once. Reds per-test as "not registered" until the
    tool exists, rather than at import."""
    agent = _agent(registry)
    registered = agent._function_toolset.tools
    assert "list_verbs" in registered, (
        "`list_verbs` is not registered on a GATHER_DEF agent — ToolSet.list_verbs / "
        "register_list_verbs_tool (registered: " + ", ".join(sorted(registered)) + ")"
    )
    ctx = RunContext(deps=_deps(tmp_path), model=agent.model, usage=None)
    out = registered["list_verbs"].function(ctx, system=system)
    if inspect.isawaitable(out):
        out = asyncio.run(out)
    assert isinstance(out, str), f"list_verbs must return a str, got {type(out).__name__}"
    return out




def test_o1_the_published_param_set_is_exactly_declared_params(tmp_path):
    """O1 — for every granted `(system, verb)` on the SHIPPED registry, the params the tool
    names are exactly `model_facing_params(fn)`: no extra, none missing.

    `_resolved_hints` additionally returns `ctx` and `return` (#900 B1), so a tool that keyed on
    the hints instead of on the declared params would publish two params `validate_params`
    refuses — the exact disagreement between publication and enforcement this tool exists to
    make impossible. Asserted per system, over all seven, because a filter that works for
    `elastic` and drops a system's whole table is otherwise invisible.

    The referent is `model_facing_params`, not `declared_params`, and the difference is the
    `@verb(wrapper_only=…)` set: a param a first-party wrapper binds and no model may. Both
    functions are asserted here rather than one — the published set must equal the model-facing
    set AND every wrapper-only param must be simultaneously unpublished and refused by
    `validate_params`. A tool that hid such a param while the boundary still accepted it would
    satisfy a bare equality check and still lie by omission, which is the same disagreement
    read from the other side."""
    registry = _registry()
    seen_verbs = seen_params = seen_reserved = 0

    for system in _GRANT_SYSTEMS:
        calls = _parse(_ask(registry, system, tmp_path))
        assert calls, f"{system}: the answer published no verb at all"
        for (named_system, verb), params in calls.items():
            assert named_system == system, (
                f"a {system} answer published a line for system {named_system!r}"
            )
            fn = registry.decide(system, verb).fn
            assert fn is not None, f"{system}.{verb} is published but not granted"
            assert set(params) == set(model_facing_params(fn)), (
                f"{system}.{verb}: published {sorted(params)} but the model-facing surface is "
                f"{sorted(model_facing_params(fn))}"
            )
            artefacts = {"ctx", "return"} & set(params)
            assert not artefacts, (
                f"{system}.{verb} published a _resolved_hints artefact ({sorted(artefacts)}) — "
                "the param surface is declared_params, not the hints"
            )
            for hidden in wrapper_only_params(fn):
                assert hidden in declared_params(fn), (
                    f"{system}.{verb} reserves {hidden!r}, which its signature does not declare"
                )
                assert hidden not in params, (
                    f"{system}.{verb} published the wrapper-only param {hidden!r}"
                )
                refusal = validate_params(fn, {hidden: True})
                assert refusal is not None, (
                    f"{system}.{verb} hides {hidden!r} from the surface but the boundary still "
                    "accepts it — publication and enforcement disagree"
                )
                assert hidden in refusal, (
                    f"{system}.{verb}'s refusal does not name {hidden!r}, so the lead cannot "
                    f"tell which param it may not bind: {refusal}"
                )
                seen_reserved += 1
            seen_verbs += 1
            seen_params += len(params)

    # Vacuity guard, derived rather than restated: every granted verb and every param those
    # verbs declare had to be published for the loop above to have measured anything. (#900
    # counted 28 granted verbs / 44 declared params at design time; the numbers are read off
    # the registry so a new adapter verb is covered the day it lands.)
    expected_verbs = sum(len(_granted(registry, s)) for s in _GRANT_SYSTEMS)
    expected_params = sum(
        len(model_facing_params(fn))
        for s in _GRANT_SYSTEMS for fn in _granted(registry, s).values()
    )
    assert (seen_verbs, seen_params) == (expected_verbs, expected_params)

    # The wrapper-only arm above is only worth anything if it ran. `ticket.list-tickets` and
    # `ticket.get-ticket` reserve `require_closed`, and gather's grant reaches the first — so a
    # tree that stopped reserving anything would silently turn that arm into a no-op.
    assert seen_reserved >= 1, (
        "no granted verb reserves a wrapper-only param — the wrapper-only assertions above "
        "never executed and this test no longer pins them"
    )


def test_o1_every_published_param_is_accepted_and_an_unpublished_one_is_refused(tmp_path):
    """O1, the heart of the suite — the round trip through the ENFORCER.

    For every granted verb: binding exactly the params the tool published passes
    `validate_params`, and adding one it did not publish is refused by it. This is what makes
    publication and enforcement unable to disagree — a name the tool invents fails the first
    arm, a name it omits fails the second. Values are synthesized from the verb's own resolved
    hints, never from the tool's rendering, so the tool cannot satisfy this by agreeing with
    itself."""
    registry = _registry()
    checked = 0

    for system in _GRANT_SYSTEMS:
        for (_, verb), params in _parse(_ask(registry, system, tmp_path)).items():
            fn = registry.decide(system, verb).fn
            full = _binding(fn, params)
            assert validate_params(fn, full) is None, (
                f"{system}.{verb}: the enforcer refused the params the tool published: "
                f"{validate_params(fn, full)}"
            )
            unpublished = "not_a_declared_param_900"
            refusal = validate_params(fn, {**full, unpublished: 1})
            assert refusal is not None, (
                f"{system}.{verb}: a param the tool did NOT publish was accepted"
            )
            assert unpublished in refusal, (
                f"{system}.{verb}: the enforcer refused for some other reason: {refusal}"
            )
            checked += 1

    assert checked == sum(len(_granted(registry, s)) for s in _GRANT_SYSTEMS)


def test_o1_the_required_optional_split_and_the_defaults_round_trip(tmp_path):
    """O1, defaults half — the tool publishes each param's default, and the required/optional
    split it thereby asserts is the one `validate_params` enforces.

    Three arms on the same rendering, so no single mistake passes: binding ONLY the params
    published without a default is accepted (an optional param really is optional), dropping any
    ONE param published without a default is refused as missing (a required param really is
    required), and the default's own value is in the descriptor. `host-state.authorized-keys` is
    the case that makes the split load-bearing — `host` and `user` are both `str`, and only the
    default tells the lead it may omit one of them.

    Default VALUES are asserted for non-`None`, non-bool defaults only (`root`, `desc`, `20`):
    those have one unambiguous spelling, while `None`/`False` are legitimately `null`/`false` in
    a JSON-shaped rendering and pinning one spelling would be a coin toss, not a demand."""
    registry = _registry()
    saw_default_value = 0

    for system in _GRANT_SYSTEMS:
        for (_, verb), params in _parse(_ask(registry, system, tmp_path)).items():
            fn = registry.decide(system, verb).fn
            declared = declared_params(fn)
            required = [p for p, d in params.items() if not _reports_default(d)]

            assert validate_params(fn, _binding(fn, required)) is None, (
                f"{system}.{verb}: binding only the params published WITHOUT a default was "
                f"refused — an optional param was published as required ({params})"
            )
            for p in required:
                short = _binding(fn, [q for q in required if q != p])
                refusal = validate_params(fn, short)
                assert refusal is not None, (
                    f"{system}.{verb}: {p!r} was published as required but the enforcer does "
                    "not require it — the published surface over-states the call"
                )
                assert "missing" in refusal, (
                    f"{system}.{verb}: dropping the required {p!r} was refused for some other "
                    f"reason: {refusal}"
                )
            for p, descriptor in params.items():
                default = declared[p].default
                if p in required:
                    assert default is inspect.Parameter.empty, (
                        f"{system}.{verb}.{p} has default {default!r} and was published "
                        "without one"
                    )
                    continue
                assert default is not inspect.Parameter.empty, (
                    f"{system}.{verb}.{p} was published with a default it does not declare"
                )
                if default is not None and not isinstance(default, bool):
                    assert str(default) in descriptor, (
                        f"{system}.{verb}.{p}: default {default!r} is not in {descriptor!r}"
                    )
                    saw_default_value += 1

    assert saw_default_value >= 3, (
        "no unambiguous default value was checked — the shipped surface carries at least "
        "`user='root'`, `limit=20` and `sort='desc'`"
    )




def test_o3_positive_control_a_resolvable_annotation_is_published_by_its_python_spelling(tmp_path):
    """O3's positive control, and the reason its negative below is not vacuous: every param
    whose annotation RESOLVES is published with the type's python spelling — the same base
    `validate_params` names in its own "'user' takes str" refusal. Without this arm, a tool that
    published no types at all would satisfy the unenforced-annotation demand trivially."""
    registry = _registry()
    checked = 0

    for system in _GRANT_SYSTEMS:
        for (_, verb), params in _parse(_ask(registry, system, tmp_path)).items():
            hints = _resolved_hints(registry.decide(system, verb).fn)
            for p, descriptor in params.items():
                if p not in hints:
                    continue
                spelled = _spelled(hints[p])
                assert re.search(rf"\b{re.escape(spelled)}\b", descriptor), (
                    f"{system}.{verb}.{p} resolves to {spelled} and is published as "
                    f"{descriptor!r} — the lead cannot tell what the enforcer will check"
                )
                checked += 1

    # Derived, not a literal: the floor is every model-facing param the shipped grant reaches,
    # so reserving a param (#900's `wrapper_only`) or landing a new adapter verb moves it
    # automatically. A hardcoded 44 went stale the moment `require_closed` stopped being
    # published, which is a vacuity guard failing for the one reason it must not — the tree
    # changed correctly.
    expected = sum(
        len(model_facing_params(fn))
        for s in _GRANT_SYSTEMS for fn in _granted(registry, s).values()
    )
    assert checked == expected, f"only {checked} typed params were checked, expected {expected}"


def test_o3_no_published_type_claims_more_than_validate_params_enforces(tmp_path):
    """O3 over the SHIPPED surface — every type the tool claims is one the enforcer really
    checks. For each published claim, a value of the wrong type must draw `validate_params`'
    wrong-type refusal specifically (not its missing-param refusal, which is why the mismatch is
    applied on top of an otherwise complete binding).

    A regression pin today rather than a live catch: #900's census found 0 unresolvable
    annotations across the 28 granted verbs. It reds the day an adapter grows one and the tool
    keeps publishing its annotation regardless."""
    registry = _registry()
    checked = 0

    for system in _GRANT_SYSTEMS:
        for (_, verb), params in _parse(_ask(registry, system, tmp_path)).items():
            fn = registry.decide(system, verb).fn
            full = _binding(fn, params)
            for p, descriptor in params.items():
                claim = _type_claim(descriptor)
                if claim is None:
                    continue
                refusal = validate_params(fn, {**full, p: _MISMATCH[claim]})
                assert refusal is not None, (
                    f"{system}.{verb}.{p} is published as {claim} but the enforcer accepts "
                    f"{_MISMATCH[claim]!r} — the published type over-promises"
                )
                assert "wrong param type" in refusal, (
                    f"{system}.{verb}.{p}: the mismatch was refused for some other reason: "
                    f"{refusal}"
                )
                checked += 1

    # Derived for the same reason as the positive control's floor above; this one stays a
    # lower bound because a param whose annotation resolves to a type outside `_MISMATCH`
    # (no wrong-typed sample exists for it) is legitimately skipped.
    reachable = sum(
        len(model_facing_params(fn))
        for s in _GRANT_SYSTEMS for fn in _granted(registry, s).values()
    )
    assert checked >= reachable - 2, f"only {checked} type claims were checked of {reachable}"


def test_o3_an_unresolvable_annotation_is_published_as_type_unenforced(tmp_path):
    """O3 — the case the shipped adapters do not reach, driven through the registry seam.

    `_resolved_hints` swallows an unresolvable annotation and returns `{}` for the WHOLE
    function (`verbs.py:166-170`: `get_type_hints` raises once and the mapping is empty), after
    which `validate_params` accepts any value for any of that verb's params. So the tool must
    publish `window` AND its perfectly-ordinary `host: str` sibling as type-unenforced: a
    claimed `str` on `host` would be exactly the over-promise O3 forbids, and it is the arm an
    implementation that special-cases only the offending param gets wrong.

    Both premises are asserted here rather than assumed, so the demand cannot quietly rest on a
    behaviour of `verbs.py` that changed. The control lives in the same rendering, on the same
    registry: the neighbouring verb's annotations resolve and ARE published as typed, so this
    test cannot be satisfied by publishing no types at all."""
    registry = _ScopedVerbs(
        {"synthetic": {"unresolved": _unresolved_verb, "resolved": _resolved_verb}},
        VerbGrant(role="gather", entries=(("synthetic", "unresolved", "r"),
                                          ("synthetic", "resolved", "r"))),
    )
    assert _resolved_hints(_unresolved_verb) == {}, (
        "the synthetic verb's annotations resolve after all — the O3 case is not being driven"
    )
    assert validate_params(_unresolved_verb, {"host": 123, "window": 5}) is None, (
        "the enforcer type-checks the synthetic verb — #900 B2's fail-open premise is gone"
    )

    calls = _parse(_ask(registry, "synthetic", tmp_path))

    unresolved = calls[("synthetic", "unresolved")]
    assert set(unresolved) == {"host", "window"}, (
        "an unenforced param must still be PUBLISHED — the surface is declared_params, and "
        "dropping it hides a param the enforcer accepts"
    )
    for p, descriptor in unresolved.items():
        assert _type_claim(descriptor) is None, (
            f"{p} is published as {_type_claim(descriptor)} while the enforcer checks nothing "
            f"about it ({descriptor!r})"
        )

    resolved = calls[("synthetic", "resolved")]
    assert _type_claim(resolved["host"]) == "str"
    assert _type_claim(resolved["limit"]) == "int"




def test_o5_a_withheld_but_declared_verb_is_never_published(tmp_path):
    """O5 — the tool never names a `(system, verb)` gather's grant withholds, and the five real
    ones are named here so the demand is measured against the shipped grant rather than a
    fixture. Each is first asserted DECLARED by its adapter (cold, off the `VERBS` literal), so
    the test cannot pass because the verb was deleted; each system's granted siblings are
    asserted present, so it cannot pass by publishing nothing for that system.

    `ticket` is the sharpest of the five: its three withheld verbs are the judge's closed-ticket
    surface, and publishing them to gather would advertise a capability the role separation
    exists to withhold."""
    registry = _registry()
    answers = {s: _ask(registry, s, tmp_path) for s in {s for s, _ in _WITHHELD}}

    for system, verb in _WITHHELD:
        assert verb in declared_verb_names(_ADAPTERS, system), (
            f"{system}.{verb} is no longer declared by its adapter — this assertion is vacuous"
        )
        assert registry.decide(system, verb).outcome != GRANTED, (
            f"{system}.{verb} is now GRANTED to gather — the fixture premise moved"
        )
        assert (system, verb) not in _parse(answers[system]), (
            f"{system}.{verb} is withheld from gather's grant and was published anyway"
        )
        assert verb not in answers[system], (
            f"{system}.{verb} is withheld and its NAME still reached the lead — a verb "
            "mentioned in prose is a verb advertised"
        )

    for system in answers:
        published = {v for _, v in _parse(answers[system])}
        assert published == set(_granted(registry, system)), (
            f"{system}: published {sorted(published)}, grant admits "
            f"{sorted(_granted(registry, system))}"
        )


def test_o5_the_published_set_is_exactly_what_decide_grants(tmp_path):
    """O5, general form — for every system in the grant, what the tool publishes equals what
    `registry.decide(...)` returns GRANTED for. The filter is the registry's decision, not a
    second list that can drift from it: `decide` is where DENIED and UNDECLARED are separated
    and where the grant/declaration class disagreement raises."""
    registry = _registry()
    for system in _GRANT_SYSTEMS:
        published = {v for _, v in _parse(_ask(registry, system, tmp_path))}
        assert published == set(_granted(registry, system)), f"{system}: {sorted(published)}"




def test_o4_an_unknown_system_degrades_loudly_and_names_it(tmp_path):
    """O4 — `registry.verbs("nope-not-a-system")` raises a BARE `KeyError` (#900 B3, asserted
    here so the premise cannot rot). The tool must not let it out as a crash of the lead's turn,
    and must not answer with silence: an empty answer reads as "this system has no verbs", which
    sends the lead to coin a query against a system that does not exist.

    Either channel discharges the demand for THIS condition — a returned line or a `ModelRetry`,
    which is the correction `template_search` already gives a lead that names an unknown system
    — because both are legible to the lead and both are recoverable by its next call. The broken
    ADAPTER below is the case where only a return will do."""
    registry = _registry()
    with pytest.raises(KeyError):
        registry.verbs("nope-not-a-system")

    try:
        out = _ask(registry, "nope-not-a-system", tmp_path)
    except ModelRetry as e:
        out = str(e)

    assert out.strip(), "an unknown system answered with the empty string"
    assert "nope-not-a-system" in out, f"the answer does not name the system: {out!r}"
    assert _LOUD.search(out), f"the degradation is not legible as one: {out!r}"
    assert not _parse(out), f"an unknown system published verbs: {out!r}"


def test_o4_a_failing_adapter_is_a_named_line_and_the_other_systems_still_answer(tmp_path):
    """O4 — a system whose adapter cannot be imported degrades to a NAMED answer, and the
    failure is contained to that system.

    A return, not a `ModelRetry`: the lead cannot fix a broken import, so a retry spends its
    bounded budget re-asking a question with the same answer. The second arm is the containment
    one — the same registry answers a healthy system in full — because the cheapest way to pass
    the first arm is a tool that degrades everything the moment one system fails."""
    def probe(ctx: VerbContext, *, host: str, limit: int = 10) -> list[dict]:
        return []

    registry = _ScopedVerbs(
        {"boom": ImportError("No module named 'boom_transport'"), "healthy": {"probe": probe}},
        VerbGrant(role="gather", entries=(("boom", "probe", "r"), ("healthy", "probe", "r"))),
    )
    with pytest.raises(ImportError):
        registry.verbs("boom")

    broken = _ask(registry, "boom", tmp_path)
    assert broken.strip(), "a failing adapter answered with the empty string"
    assert "boom" in broken, f"the answer does not name the failing system: {broken!r}"
    assert _LOUD.search(broken), f"the failure is not legible as one: {broken!r}"
    assert not _parse(broken), f"a failing adapter published verbs anyway: {broken!r}"

    healthy = _parse(_ask(registry, "healthy", tmp_path))
    assert set(healthy) == {("healthy", "probe")}
    assert set(healthy[("healthy", "probe")]) == {"host", "limit"}


def test_o4_a_system_whose_grant_admits_nothing_is_not_reported_as_a_broken_one(tmp_path):
    """O4/O5 corner — a DECLARED, LOADABLE system whose grant admits no verb is the other
    condition that empties the answer, and it wants the opposite thing said from a broken
    adapter: "this role holds no verb here" is actionable (dispatch elsewhere), while "this
    system failed" sends the lead to retry or to report an outage that is not happening. The
    same split `test_gather_template_discovery.py`'s all-denied-grant test pins for the template
    index.

    Both arms on one registry, so a collapse back to a single message cannot pass by satisfying
    whichever arm the test happened to check."""
    def probe(ctx: VerbContext, *, host: str) -> list[dict]:
        return []

    registry = _ScopedVerbs(
        {"ungranted": {"probe": probe}, "granted": {"probe": probe}},
        VerbGrant(role="gather", entries=(("granted", "probe", "r"),)),
    )

    out = _ask(registry, "ungranted", tmp_path)
    assert out.strip(), "a grant-empty system answered with the empty string, which reads to " \
                        "the lead as 'this system has no verbs'"
    assert "ungranted" in out, f"the answer does not name the system: {out!r}"
    assert not _parse(out), f"a withheld verb was published anyway: {out!r}"
    assert "probe" not in out, f"a withheld verb was named in prose: {out!r}"

    broken = _ask(
        _ScopedVerbs({"ungranted": ImportError("boom")},
                     VerbGrant(role="gather", entries=(("ungranted", "probe", "r"),))),
        "ungranted", tmp_path,
    )
    assert out != broken, (
        "a system whose grant admits nothing and a system whose adapter is broken got the same "
        f"answer ({out!r}) — one of the two lead readings is false"
    )




def test_toolset_carries_the_list_verbs_bit():
    """The tool is a declarative bit on the `ToolSet`, per the `template_search`/`lesson_read`
    mould — not a special case inside `register_tools`. Fed the REAL defs: a synthetic
    `ToolSet(...)` assertion stays green while `GATHER_DEF` drifts."""
    assert ToolSet().list_verbs is False
    assert ToolSet(list_verbs=True).list_verbs is True
    assert GATHER_DEF.tools.list_verbs is True
    assert MAIN_DEF.tools.list_verbs is False


def test_only_gather_holds_list_verbs_and_the_judge_does_not():
    """Role separation at the capability bit. The judge is named explicitly because it is the
    other verb-bearing role — it holds `closed_tickets` and its own grant over the same ticket
    adapter — so "the discovery tool is gather's" is a claim about the judge before it is a
    claim about anyone else. `effective_tools_for` is the reader, because the judge's ToolSet is
    switched per leg by a runtime `replace()` well past `AGENTS`."""
    for role, defn in AGENTS.items():
        assert effective_tools_for(defn).list_verbs is (role is AgentRole.GATHER), (
            f"{role.name} holds list_verbs={effective_tools_for(defn).list_verbs}"
        )


def test_gather_registers_list_verbs_and_main_does_not():
    """Registration derives from the DEF's ToolSet through the real `_register_deferred_tools`
    seam — the same route `template_search` and `query` take."""
    gather = _agent(FakeVerbs({}))
    assert "list_verbs" in gather._function_toolset.tools
    assert "query" in gather._function_toolset.tools, "the sibling tool went missing"

    main = Agent(
        FunctionModel(lambda messages, info: ModelResponse(parts=[TextPart(content="x")])),
        deps_type=runtime_tools.AgentDeps,
    )
    runtime_tools.register_tools(main, MAIN_DEF.tools)
    assert "list_verbs" not in main._function_toolset.tools


def test_list_verbs_takes_a_required_system_and_nothing_else():
    """The model-facing signature: `system` is the ONLY param and it is REQUIRED.

    Not cosmetic. An optional `system` makes "list everything" the default call, which is the
    all-systems block #900's N1 rejected on caching grounds — and it is the shape that turns one
    broken adapter into a degraded answer for all seven. A second param is a second thing the
    lead can get wrong on a tool whose entire purpose is to stop it guessing."""
    agent = _agent(FakeVerbs({}))
    tool = agent._function_toolset.tools["list_verbs"]
    schema = tool.tool_def.parameters_json_schema

    assert set(schema["properties"]) == {"system"}, schema["properties"]
    assert schema.get("required") == ["system"], schema.get("required")
    params = set(inspect.signature(tool.function).parameters) - {"ctx"}
    assert params == {"system"}, params


def test_the_registration_entry_point_is_named_and_registers_the_tool():
    """`register_list_verbs_tool(agent, registry)` is the named seam `_register_deferred_tools`
    calls, mirroring `register_query_tool` / `register_template_search_tool`. Pinned directly so
    the tool cannot be smuggled in as an inline `@agent.tool` inside another registrar, where
    nothing could register it without also registering `query`."""
    register = getattr(query_tool, "register_list_verbs_tool", None)
    assert register is not None, (
        "defender/runtime/query_tool.py declares no register_list_verbs_tool"
    )
    agent = Agent(
        FunctionModel(lambda messages, info: ModelResponse(parts=[TextPart(content="x")])),
        deps_type=runtime_tools.AgentDeps,
    )
    register(agent, FakeVerbs({}))
    assert "list_verbs" in agent._function_toolset.tools




def test_list_verbs_writes_no_queries_row_and_leaves_the_guards_untouched(tmp_path):
    """The queries table is "what the defender RAN" — the join the whole offline learning loop
    rests on. `list_verbs` runs nothing: it inspects signatures and never calls an adapter, so a
    row for it would put a query in the record that never reached a system, and a payload digest
    for an answer no system produced.

    Mirrors `test_query_tool_611.py:771` (`capture_fires_only_for_the_query_tool`), driving the
    REAL run: an `AbstractCapability` hook fires for EVERY tool, so the `TOOL_NAME` guard in
    `QueryCapture` is the only thing keeping this tool out of the table, the circuit breaker and
    the repeat guard.

    THREE identical calls, not one. `repeat_trip`'s threshold is three: if `list_verbs` fed the
    repeat guard, the third would come back as a `GatherDeadEnd` instead of an answer and the
    lead would be ended by a discovery call. All three must answer, and the table must still be
    empty of this lead's rows — including the `∅.`-prefixed sentinels a trip would write."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    def probe(ctx: VerbContext, *, native_query: str, limit: int = 10) -> list[dict]:
        return []

    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([
        Turn(tool_calls=[("list_verbs", {"system": "elastic"})]),
        Turn(tool_calls=[("list_verbs", {"system": "elastic"})]),
        Turn(tool_calls=[("list_verbs", {"system": "elastic"})]),
        Turn(text="Summary: read the verb surface."),
    ])
    drive(run_dir, run_id="lv900", main=main, gather=gather,
          verbs=FakeVerbs({"elastic": {"probe": probe}}))

    assert gather.calls == 4, (
        "a list_verbs turn derailed the gather loop — the third call was refused or the tool "
        "raised"
    )
    assert 'verb="probe"' in gather.seen[-1], (
        "the published verb surface never reached the gather model — the tool answered "
        "nothing, or is not registered on the real gather agent"
    )

    from defender.runtime.lead_zero import RESERVED_LEAD_IDS
    own_rows = [
        row for row in read_jsonl_rows(run_dir / "executed_queries.jsonl")
        if row.get("lead_id") not in RESERVED_LEAD_IDS
    ]
    assert own_rows == [], f"a list_verbs call wrote a queries row: {own_rows}"
    assert not (run_dir / "gather_raw" / LEAD).exists(), "a list_verbs call persisted a payload"




def _resolved_verb(ctx: VerbContext, *, host: str, limit: int = 10) -> list[dict]:
    """The control for the O3 pair: annotations that resolve, so `_resolved_hints` reports them
    and `validate_params` really checks them."""
    return []


def _unresolved_verb(ctx: VerbContext, *, host: str, window: _WindowSpec = "24h") -> list[dict]:
    """A verb whose annotations DO NOT resolve — `_WindowSpec` is a TYPE_CHECKING-only import,
    so `get_type_hints` raises NameError at runtime and `_resolved_hints` returns `{}` for the
    whole function, `host` included. This module carries `from __future__ import annotations`
    exactly as every shipped adapter does, so the shape is the adapters' own."""
    return []
