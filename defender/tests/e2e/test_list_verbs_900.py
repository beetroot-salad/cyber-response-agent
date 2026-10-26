"""Executable spec for #900 — `list_verbs`, gather's verb/param discovery tool."""
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
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    GRANTED,
    ModuleVerbRegistry,
    VerbContext,
    VerbRegistry,
    _resolved_hints,
    is_system_name,
    validate_params,
)
from defender.kit.verbs import declared_params, model_facing_params, wrapper_only_params
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    drive,
    materialize,
)
from defender.runtime.verbs import read_roster  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Sequence as _WindowSpec

pytestmark = pytest.mark.e2e

_ADAPTERS = DEFENDER / "integrations"
LEAD = "l-001"

def _shipped_gather_grant():
    """The shipped gather grant — the committed playground tenant's (#1106 M4: `GATHER_DEF`
    carries none; a run's grant is projected from its tenant's table)."""
    from defender.tests.support.tenancy import _tenants1106 as T1106

    return T1106.fixture_grants().gather


def _grant_systems() -> tuple[str, ...]:
    """The systems the shipped gather grant reaches. Read off the grant rather than restated,
    so a new system in the table is covered by this suite the day it lands."""
    return tuple(sorted(_shipped_gather_grant().systems))

_WITHHELD = (
    ("cmdb", "list-roles"),
    ("identity", "list-authorized-hosts"),
    ("ticket", "get-ticket"),
    ("ticket", "case-opened-at"),
    ("ticket", "key-pattern"),
)

_LOUD = re.compile(
    r"unknown|unavailable|unresolvable|could not|cannot|can't|failed|no such|not registered|"
    r"no adapter|does not|doesn't|error|missing|no verb|none of",
    re.I,
)

_CALL_RE = re.compile(
    r"""query\(\s*system\s*=\s*["'](?P<system>[^"']*)["']\s*,\s*"""
    r"""verb\s*=\s*["'](?P<verb>[^"']*)["']\s*,\s*"""
    r"""params\s*=\s*\{(?P<params>[^{}]*)\}[^)]*\)""",
    re.S,
)
_KEY_RE = re.compile(r"""["'](?P<name>[A-Za-z_][A-Za-z0-9_]*)["']\s*:""")

_is_name = is_system_name

#: The type spellings a descriptor may claim, and a value of the WRONG type for each. A claim
#: is only honest if `validate_params` refuses the mismatch (O3).
_MISMATCH: dict[str, Any] = {
    "bool": "yes", "int": "20", "float": "x", "str": 123, "list": "x", "dict": "x",
}


def _parse(out: str) -> dict[tuple[str, str], dict[str, str]]:
    """`{(system, verb): {param: descriptor}}` — the whole of this spec's rendering contract."""
    calls: dict[tuple[str, str], dict[str, str]] = {}
    for m in _CALL_RE.finditer(out):
        if not (_is_name(m.group("system")) and _is_name(m.group("verb"))):
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
    return ModuleVerbRegistry(read_roster(_ADAPTERS), _shipped_gather_grant())


def _granted(registry: VerbRegistry, system: str) -> dict[str, Any]:
    """`{verb: fn}` for what the grant admits — the oracle O5's filter must reproduce."""
    return {
        verb: registry.decide(system, verb).fn
        for verb in sorted(registry.verbs(system))
        if registry.decide(system, verb).outcome == GRANTED
    }


class _ScopedVerbs(VerbRegistry):
    """An injected registry whose GRANT the scenario authors, and whose systems may FAIL."""

    def __init__(self, table: dict[str, Any], grant: VerbGrant):
        super().__init__(grant)
        self._table = dict(table)

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def _cold_verb_names(self, system: str) -> frozenset[str]:
        entry = self._table.get(system, {})
        return frozenset(entry) if isinstance(entry, dict) else frozenset(
            verb for granted_system, verb, _ in self.grant.entries if granted_system == system)

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
    from defender.tests.support.tenancy import _tenants1106 as T1106

    return bind(T1106.fixture_gather_def(), run_dir)


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
    names are exactly `model_facing_params(fn)`: no extra, none missing."""
    registry = _registry()
    seen_verbs = seen_params = seen_reserved = 0

    for system in _grant_systems():
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

    expected_verbs = sum(len(_granted(registry, s)) for s in _grant_systems())
    expected_params = sum(
        len(model_facing_params(fn))
        for s in _grant_systems() for fn in _granted(registry, s).values()
    )
    assert (seen_verbs, seen_params) == (expected_verbs, expected_params)

    assert seen_reserved >= 1, (
        "no granted verb reserves a wrapper-only param — the wrapper-only assertions above "
        "never executed and this test no longer pins them"
    )


def test_o1_every_published_param_is_accepted_and_an_unpublished_one_is_refused(tmp_path):
    """O1, the heart of the suite — the round trip through the ENFORCER."""
    registry = _registry()
    checked = 0

    for system in _grant_systems():
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

    assert checked == sum(len(_granted(registry, s)) for s in _grant_systems())


def test_o1_the_required_optional_split_and_the_defaults_round_trip(tmp_path):
    """O1, defaults half — the tool publishes each param's default, and the required/optional
    split it thereby asserts is the one `validate_params` enforces."""
    registry = _registry()
    saw_default_value = 0

    for system in _grant_systems():
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


def test_o3_no_published_type_claims_more_than_validate_params_enforces(tmp_path):
    registry = _registry()
    checked = 0

    for system in _grant_systems():
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

    reachable = sum(
        len(model_facing_params(fn))
        for s in _grant_systems() for fn in _granted(registry, s).values()
    )
    assert checked >= reachable - 2, f"only {checked} type claims were checked of {reachable}"


def test_o3_an_unresolvable_annotation_is_published_as_type_unenforced(tmp_path):
    """O3 — the case the shipped adapters do not reach, driven through the registry seam."""
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
    registry = _registry()
    answers = {s: _ask(registry, s, tmp_path) for s in {s for s, _ in _WITHHELD}}

    declared = read_roster(_ADAPTERS)
    for system, verb in _WITHHELD:
        assert verb in declared.declared_verbs(system), (
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
    registry = _registry()
    for system in _grant_systems():
        published = {v for _, v in _parse(_ask(registry, system, tmp_path))}
        assert published == set(_granted(registry, system)), f"{system}: {sorted(published)}"


def test_o4_an_unknown_system_degrades_loudly_and_names_it(tmp_path):
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
    failure is contained to that system."""
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


def test_list_verbs_writes_no_queries_row_and_leaves_the_guards_untouched(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='lv900')

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
    whole function, `host` included. This module carries `from __future__ import annotations`"""
    return []
