"""#872 — O7/M6's seam, the gate's reach, and provenance
(`d19`, `d20`, `d21`, `d22`, `d23`, `d35`, `d40`, `d44`, `d59`, `d74`, `d75`).

O1 is UNDRIVABLE on the shipped tree — all fourteen registered tools are annotated `-> str`
except `query`, and `query`'s dict is discarded by `QueryCapture` at every candidate seam — so
the seam is part of the contract rather than a test convenience. Every demand here is
therefore an OUTCOME: install a foreign toolset through the declared seam and read the
model-visible text. Signature inspection discharges nothing, and there is no
`monkeypatch.setattr` anywhere in this suite.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

import toons  # noqa: E402

from pydantic_ai.capabilities import AbstractCapability  # noqa: E402

from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    ToolRoster,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e._toon872 import (  # noqa: E402
    REPO_ROOT,
    RUN_ID,
    Dispatched,
    PartRecorder,
    agent_run,
    corpus,
    foreign_toolset,
    framed_content,
    owned_toolset,
    run_isolated,
    toon_rows,
    wire_text,
)
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402

pytestmark = pytest.mark.e2e


def _payload() -> dict:
    return toon_rows(corpus()["fx-33"])


def _gather_turn(lead: str = "l-001") -> Turn:
    return Turn(tool_calls=[("gather", {
        "lead_id": lead, "system": "elastic", "goal": "measure this lead",
        "what_to_summarize": ["auth events"],
    })])


def test_a_foreign_toolset_injected_at_the_entry_point_reaches_the_model_through_the_gate(
    tmp_path: Path,
) -> None:
    """A foreign dict-returning toolset installed through the declared seam at
    `run_investigation` is offered to the model, called, and its result reaches the model as
    the framed TOON view.

    DELIBERATELY NOT "run_investigation accepts a toolset= parameter". A dependency the design
    gives no seam makes the seam part of the contract, and the contract is an OUTCOME:
    signature inspection would certify that a field exists and say nothing about whether the
    toolset is wired to the agent the model talks to, which is the escape the whole demand set
    is written against.

    TWO THREADING SITES, not one: `run.py`'s single production call and the replay harness's
    `seams` dict, which already threads seven. This drives the second, which is the one a test
    can reach without a provider.
    """
    value = _payload()
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    main = PartRecorder([Turn(tool_calls=[("fetch_rows", {})]), Turn(text="Complete.")])
    drive(run_dir, run_id=RUN_ID, main=main, toolset=foreign_toolset(value))

    view = main.dispatched.text("fetch_rows")
    assert framed_content(view) == toons.dumps(value), (
        "the foreign result did not reach the model as the framed TOON view"
    )


def test_the_gate_declares_its_encoder_and_toolset_seams_at_the_composition_root(
    tmp_path: Path,
) -> None:
    """The gate's two dependencies enter through declared seams at the composition root: the
    foreign TOOLSET threads from `run_investigation` into `build_agent_core`, and the ENCODER is
    a constructor argument the same build site accepts.

    A dependency the design gives no seam makes the seam part of the contract, and O9(b) is
    what forces the second one: its oracle is stated as "for a payload the validator refuses,
    the encoder is NEVER CALLED — observable on a spy encoder's call count, not inferred from
    the return value", and a refusal and a fault are indistinguishable from outside the gate.
    The project profile forbids `monkeypatch.setattr`, so a value the build is handed is the
    only route the house allows.

    Driven rather than inspected: the encoder seam is observed by handing one build a spy and
    two payloads that must produce DIFFERENT call counts through it — a refused one (0) and a
    substituting one (1) — which no signature check could establish; the toolset seam is
    observed by threading a foreign toolset from the entry point and reading the model-visible
    text at the far end.

    IT IS ALSO THE SEGFAULT CONTAINMENT the rest of this suite rests on: `toons.dumps` SIGSEGVs
    on a self-referential container and on a deep acyclic one, so a sealed encoder is what lets
    a wrong implementation fail a test rather than end the process running it.
    """
    value = _payload()
    from defender.tests.e2e._toon872 import EncoderFault, SpyEncoder

    sealed = SpyEncoder(EncoderFault(dumps_returns="<the encoder must not have been called>"))
    refused = agent_run(toolset=foreign_toolset({"rows": [{"a": "x" + chr(0)}]}), encoder=sealed)
    assert refused.error is None
    assert sealed.dumps_calls == 0, "the encoder seam is not the object the gate calls"

    spy = SpyEncoder()
    substituted = agent_run(toolset=foreign_toolset(value), encoder=spy)
    assert spy.dumps_calls == 1, (
        "the injected encoder is never reached, so every call count this suite reads through "
        "it is measuring nothing"
    )
    assert framed_content(substituted.dispatched.text()) == toons.dumps(value)

    run_dir = materialize(tmp_path, GOLDEN_AB3)
    main = PartRecorder([Turn(tool_calls=[("fetch_rows", {})]), Turn(text="Complete.")])
    drive(run_dir, run_id=RUN_ID, main=main, toolset=foreign_toolset(value))
    assert framed_content(main.dispatched.text("fetch_rows")) == toons.dumps(value), (
        "the toolset seam does not thread from the entry point to the agent the model talks to"
    )


def test_the_shipped_tool_set_is_unchanged_when_the_seam_is_not_supplied(
    tmp_path: Path,
) -> None:
    """A run that supplies nothing at the new seam offers the model an IDENTICAL tool set,
    capability list and model-visible text to today's, and no foreign tool is callable.

    A DI seam that defaults to something is how a test hook becomes a production hole. The
    roster is read off `AgentInfo.function_tools` — the tool definitions as the MODEL is
    offered them — which is the only honest place to read a registration from: a registry
    entry, or an annotation re-inspected off the function object, would both pass while the
    wire carried something else.

    BOUND ON EVERY SURFACE THE ABSENCE COULD REACH: the roster the model is offered, and the
    text of every part it receives. `d20` is the positive control and is driven here too, in
    the same shape, so "no foreign tool" is not green merely because nothing was installed
    anywhere.
    """
    bare_dir = materialize(tmp_path / "bare", GOLDEN_AB3)
    bare = ToolRoster([Turn(text="Complete.")])
    drive(bare_dir, run_id=RUN_ID, main=bare)
    bare_names = sorted(t.name for t in (bare.tool_defs or []))
    assert bare_names, "the roster was never captured, so this negative reads an empty list"
    assert "fetch_rows" not in bare_names
    assert all("fetch_rows" not in seen for seen in bare.seen)

    with_dir = materialize(tmp_path / "with", GOLDEN_AB3)
    supplied = ToolRoster([Turn(tool_calls=[("fetch_rows", {})]), Turn(text="Complete.")])
    drive(with_dir, run_id=RUN_ID, main=supplied,
          toolset=foreign_toolset(_payload()))
    supplied_names = sorted(t.name for t in (supplied.tool_defs or []))
    assert "fetch_rows" in supplied_names, (
        "the seam installs nothing even when supplied, so the negative above is vacuous"
    )
    assert sorted(set(supplied_names) - {"fetch_rows"}) == bare_names, (
        "supplying the seam changed the shipped tool set beyond adding the foreign tool"
    )


def test_the_seams_presence_or_absence_holds_for_every_call_across_the_whole_run(
    tmp_path: Path,
) -> None:
    """A toolset supplied once at `run_investigation` holds for EVERY call across the whole
    run — the way the nine existing optional seams do — and its absence holds for every call
    too.

    The failure this forbids is a seam wired per-turn or per-agent-build: a gate that covered
    the first foreign call and not the third would satisfy every single-call demand in this
    suite. Three calls are driven across three separate model turns, so each crosses a fresh
    request/response round, and all three are asserted.
    """
    value = _payload()
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    main = PartRecorder([
        Turn(tool_calls=[("fetch_rows", {})]),
        Turn(tool_calls=[("fetch_rows", {})]),
        Turn(tool_calls=[("fetch_rows", {})]),
        Turn(text="Complete."),
    ])
    drive(run_dir, run_id=RUN_ID, main=main, toolset=foreign_toolset(value))

    texts = main.dispatched.texts("fetch_rows")
    assert len(texts) == 3, f"expected three foreign returns in the final history, got {len(texts)}"
    for i, text in enumerate(texts):
        assert framed_content(text) == toons.dumps(value), (
            f"call {i + 1} of 3 was not gated — the seam did not hold for the whole run"
        )


def test_a_foreign_toolset_installed_but_never_called_leaves_the_run_identical() -> None:
    """A foreign toolset installed at the seam but never CALLED leaves the run identical: no
    encode, no decode, no substitution, nothing framed that was not framed before.

    ALTITUDE NOTE, and it is why this test carries its control inline: the assertion is vacuous
    on its own — it passes over a gate that was never installed at all — so `d20`'s outcome is
    driven in the same test. What the pair establishes is that the gate acts on results and
    not on installation.
    """
    idle = agent_run(toolset=foreign_toolset(_payload()), calls=[])
    assert idle.encoder.dumps_calls == 0
    assert idle.encoder.loads_calls == 0
    assert idle.dispatched.parts == []

    called = agent_run(toolset=foreign_toolset(_payload()))
    assert called.encoder.dumps_calls == 1, (
        "the installed toolset is never gated even when called, so the idle assertion above "
        "is about a gate that does nothing"
    )


def test_call_tool_receives_the_tools_own_return_with_a_capture_shaped_capability_installed() -> None:
    """`call_tool` receives the TOOL'S OWN return value in either capability order, including
    with a capture-shaped capability that discards the wrapper's return.

    The discriminator that decided f4, driven as a test. The wrapper's INPUT is the invariant,
    not its return: `call_tool` is not the last word — the library applies the first capability
    outermost, so an outer `wrap_tool_execute` overrides what the wrapper returns, and
    `QueryCapture` does exactly that for `query` today. That cost is a CONTRACT, not a caveat
    (`d69` is the examined no).

    Both orders are driven, plus the order the composition root actually produces
    (`[Hooks, *extra, QueryCapture]`, first outermost). Installing at `wrap_tool_execute` or
    `after_tool_execute` instead was REJECTED: both are ordering-dependent against
    `QueryCapture`, and `test_query_tool_611.py` already pins that capture must not take
    `after_tool_execute`.
    """
    value = _payload()

    class Capture(AbstractCapability):
        """A capture-shaped capability: it awaits the handler, records what it got, and
        returns its OWN string — `QueryCapture`'s shape, without its policy."""

        def __init__(self) -> None:
            self.seen: list = []

        async def wrap_tool_execute(self, ctx, *, call, args, handler, **_):  # noqa: ANN001, ANN003
            result = await handler(args)
            self.seen.append(result)
            return "capture's own rendering"

    outer = Capture()
    out = agent_run(toolset=foreign_toolset(value), extra=(outer,))
    assert out.encoder.dumps_calls == 1, "the wrapper never saw the tool's value"
    assert outer.seen, "the capture-shaped capability never ran"
    assert out.dispatched.text() == "capture's own rendering", (
        "the outer hook did not override the wrapper's return, so the ordering this demand "
        "is about is not the ordering under test"
    )
    assert framed_content(str(outer.seen[0])) == toons.dumps(value), (
        "the wrapper was handed something other than the tool's own value"
    )


def test_the_query_tool_path_is_byte_identical_with_the_gate_installed(
    tmp_path: Path,
) -> None:
    """With the gate installed the model still sees `QueryCapture`'s rendered salt-wrapped
    string for `query`, the executed-queries row is still appended — and a foreign dict in the
    SAME run is substituted.

    The gate's inertness on the shipped tree is a CONTRACT, not an accident. `query` is the one
    registered tool annotated `-> Any` and the only in-tree dict crossing the seam, and
    `QueryCapture.wrap_tool_execute` discards `call_tool`'s return for it at every candidate
    placement — so O1 is unreachable through defender's own tools and O2 must hold for them.

    The foreign call in the same run is what makes this a survival demand rather than a
    tautology: without it, "the query path is unchanged" is green over a gate that never fired.
    It is also the positive control `d27` and `d29` name.
    """
    from defender._io import read_jsonl_rows
    from defender._run_paths import RunPaths

    def _run(root: Path, toolset):
        run_dir = materialize(root, GOLDEN_AB3)
        rec = VerbRecorder()
        main = PartRecorder([
            _gather_turn(),
            *([Turn(tool_calls=[("fetch_rows", {})])] if toolset is not None else []),
            Turn(text="Complete."),
        ])
        gather = PartRecorder([q("elastic", "query", {"native_query": "FROM logs"}), DONE])
        drive(run_dir, run_id=RUN_ID, main=main, gather=gather,
              verbs=elastic_ok(rec), toolset=toolset)
        return run_dir, main, gather

    idle_dir, _, idle_gather = _run(tmp_path / "idle", None)
    live_dir, live_main, live_gather = _run(tmp_path / "live", foreign_toolset(_payload()))

    assert read_jsonl_rows(RunPaths(live_dir).executed_queries), (
        "no executed-queries row was written, so the query path did not run"
    )
    assert live_gather.dispatched.text("query") == idle_gather.dispatched.text("query"), (
        "the query tool's model-visible text changed in the run where the gate was active"
    )
    assert re.search(r"<run-[0-9a-f]+-untrusted>", live_gather.dispatched.text("query")), (
        "query's own rendering lost its frame, so the comparison above is over empty text"
    )
    assert read_jsonl_rows(RunPaths(live_dir).executed_queries) == read_jsonl_rows(
        RunPaths(idle_dir).executed_queries), "the queries table diverged between the two runs"
    assert framed_content(live_main.dispatched.text("fetch_rows")) == toons.dumps(
        _payload()), "no foreign substitution happened, so the inertness above proves nothing"


def test_an_owned_agent_tool_result_is_untouched_while_a_foreign_one_is_gated() -> None:
    """An owned `@agent.tool` result and a foreign toolset's tool OF THE SAME NAME are driven
    in ONE run, and only the foreign one is gated.

    Provenance-gated, decided at §7 r2 (P1 = B). The gate reads the toolset's label at the
    seam and substitutes only for results it marks foreign, which is what keeps O2 true for the
    13 of 14 registered tools annotated `-> str` with NOTHING ENFORCING the annotation: under
    the provenance-blind reading, any of them returning a dict would have had its model-visible
    text silently changed.

    THE SAME NAME IS THE POINT: a name list would pass a same-named foreign tool. It cannot be
    driven in ONE run, and that is a library constraint rather than an omission — pydantic-ai
    refuses the registration outright (`UserError: FunctionToolset defines a tool whose name
    conflicts with existing tool from the agent: 'fetch_rows'`, executed against 1.107.0), so
    two tools of one name never coexist on one agent. It IS drivable across two runs, and that
    is the form the discriminator takes here: ONE tool name, ONE payload, TWO provenances,
    OPPOSITE verdicts. Any implementation that is a function of the tool's NAME gives the same
    answer twice and fails, whichever answer it gives; only something that reads the toolset's
    own label can give two.

    The one-run arm below is kept as well, at the two names the library permits, because it is
    the only place the two verdicts are read out of a SINGLE dispatched history — a gate that
    got provenance right per-build and wrong per-call would pass the two-run arm.

    The library constraint is recorded in `handoff.deviations` beside the other five, so a
    later reader does not read the two-run shape as a weakening someone chose.
    """
    value = _payload()

    # THE SAME-NAME DISCRIMINATOR, at the finest grain the library allows.
    foreign = agent_run(toolset=foreign_toolset(value, name="fetch_rows"))
    owned = agent_run(toolset=owned_toolset(value, name="fetch_rows"))
    assert framed_content(foreign.dispatched.text("fetch_rows")) == toons.dumps(value), (
        "the foreign `fetch_rows` was not gated"
    )
    assert owned.dispatched.text("fetch_rows") == wire_text(value), (
        "the OWNED `fetch_rows` — same name, same payload — was gated too, so the verdict is a "
        "function of the tool's name and a same-named foreign tool would walk through a name list"
    )

    # THE ONE-RUN ARM, at the two names one agent can carry.
    def own_rows() -> dict:
        return value

    out = agent_run(
        toolset=foreign_toolset(value, name="fetch_rows"),
        own_tool=own_rows,
        calls=[("fetch_rows", {}), ("own_rows", {})],
    )
    foreign_text = out.dispatched.text("fetch_rows")
    owned_text = out.dispatched.text("own_rows")

    assert framed_content(foreign_text) == toons.dumps(value), (
        "the foreign result was not gated"
    )
    assert owned_text == wire_text(value), (
        "an owned tool's model-visible text was changed by the gate — exactly what O2 forbids"
    )


def test_an_unlabelled_toolset_is_treated_as_foreign_and_only_the_composition_root_marks_owned() -> None:
    """An UNLABELLED toolset is treated as foreign — gated and framed — and a toolset carrying
    defender's owned label is not.

    THE WHOLE COST OF P1 READING B, and the human took B knowing it. Three things the
    resolution names, and a test pinning one goes green over an implementation that got the
    other two wrong. WHAT THE LABEL IS: the gate reads the toolset's own metadata at the seam,
    applied here through the production marker rather than by spelling a key in the test.
    WHO MAY SET IT: `owned` is a property of the INSTALLATION SITE — defender's own composition
    root marks the tools it registers, which is why an owned `@agent.tool` is untouched
    (`d19`). WHAT AN UNLABELLED TOOLSET DEFAULTS TO: FOREIGN, the safe direction, because an
    unlabelled foreign source is then gated and framed rather than silently exempt.

    The mislabel hazard in the other direction — a foreign source installed with an owned label
    — is the accepted limitation at `d60` and is deliberately not defended here.
    """
    value = _payload()
    unlabelled = agent_run(toolset=foreign_toolset(value, name="fetch_rows"))
    assert framed_content(unlabelled.dispatched.text()) == toons.dumps(value), (
        "an unlabelled toolset defaulted to owned — the unsafe direction"
    )

    labelled = agent_run(toolset=owned_toolset(value, name="fetch_rows"))
    assert labelled.encoder.dumps_calls == 0, "an owned-labelled toolset reached the encoder"
    assert labelled.dispatched.text() == wire_text(value), (
        "an owned-labelled result was gated or framed"
    )


def test_every_build_function_routes_through_the_site_that_installs_the_gate(
    tmp_path: Path,
) -> None:
    """Each of the FIVE BUILD FUNCTIONS is invoked as itself — `build_agent`,
    `build_gather_agent`, `build_stage_agent`, `build_judge_agent` and `review_roles`' injected
    `build` seam — and the agent each one returns gates a foreign result.

    §7 r5 split P2: reading A for the CAPABILITY (constructed at the single `Agent(...)` in
    `build_agent_core`, so no build path can be silently missed — there are five and the
    original census found one) and reading B for the TOOLSET.

    THE CENSUS CLAIM IS ABOUT THE FUNCTIONS, NOT ABOUT THE DEFINITIONS, and that distinction is
    the whole of this demand (`92-reconciliation.md` F5). Calling `build_agent_core` five times
    with five `AgentDefinition`s establishes that the gate's construction is
    definition-independent; it says nothing about whether `build_agent` and the other four
    still ROUTE through that site, which is the only thing reading A was bought for and the
    exact failure the original census found once: a build path that constructs its own agent.
    So each build function is called here, with its own signature and its own dependencies, and
    what is asserted about the result is the GATE'S EFFECT on a foreign result it is handed.
    An `isinstance` sweep over the capability list would certify that a field exists and never
    that it is wired; a re-drive of the shared site would certify nothing about the callers.

    THE FOREIGN TOOLSET ARRIVES AT RUN TIME for the four that build an agent directly, because
    none of them takes the `toolset=` seam — §7 r5 gave that to `run_investigation` alone — and
    pydantic-ai applies a capability's wrapper to run-level toolsets as well (executed; see
    `run_with_foreign_toolset`). The review lens is the exception and takes the seam it has:
    `live_review_stages(build=...)` is a declared DI seam whose production default IS
    `build_agent_core` (`review_roles.py:249`), so the lens is driven through it end to end —
    built, bound and RUN by `_make_live_stage`'s own body.

    The lanes this reaches but does not drive END TO END — the three review lenses and the six
    learning stages in their own runtimes, where which salt frames a tool return is unprobed —
    are the examined no at `d68`. The reach is asserted here; the coverage is not claimed.
    """
    import types

    from defender.agents import AGENTS
    from defender.learning.core.config import StageWiring
    from defender.learning.pipeline._pydantic_stage import build_stage_agent
    from defender.learning.pipeline.judge.engine_pydantic import build_judge_agent
    from defender.runtime import challenge_gate, driver, review_roles
    from defender.runtime.agent_definition import AgentRole
    from defender.tests.e2e._toon872 import (
        DEFENDER,
        SpyEncoder,
        _deps,
        _NullLogger,
        probe_model,
        run_with_foreign_toolset,
    )

    value = _payload()
    expected = toons.dumps(value)

    def _check(label: str, dispatched) -> None:
        text = dispatched.text("fetch_rows")
        assert framed_content(text) == expected, (
            f"{label} returned an agent whose foreign result is not gated — the build path "
            "does not route through the composition root that installs the gate"
        )

    # 1 — MAIN. `build_agent` is the one build path that takes NO `extra_capabilities`, which
    # is why B2/F6 named it: it is the path a capability added at any other site would miss.
    make_model, rec = probe_model()
    agent = driver.build_agent(DEFENDER, _NullLogger(), make_model,
                               bounds=challenge_gate.Bounds())
    _check("build_agent", run_with_foreign_toolset(
        agent, _deps(AGENTS[AgentRole.MAIN]), rec, value))

    # 2 — the gather subagent, one per lead.
    make_model, rec = probe_model()
    agent = driver.build_gather_agent(DEFENDER, _NullLogger(), "gather:l-001", make_model)
    _check("build_gather_agent", run_with_foreign_toolset(
        agent, _deps(AGENTS[AgentRole.GATHER]), rec, value))

    # 3 — a learning stage. The wiring's prompt is the real one on disk, so the definition the
    # stage builds from is the definition production builds from.
    make_model, rec = probe_model()
    wiring = StageWiring(
        prompt_path=DEFENDER / "learning" / "pipeline" / "malicious_actor" / "prompt.md",
        model=AGENTS[AgentRole.ACTOR].model(), effort=None,
        trace_name="actor", label="actor",
    )
    agent = build_stage_agent(AGENTS[AgentRole.ACTOR].deps_cls, wiring, _NullLogger(),
                              make_model=make_model)
    _check("build_stage_agent", run_with_foreign_toolset(
        agent, _deps(AGENTS[AgentRole.ACTOR]), rec, value))

    # 4 — the judge. A separate function even though it delegates to build_stage_agent: the
    # census is over the functions a caller can reach, and this is one of them.
    make_model, rec = probe_model()
    wiring = StageWiring(
        prompt_path=DEFENDER / "learning" / "pipeline" / "judge" / "malicious.md",
        model=AGENTS[AgentRole.JUDGE].model(), effort=None,
        trace_name="judge", label="judge",
    )
    agent = build_judge_agent(wiring, _NullLogger(), make_model=make_model)
    _check("build_judge_agent", run_with_foreign_toolset(
        agent, _deps(AGENTS[AgentRole.JUDGE]), rec, value))

    # 5 — a review lens, through the injected `build` seam whose production default is
    # `build_agent_core`. The lens builds AND runs its own agent inside `_make_live_stage`, so
    # the toolset is supplied at the seam rather than at the run.
    make_model, rec = probe_model()
    spy = SpyEncoder()
    built_for: list[str] = []

    def _build(defn, **kw):
        built_for.append(kw.get("agent_id", ""))
        return driver.build_agent_core(
            defn, make_model=make_model, toolset=foreign_toolset(value),
            toon_encoder=spy, **kw,
        )

    run_dir = tmp_path / "review"
    run_dir.mkdir(parents=True, exist_ok=True)
    stages = review_roles.live_review_stages(
        run_dir, DEFENDER, logger=_NullLogger(), build=_build)
    import asyncio
    asyncio.run(stages.stage("support")(types.SimpleNamespace(prompt="go")))
    assert built_for == ["review:support"], (
        "the review lens did not reach the injected build seam, so this arm says nothing "
        f"about the lens's build path (saw {built_for!r})"
    )
    _check("review_roles' injected build", Dispatched(rec.requests, []))


def test_a_missing_toons_wheel_refuses_the_gate_without_killing_any_build_path() -> None:
    """With `toons` absent, `build_agent_core` still builds an agent on every one of its five
    build paths, AND a foreign call in that child still reaches the model with the tool's own
    JSON rather than a propagated ImportError.

    THE SECOND HALF IS THE DEMAND'S OWN SENTENCE AND IT USED TO BE ASSERTED NOWHERE
    (`92-reconciliation.md` F8). "The import is deferred AND cannot take down a build path" is
    two claims; blocking `toons` and asserting five builds drives only the deferral, because a
    module-scope import would have failed the child at import time. An implementation that
    defers the import and then raises at the first foreign call passes that half and fails the
    demand — so the child drives a foreign call too, and the observable is what the model got:
    the tool's own wire JSON, present in the delivered text, with nothing raised.

    THE OBSERVABLE THIS ARM IMPLIES IS A FACT, NOT A DECISION — which is exactly the question
    §7 left open. The import is DEFERRED (function-scope, at the seam), never module-scope,
    because with the gate at the single `Agent(...)` a module-scope `import toons` fails at
    IMPORT time and kills MAIN, the gather subagent, the three review lenses, the six learning
    stages and the judge TOGETHER. That is the negative arm, and it is what the block on the
    meta path makes observable.

    Two probed facts settle the shape. PACKAGING: `toons` is not a core dependency and ships
    only in the `runtime` extra ALONGSIDE `pydantic-ai-slim`, and `driver.py` imports
    pydantic-ai at module scope, so a process that can reach the gate's install site
    necessarily has the extra — "the encoder is missing at a live seam" is not reachable
    through a supported configuration. PRECEDENT: the tree's only two consumers of that extra
    both defer and refuse LOUDLY. A run-record `degraded` field is harmless but NOT PINNABLE —
    nothing could drive it in a supported install — so no demand asserts one.
    """
    child = '''
import json, sys

class _Block:
    def find_module(self, name, path=None):
        return self.find_spec(name, path)
    def find_spec(self, name, path=None, target=None):
        if name == "toons" or name.startswith("toons."):
            raise ImportError("no toons wheel in this environment")
        return None

sys.meta_path.insert(0, _Block())
sys.modules.pop("toons", None)

import importlib
from defender.runtime import driver
from defender.agents import AGENTS
from defender.runtime.agent_definition import AgentRole, ToolSet, bind
from dataclasses import replace
from pathlib import Path
import tempfile

from defender.runtime.agent_definition import DENY_ALL, RunScope
from defender.runtime.providers import BuiltModel
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.toolsets import FunctionToolset
import asyncio

class _L:
    def log(self, **kw): pass
    def log_budget_refusal(self, **kw): pass

DEFENDER_DIR = Path(driver.__file__).resolve().parents[1]

def _stripped(role):
    # The same strip `_toon872._defn` makes, and for the same reason: three of the five roles
    # carry a non-empty `verb_grant` or a corpus, and `bind` refuses a definition whose
    # verb-bearing tool bit is off while its grant is not.
    return replace(AGENTS[role], tools=ToolSet(), write_shapes=(), bash_shapes=(),
                   budget_enforced=False, verb_grant=DENY_ALL, corpus_dirs=(),
                   requires_corpus=False)

def _bound(defn):
    run_dir = Path(tempfile.mkdtemp())
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    scope = RunScope(read_confine=(run_dir,)) if defn.requires_confine else RunScope()
    return bind(defn, run_dir, scope=scope, defender_dir=DEFENDER_DIR)

built = []
for role in (AgentRole.MAIN, AgentRole.GATHER, AgentRole.SUPPORT, AgentRole.ACTOR,
             AgentRole.JUDGE):
    defn = _stripped(role)
    deps = _bound(defn)
    def model(messages, info):
        return ModelResponse(parts=[TextPart(content="done")])
    agent = driver.build_agent_core(
        defn, deps_type=type(deps), instructions="x", logger=_L(), agent_id="a",
        make_model=lambda n, e: BuiltModel(FunctionModel(model), None),
    )
    built.append(agent is not None)

# THE SECOND HALF: the gate's own work refused rather than propagated. The toolset is
# supplied at RUN time, so this arm needs no build-time seam and stays a statement about the
# encoder's absence rather than about the toolset seam.
value = {"rows": [{"a": i, "b": "row-%d" % i} for i in range(40)]}
ts = FunctionToolset()
def fetch_rows():
    return value
ts.tool_plain(fetch_rows)

requests = []
turn = {"n": 0}
def caller(messages, info):
    requests.append(list(messages))
    turn["n"] += 1
    if turn["n"] == 1:
        return ModelResponse(parts=[ToolCallPart(tool_name="fetch_rows", args={})])
    return ModelResponse(parts=[TextPart(content="done")])

defn = _stripped(AgentRole.MAIN)
deps = _bound(defn)
agent = driver.build_agent_core(
    defn, deps_type=type(deps), instructions="x", logger=_L(), agent_id="a",
    make_model=lambda n, e: BuiltModel(FunctionModel(caller), None),
)
raised = None
try:
    asyncio.run(agent.run("go", deps=deps, toolsets=[ts]))
except BaseException as exc:
    raised = type(exc).__name__

parts = [p for msg in (requests[-1] if requests else [])
         for p in getattr(msg, "parts", []) if isinstance(p, ToolReturnPart)]
delivered = parts[0].content if parts else None
baseline = ToolReturnPart(tool_name="probe", content=value,
                          tool_call_id="probe").model_response_str()

print(json.dumps({
    "built": built,
    "foreign_raised": raised,
    "delivered": delivered if isinstance(delivered, str) else None,
    "baseline": baseline,
}))
'''
    outcome = run_isolated(child, timeout=120.0)
    assert outcome.returncode == 0, (
        "a missing toons wheel killed a build path — the import is module-scope, which with "
        f"the gate at the single Agent(...) kills all five together: {outcome.stderr[-800:]}"
    )
    result = json.loads(outcome.stdout.strip().splitlines()[-1])
    assert result["built"] == [True] * 5
    assert result["foreign_raised"] is None, (
        "the gate PROPAGATED its own missing dependency to a foreign call "
        f"({result['foreign_raised']}) instead of refusing its own work"
    )
    assert result["delivered"] is not None, (
        "a foreign result reached the model as something other than text with `toons` absent "
        "— the refusal arm does not stringify, so the gate is not on this path at all"
    )
    assert result["baseline"] in result["delivered"], (
        "the model did not receive the tool's own wire JSON with `toons` absent, so the "
        "refusal rewrote or lost the payload instead of passing it through"
    )


def test_the_golden_case_generators_subprocess_child_carries_the_gate() -> None:
    """The golden-case generator's subprocess child reaches `build_agent_core`, so the gate is
    on that path unconditionally.

    `evals/oracle_golden/generate_case.py` re-executes `defender/run.py` as a SUBPROCESS, and
    that child reaches `build_agent_core` REGARDLESS of the ambient environment: `run.py` puts
    the real repo root on `sys.path` itself, so the install site is on the child's path with
    `PYTHONPATH` set and with it unset alike (`cN13`, executed both ways).

    MODELLED, NOT WAIVED — for this half no waiver is available at all, because the reach is
    unconditional and executed. The other subprocess driver context, `evals/harness_lead.py`,
    IS waived (`d76`): the harness copies only `learning/`, `_untrusted.py` and `skills/` into
    its temp tree, so in a clean environment `defender.runtime` does not resolve and the child
    dies at import before any agent is built.

    Driven, not read: the child is spawned with `PYTHONPATH` DELETED, which is the ambient
    condition the reach must not depend on, and it reports whether the gate's install site
    resolved and was exercised.
    """
    child = '''
import json, os, sys

# `run.py:39-40`'s own move, reproduced: the re-executed child puts the real repo root on
# sys.path ITSELF, which is why the reach does not depend on the ambient environment. The
# inherited PYTHONPATH is deleted first, so anything that resolves below resolves the way the
# generator's child resolves it and not the way this test process was launched.
os.environ.pop("PYTHONPATH", None)
for name in [m for m in sys.modules if m == "defender" or m.startswith("defender.")]:
    del sys.modules[name]
sys.path.insert(0, RUN_PY_ROOT)

from defender.tests.e2e import _toon872 as T
import toons

value = T.toon_rows(T.corpus()["fx-33"])
out = T.agent_run(toolset=T.foreign_toolset(value))
print(json.dumps({
    "gated": T.framed_content(out.dispatched.text()) == toons.dumps(value),
    "encoded": out.encoder.dumps_calls,
}))
'''
    outcome = run_isolated(child.replace("RUN_PY_ROOT", repr(str(REPO_ROOT))),
                           timeout=120.0, pythonpath=False)
    assert outcome.returncode == 0, (
        f"the re-executed child did not reach the gate's install site: {outcome.stderr[-800:]}"
    )
    result = json.loads(outcome.stdout.strip().splitlines()[-1])
    not_on_path = ("the golden-case generator's child builds an agent the gate is not on, so "
                   "any behavior change this gate makes would not land in the generated cases")
    assert result["encoded"] == 1, not_on_path
    assert result["gated"] is True, not_on_path
