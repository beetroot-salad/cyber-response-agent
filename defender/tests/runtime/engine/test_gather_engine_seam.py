"""Gather-engine seams (no model): dispatch prompt composition and cache order, malformed system/goal retried at the seam, one session per lead_id, lead_id validation."""
from __future__ import annotations

from dataclasses import replace as _with_live_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _live_run_1165

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[3]

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UsageLimitExceeded  # noqa: E402

from defender.runtime import tools  # noqa: E402
from defender.runtime.agent_definition import bind, compile_policy_for  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106


def _deps() -> tools.AgentDeps:
    return tools.AgentDeps(
        run_dir=Path("/tmp/x"), defender_dir=_DEFENDER, run_id="r",
        policy=compile_policy_for(MAIN_DEF, run_dir=Path("/tmp/x"), defender_dir=_DEFENDER),
        cwd_anchor=Path("/tmp/x"),
    )


def test_835_the_per_lead_dispatch_comes_last_behind_the_two_fixed_indexes():
    """Section ORDER is the cache prefix (#835). The descriptor index and the template index vary
    only with the dispatched system and the tree; the Dispatch YAML varies with every lead."""
    deps = _deps()
    cat = "- `elastic`: desc"
    a = tools._gather_prompt(deps, tools.GatherRequest("l-001", "elastic", "g1", ("d",)), cat)
    b = tools._gather_prompt(deps, tools.GatherRequest("l-002", "elastic", "g2", ("e",)), cat)
    other = tools._gather_prompt(deps, tools.GatherRequest("l-003", "cmdb", "g3", ("d",)), cat)

    for prompt in (a, b, other):
        assert prompt.index("## Query templates") < prompt.index("## Dispatch")
        assert prompt.index("## Systems of record") < prompt.index("## Query templates")

    shared = a.split("## Dispatch")[0]
    assert b.startswith(shared), "two leads on one system no longer share a prompt prefix"
    assert "## Query templates" in shared
    assert "elastic.sshd-auth-history" in shared
    assert not other.startswith(shared), "the prefix stopped varying with the dispatched system"

    assert "lead_id: l-001" in a.split("## Dispatch")[1]
    assert a.endswith("```\n"), "something was appended after the lead's own question"


def test_a_malformed_system_is_retried_at_the_seam_not_silently_degraded(tmp_path):
    """#835 made `system` load-bearing twice: it selects the template index's on-target tier, and it
    is the prompt-cache lane key the composition root hands the provider."""
    import asyncio

    from defender.runtime import tools_gather
    from defender.runtime.agent_definition import bind
    from pydantic_ai.exceptions import ModelRetry

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    deps = _with_run_state(_with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=_DEFENDER), run=_live_run_1165(run_dir)))

    def _never(agent_id, system, request_limit):  # pragma: no cover — reaching it IS the failure
        raise AssertionError(f"a malformed system reached the factory: {system!r}")

    for bad in ("Elastic", "elastic\nx", "el astic", "e" * 200):
        with pytest.raises(ModelRetry, match="malformed system"):
            asyncio.run(tools_gather._run_gather(
                deps, _never, 40,
                tools_gather.GatherRequest("l-001", bad, "goal", ("what",)),
                T1106.fixture_grants().gather, catalog=None,
            ))
    assert not list((run_dir / "gather_raw").glob("*.lead.json")), \
        "a rejected dispatch claimed the lead id anyway — the retry cannot reuse it"

    seen: list[str] = []

    class _Stop:
        async def run(self, *a, **kw):
            raise UsageLimitExceeded("far enough — the dispatch was admitted")

    def _record(agent_id, system, request_limit):
        seen.append(system)
        return _Stop()

    asyncio.run(tools_gather._run_gather(
        deps, _record, 40,
        tools_gather.GatherRequest("l-002", "ghost", "goal", ("what",)),
        T1106.fixture_grants().gather, catalog=None,
    ))
    assert seen == ["ghost"], "a well-formed system outside the ROLE grant must still dispatch"


class _StopAfterDispatch:
    """A gather agent that proves the dispatch was ADMITTED and gets no further: reaching
    `.run` is the observation, and `UsageLimitExceeded` is the arm `_run_gather` degrades into
    a summary rather than one that would need a whole replay model behind it."""

    async def run(self, *a, **kw):
        raise UsageLimitExceeded("far enough — the dispatch was admitted")


def _with_run_state(deps: tools.AgentDeps) -> tools.AgentDeps:
    """MAIN's deps carrying the run's one `RunState` (#1235 round 2), as the driver hands them:
    an admitted dispatch's breaker screen reads it."""
    from defender.runtime.run_state import RunState

    return replace(deps, run_state=RunState(deps.run_dir, "r-seam"))


def _seam_deps(tmp_path: Path):
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    return run_dir, _with_run_state(_with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=_DEFENDER), run=_live_run_1165(run_dir)))


def test_an_empty_goal_is_retried_at_the_seam_and_leaves_the_id_takeable(tmp_path):
    """#855 F-12, the reachable half."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools_gather

    run_dir, deps = _seam_deps(tmp_path)

    def _never(agent_id, system, request_limit):  # pragma: no cover — reaching it IS the failure
        raise AssertionError("an unclaimed dispatch reached the gather factory")

    for empty in ("", "   ", "\n"):
        with pytest.raises(ModelRetry, match="empty goal"):
            asyncio.run(tools_gather._run_gather(
                deps, _never, 40,
                tools_gather.GatherRequest("l-001", "elastic", empty, ("what",)),
                T1106.fixture_grants().gather, catalog=None,
            ))
    assert not list((run_dir / "gather_raw").glob("*.lead.json")), \
        "a dispatch that never ran claimed the lead id anyway"

    seen: list[str] = []

    def _record(agent_id, system, request_limit):
        seen.append(system)
        return _StopAfterDispatch()

    asyncio.run(tools_gather._run_gather(
        deps, _record, 40,
        tools_gather.GatherRequest("l-001", "elastic", "the corrected question", ("what",)),
        T1106.fixture_grants().gather, catalog=None,
    ))
    assert seen == ["elastic"], "the corrected re-dispatch of the same id was refused"
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file(), \
        "the corrected dispatch ran without claiming its lead id"


def test_the_second_dispatch_of_one_lead_id_is_always_refused(tmp_path):
    """The gate #855 F-12 defeated, stated as the property it protects: ONE gather session per
    `lead_id`, whatever happened to the first attempt."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools_gather

    run_dir, deps = _seam_deps(tmp_path)
    runs: list[str] = []

    def _factory(agent_id, system, request_limit):
        runs.append(agent_id)
        return _StopAfterDispatch()

    def _dispatch(goal: str):
        return asyncio.run(tools_gather._run_gather(
            deps, _factory, 40,
            tools_gather.GatherRequest("l-003", "elastic", goal, ("what",)),
            T1106.fixture_grants().gather, catalog=None,
        ))

    for _ in range(2):
        with pytest.raises(ModelRetry, match="empty goal"):
            _dispatch("")
    _dispatch("confirm the lead")
    with pytest.raises(ModelRetry, match="already dispatched"):
        _dispatch("confirm the lead")
    assert runs == ["gather:l-003"], \
        f"{len(runs)} gather sessions ran under one lead_id; exactly one may"


def test_the_gather_factory_is_handed_the_ceiling_this_dispatch_will_enforce(tmp_path):
    """#880 F-19's residue, closed at the seam rather than by two literals agreeing."""
    from defender.runtime import tools_gather

    run_dir, deps = _seam_deps(tmp_path)
    handed: list[int] = []

    def _factory(agent_id, system, request_limit):
        handed.append(request_limit)
        return _StopAfterDispatch()

    for i, ceiling in enumerate((40, 8)):
        asyncio.run(tools_gather._run_gather(
            deps, _factory, ceiling,
            tools_gather.GatherRequest(f"l-8{i}0", "elastic", "confirm the lead", ("what",)),
            T1106.fixture_grants().gather, catalog=None,
        ))

    assert handed == [40, 8], (
        f"the factory was handed {handed} for dispatches ceilinged at [40, 8] — it is reading "
        "a ceiling of its own rather than this run's, which is the shape of #880 F-19: the "
        "recorder it builds then withholds the doomed round against a number no dispatch here "
        "will enforce"
    )


def test_the_dispatch_renders_the_catalog_it_is_handed_and_builds_none(tmp_path):
    from defender.runtime import tools_gather

    run_dir, deps = _seam_deps(tmp_path)
    prompts: list[str] = []

    class _Capture:
        async def run(self, prompt, **kw):
            prompts.append(prompt)
            raise UsageLimitExceeded("far enough — the prompt was captured")

    class _HandedIndex:
        """A stand-in for the index run start builds and hands down: it lists the systems its
        lines name (`systems`, read by the dispatch to mark those that are down), renders to
        `text`, whatever down map it is rendered against, and records each rendering."""

        systems = ("elastic",)

        def __init__(self, text: str) -> None:
            self.text = text
            self.renders: list[tuple[tuple, dict]] = []

        def render(self, *args: object, **kw: object) -> str:
            self.renders.append((args, kw))
            return self.text

    sentinel = "- `elastic`: THE-CATALOG-THIS-RUN-WAS-HANDED"
    index = _HandedIndex(sentinel)
    for lead, catalog in (("l-901", index), ("l-902", None)):
        asyncio.run(tools_gather._run_gather(
            deps, lambda agent_id, system, request_limit: _Capture(), 40,
            tools_gather.GatherRequest(lead, "elastic", "confirm the lead", ("what",)),
            T1106.fixture_grants().gather, catalog=catalog,
        ))
    handed, none = prompts
    assert index.renders, (
        "the dispatch never rendered the index it was handed (#1256 r4: it is rendered at use, "
        "against the run's current down map)")
    assert sentinel in handed, "the index this dispatch was handed is not in its prompt"
    assert "## Systems of record" in handed
    assert "## Systems of record" not in none, \
        "handed no catalog, the dispatch rendered one anyway — it built its own from the tree"


def test_a_claim_that_could_not_be_written_is_a_retry_not_a_dispatch(tmp_path):

    from defender.hooks.record_lead import NOT_CLAIMED
    from defender.runtime import tools_gather

    run_dir, deps = _seam_deps(tmp_path)

    def _never(agent_id, system, request_limit):  # pragma: no cover — reaching it IS the failure
        raise AssertionError("an unwritten claim dispatched gather anyway")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(tools_gather, "_claim_lead", lambda dispatch, **kw: NOT_CLAIMED)
        # #1222 C40: a host-side write fault ends the run through the store exit; no retry.
        with pytest.raises(tools_gather.LeadRecordFault, match="could not be claimed"):
            asyncio.run(tools_gather._run_gather(
                deps, _never, 40,
                tools_gather.GatherRequest("l-004", "elastic", "a real goal", ("what",)),
                T1106.fixture_grants().gather, catalog=None,
            ))
    assert not (run_dir / "gather_summaries").exists(), \
        "a dispatch that never ran wrote a gather summary"


def test_an_overlong_lead_id_never_reaches_the_claim(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools_gather

    run_dir, deps = _seam_deps(tmp_path)

    def _never(agent_id, system, request_limit):  # pragma: no cover — reaching it IS the failure
        raise AssertionError("an unbounded lead_id dispatched gather")

    with pytest.raises(ModelRetry, match="invalid lead_id"):
        asyncio.run(tools_gather._run_gather(
            deps, _never, 40,
            tools_gather.GatherRequest("l-" + "a" * 300, "elastic", "a real goal", ("what",)),
            T1106.fixture_grants().gather, catalog=None,
        ))
    assert not list((run_dir / "gather_raw").glob("*.lead.json"))
