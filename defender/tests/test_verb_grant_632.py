"""#632 part 1: the verb grant, the scoped registry seam and the compiled policy. A registry cannot be built without a grant, a grant naming an unknown verb fails at load, a verb whose class contradicts its grant cannot be invoked, one broken adapter costs only its own system."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.runtime.lead_zero import RESERVED_LEAD_IDS  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    ADAPTERS_DIR,
    DENIED,
    DENY_ALL,
    DONE,
    GATHER_PAIRS,
    GRANTED,
    HEALTH_CHECK,
    SYSTEMS,
    UNDECLARED,
    VERB_CLASSES,
    GrantError,
    ScopedFakeVerbs,
    VerbGrant,
    grant_of,
    q,
    recording_table,
    run_gather,
)
from defender.runtime.verbs import read_roster  # noqa: E402

pytestmark = pytest.mark.e2e



#: TWO DEMANDS LEFT THIS FILE WITH #922, AND THEY ARE NOT REPLACED — recorded here rather than
#: deleted silently, because their absence is a real reduction in what this suite witnesses.

def _elastic(rec: VerbRecorder, granted=(("elastic", "query"),), declared=("query", "esql")):
    table = recording_table(rec, {"elastic": declared})
    return ScopedFakeVerbs(table, grant_of("gather", granted))


def test_a_verb_registry_cannot_be_constructed_without_a_grant(tmp_path: Path):
    """A verb_registry cannot be built without a verb_grant: every construction route —
    the driver's ternary, the driver's fallback, the judge engine, the memoised catalog
    builder and the dev scaffold — must supply one, so no execution path can mint a global"""
    with pytest.raises(TypeError):
        ModuleVerbRegistry(read_roster(ADAPTERS_DIR))  # type: ignore[call-arg]

    for bad in (None, {"elastic": ("query",)}, "gather"):
        with pytest.raises((GrantError, TypeError)):
            ModuleVerbRegistry(read_roster(ADAPTERS_DIR), bad)  # type: ignore[arg-type]

    reg = ModuleVerbRegistry(read_roster(ADAPTERS_DIR), grant_of("gather", GATHER_PAIRS))
    assert reg.grant.role == "gather", "a built registry does not carry the grant it was scoped by"






def test_the_verb_grant_compiles_into_the_agent_policy(tmp_path: Path):
    """A role's verb_grant is declared on its agent definition beside `bash_shapes` and
    compiles into the same agent policy, so "what may this role do" is assembled in one
    place. A seam claim, not a signature claim: `compile_policy` builds `bash_allow` by"""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # #1106 M4: gather is bound with a RUN's grant (the playground tenant's here).
    gather_def = T1106.fixture_gather_def()
    policy = compile_policy_for(gather_def, run_dir)

    assert policy.verb_allow is gather_def.verb_grant, \
        "the compiled policy does not carry the definition's own grant object"
    assert policy.bash_allow, "the bash half vanished — the two halves must compile together"
    assert set(policy.verb_allow.entries), "gather compiled with an empty verb allowance"

    effective = compile_policy_for(gather_def, run_dir, tools=gather_def.tools)
    assert effective.verb_allow is gather_def.verb_grant, \
        "compile_policy_for accepts no effective ToolSet — a stage's runtime-set bit cannot reach it"


def test_the_compiled_policy_answers_what_this_role_may_do_with_verbs_beside_bash_shapes(
    tmp_path: Path,
):
    """The operator question "what may this role do" is answered by the compiled policy with
    the granted verbs ALONGSIDE the bash shapes — one answer, one place. The grant compiling
    in is one property; the compiled object answering is the other, and it is the one an
    operator-facing audit reads."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    gather = compile_policy_for(T1106.fixture_gather_def(), run_dir)
    main = compile_policy_for(MAIN_DEF, run_dir)

    pairs = {(s, v) for s, v, _ in gather.verb_allow.entries}
    assert ("elastic", "esql") in pairs
    assert ("ticket", "get-ticket") not in pairs
    assert {g.program for g in gather.bash_allow}, "no bash program is answerable for this role"

    assert main.verb_allow.entries == (), "main answers with verbs it holds no verb tool for"
    assert {g.program for g in main.bash_allow}, "main's bash half is unanswerable"


def test_a_role_definition_without_a_grant_gets_an_empty_deny_all(tmp_path: Path):
    """A role definition that names no verb_grant gets an explicit EMPTY DENY-ALL, never
    `None` and never an absent field (§7 R7). Eight of the nine agent definitions get no
    grant; an absent default would either break their construction or reopen the `None`"""
    assert MAIN_DEF.verb_grant is not None
    assert MAIN_DEF.verb_grant == DENY_ALL
    assert MAIN_DEF.verb_grant.entries == ()
    assert MAIN_DEF.verb_grant.allows("elastic", "query") is False

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    assert compile_policy_for(MAIN_DEF, run_dir).verb_allow.entries == ()

    reg = ModuleVerbRegistry(read_roster(ADAPTERS_DIR), DENY_ALL)
    decision = reg.decide("elastic", "query")
    assert decision.outcome != GRANTED, \
        "a deny-all grant admitted a call — an empty grant read as 'no filter'"
    assert decision.outcome == UNDECLARED, \
        "a system a grant reaches nowhere read as denied rather than unresolvable"








def test_a_grant_naming_a_verb_the_registry_lacks_fails_at_load(tmp_path: Path):
    """A verb_grant naming a `(system, verb)` the registry does not admit fails at LOAD, and
    the check is TOTAL — a phantom verb is caught even in a system the role never calls, and
    even when that system's adapter would raise on import, because the names are read cold"""
    phantom = grant_of("gather", (*GATHER_PAIRS, ("cmdb", "host-trust-edges")))
    with pytest.raises(GrantError) as caught:
        ModuleVerbRegistry(read_roster(ADAPTERS_DIR), phantom)
    assert "host-trust-edges" in str(caught.value)

    wrong_system = grant_of("gather", (("elastic", "list-tickets"),))
    with pytest.raises(GrantError):
        ModuleVerbRegistry(read_roster(ADAPTERS_DIR), wrong_system)

    # THE COLD READER IS CROSS-CHECKED AGAINST THE IMPORTED NAMES, on every shipped adapter.
    # Without this the reader is unfalsifiable in the direction that matters: a syntactic scan
    # of the `VERBS = {...}` literal agrees with itself, so an adapter whose table is built any
    # other way declares NOTHING to the check while declaring everything to the runtime — and
    # a grant naming a phantom verb on that system then passes at load. Importing is legal
    # HERE, in the test, precisely because it is what the production reader must not do.
    roster = read_roster(ADAPTERS_DIR)
    for system in SYSTEMS:
        module = importlib.import_module(f"defender.scripts.adapters.{system.replace('-', '_')}_adapter")
        assert set(roster.declared_verbs(system)) == set(module.VERBS), (
            f"the cold reader and the real {system} adapter disagree on which verbs exist — "
            f"cold={sorted(roster.declared_verbs(system))} "
            f"imported={sorted(module.VERBS)}"
        )

    # An adapter whose table is assembled rather than written as a literal: the check must not
    # go quiet on it. Either the reader resolves the names or the load fails — what it may not
    # do is treat "I could not read this system" as "this system declares whatever you like".
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "alpha_adapter.py").write_text(
        "def look(ctx, *, name: str) -> dict:\n    return {'name': name}\n"
        "VERBS = {}\n"
        "for _n, _f in (('look', look),):\n    VERBS[_n] = _f\n", encoding="utf-8")
    with pytest.raises(GrantError):
        ModuleVerbRegistry(read_roster(adapters), grant_of("gather", (("alpha", "no-such-verb"),)))


def test_grant_authoring_integrity_rejects_a_bad_class_token_and_a_conflicting_duplicate():
    """The verb_class vocabulary is CLOSED at two, and a verb_grant is rejected at load for a
    class token outside it and for one `(system, verb)` declared twice with conflicting
    classes (§7 R13). A third tier arrives with the deferred write-verb work and brings its"""
    assert frozenset({"r", "rw"}) == VERB_CLASSES

    with pytest.raises(GrantError):
        VerbGrant(role="gather", entries=(("elastic", "query", "read-only"),))
    with pytest.raises(GrantError):
        VerbGrant(role="gather", entries=(("elastic", "query", ""),))
    with pytest.raises(GrantError):
        VerbGrant(role="gather", entries=(("elastic", "query", "r"), ("elastic", "query", "rw")))

    ok = VerbGrant(role="gather", entries=(("elastic", "query", "r"), ("elastic", "query", "r")))
    assert ok.allows("elastic", "query"), "a harmless exact duplicate was rejected too"


def test_a_verb_whose_declared_class_contradicts_its_grant_cannot_be_invoked(tmp_path: Path):
    """A real verb_grant with one verb's declared verb_class contradicting the class the
    grant expects fails the run CLOSED at first resolution, rather than executing the verb."""
    rec = VerbRecorder()
    table = recording_table(rec, {"elastic": ("query",)})
    registry = ScopedFakeVerbs(table, grant_of("gather", (("elastic", "query"),), verb_class="rw"))

    with pytest.raises(GrantError):
        registry.decide("elastic", "query")
    assert rec.calls == [], "the verb ran despite the class disagreement"

    agreeing = ScopedFakeVerbs(table, grant_of("gather", (("elastic", "query"),)))
    assert agreeing.decide("elastic", "query").outcome == GRANTED


def test_compiling_a_policy_imports_no_adapter_and_a_broken_one_costs_only_its_own_system(
    tmp_path: Path,
):
    """Compiling an agent policy imports NO adapter module, and one adapter that fails to
    import costs its own system per call rather than the whole stage. This is the #672
    fault-containment regression guard, and it is what makes the agreement check's stated
    timing — first resolution, not policy compile — observable rather than a comment."""
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "elastic_adapter.py").write_text(
        "def query(ctx, *, native_query: str) -> dict:\n    return {'ok': True}\n"
        "VERBS = {'query': query}\n", encoding="utf-8",
    )
    (adapters / "cmdb_adapter.py").write_text(
        "raise RuntimeError('this adapter cannot be imported')\n"
        "VERBS = {'get-host': None}\n", encoding="utf-8",
    )

    grant = grant_of("gather", (("elastic", "query"), ("cmdb", "get-host")))
    registry = ModuleVerbRegistry(read_roster(adapters), grant)  # cold names only — must not import

    assert registry.decide("elastic", "query").outcome == GRANTED, \
        "a broken sibling adapter cost the whole registry"
    with pytest.raises(RuntimeError):
        registry.decide("cmdb", "get-host")


def test_health_check_is_granted_uniformly_to_gather(tmp_path: Path):
    """health-check is granted uniformly to gather rather than per system — a deliberate
    uniformity exception, since gather does call it and the split carries no security
    content. The investigator can call it on any system its verb_grant reaches; a non-gather"""
    rec = VerbRecorder()
    table = recording_table(rec, {"elastic": ("query", HEALTH_CHECK)})

    gather = ScopedFakeVerbs(table, T1106.fixture_grants().gather)
    assert gather.decide("elastic", HEALTH_CHECK).outcome == GRANTED

    other = ScopedFakeVerbs(table, grant_of("main", ()))
    assert other.decide("elastic", HEALTH_CHECK).outcome != GRANTED, \
        "health-check is reachable by a role whose grant names nothing"
    assert other.decide("elastic", HEALTH_CHECK).outcome == UNDECLARED

    held_elsewhere = ScopedFakeVerbs(table, grant_of("main", (("elastic", "query"),)))
    assert held_elsewhere.decide("elastic", HEALTH_CHECK).outcome == DENIED, \
        "health-check leaked to a role that holds the system but was never granted the verb"

    r = run_gather(tmp_path, verbs=gather, turns=[q("elastic", HEALTH_CHECK), DONE],
                   run_id="hc632")
    assert [c.verb for c in rec.calls] == [HEALTH_CHECK]
    # lead-0 (#808) also attempts `alerts` against this table ahead of the model's own
    # turn — `alerts` is nominally granted (the full gather grant) but not declared in
    # this test's narrow table, so it lands one l-000 UNDECLARED usage row and never
    # reaches a verb body. Scope the row assertion to the model's own lead.
    own_rows = [row for row in r.rows if row["lead_id"] not in RESERVED_LEAD_IDS]
    assert len(own_rows) == 1
    assert own_rows[0]["exit_code"] == 0
