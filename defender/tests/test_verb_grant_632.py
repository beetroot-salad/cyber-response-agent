"""#632 part 1 — the grant, the scoped registry seam, and the one compiled policy.

Every test here is one demand of `spec-flow/specs/spec_graph_632-verb-authorization.yaml`,
named by that demand's `discharged_by`. The suite is RED against `d01001e6` by
construction: the imports name the surface the implementation must build.

Authority order, because the design doc was never revised: `05-early-resolutions.md`
(R-A1/R-A2) and `70-resolutions.md` (§7) win over `.spec-flow/632-design.md` wherever they
disagree — D6 in particular is refuted (g10), not narrowed.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
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
    declared_verb_names,
    grant_of,
    q,
    recording_table,
    run_gather,
)

pytestmark = pytest.mark.e2e



#: TWO DEMANDS LEFT THIS FILE WITH #922, AND THEY ARE NOT REPLACED — recorded here rather than
#: deleted silently, because their absence is a real reduction in what this suite witnesses.
#:
#: `test_two_roles_in_one_process_{never_share_a_scoped_registry,each_get_their_own_catalog}`
#: needed TWO roles holding verb grants in one process. The judge was the second one, and its
#: grant went with the pipeline (#922) — gather is now the only verb-bearing role that ships.
#: The property is still true and still worth having; it simply has no witness until a second
#: role holds a grant again. It cannot be faked with a synthetic definition: what those tests
#: pinned is that two SHIPPED roles do not share a catalog, and a role invented in the test
#: proves only that the mechanism can keep two things apart, which was never in doubt.
#:
#: Restore them in the change that gives a second role a verb grant. #1008's family judge is
#: NOT that change — it is deny-all by design and holds no grant.

def _elastic(rec: VerbRecorder, granted=(("elastic", "query"),), declared=("query", "esql")):
    table = recording_table(rec, {"elastic": declared})
    return ScopedFakeVerbs(table, grant_of("gather", granted))


def test_a_verb_registry_cannot_be_constructed_without_a_grant(tmp_path: Path):
    """A verb_registry cannot be built without a verb_grant: every construction route —
    the driver's ternary, the driver's fallback, the judge engine, the memoised catalog
    builder and the dev scaffold — must supply one, so no execution path can mint a global
    unscoped registry. The requirement is UNCONSTRUCTABLE, not merely un-passed.

    Deliberately not pinned against `register_tools`' existing "a query tool with no
    registry has no allowlist" ValueError: `build_agent_core` fills the None before calling
    it (g17), so that guard is unreachable from the build path and a test on it would pin
    dead code green."""
    with pytest.raises(TypeError):
        ModuleVerbRegistry(ADAPTERS_DIR)  # type: ignore[call-arg]

    for bad in (None, {"elastic": ("query",)}, "gather"):
        with pytest.raises((GrantError, TypeError)):
            ModuleVerbRegistry(ADAPTERS_DIR, bad)  # type: ignore[arg-type]

    reg = ModuleVerbRegistry(ADAPTERS_DIR, grant_of("gather", GATHER_PAIRS))
    assert reg.grant.role == "gather", "a built registry does not carry the grant it was scoped by"






def test_the_verb_grant_compiles_into_the_agent_policy(tmp_path: Path):
    """A role's verb_grant is declared on its agent definition beside `bash_shapes` and
    compiles into the same agent policy, so "what may this role do" is assembled in one
    place. A seam claim, not a signature claim: `compile_policy` builds `bash_allow` by
    CALLING each bash shape with ResolvedRoots, while a verb grant is static data needing
    no roots (n11).

    The second half of the seam is the one g16 forces: the policy build must accept the
    EFFECTIVE ToolSet a stage builds with, not only the one its definition declares. The
    judge's verb capability is switched on by a runtime `replace()` AFTER `bind` has already
    compiled its policy, so without this parameter the compiled policy structurally cannot
    see the judge's capability and the agreement check d61 demands has nothing to compare
    against. The design names no mechanism here; the seam is the contract."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    policy = compile_policy_for(GATHER_DEF, run_dir)

    assert policy.verb_allow is GATHER_DEF.verb_grant, \
        "the compiled policy does not carry the definition's own grant object"
    assert policy.bash_allow, "the bash half vanished — the two halves must compile together"
    assert set(policy.verb_allow.entries), "gather compiled with an empty verb allowance"

    effective = compile_policy_for(GATHER_DEF, run_dir, tools=GATHER_DEF.tools)
    assert effective.verb_allow is GATHER_DEF.verb_grant, \
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
    gather = compile_policy_for(GATHER_DEF, run_dir)
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
    grant; an absent default would either break their construction or reopen the `None`
    fallback D1 exists to close. Inertness is rejected: a `None` grant is the state in
    which re-enabling a capability bit later silently grants everything a stale grant
    still names.

    The observable that discriminates is `allows` and the non-GRANTED outcome, not the
    DENIED label: an empty grant reaches no system at all, so under §7 R11 read literally
    every call it meets is UNRESOLVABLE rather than denied. The failure this excludes is an
    empty grant reading as 'no filter' — and that failure shows up as GRANTED, whichever
    refusal label the other branch carries."""
    assert MAIN_DEF.verb_grant is not None
    assert MAIN_DEF.verb_grant == DENY_ALL
    assert MAIN_DEF.verb_grant.entries == ()
    assert MAIN_DEF.verb_grant.allows("elastic", "query") is False

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    assert compile_policy_for(MAIN_DEF, run_dir).verb_allow.entries == ()

    reg = ModuleVerbRegistry(ADAPTERS_DIR, DENY_ALL)
    decision = reg.decide("elastic", "query")
    assert decision.outcome != GRANTED, \
        "a deny-all grant admitted a call — an empty grant read as 'no filter'"
    assert decision.outcome == UNDECLARED, \
        "a system a grant reaches nowhere read as denied rather than unresolvable"








def test_a_grant_naming_a_verb_the_registry_lacks_fails_at_load(tmp_path: Path):
    """A verb_grant naming a `(system, verb)` the registry does not admit fails at LOAD, and
    the check is TOTAL — a phantom verb is caught even in a system the role never calls, and
    even when that system's adapter would raise on import, because the names are read cold
    (§7 R10). Load-bearing, not ceremony: five historical pairs name template ids rather
    than verbs, so a grant derived from run history names five verbs that do not exist
    (c19)."""
    phantom = grant_of("gather", (*GATHER_PAIRS, ("cmdb", "host-trust-edges")))
    with pytest.raises(GrantError) as caught:
        ModuleVerbRegistry(ADAPTERS_DIR, phantom)
    assert "host-trust-edges" in str(caught.value)

    wrong_system = grant_of("gather", (("elastic", "list-tickets"),))
    with pytest.raises(GrantError):
        ModuleVerbRegistry(ADAPTERS_DIR, wrong_system)

    # THE COLD READER IS CROSS-CHECKED AGAINST THE IMPORTED NAMES, on every shipped adapter.
    # Without this the reader is unfalsifiable in the direction that matters: a syntactic scan
    # of the `VERBS = {...}` literal agrees with itself, so an adapter whose table is built any
    # other way declares NOTHING to the check while declaring everything to the runtime — and
    # a grant naming a phantom verb on that system then passes at load. Importing is legal
    # HERE, in the test, precisely because it is what the production reader must not do.
    for system in SYSTEMS:
        module = importlib.import_module(f"defender.scripts.adapters.{system.replace('-', '_')}_adapter")
        assert set(declared_verb_names(ADAPTERS_DIR, system)) == set(module.VERBS), (
            f"the cold reader and the real {system} adapter disagree on which verbs exist — "
            f"cold={sorted(declared_verb_names(ADAPTERS_DIR, system))} "
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
        ModuleVerbRegistry(adapters, grant_of("gather", (("alpha", "no-such-verb"),)))


def test_grant_authoring_integrity_rejects_a_bad_class_token_and_a_conflicting_duplicate():
    """The verb_class vocabulary is CLOSED at two, and a verb_grant is rejected at load for a
    class token outside it and for one `(system, verb)` declared twice with conflicting
    classes (§7 R13). A third tier arrives with the deferred write-verb work and brings its
    own policy question; until then a typo has a vocabulary to be outside of.

    Recorded and NOT built (RS5): a copy-pasted wrong system prefix resolves cleanly — two
    systems both define `list-roles` — so only the shipped-contents test catches it, and only
    for today's grant."""
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
    grant expects fails the run CLOSED at first resolution, rather than executing the verb.
    All 25 non-health-check verbs are `r` today (g3), so the disagreement has to be
    constructed rather than found — which is exactly what makes it falsifiable against real
    policy with no invented fixture."""
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
    registry = ModuleVerbRegistry(adapters, grant)  # cold names only — must not import

    assert registry.decide("elastic", "query").outcome == GRANTED, \
        "a broken sibling adapter cost the whole registry"
    with pytest.raises(RuntimeError):
        registry.decide("cmdb", "get-host")


def test_health_check_is_granted_uniformly_to_gather(tmp_path: Path):
    """health-check is granted uniformly to gather rather than per system — a deliberate
    uniformity exception, since gather does call it and the split carries no security
    content. The investigator can call it on any system its verb_grant reaches; a non-gather
    role cannot call it at all, so the uniformity is an exception inside the grant rather
    than a hole beside it.

    Two refusal shapes, both non-GRANTED, and the labels follow §7 R11 read literally: a
    role whose grant names nothing reaches `elastic` nowhere, so its health-check is
    UNRESOLVABLE, while a role that holds elastic but not this verb would be DENIED. What
    the uniformity claim needs is that the non-gather role never gets GRANTED — the label is
    R11's business, not this demand's."""
    rec = VerbRecorder()
    table = recording_table(rec, {"elastic": ("query", HEALTH_CHECK)})

    gather = ScopedFakeVerbs(table, GATHER_DEF.verb_grant)
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
