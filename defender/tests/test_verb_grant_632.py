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
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF  # noqa: E402
from defender.runtime.agent_definition import bind, compile_policy_for  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime.lead_zero import RESERVED_LEAD_IDS  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.tests._closed_ticket_672 import (  # noqa: E402
    TOOL_GET,
    TOOL_LIST,
    DONE as JUDGE_DONE,
    _drive,
    _list,
    _ticket_registry,
)
from defender.tests._verb_authorization_632 import (  # noqa: E402
    ADAPTERS_DIR,
    BENIGN_JUDGE_PAIRS,
    DENIED,
    DENY_ALL,
    DONE,
    GATHER_PAIRS,
    GRANTED,
    HEALTH_CHECK,
    JUDGE_ROLE as JUDGE_DEF_ROLE,
    SYSTEMS,
    UNDECLARED,
    UNGRANTED_PAIRS,
    VERB_CLASSES,
    GrantError,
    RegistryShaped,
    ScopedFakeVerbs,
    VerbGrant,
    declared_verb_names,
    grant_of,
    q,
    recording_table,
    run_gather,
    scoped_ticket_registry,
)

pytestmark = pytest.mark.e2e


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


def test_a_registry_shaped_object_is_rejected_at_the_seam_the_build_path_reaches(tmp_path: Path):
    """A registry-shaped object that never went through the verb_registry constructor is
    refused at EVERY entry point that takes a registry, so `unconstructable` is not one
    duck-typed helper away from decorative (§7 R15). Positive control: the same drives with a
    real scoped registry run the granted verb.

    BOTH MODEL-FACING ENTRY POINTS ARE DRIVEN, and that is the tightening. A guard wired at
    the outermost entry point alone leaves the second one open: the judge's leg takes its own
    registry through its own seam and never passes through the runtime's, so a table that
    merely answers the registry's questions reaches the closed-ticket tool and runs
    unauthorized while every assertion about the runtime's entry point stays green. The
    duck-typed stand-in below carries a `decide()` that answers GRANTED to everything — it
    holds no grant, which is exactly why a structural check ("does it answer?") cannot tell it
    from the real thing and only the TYPE can."""
    rec = VerbRecorder()
    shaped = RegistryShaped(recording_table(rec, {"elastic": ("query",)}))

    with pytest.raises((TypeError, ValueError)):
        run_gather(tmp_path / "duck", verbs=shaped, turns=[q("elastic", "query"), DONE],
                   run_id="duck632")
    # lead-0 (#808) resolves BEFORE this build path's type check ever runs — it is
    # harness-issued pre-ORIENT work, not a model-facing call, and it takes whatever
    # `verbs` object was injected (duck-typed or not) through its own reserved lead
    # (`l-000`). That is accepted, documented behaviour, not the hole this demand
    # guards: the guard is that no MODEL-driven call ever reaches a verb body through
    # the rejected registry, which the run's own table (keyed by lead_id) can still
    # show directly even though `VerbRecorder` itself can't tell the two callers apart.
    duck_rows = read_jsonl_rows(tmp_path / "duck" / "run" / "executed_queries.jsonl")
    own_duck_rows = [r for r in duck_rows if r.get("lead_id") not in RESERVED_LEAD_IDS]
    assert own_duck_rows == [], "a duck-typed registry reached a verb body via a model-driven call"

    rec2 = VerbRecorder()
    ok = run_gather(tmp_path / "typed", verbs=_elastic(rec2), turns=[q("elastic", "query"), DONE],
                    run_id="typed632")
    # lead-0's own shell fetch (`alerts`) is UNDECLARED against this scoped table (only
    # `query`/`esql` are granted) — that raises `ModelRetry` before its handler ever
    # runs, writing l-000 exactly one usage row and never reaching a verb body, so
    # `rec2` still sees only the model's own scripted `query` call.
    assert [c.verb for c in rec2.calls] == ["query"]
    own_ok_rows = [r for r in ok.rows if r.get("lead_id") not in RESERVED_LEAD_IDS]
    assert len(own_ok_rows) == 1

    # The second model-facing site: the judge's own leg, through its own registry seam.
    judge_rec = VerbRecorder()
    duck_judge = RegistryShaped({"ticket": dict(_ticket_registry(judge_rec).verbs("ticket"))})
    with pytest.raises((TypeError, ValueError)):
        _drive(tmp_path / "duck-judge", [JUDGE_DONE], registry=duck_judge)
    assert judge_rec.calls == [], \
        "a duck-typed registry reached a ticket verb at the judge site — the type guard is " \
        "wired at the runtime entry point only"

    typed_rec = VerbRecorder()
    run = _drive(tmp_path / "typed-judge", [_list(label=None), JUDGE_DONE],
                 registry=scoped_ticket_registry(typed_rec, BENIGN_JUDGE_PAIRS))
    assert TOOL_LIST in run.tool_names(), "the judge control never registered its tool"
    # #683 (landed on main after this spec was written) added the case-opened recency
    # boundary lookup ahead of list-tickets; the intent this assertion pins — no extraneous
    # verb call reached the store — still holds, widened to admit that lookup.
    assert [c.verb for c in typed_rec.calls] == ["case-opened-at", "list-tickets"]


def test_two_roles_in_one_process_never_share_a_scoped_registry():
    """Two roles resolving a verb_registry in one process never share one: the role is part
    of any memo key gating registry reuse, so one role's grant never serves another's call.
    Two DISTINCT REAL role ids, never placeholders — a placeholder pair passes under exactly
    the falsy-key collapse this excludes (§7 R16).

    The two refusals below carry DIFFERENT labels, and that is §7 R11 read literally rather
    than an inconsistency: gather holds `ticket` (list-tickets), so a withheld ticket verb is
    DENIED; the judge holds nothing on `elastic` at all, so an elastic verb is UNRESOLVABLE.
    What the memo-key demand needs is that neither role's grant ever answers GRANTED for the
    other's call."""
    gather = ModuleVerbRegistry(ADAPTERS_DIR, grant_of("gather", GATHER_PAIRS))
    judge = ModuleVerbRegistry(ADAPTERS_DIR, grant_of(JUDGE_DEF_ROLE, BENIGN_JUDGE_PAIRS))

    assert gather is not judge
    assert gather.decide("ticket", "get-ticket").outcome == DENIED, \
        "gather resolved get-ticket — the judge's grant served gather's call"
    assert judge.decide("ticket", "get-ticket").outcome == GRANTED
    assert judge.decide("elastic", "esql").outcome == UNDECLARED, \
        "the judge reached elastic — gather's grant served the judge's call"


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
    `None` and never an absent field (§7 R7). Six of the eight agent definitions get no
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


def test_a_grant_and_a_switched_off_tool_disagree_in_either_direction_at_build(tmp_path: Path):
    """Both disagreement directions between a verb_grant and the tool bit that reaches the
    registry fail AT BUILD (§7 R7), against the bit the stage ACTUALLY BUILDS WITH.

    `g16` is the whole reason this demand exists, and it is the judge that carries it:
    `GATHER_DEF` declares its capability statically, but the judge's `closed_tickets` bit is
    NOT on `JUDGE_DEF` — it is set by a runtime `replace(JUDGE_DEF.tools, …)` from the
    stage's own scope object at build time, so the compiled policy never sees it. A check
    written against the two statically declared definitions passes an implementation that
    reads only what the definition declares — which is precisely the case g16 refuted. So
    the effective ToolSet is what the build must be handed and what both directions below
    are constructed from.

    Direction 1: the build sees `closed_tickets=False` while the grant it is handed names
    ticket verbs — a stale grant sitting behind a switched-off capability, the state §7 R7
    rejects inertness to avoid. Direction 2: the bit is on and the grant reaches none of the
    tool's verbs — an enabled capability with nothing behind it. Both bite here, and the
    rule carries no exception at any site.

    DIRECTION 1 IS PINNED AT THE POLICY BUILD AND NOT THROUGH A STAGE, and that is now a
    consequence of a decision rather than an avoidance. Read literally the rule fails the
    adversarial judge's stage, which builds with the capability off from the one definition
    whose grant names ticket verbs — half the learning loop stops building. §7 R7's amendment
    resolves that in the CONFIGURATION and not in the rule: the same runtime `replace()` that
    sets the capability bit scopes the grant beside it, so a build with the tool off is handed
    the empty deny-all and the disagreement cannot arise at a stage at all. The demand for
    that correction is the adversarial-stage test beside this one; without it, an implementer
    satisfies this test and finds the malicious judge no longer builds.

    THE RULE IS PINNED ON THE PRODUCTION BIND PATH, not only on the operator-facing wrapper.
    `bind` compiles its policy directly; the wrapper is a second door onto the same builder.
    A check installed in the wrapper alone satisfies every assertion written through it while
    running on NO real build — every shipped agent would bind with a grant its capability bit
    contradicts, and the demand's whole content is that this state cannot be built. The bind
    drive below uses a NON-judge role for the second half of the same reason: a check that
    names the judge as an exception passes every judge-shaped case in this test and fails
    exactly there. One rule, no carve-out, on the path production takes.

    THE LAST BLOCK DRIVES THE JUDGE'S OWN STAGE BUILD, and it is the half that pins the
    wiring rather than the seam. Handing an effective ToolSet in from a test body proves the
    parameter EXISTS; it does not prove the stage passes it. An implementation that accepts
    the parameter, satisfies both directions above and still compiles its policy from
    `JUDGE_DEF.tools` ships the refuted condition intact in production — which is the shape
    the previous pass's repair moved one site over instead of closing. The disagreement is
    constructed through the seam the stage already has: the registry the stage is built with
    carries the role's grant, so a registry scoped by a grant that reaches NO ticket verb,
    driven against the benign wiring whose scope switches `closed_tickets` ON, is direction 2
    assembled entirely by production code. Nothing raises unless the runtime-set bit reached
    the policy build — `JUDGE_DEF.tools` declares that bit OFF, and an off bit beside a grant
    that names nothing is no disagreement at all."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    judge_grant = grant_of(JUDGE_DEF_ROLE, BENIGN_JUDGE_PAIRS)

    switched_off = replace(JUDGE_DEF.tools, closed_tickets=False)
    with pytest.raises(GrantError):
        compile_policy_for(replace(JUDGE_DEF, verb_grant=judge_grant), run_dir,
                           tools=switched_off)

    switched_on = replace(JUDGE_DEF.tools, closed_tickets=True)
    with pytest.raises(GrantError):
        compile_policy_for(replace(JUDGE_DEF, verb_grant=DENY_ALL), run_dir, tools=switched_on)

    # The agreeing pair is the positive control: the same dynamic bit, with a grant that
    # reaches the tool's verbs, compiles — so the two failures above are the disagreement
    # and not the `tools=` seam refusing everything handed to it.
    ok = compile_policy_for(replace(JUDGE_DEF, verb_grant=judge_grant), run_dir,
                            tools=switched_on)
    assert ok.verb_allow is judge_grant

    # The statically declared direction still fails too — one rule, not a judge carve-out.
    with pytest.raises(GrantError):
        compile_policy_for(replace(MAIN_DEF, verb_grant=grant_of("main", (("elastic", "query"),))),
                           run_dir)

    # ON THE PRODUCTION BIND PATH, for a role that is not the judge. `bind` compiles its
    # policy directly and does NOT go through the operator-facing wrapper above, so a check
    # installed only in that wrapper never runs on any real build — every assertion above
    # passes while every shipped agent binds with a grant its capability bit contradicts. And
    # driving it on a NON-judge role is what closes the other half: a check that exempts the
    # judge by name satisfies the judge-shaped cases above and fails here.
    for defn, grant in (
        # a grant naming verbs behind a switched-off query capability
        (replace(GATHER_DEF, tools=replace(GATHER_DEF.tools, query=False)),
         grant_of("gather", (("elastic", "query"),))),
        # the capability on, and a grant that reaches none of its verbs
        (GATHER_DEF, DENY_ALL),
    ):
        with pytest.raises(GrantError):
            bind(replace(defn, verb_grant=grant), run_dir)

    # The agreeing pair at the same site: the real definition, its real grant, its real bit.
    assert bind(GATHER_DEF, run_dir) is not None, \
        "the bind path refuses the shipped agreeing configuration — the check is not the rule"

    # Through the judge's REAL stage build, where the bit is set by the runtime replace().
    starved = VerbRecorder()
    with pytest.raises(GrantError):
        _drive(tmp_path / "stage-disagrees", [JUDGE_DONE],
               registry=scoped_ticket_registry(starved, ()))
    assert starved.calls == [], "the stage reached a ticket verb behind a disagreeing grant"

    # The agreeing pair at the same site: the stage's own bit, a grant that reaches the
    # tool's verbs, and the run completes with the tool registered — so the failure above is
    # the disagreement and not the stage build refusing every grant it is handed.
    agreeing = VerbRecorder()
    run = _drive(tmp_path / "stage-agrees", [_list(label=None), JUDGE_DONE],
                 registry=scoped_ticket_registry(agreeing, BENIGN_JUDGE_PAIRS))
    assert TOOL_LIST in run.tool_names(), "the agreeing stage build registered no closed-ticket tool"
    # #683 (landed on main after this spec was written) added the case-opened recency
    # boundary lookup ahead of list-tickets; the intent this assertion pins — no extraneous
    # verb call reached the store — still holds, widened to admit that lookup.
    assert [c.verb for c in agreeing.calls] == ["case-opened-at", "list-tickets"]


def test_the_adversarial_judge_stage_builds_with_its_grant_scoped_off_beside_the_bit(
    tmp_path: Path,
):
    """The adversarial judge's stage BUILDS, and reaches no ticket verb: a stage that switches
    its verb capability OFF is handed an empty deny-all grant, scoped by the same runtime
    `replace()` that sets the bit.

    THIS IS A CORRECTION TO THE SHIPPED CONFIGURATION, and it is the price of R7's first
    direction carrying no exception. There is one judge definition and one grant on it, and
    that grant names the benign judge's ticket verbs. The adversarial stage builds from the
    same definition with `closed_ticket_read` off — so a grant naming verbs for a switched-off
    tool is not a hypothetical the rule forbids, it is what production ships, and the rule
    applied as written stops half the learning loop building. §7 R7 was amended rather than
    softened: the disagreement is real and the configuration is what is wrong. The grant still
    LIVES on the role definition — that is where the capability-on build reads it from — but
    the effective grant a build compiles is scoped to the capability the build actually has.

    What makes this falsifiable rather than a restatement: the two drives differ ONLY in the
    stage's capability bit, and they are handed the SAME grant — the one that names the ticket
    verbs, exactly as the shipped definition does. Off: the stage builds, offers the model no
    closed-ticket tool, and no ticket verb is reached. On: the same grant, the tools registered,
    the verb reached. An implementation that passes the definition's grant through unscoped
    raises on the first drive; one that scopes it off unconditionally fails the second."""
    off = VerbRecorder()
    adversarial = _drive(tmp_path / "adversarial", [JUDGE_DONE], benign=False,
                         registry=scoped_ticket_registry(off, BENIGN_JUDGE_PAIRS))

    assert adversarial.tool_names(), "the adversarial stage never called the model"
    assert TOOL_LIST not in adversarial.tool_names(), \
        "the capability-off stage offered the closed-ticket tool"
    assert TOOL_GET not in adversarial.tool_names()
    assert off.calls == [], "a ticket verb was reached from the capability-off stage"

    on = VerbRecorder()
    benign = _drive(tmp_path / "benign", [_list(label=None), JUDGE_DONE], benign=True,
                    registry=scoped_ticket_registry(on, BENIGN_JUDGE_PAIRS))

    assert TOOL_LIST in benign.tool_names(), \
        "the grant was scoped off for the capability-ON stage too — the bit is not read"
    # #683 (landed on main after this spec was written) added the case-opened recency
    # boundary lookup ahead of list-tickets; the intent this assertion pins — no extraneous
    # verb call reached the store — still holds, widened to admit that lookup.
    assert [c.verb for c in on.calls] == ["case-opened-at", "list-tickets"]


def test_the_shipped_grants_name_exactly_the_censused_verbs():
    """The shipped verb_grant entries name exactly gather's 21 read verbs plus health-check
    and the benign judge's 3 read verbs — no `rw` entry, and neither `cmdb.list-roles` nor
    `identity.list-authorized-hosts`, which no template and no run exercises. The grant is
    derived from the committed templates plus 20 runs of history, and it partitions the 25
    non-health-check verbs exactly, with no residue (g4).

    rejected: deriving the grant from the registry, which would grant everything and
    reproduce the status quo with ceremony; and deriving it mechanically from run history,
    which names five verbs that do not exist (c19)."""
    gather = {(s, v) for s, v, _ in GATHER_DEF.verb_grant.entries}
    systems = {s for s, _ in GATHER_PAIRS}

    assert {(s, v) for s, v in gather if v != HEALTH_CHECK} == set(GATHER_PAIRS)
    assert {s for s, v in gather if v == HEALTH_CHECK} == systems, \
        "health-check is granted per system rather than uniformly across gather's systems"
    assert all(k == "r" for _, _, k in GATHER_DEF.verb_grant.entries), "a shipped entry is not `r`"

    judge = {(s, v) for s, v, _ in JUDGE_DEF.verb_grant.entries if v != HEALTH_CHECK}
    assert judge == set(BENIGN_JUDGE_PAIRS)

    for pair in UNGRANTED_PAIRS:
        assert pair not in gather, f"{pair} is granted to nobody but appears in gather's grant"
        assert pair not in judge, f"{pair} is granted to nobody but appears in the judge's grant"


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
