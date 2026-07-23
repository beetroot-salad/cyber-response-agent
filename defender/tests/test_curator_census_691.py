"""#691 — the generic registry census reaches the curator (M9/O1), and the corpus name is
demanded legibly (M8). Executable spec, phase E. RED against HEAD by design: CORPUS_AUTHOR_DEF
is ``bindable=False`` today, so the generic census EXCLUDES it and binding it raises.

Census hardening (author charge): the census enumeration only PICKS the subject — it is NEVER
the assertion. Every test below drives ONE real subject through the real ``bind`` seam and
observes the compiled policy's effect (a corpus-rooted write scope), and pairs the enumeration
with a positive control (a misconfigured def RAISES at bind — the census is not a weak
``has-an-executor`` check).
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from _curator_691_harness import (  # noqa: E402
    bind_curator,
    curator_deps,
    make_worktree,
    pending_run_dir,
)

from defender.agents import AGENTS  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    AgentDefinition,
    ToolSet,
    bind,
    build_registry,
)
from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF, CuratorDeps  # noqa: E402


def _bash_roles() -> set[AgentRole]:
    """The generic bash census predicate #0 collapses to: ``d.tools.bash`` (NO ``d.bindable`` gate)."""
    return {d.role for d in AGENTS.values() if d.tools.bash}


def _misconfigured_writer_def() -> AgentDefinition:
    """A def that is a writer (``write=True``) but declares NO ``write_shapes`` — the write
    co-constraint (``compile_policy``/``build_registry``) must reject it at bind. This is the
    positive control that proves the census is a real bind, not a field-existence assertion."""
    return AgentDefinition(
        role=AgentRole.MAIN, model=lambda: "x", effort=None,
        tools=ToolSet(bash=True, write=True), write_shapes=(), deps_cls=CuratorDeps,
    )


def test_the_generic_bash_census_enumerates_the_curator(tmp_path):
    """The generic census predicate ``d.tools.bash`` enumerates every bash-enabled role INCLUDING
    the curator, with no special case — six roles, not five. Binding that curator subject yields a
    REAL compiled policy whose write scope roots at the worktree corpus (the enumeration picks the
    subject; the compiled effect is the assertion). Positive control (F21): a misconfigured writer
    def RAISES at bind, so the census is not a weak 'carries an executor' check."""
    assert AgentRole.CORPUS_AUTHOR in _bash_roles()
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")  # RED today: bindable=False raises
    assert any(pat.fullmatch(str((wt / "defender" / "lessons" / "x.md").resolve()))
               for pat in deps.policy.write_allow)
    with pytest.raises(ValueError):  # noqa: PT011 - the co-constraint fires at bind, not at a census assertion
        build_registry((_misconfigured_writer_def(),))


def test_the_census_prose_and_the_census_predicate_disagree(tmp_path):
    """The ``d.tools.bash`` predicate yields SIX roles; the prose count beside it (five) goes stale
    and must be updated (K9/x5). The curator is among the six and is now bindable — RED today, where
    ``CORPUS_AUTHOR_DEF.bindable`` is still False."""
    assert _bash_roles() == {
        AgentRole.MAIN, AgentRole.GATHER, AgentRole.JUDGE, AgentRole.ACTOR,
        AgentRole.LEAD_AUTHOR, AgentRole.CORPUS_AUTHOR,
    }
    assert CORPUS_AUTHOR_DEF.bindable is True  # RED today (False)


def test_the_second_census_hiding_inside_the_first(tmp_path):
    """The tautological second census — the ``if d.bindable and d.tools.bash`` filter (test_540's
    exec-seam loop) whose ``d.bindable`` conjunct excluded exactly the curator — folds into the
    first once the curator is bindable: the ``d.tools.bash`` census and the ``d.bindable and
    d.tools.bash`` census name the SAME roles (K8). RED today: the curator is in the left set, not
    the right."""
    assert {d.role for d in AGENTS.values() if d.tools.bash} == {
        d.role for d in AGENTS.values() if d.bindable and d.tools.bash
    }


def test_agent_definition_has_no_bindable_field(tmp_path):
    """#0 removes the per-role ``bindable`` opt-out: no def can declare itself unbindable, so the
    field is gone from ``AgentDefinition``. RED today — the field still exists."""
    assert "bindable" not in AgentDefinition.__dataclass_fields__


def test_bind_refuses_no_registered_role_for_being_unbindable(tmp_path):
    """No REGISTERED role is refused by bind for being unbindable — after #0 every registered def is
    bindable, so the curator subject compiles a real policy through the one seam. Positive control
    (complementary condition, so the negative is not vacuous): an UNREGISTERED misconfigured def
    still raises at bind. RED today: the curator is the one registered role still unbindable."""
    assert all(d.bindable for d in AGENTS.values())  # RED today (curator is False)
    with pytest.raises(ValueError):  # noqa: PT011
        build_registry((_misconfigured_writer_def(),))  # the control still refuses


def test_the_registry_validates_the_curator_at_import_time(tmp_path):
    """``build_registry`` drops ``if d.bindable``, so importing ``defender.agents`` validates
    CORPUS_AUTHOR_DEF's write co-constraint before any spawn exists (f16/M9) — which means the
    curator must DECLARE its write scope (a bindable writer with empty ``write_shapes`` would raise
    the co-constraint at import). RED today: the curator carries no ``write_shapes`` (it builds them
    per-spawn, bindable=False). Positive control: the real AGENTS import succeeded."""
    assert CORPUS_AUTHOR_DEF.write_shapes != ()  # RED today (empty)
    with pytest.raises(ValueError):  # noqa: PT011
        build_registry((_misconfigured_writer_def(),))  # the un-skipped validation bites
    assert CORPUS_AUTHOR_DEF in AGENTS.values()


def test_the_workflow_that_depended_on_this_role_being_unbindable(tmp_path):
    """The workflows that SKIPPED the curator because it was unbindable — the policy printer, the
    seam suite, the registry-validation skip — now each get a REAL compiled policy through bind
    (M9/c13). Drive the substitute: binding the curator completes and yields a policy. RED today."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")  # RED today
    assert deps.policy.write_allow  # a real compiled policy, not a skip


def test_a_corpus_name_is_supplied_to_a_role_that_declares_no_corpus(tmp_path):
    """A corpus name supplied to a role that declares no corpus is ACCEPTED and UNREAD — no effect
    on the compiled policy (M8 is one-directional; F83: corpus_name is optional-with-sentinel).
    Drive a non-declaring role bound with a scope carrying a corpus name vs without; the two
    compiled policies are equal. RED today: RunScope has no ``corpus_name`` field."""
    from defender.runtime.agent_definition import RunScope
    rd = pending_run_dir(tmp_path)
    gather = AGENTS[AgentRole.GATHER]
    from defender.runtime.agent_definition import compile_policy_for
    plain = compile_policy_for(gather, rd)
    named = compile_policy_for(gather, rd, scope=RunScope(corpus_name="lessons"))  # RED: no field
    assert named.write_allow == plain.write_allow
    assert named.read_allow == plain.read_allow


def test_one_shared_spawn_request_drives_every_role_in_the_registry(tmp_path):
    """Every role binds from the ONE shared request, and the corpus name it carries is consumed by
    exactly one of them (the curator) and INERT for all the rest. Drive one shared scope (carrying a
    corpus_name) across every non-curator role and assert each role's policy is IDENTICAL to its
    bare-scope policy (the shared name changes nothing for a non-declaring role), then the curator
    consumes the SAME request's name into a real corpus-rooted write scope (c19/g19). RED today: the
    shared scope carries a corpus_name field that does not exist, and the curator is unbindable."""
    from defender.runtime.agent_definition import RunScope, compile_policy_for
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    shared = RunScope(corpus_name="lessons")  # RED: no field
    non_curator = 0
    for role, defn in AGENTS.items():
        if role is AgentRole.CORPUS_AUTHOR:
            continue
        with_name = compile_policy_for(defn, rd, scope=shared)      # the shared request drives it
        bare = compile_policy_for(defn, rd, scope=RunScope())
        assert with_name.write_allow == bare.write_allow           # the shared name is inert here
        assert with_name.read_allow == bare.read_allow
        non_curator += 1
    assert non_curator == len(AGENTS) - 1                          # every non-curator role survived
    curator = bind_curator(wt, rd, "lessons")                      # the one role that consumes it
    assert curator.policy.write_allow                              # into a real corpus-rooted scope


def test_every_role_in_the_registry_binds_through_the_one_seam(tmp_path):
    """Every role in AGENTS binds through the ONE ``bind`` seam (drives(role_census->bind), RunScope):
    after #0 the curator has no private ``_corpus_author_policy`` back-door — its policy is compiled
    by the SAME ``bind``/``compile_policy_for`` every other role goes through. Drive a non-curator role
    (green control — it already reaches a compiled policy through the seam) and the curator through the
    seam and observe each yields a real compiled write scope. RED today: the curator's policy is built
    OFF the seam (bindable=False), so binding it raises."""
    from defender.runtime.agent_definition import RunScope, compile_policy_for
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    # a non-curator role reaches a compiled policy through the seam — the positive control.
    gather_policy = compile_policy_for(AGENTS[AgentRole.GATHER], rd, scope=RunScope())
    assert gather_policy.bash_allow  # a real policy came back through the one seam
    # the curator reaches ITS compiled policy through the SAME seam, no private path.
    curator = bind_curator(wt, rd, "lessons")
    assert curator.policy.write_allow  # a real corpus-rooted write scope, produced by bind


def test_shared_runscope_reused_across_role_loop_iterations(tmp_path):
    """Reusing one RunScope across role-loop iterations has no observable effect on the next role's
    bind — bind READS the scope, never writes back to it. Drive two binds from one scope object;
    the second's policy is independent of the first. RED today (corpus_name field / bindable)."""
    from defender.runtime.agent_definition import RunScope, compile_policy_for
    rd = pending_run_dir(tmp_path)
    scope = RunScope(corpus_name="lessons")  # RED: no field
    p1 = compile_policy_for(AGENTS[AgentRole.GATHER], rd, scope=scope)
    p2 = compile_policy_for(AGENTS[AgentRole.JUDGE], rd, scope=scope)
    # two distinct roles compiled from the ONE reused scope get distinct policies — the shared
    # scope did not leak the first role's policy into the second (discriminating: fails if bind
    # mutated the scope so the second bind reproduced the first).
    assert p1.write_allow != p2.write_allow or p1.read_allow != p2.read_allow
    assert scope.read_confine == ()  # unchanged: bind never wrote back


def test_the_generic_bind_callers_survive_the_corpus_requirement(tmp_path):
    """The existing generic callers pass NO corpus name and MUST keep working: M8 fires only for
    DECLARING defs, and F83 makes corpus_name optional-with-sentinel. Drive TWO real generic callers
    for a non-corpus role — the bare-scope compile seam AND ``policy_cli``'s own bare ``RunScope()``
    path (c19/g19) — and assert each returns a real compiled policy carrying GATHER's actual bash
    grants, not a degenerate empty policy. Green preserved-behavior pin: it FAILS if the corpus
    requirement broke a bare-``RunScope()`` caller (the sole-seam suite is the third caller, covered
    by its own file)."""
    from defender.runtime.agent_definition import RunScope, compile_policy_for
    from defender.scripts import policy_cli
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    gather = AGENTS[AgentRole.GATHER]
    seam_pol = compile_policy_for(gather, rd, scope=RunScope())      # caller 1: the bare compile seam
    cli_pol = policy_cli._policy(gather, rd, wt / "defender")        # caller 2: policy_cli's bare scope
    assert seam_pol.bash_allow  # a real policy with GATHER's grants, not a degenerate stub
    assert cli_pol.bash_allow   # the policy_cli caller survives the corpus requirement too


def test_curator_deps_for_run_is_a_thin_wrapper_over_bind(tmp_path):
    """M9: ``CuratorDeps.for_run`` collapses to a thin wrapper over ``bind`` — the deps ``for_run``
    returns is bind-equivalent (same compiled write/read/confine scope) to ``bind`` for the same
    corpus. RED today: ``for_run`` bypasses bind (RG-PO6) and carries no confine, so the two
    policies DIVERGE; the demand is that they AGREE."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    via_bind = bind_curator(wt, rd, "lessons")  # RED today
    via_for_run = curator_deps(wt, rd, "lessons")
    assert via_for_run.policy.write_allow == via_bind.policy.write_allow
    assert via_for_run.policy.read_confine == via_bind.policy.read_confine


def test_policy_cli_prints_a_compiled_curator_policy(tmp_path):
    """M9: ``defender-policy show corpus_author`` prints a COMPILED curator policy instead of the
    old ``SystemExit`` ('builds its policy per-spawn, bindable=False'). Drive ``policy_cli._policy``
    for the curator — it must return a policy, not raise SystemExit. RED today (SystemExit)."""
    from defender.scripts import policy_cli
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    pol = policy_cli._policy(CORPUS_AUTHOR_DEF, rd, wt / "defender")  # RED today: SystemExit
    assert pol.write_allow


def test_binding_a_corpus_requiring_role_without_a_name_raises_legibly(tmp_path):
    """M8: binding a corpus-REQUIRING role (the curator) with NO corpus name raises a LEGIBLE
    ValueError naming the role and the missing input — never an IndexError. F86: M8 owns the
    absent name (None); M7 owns a supplied-but-degenerate value. RED today: the mechanism is not
    built (binding the curator raises the generic bindable error, not the named missing-name one)."""
    from defender.runtime.agent_definition import RunScope
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=r"(?i)corpus[_ ]?name|corpus name"):
        bind(CORPUS_AUTHOR_DEF, rd, scope=RunScope(), defender_dir=wt / "defender")


def test_corpus_name_absent_for_a_role_that_declares_it_needs_one(tmp_path):
    """M8, from the def-declares-it angle: a role that declares it needs a corpus, bound with no
    name, raises a legible ValueError (naming the role + the missing input) — never the old
    IndexError. Positive control: the curator bound WITH a name binds. RED today."""
    from defender.runtime.agent_definition import RunScope
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError):  # noqa: PT011
        bind(CORPUS_AUTHOR_DEF, rd, scope=RunScope(), defender_dir=wt / "defender")
    bind_curator(wt, rd, "lessons")  # positive control (RED today: bindable)


def test_policy_cli_is_given_a_role_that_requires_a_corpus_with_no_corpus_name_argument(tmp_path):
    """``policy_cli`` given the curator role with no corpus-name argument surfaces M8's legible
    missing-name error; the old ``SystemExit`` is gone (M8+M9). Drive ``policy_cli._policy`` with no
    corpus name and assert the legible missing-name ValueError. RED today (SystemExit bindable=False)."""
    from defender.scripts import policy_cli
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=r"(?i)corpus"):
        policy_cli._policy(CORPUS_AUTHOR_DEF, rd, wt / "defender")
