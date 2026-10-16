"""Registry census reaches the curator through the one bind seam; a corpus name is demanded legibly."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from _curator_691_harness import (  # noqa: E402
    bind_curator,
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
from defender.tests import _tenants1106 as T1106  # noqa: E402


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
    gather_policy = compile_policy_for(T1106.fixture_gather_def(), rd, scope=RunScope())
    assert gather_policy.bash_allow  # a real policy came back through the one seam
    # the curator reaches ITS compiled policy through the SAME seam, no private path.
    curator = bind_curator(wt, rd, "lessons")
    assert curator.policy.write_allow  # a real corpus-rooted write scope, produced by bind


def test_policy_cli_prints_a_compiled_curator_policy(tmp_path):
    """M9: ``defender-policy show corpus_author --corpus-name lessons`` prints a COMPILED curator
    policy instead of the old ``SystemExit`` ('builds its policy per-spawn, bindable=False'). Drive
    ``policy_cli._policy`` for the curator WITH its corpus name (M8 demands one; the CLI's
    ``--corpus-name`` flag is how an operator supplies it) — it must return a real compiled policy,
    not raise SystemExit. RED today (SystemExit)."""
    from defender.scripts import policy_cli
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    pol = policy_cli._policy(CORPUS_AUTHOR_DEF, rd, wt / "defender", "lessons")
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


