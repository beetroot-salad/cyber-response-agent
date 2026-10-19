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
    the curator, with no special case — six roles, not five."""
    assert AgentRole.CORPUS_AUTHOR in _bash_roles()
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")  # RED today: bindable=False raises
    assert any(pat.fullmatch(str((wt / "defender" / "lessons" / "x.md").resolve()))
               for pat in deps.policy.write_allow)
    with pytest.raises(ValueError):  # noqa: PT011 - the co-constraint fires at bind, not at a census assertion
        build_registry((_misconfigured_writer_def(),))


def test_the_registry_validates_the_curator_at_import_time(tmp_path):
    assert CORPUS_AUTHOR_DEF.write_shapes != ()  # RED today (empty)
    with pytest.raises(ValueError):  # noqa: PT011
        build_registry((_misconfigured_writer_def(),))  # the un-skipped validation bites
    assert CORPUS_AUTHOR_DEF in AGENTS.values()


def test_every_role_in_the_registry_binds_through_the_one_seam(tmp_path):
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
    policy instead of the old ``SystemExit`` ('builds its policy per-spawn, bindable=False')."""
    from defender.scripts import policy_cli
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    pol = policy_cli._policy(CORPUS_AUTHOR_DEF, rd, wt / "defender", "lessons")
    assert pol.write_allow


def test_binding_a_corpus_requiring_role_without_a_name_raises_legibly(tmp_path):
    """M8: binding a corpus-REQUIRING role (the curator) with NO corpus name raises a LEGIBLE
    ValueError naming the role and the missing input — never an IndexError."""
    from defender.runtime.agent_definition import RunScope
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=r"(?i)corpus[_ ]?name|corpus name"):
        bind(CORPUS_AUTHOR_DEF, rd, scope=RunScope(), defender_dir=wt / "defender")
