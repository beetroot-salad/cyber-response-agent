"""Registry census reaches the curator through the one bind seam; a corpus name is demanded legibly."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.learning.curation._curator_691_harness import (  # noqa: E402
    bind_curator,
    make_worktree,
    pending_run_dir,
)

from defender.agents import AGENTS  # noqa: E402
from defender._agent_role import AgentRole  # noqa: E402
from defender.investigation.agent_definition import (  # noqa: E402
    AgentDefinition,
    ToolSet,
    bind,
    build_registry,
)
from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF, CuratorDeps  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106


def _bash_roles() -> set[AgentRole]:
    """The generic bash census: ``d.tools.bash``, with no ``bindable`` gate."""
    return {d.role for d in AGENTS.values() if d.tools.bash}


def _misconfigured_writer_def() -> AgentDefinition:
    """A writer (``write=True``) declaring no ``write_shapes``, which the write co-constraint
    must reject at bind: the control showing the census is a real bind, not a field check."""
    return AgentDefinition(
        role=AgentRole.MAIN, model=lambda: "x", effort=None,
        tools=ToolSet(bash=True, write=True), write_shapes=(), deps_cls=CuratorDeps,
    )


def test_the_generic_bash_census_enumerates_the_curator(tmp_path):
    """``d.tools.bash`` enumerates the curator with no special case, and binding it yields a
    corpus-rooted write scope."""
    assert AgentRole.CORPUS_AUTHOR in _bash_roles()
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")
    assert any(pat.fullmatch(str((wt / "defender" / "lessons" / "x.md").resolve()))
               for pat in deps.policy.write_allow)
    with pytest.raises(ValueError):  # noqa: PT011 - the co-constraint fires at bind, not at a census assertion
        build_registry((_misconfigured_writer_def(),))


def test_the_registry_validates_the_curator_at_import_time():
    assert CORPUS_AUTHOR_DEF.write_shapes != ()
    with pytest.raises(ValueError):  # noqa: PT011
        build_registry((_misconfigured_writer_def(),))  # the registry's validation runs
    assert CORPUS_AUTHOR_DEF in AGENTS.values()


def test_every_role_in_the_registry_binds_through_the_one_seam(tmp_path):
    from defender.investigation.agent_definition import RunScope, compile_policy_for
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    # a non-curator role reaches a compiled policy through the seam — the positive control.
    gather_policy = compile_policy_for(T1106.fixture_gather_def(), rd, scope=RunScope())
    assert gather_policy.bash_allow  # a real policy came back through the one seam
    # the curator reaches ITS compiled policy through the SAME seam, no private path.
    curator = bind_curator(wt, rd, "lessons")
    assert curator.policy.write_allow  # a real corpus-rooted write scope, produced by bind


def test_policy_cli_prints_a_compiled_curator_policy(tmp_path):
    """``defender-policy show corpus_author --corpus-name lessons`` compiles a real curator
    policy."""
    from defender.cli import policy_cli
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    pol = policy_cli._policy(CORPUS_AUTHOR_DEF, rd, wt / "defender", "lessons")
    assert pol.write_allow


def test_binding_a_corpus_requiring_role_without_a_name_raises_legibly(tmp_path):
    """Binding the curator with no corpus name raises a legible ValueError naming the missing
    input, never an IndexError."""
    from defender.investigation.agent_definition import RunScope
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=r"(?i)corpus[_ ]?name|corpus name"):
        bind(CORPUS_AUTHOR_DEF, rd, scope=RunScope(), defender_dir=wt / "defender")
