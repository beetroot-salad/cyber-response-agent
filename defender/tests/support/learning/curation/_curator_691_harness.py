"""Shared machinery for the #691 curator-binding tests: worktree fixtures, the curator bind, and
real-gate drivers."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import RunScope, bind  # noqa: E402
from defender.investigation.tools import _tool_edit_file, _tool_write_file  # noqa: E402
from defender.investigation.tools.lesson_read import _tool_lesson_read  # noqa: E402

from defender.learning.author.curator_engine import (  # noqa: E402
    CORPUS_AUTHOR_DEF,
    CuratorDeps,
)

#: The shipped lesson corpora: the exact-match membership set and the read confine. Spelled
#: here, not imported, so a test can observe the production constant diverging from it.
SHIPPED: tuple[str, ...] = ("lessons", "lessons-questioner")


# On-disk fixtures: a worktree (where lessons are authored) and the `_pending` run dir every
# spawn drains into.

def make_worktree(tmp_path: Path) -> Path:
    """A tmp batch worktree: the shipped corpora exist (so real writes land), plus two real
    non-lesson dirs (``docs``/``skills``) that pass the path-shape check but that the confine
    must exclude."""
    root = tmp_path / "wt"
    for name in (*SHIPPED, "docs", "skills"):
        (root / "defender" / name).mkdir(parents=True, exist_ok=True)
    (root / "defender" / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    return root


def pending_run_dir(tmp_path: Path) -> Path:
    """The production run-dir shape, ``<MAIN>/defender/learning/_pending``: a different tree
    from the authored worktree, with ``run_id == "_pending"`` for every spawn."""
    d = tmp_path / "MAIN" / "defender" / "learning" / "_pending"
    d.mkdir(parents=True, exist_ok=True)
    return d


def corpus(wt: Path, corpus_name: str) -> Path:
    return wt / "defender" / corpus_name


def confine(wt: Path) -> tuple[Path, ...]:
    """The read confine: the shipped corpora, resolved (``decide_read`` resolves both sides)."""
    return tuple(corpus(wt, n).resolve() for n in SHIPPED)


def rel(corpus_name: str, filename: str = "lesson.md") -> str:
    """The repo-relative operand spelling the agent (cwd=worktree) types, e.g.
    ``defender/lessons-questioner/x.md`` — rebased on the deps' ``cwd_anchor`` by ``_resolve_operand``."""
    return f"defender/{corpus_name}/{filename}"


# The binding seam under test.

def curator_scope(wt: Path, corpus_name: str = "lessons", *, read_confine=None) -> RunScope:
    """The ``RunScope`` a curator bind takes: the per-spawn corpus name plus the read confine."""
    conf = confine(wt) if read_confine is None else read_confine
    return RunScope(corpus_name=corpus_name, read_confine=conf)  # type: ignore[call-arg]


def bind_curator(
    wt: Path, run_dir: Path, corpus_name: str = "lessons", *,
    read_confine=None, defender_dir: Path | None = None,
):
    """Bind the curator by corpus name against its worktree tree, through the real ``bind``."""
    dd = (wt / "defender") if defender_dir is None else defender_dir
    return bind(
        CORPUS_AUTHOR_DEF, run_dir,
        scope=curator_scope(wt, corpus_name, read_confine=read_confine),
        defender_dir=dd,
    )


def curator_deps(
    wt: Path, run_dir: Path, corpus_name: str = "lessons", *, box=None,
) -> CuratorDeps:
    """A ``CuratorDeps`` through the production ``for_run`` entry point (a thin wrapper over
    ``bind``); tests drive its ``.policy`` through the real gates."""
    return CuratorDeps.for_run(run_dir, wt, corpus(wt, corpus_name), box=box)


# Real-gate drivers: each hits a real permission primitive, and tests assert on its Decision or
# raised ModelRetry. One home, so the test files never re-roll them (the duplicate-helpers lint).

def bash_decision(deps, cmd: str):
    """The bash lane the way ``_tool_bash`` drives it (run_dir + defender_dir + cwd_anchor)."""
    return permission.decide_bash(
        cmd, policy=deps.policy,
        run_dir=deps.run_dir, defender_dir=deps.defender_dir, cwd_anchor=deps.cwd_anchor,
    )


def read_decision(deps, path: str):
    """``decide_read`` over an operand resolved against the deps' cwd_anchor (the lesson-read lane)."""
    p = Path(path)
    rp = p if p.is_absolute() else deps.cwd_anchor / p
    return permission.decide_read(
        rp, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )


def write_file(deps, path: str, content: str = "body\n") -> str:
    """The write_file tool wrapper (raises ModelRetry on a decide_write deny; lands the file on allow)."""
    return _tool_write_file(deps, path, content)


def edit_file(deps, path: str, old: str, new: str) -> str:
    """The edit_file tool wrapper (decide_read THEN decide_write; raises ModelRetry on either deny)."""
    return _tool_edit_file(deps, path, old, new)


def lesson_read(deps, path: str, part: str = "body", pattern=None) -> str:
    """The lesson_read tool wrapper (raises ModelRetry on a decide_read deny)."""
    return _tool_lesson_read(deps, path, part, pattern)
