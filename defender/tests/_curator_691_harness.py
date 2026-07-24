"""Shared machinery for the #691 curator-bindable executable spec (write-tests phase E).

The #691 change makes CORPUS_AUTHOR *bindable*: its per-spawn policy is compiled through
``bind`` (not a private ``_corpus_author_policy`` that roots write_allow at ``run_dir``), its
corpus is found BY NAME (M1), its reads are confined to the three shipped lesson corpora (R4),
and ``CuratorDeps.for_run`` collapses to a thin wrapper over ``bind`` (M9). None of that exists
at HEAD — ``CORPUS_AUTHOR_DEF.bindable`` is ``False`` and ``for_run`` bypasses ``bind`` — so the
binding-seam calls below RAISE or mis-resolve today. That is the design: these tests ARE the
contract the refactor is written against, RED against HEAD by construction.

This module is the ONE reconcile point for the provisional target API (phase-D forks f1-f6):
the corpus name rides on ``RunScope`` (F89 — a bind INPUT resolved before ``bind`` returns; F83 —
optional-with-sentinel so every bare ``RunScope()`` caller survives), the confine is the three
shipped corpora (R4), and the tree is the spawn's worktree (M3). ``write-code-from-spec``
reconciles the code's actual spelling against these call sites; the join stays HERE so there is
exactly one place to fix, never N. The leading underscore keeps pytest from collecting it.

Two seam entry points, deliberately distinct:

* ``bind_curator`` drives the binding seam ITSELF (``bind(CORPUS_AUTHOR_DEF, …)``) — for the
  construction / census / M-mechanism demands. RED today (bindable=False raises; RunScope has no
  ``corpus_name`` field yet). The tests that use it assert on the message / observable so the raise
  they see is the DEMANDED one once #0 lands, not an incidental import error.
* ``curator_deps`` builds a ``CuratorDeps`` through the STABLE ``for_run`` entry point (M9 keeps it)
  and its real ``.policy`` is then driven through the real gates. The confine / membership / rm
  corrections surface as the policy's OWN decisions changing under the refactor — each test red on
  its own assertion, not on a shared crash.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind  # noqa: E402
from defender.runtime.tools import _tool_edit_file, _tool_write_file  # noqa: E402
from defender.learning.author.lesson_read import _tool_lesson_read  # noqa: E402

# curator_engine EXISTS today (bindable=False); these imports are not the red.
from defender.learning.author.curator_engine import (  # noqa: E402
    CORPUS_AUTHOR_DEF,
    CuratorDeps,
)
from defender.learning.author.verify_forward.checks import FINDINGS_CHECK  # noqa: E402

# The three shipped lesson corpora — the exact-match membership set (MD-6) and the read confine (R4).
SHIPPED: tuple[str, ...] = ("lessons", "lessons-actor", "lessons-environment")


# --------------------------------------------------------------------------- #
# On-disk fixtures: a worktree (where lessons are authored) + a _pending run dir
# (the shared state root every spawn drains into; run_id == "_pending", P4).
# --------------------------------------------------------------------------- #

def make_worktree(tmp_path: Path) -> Path:
    """A tmp batch worktree: the three lesson corpora exist (so real writes land) plus two
    real NON-lesson dirs (``docs``/``skills``) the confine must exclude and M7 shape-admits."""
    root = tmp_path / "wt"
    for name in (*SHIPPED, "docs", "skills"):
        (root / "defender" / name).mkdir(parents=True, exist_ok=True)
    (root / "defender" / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    return root


def pending_run_dir(tmp_path: Path) -> Path:
    """The production run-dir shape: ``<MAIN>/defender/learning/_pending`` — a DIFFERENT tree
    from the authored worktree, ``run_id == "_pending"`` for every spawn (P4)."""
    d = tmp_path / "MAIN" / "defender" / "learning" / "_pending"
    d.mkdir(parents=True, exist_ok=True)
    return d


def corpus(wt: Path, corpus_name: str) -> Path:
    return wt / "defender" / corpus_name


def confine(wt: Path) -> tuple[Path, ...]:
    """The R4 read confine: the three shipped corpora, resolved (``decide_read`` resolves both sides)."""
    return tuple(corpus(wt, n).resolve() for n in SHIPPED)


def rel(corpus_name: str, filename: str = "lesson.md") -> str:
    """The repo-relative operand spelling the agent (cwd=worktree) types, e.g.
    ``defender/lessons-actor/x.md`` — rebased on the deps' ``cwd_anchor`` by ``_resolve_operand``."""
    return f"defender/{corpus_name}/{filename}"


# --------------------------------------------------------------------------- #
# The binding seam under test (RED against HEAD).
# --------------------------------------------------------------------------- #

def curator_scope(wt: Path, corpus_name: str = "lessons", *, read_confine=None) -> RunScope:
    """The target ``RunScope`` a curator bind takes: the per-spawn corpus NAME (F89 — a bind input;
    F83 — optional-with-sentinel) + the three-corpus read confine (R4). RED shape today: ``RunScope``
    carries no ``corpus_name`` field, so this raises ``TypeError`` — the missing M1/#0 field."""
    conf = confine(wt) if read_confine is None else read_confine
    return RunScope(corpus_name=corpus_name, read_confine=conf)  # type: ignore[call-arg]


def bind_curator(
    wt: Path, run_dir: Path, corpus_name: str = "lessons", *,
    read_confine=None, defender_dir: Path | None = None,
):
    """Bind the curator BY NAME against its worktree tree — THE binding seam #0 builds.

    RED against HEAD: ``CORPUS_AUTHOR_DEF.bindable`` is ``False`` (``compile_policy_for`` raises),
    ``RunScope`` has no ``corpus_name``, and ``CuratorDeps._for_run`` still requires the six bare
    fields ``bind`` does not forward (c9). The tests that call this assert on the DEMANDED observable
    (message, compiled scope, raised class) so a green #0 is what turns them, not an incidental error.
    """
    dd = (wt / "defender") if defender_dir is None else defender_dir
    return bind(
        CORPUS_AUTHOR_DEF, run_dir,
        scope=curator_scope(wt, corpus_name, read_confine=read_confine),
        defender_dir=dd,
    )


def curator_deps(wt: Path, run_dir: Path, corpus_name: str = "lessons") -> CuratorDeps:
    """A ``CuratorDeps`` through the STABLE ``for_run`` entry point (M9 keeps it as a thin wrapper
    over ``bind``). Drive ``.policy`` through the real gates; the confine / membership / rm
    corrections surface as the policy's OWN decisions changing under the refactor."""
    return CuratorDeps.for_run(
        run_dir, wt, corpus(wt, corpus_name),
        check=FINDINGS_CHECK, runs_dir=wt / "runs",
        pending=wt / "_pending" / "findings.jsonl", queued_ids=frozenset(),
    )


# --------------------------------------------------------------------------- #
# Real-gate drivers — the OBSERVABLE channels. One home for each so the four test
# files never re-roll them (the duplicate-helpers ratchet). Every driver hits a
# REAL permission primitive; assertions are on its Decision / raised ModelRetry.
# --------------------------------------------------------------------------- #

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


def forward_check_gate(deps, operand: str) -> Path:
    """The forward_check tool's own lesson gate (``_gate_lesson_path`` → ``decide_write``; raises
    ModelRetry on deny) — the fourth write-capable lane."""
    from defender.learning.author.verify_forward.tool import _gate_lesson_path
    return _gate_lesson_path(deps, operand)
