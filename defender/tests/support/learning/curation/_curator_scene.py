"""The curator scene the lesson-read suites build."""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

from defender.learning.author.curator_engine import CuratorDeps


def curator_scene(tmp_path: Path, *, extra_corpora: Sequence[str] = ()) -> SimpleNamespace:
    """A worktree, a lessons corpus and the `_pending` run dir.

    `extra_corpora` creates sibling lesson corpora (`lessons-questioner`) for the
    read-confinement suite, whose checks are vacuous if the sibling does not exist.
    """
    repo = tmp_path / "wt"
    corpus = repo / "defender" / "lessons"
    corpus.mkdir(parents=True)
    for name in extra_corpora:
        (repo / "defender" / name).mkdir(parents=True)
    curdir = tmp_path / "state" / "_pending"
    curdir.mkdir(parents=True)
    return SimpleNamespace(tmp=tmp_path, repo=repo, corpus=corpus, curdir=curdir)


def curator_deps(scene, *, corpus: Path | None = None) -> CuratorDeps:
    """`CuratorDeps` over the scene, through the real `for_run` entry point."""
    return CuratorDeps.for_run(
        scene.curdir,
        scene.repo,
        corpus if corpus is not None else scene.corpus,
        box=None,
    )


def build_curator_agent(tmp_path: Path, prompt_path: Path, make_model):
    """A CORPUS_AUTHOR stage agent over `prompt_path` and `make_model`, plus the logger to
    close. The logger is created first and closed on any failure, so a build that raises does
    not leak the open trace file.
    """
    from defender.learning.core.config import StageWiring
    from defender.learning._pydantic_stage import build_stage_agent
    from defender.investigation import observe

    logger = observe.RequestLogger(tmp_path / "t.jsonl")
    try:
        agent = build_stage_agent(
            CuratorDeps,
            StageWiring(
                prompt_path=prompt_path, model="m", effort="low",
                trace_name="t.jsonl", label="curator",
            ),
            logger,
            make_model=make_model,
        )
        return agent, logger
    except Exception:
        logger.close()
        raise


def write_prompt(tmp_path: Path, name: str, text: str) -> Path:
    """A prompt file `name` holding `text`, for a stage agent."""
    p = tmp_path / name
    p.write_text(text)
    return p
