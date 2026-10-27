"""The curator scene the lesson-read suites build."""
from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

from defender.learning.author.curator_engine import CuratorDeps


def curator_scene(tmp_path: Path, *, extra_corpora: Sequence[str] = ()) -> SimpleNamespace:
    """A worktree, a lessons corpus, a runs dir and an empty pending-findings file.

    `extra_corpora` creates sibling lesson corpora (`lessons-questioner`) for the
    read-confinement suite, whose checks are vacuous if the sibling does not exist.
    """
    repo = tmp_path / "wt"
    corpus = repo / "defender" / "lessons"
    corpus.mkdir(parents=True)
    for name in extra_corpora:
        (repo / "defender" / name).mkdir(parents=True)
    runs = tmp_path / "state" / "runs"
    runs.mkdir(parents=True)
    curdir = tmp_path / "state" / "_pending"
    pending = curdir / "findings.jsonl"
    pending.parent.mkdir(parents=True, exist_ok=True)
    pending.write_text("")
    return SimpleNamespace(
        tmp=tmp_path, repo=repo, corpus=corpus, runs=runs, pending=pending, curdir=curdir,
    )


def curator_deps(scene, *, corpus: Path | None = None, box=None) -> CuratorDeps:
    """`CuratorDeps` over the scene, through the real `for_run` entry point."""
    return CuratorDeps.for_run(
        scene.curdir,
        scene.repo,
        corpus if corpus is not None else scene.corpus,
        box=box,
    )


#: One parse of the BATCH summary for both accessors below; every count is required, so a field
#: that stops being emitted fails the match loudly instead of reading as zero.
_BATCH_RE = re.compile(
    r"BATCH:\s*n_good=(?P<good>\d+)\s+n_bad=(?P<bad>\d+)"
    r"\s+n_exempt=(?P<exempt>\d+)\s+n_error=(?P<error>\d+)"
)


def _batch(out: str) -> dict[str, int]:
    m = _BATCH_RE.search(out)
    assert m, f"no BATCH summary line in output:\n{out}"
    return {k: int(v) for k, v in m.groupdict().items()}


def batch_counts(out: str) -> tuple[int, int, int]:
    """`(n_good, n_bad, n_error)` off the BATCH summary line; `n_exempt` has its own accessor."""
    counts = _batch(out)
    return counts["good"], counts["bad"], counts["error"]


def batch_exempt(out: str) -> int:
    """How many pairs the check declared out of its own scope."""
    return _batch(out)["exempt"]


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
