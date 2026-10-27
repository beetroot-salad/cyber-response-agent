"""The curator scene the forward-check and lesson-read suites all build."""
from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

from defender.learning.author.curator_engine import CuratorDeps


def curator_scene(tmp_path: Path, *, extra_corpora: Sequence[str] = ()) -> SimpleNamespace:
    """A worktree, a lessons corpus, a runs dir and an empty pending-findings file.

    `extra_corpora` creates sibling lesson corpora (`lessons-questioner`) that only the
    read-confinement suite needs — its confinement checks are vacuous if the sibling does not
    exist. (#1108 P4 U5: the retired `lessons-actor`/`lessons-environment` are deleted.)
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
    """`CuratorDeps` over the scene, through the real `for_run` entry point.

    #773 M1: the forward-check config group `for_run` used to attach is gone — the check
    moved out of the curator's own spawn entirely, so there is nothing left to vary here
    but the corpus and the box."""
    return CuratorDeps.for_run(
        scene.curdir,
        scene.repo,
        corpus if corpus is not None else scene.corpus,
        box=box,
    )


#: One parse of the BATCH summary, so the two accessors below cannot read it two ways. Every
#: count is named and optional-free: a field that stops being emitted fails the match loudly
#: here rather than silently reading as zero at one call site and raising at the other.
_BATCH_RE = re.compile(
    r"BATCH:\s*n_good=(?P<good>\d+)\s+n_bad=(?P<bad>\d+)"
    r"\s+n_exempt=(?P<exempt>\d+)\s+n_error=(?P<error>\d+)"
)


def _batch(out: str) -> dict[str, int]:
    m = _BATCH_RE.search(out)
    assert m, f"no BATCH summary line in output:\n{out}"
    return {k: int(v) for k, v in m.groupdict().items()}


def batch_counts(out: str) -> tuple[int, int, int]:
    """`(n_good, n_bad, n_error)` off the BATCH summary line.

    THREE, still: `n_exempt` gets its own accessor rather than a fourth slot here, because every
    existing caller unpacks this into three names and a widened tuple would break them all at
    once for a count none of them asks about."""
    counts = _batch(out)
    return counts["good"], counts["bad"], counts["error"]


def batch_exempt(out: str) -> int:
    """How many pairs the check declared out of its own scope."""
    return _batch(out)["exempt"]


def build_curator_agent(tmp_path: Path, prompt_path: Path, make_model):
    """A CORPUS_AUTHOR stage agent over `prompt_path`, plus the logger to close.

    The prompt is a PARAMETER and must stay one: the two suites that build this agent
    write different prompts (a forward-check verdict prompt, a curation prompt), and a
    builder that picked one would hand the other suite an agent whose prompt is not the
    one its tests are about. `make_model` likewise — each suite scripts its own replay.

    The logger is created before the agent and closed on any failure, so a build that
    raises does not leak the open trace file.
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
    """A prompt file for a stage agent.

    Takes the name AND the text: the two suites that build a curator agent write
    *different* prompts (a forward-check verdict prompt, a curation prompt), and a shared
    builder that picked one would silently give the other suite a prompt whose contract it
    is not testing.
    """
    p = tmp_path / name
    p.write_text(text)
    return p
