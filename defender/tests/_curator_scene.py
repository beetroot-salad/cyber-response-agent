"""The curator scene the forward-check and lesson-read suites all build.

Three suites — `test_forward_check_tool`, `test_forward_check_trace`,
`test_lesson_read_tool` — each need the same starting world before they can drive
anything: a worktree with a lessons corpus in it, a runs dir, an empty pending-findings
file, and a `CuratorDeps` wired to those. All three had hand-rolled it, and they had
already drifted — one `_scene` created the two sibling corpora and the other two did not,
one `_deps` could take a box and the other could not — which is the shape where a test
starts asserting against a world its siblings do not have.

What is deliberately NOT here: each suite's `_lesson`. The three signatures are genuinely
different questions (a fenced lesson at a named corpus, a lesson keyed by `name` vs by
`techniques`, a lesson whose repo-relative operand is the return value), and collapsing
them would mean a helper with three modes and no caller that wants two of them.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

from defender.learning.author.curator_engine import CuratorDeps, ForwardCheckConfig
from defender.learning.author.verify_forward.checks import FINDINGS_CHECK


def curator_scene(tmp_path: Path, *, extra_corpora: Sequence[str] = ()) -> SimpleNamespace:
    """A worktree, a lessons corpus, a runs dir and an empty pending-findings file.

    `extra_corpora` creates the sibling lesson corpora (`lessons-actor`,
    `lessons-environment`) that only the read-confinement suite needs — it asserts the
    curator can reach all three shipped corpora, which is vacuous if two do not exist.
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


def source_bundle(
    scene, run_id: str, *, transcript: str | None = None, disposition: str = "malicious"
) -> Path:
    """One source run bundle under `scene.runs` — the transcript + its disposition."""
    d = scene.runs / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "investigation.md").write_text(transcript or f"TRANSCRIPT-for-{run_id}\n")
    (d / "source_refs.yaml").write_text(f"normalized_disposition: {disposition}\n")
    return d


def curator_deps(
    scene,
    *,
    run_verify,
    check=None,
    queued=(),
    corpus: Path | None = None,
    runs: Path | None = None,
    pending: Path | None = None,
    box=None,
) -> CuratorDeps:
    """`CuratorDeps` over the scene, through the real `for_run` entry point.

    Every override defaults to the scene's own path so a caller names only the axis its
    test varies; `run_verify` has no default because a check that does not say what it
    verifies with is the one mistake this helper must not make silent.
    """
    return CuratorDeps.for_run(
        scene.curdir,
        scene.repo,
        corpus if corpus is not None else scene.corpus,
        cfg=ForwardCheckConfig(
            check=check if check is not None else FINDINGS_CHECK,
            runs_dir=runs if runs is not None else scene.runs,
            pending=pending if pending is not None else scene.pending,
            queued_ids=frozenset(queued),
            run_verify=run_verify,
        ),
        box=box,
    )


def batch_counts(out: str) -> tuple[int, int, int]:
    """`(n_good, n_bad, n_error)` off the BATCH summary line."""
    m = re.search(r"BATCH:\s*n_good=(\d+)\s+n_bad=(\d+)\s+n_error=(\d+)", out)
    assert m, f"no BATCH summary line in output:\n{out}"
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


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
    from defender.learning.pipeline._pydantic_stage import build_stage_agent
    from defender.runtime import observe

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
