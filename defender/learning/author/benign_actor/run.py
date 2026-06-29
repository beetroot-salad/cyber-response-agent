#!/usr/bin/env python3
"""Environment lessons curator — consumer half of the env-observation queues.

Drains an env-observation queue into the checked-in, **shared** environment corpus
at ``defender/lessons-environment/`` — the corpus both actors retrieve by
classification before constructing a story. Two sources feed that one corpus, each
via its own queue + ``CuratorConfig`` (issue #298):

  - **benign (FP) direction** — ``BENIGN_CONFIG``. The false-positive analog of
    ``author_actor.py``. Drains ``_pending/environment_observations.jsonl``. Finding-
    bearing outcome: ``survived`` (the confirmed-FP story whose grounded routine
    explanation yields reliable standing facts). Commit trailer ``Benign-Actor-Model:``.
  - **adversarial direction** — ``ADVERSARIAL_CONFIG``. Drains
    ``_pending/actor_environment_observations.jsonl`` (positive-polarity env facts the
    adversarial judge extracts from grounded mispredictions). Finding-bearing
    outcomes: ``caught``/``incoherent``. Commit trailer ``Actor-Env-Model:``. Exposed
    via the thin ``author_actor_env.py`` entry point.

Both configs share the corpus, the transaction envelope (``_author_curator``), the
corpus-wide idempotency set, the repo lock, and the ``verify_forward_env.py`` gate —
only the queue paths, outcome policy, commit trailer + generation counter, and the
actor model differ.
"""
from __future__ import annotations

import functools
import os
import sys
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import curator as _curator
from defender.learning.author import runner as _runner
from defender.learning.author import shared as _shared
from defender.learning.core.config import (
    ACTOR_MODEL,
    BENIGN_ACTOR_MODEL,
    DEFAULT_PATHS,
    LoopPaths,
)


LESSONS_ENV_DIR_REL = "defender/lessons-environment/"
VERIFY_SCRIPT_REL = "defender/learning/author/verify_forward/env.py"

# The curator *agent* model/effort/timeout are shared across directions — only the
# *actor* model differs per source. The actor model is NOT authoring input (the
# curator agent never sees it): it is commit provenance, stamped into the per-source
# trailer (Benign-Actor-Model: / Actor-Env-Model:). ACTOR_MODEL/BENIGN_ACTOR_MODEL
# are imported from core.config — the SAME constants the real actor invocations read
# (pipeline/*_actor/run.py) — so the recorded model can't diverge from the model the
# actor actually ran at via a second env read (issue #449).
AUTHOR_ENV_MODEL = os.environ.get("LEARNING_AUTHOR_ENV_MODEL", "claude-sonnet-4-6")
AUTHOR_ENV_TIMEOUT = int(os.environ.get("LEARNING_AUTHOR_ENV_TIMEOUT_SECONDS", "1800"))
AUTHOR_ENV_EFFORT = os.environ.get("LEARNING_AUTHOR_ENV_EFFORT", "low")

# Re-exported for callers/tests that referenced the curator's fatal error type here.
AuthorError = _curator.AuthorError


def invoke_agent(
    observations: list[dict],
    batch_id: str,
    cfg: _curator.CuratorConfig,
) -> dict:
    """Spawn the environment curator agent. Returns the parsed AUTHOR_RESULT dict.

    The env corpus forward-checks the whole batch in one pass
    (``verify_forward_env.py --corpus --pending``), so it hands the agent that single
    command. The commit-trailer provenance (including the per-direction trailer label)
    is stamped by the loop, not the agent, so nothing trailer-related goes in the
    prompt."""
    verifier_py = _runner.resolve_verifier_python(cfg.repo_root)
    forward_check_command = (
        f"{verifier_py} {VERIFY_SCRIPT_REL} "
        f"--corpus {cfg.corpus_dir_rel} --pending {cfg.pending_file_rel}"
    )
    extra_prompt = (
        f"forward_check_command: {forward_check_command}\n"
    )
    extra_tools = f"Bash({verifier_py} {VERIFY_SCRIPT_REL}:*),"
    return _curator.invoke_curator_agent(
        cfg, observations, batch_id,
        extra_prompt=extra_prompt, extra_tools=extra_tools,
    )


def _env_config(  # noqa: PLR0913 — every parameter is the per-direction field that varies
    paths: LoopPaths,
    *,
    pending_file: Path,
    consumed_file: Path,
    lock_file: Path,
    outcome_author: frozenset[str],
    outcome_skip: frozenset[str],
    trailer_label: str,
    generation_fn,
    actor_model: str,
    log_prefix: str,
) -> _curator.CuratorConfig:
    """Build a CuratorConfig for the shared lessons-environment/ corpus — only the
    queue + policy + trailer + actor-model fields vary between the two directions."""
    return _curator.CuratorConfig(
        repo_root=paths.repo_root,
        pending_dir=paths.pending_dir,
        corpus_dir=paths.lessons_environment_dir,
        corpus_dir_rel=LESSONS_ENV_DIR_REL,
        pending_file=pending_file,
        consumed_file=consumed_file,
        lock_file=lock_file,
        repo_lock_file=paths.author_lock_file,
        repo_lock_wait_seconds=_shared.REPO_LOCK_WAIT_SECONDS,
        outcome_author=outcome_author,
        outcome_skip=outcome_skip,
        trailer_label=trailer_label,
        generation_fn=generation_fn,
        actor_model=actor_model,
        log_prefix=log_prefix,
        author_prompt=paths.learning_dir / "author" / "benign_actor" / "prompt.md",
        author_model=AUTHOR_ENV_MODEL,
        author_timeout=AUTHOR_ENV_TIMEOUT,
        author_effort=AUTHOR_ENV_EFFORT,
        invoke_agent=invoke_agent,
    )


def build_benign_config(paths: LoopPaths = DEFAULT_PATHS) -> _curator.CuratorConfig:
    """Benign (FP) direction — ``survived`` is the confirmed-FP outcome whose routine
    story held against the evidence, so the standing facts it grounds are reliable."""
    return _env_config(
        paths,
        pending_file=paths.environment_observations_file,
        consumed_file=paths.environment_observations_consumed_file,
        lock_file=paths.environment_observations_lock_file,
        outcome_author=frozenset({"survived"}),
        outcome_skip=frozenset({"refuted", "undecidable", "incoherent"}),
        trailer_label="Benign-Actor-Model",
        generation_fn=functools.partial(_shared.benign_generation_count, paths.repo_root),
        actor_model=BENIGN_ACTOR_MODEL,
        log_prefix="author_actor_benign",
    )


def build_adversarial_config(paths: LoopPaths = DEFAULT_PATHS) -> _curator.CuratorConfig:
    """Adversarial direction (issue #298) — env facts the adversarial judge extracts from
    grounded mispredictions. Finding-bearing outcomes mirror author_actor.py:
    ``caught``/``incoherent`` (the refutation cited real telemetry)."""
    return _env_config(
        paths,
        pending_file=paths.actor_environment_observations_file,
        consumed_file=paths.actor_environment_observations_consumed_file,
        lock_file=paths.actor_environment_observations_lock_file,
        outcome_author=frozenset({"caught", "incoherent"}),
        outcome_skip=frozenset({"survived", "undecidable"}),
        trailer_label="Actor-Env-Model",
        generation_fn=functools.partial(_shared.actor_env_generation_count, paths.repo_root),
        actor_model=ACTOR_MODEL,
        log_prefix="author_actor_env",
    )


# Production default configs; tests build their own via build_*_config(tmp paths).
BENIGN_CONFIG = build_benign_config(DEFAULT_PATHS)
ADVERSARIAL_CONFIG = build_adversarial_config(DEFAULT_PATHS)


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths = DEFAULT_PATHS,
    cfg: _curator.CuratorConfig | None = None,
) -> int:
    # Default to the benign direction built from the injected paths; the adversarial
    # entry (author_actor_env) passes its own cfg explicitly.
    if cfg is None:
        cfg = build_benign_config(paths)
    return _curator.run_batch(hold_committed=hold_committed, cfg=cfg)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_benign.py", file=sys.stderr)
        return 64
    return run_batch(cfg=BENIGN_CONFIG)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
