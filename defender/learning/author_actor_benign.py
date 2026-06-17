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

import os
import sys
from pathlib import Path

# Sibling modules — imported by path (no package __init__ chain).
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import _author_curator as _curator  # type: ignore[import-not-found]
    import _author_runner as _runner  # type: ignore[import-not-found]
    import _author_shared as _shared  # type: ignore[import-not-found]
    from _loop_config import DEFAULT_PATHS  # type: ignore[import-not-found]
finally:
    sys.path.pop(0)


REPO_ROOT = _curator.REPO_ROOT
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
LESSONS_ENV_DIR = REPO_ROOT / "defender" / "lessons-environment"
LESSONS_ENV_DIR_REL = "defender/lessons-environment/"

AUTHOR_PROMPT = LEARNING_DIR / "author_actor_benign.md"
VERIFY_SCRIPT_REL = "defender/learning/verify_forward_env.py"

# The curator *agent* model/effort/timeout are shared across directions — only the
# *actor* model (recorded in the commit trailer + handed to the curator as context)
# differs per source.
AUTHOR_ENV_MODEL = os.environ.get("LEARNING_AUTHOR_ENV_MODEL", "claude-sonnet-4-6")
AUTHOR_ENV_TIMEOUT = int(os.environ.get("LEARNING_AUTHOR_ENV_TIMEOUT_SECONDS", "1800"))
AUTHOR_ENV_EFFORT = os.environ.get("LEARNING_AUTHOR_ENV_EFFORT", "low")

BENIGN_ACTOR_MODEL = os.environ.get("BENIGN_ACTOR_MODEL", "claude-sonnet-4-6")
ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")

# Re-exported for callers/tests that referenced the curator's fatal error type here.
AuthorError = _curator.AuthorError


def invoke_agent(
    observations: list[dict],
    batch_id: str,
    generation: int,
    cfg: _curator.CuratorConfig,
) -> dict:
    """Spawn the environment curator agent. Returns the parsed AUTHOR_RESULT dict.

    The env corpus forward-checks the whole batch in one pass
    (``verify_forward_env.py --corpus --pending``), so it hands the agent that single
    command plus the trailer label it must stamp."""
    verifier_py = _runner.resolve_verifier_python(REPO_ROOT)
    forward_check_command = (
        f"{verifier_py} {VERIFY_SCRIPT_REL} "
        f"--corpus {LESSONS_ENV_DIR_REL} --pending {cfg.pending_file_rel}"
    )
    extra_prompt = (
        f"trailer_label: {cfg.trailer_label}\n"
        f"forward_check_command: {forward_check_command}\n"
    )
    extra_tools = f"Bash({verifier_py} {VERIFY_SCRIPT_REL}:*),"
    return _curator.invoke_curator_agent(
        cfg, observations, batch_id, generation,
        extra_prompt=extra_prompt, extra_tools=extra_tools,
    )


def _env_config(  # noqa: PLR0913 — every parameter is the per-direction field that varies
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
        corpus_dir=LESSONS_ENV_DIR,
        corpus_dir_rel=LESSONS_ENV_DIR_REL,
        pending_file=pending_file,
        consumed_file=consumed_file,
        lock_file=lock_file,
        outcome_author=outcome_author,
        outcome_skip=outcome_skip,
        trailer_label=trailer_label,
        generation_fn=generation_fn,
        actor_model=actor_model,
        log_prefix=log_prefix,
        author_prompt=AUTHOR_PROMPT,
        author_model=AUTHOR_ENV_MODEL,
        author_timeout=AUTHOR_ENV_TIMEOUT,
        author_effort=AUTHOR_ENV_EFFORT,
        invoke_agent=invoke_agent,
    )


# Benign (FP) direction — ``survived`` is the confirmed-FP outcome whose routine
# story held against the evidence, so the standing facts it grounds are reliable.
BENIGN_CONFIG = _env_config(
    pending_file=DEFAULT_PATHS.environment_observations_file,
    consumed_file=DEFAULT_PATHS.environment_observations_consumed_file,
    lock_file=DEFAULT_PATHS.environment_observations_lock_file,
    outcome_author=frozenset({"survived"}),
    outcome_skip=frozenset({"refuted", "undecidable", "incoherent"}),
    trailer_label="Benign-Actor-Model",
    generation_fn=_shared.benign_generation_count,
    actor_model=BENIGN_ACTOR_MODEL,
    log_prefix="author_actor_benign",
)

# Adversarial direction (issue #298) — env facts the adversarial judge extracts from
# grounded mispredictions. Finding-bearing outcomes mirror author_actor.py:
# ``caught``/``incoherent`` (the refutation cited real telemetry).
ADVERSARIAL_CONFIG = _env_config(
    pending_file=DEFAULT_PATHS.actor_environment_observations_file,
    consumed_file=DEFAULT_PATHS.actor_environment_observations_consumed_file,
    lock_file=DEFAULT_PATHS.actor_environment_observations_lock_file,
    outcome_author=frozenset({"caught", "incoherent"}),
    outcome_skip=frozenset({"survived", "undecidable"}),
    trailer_label="Actor-Env-Model",
    generation_fn=_shared.actor_env_generation_count,
    actor_model=ACTOR_MODEL,
    log_prefix="author_actor_env",
)


def run_batch(
    *, hold_committed: bool = False, cfg: _curator.CuratorConfig = BENIGN_CONFIG
) -> int:
    return _curator.run_batch(hold_committed=hold_committed, cfg=cfg)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_benign.py", file=sys.stderr)
        return 64
    return run_batch(cfg=BENIGN_CONFIG)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
