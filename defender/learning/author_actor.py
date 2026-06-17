#!/usr/bin/env python3
"""Actor lessons curator — consumer half of the actor learning queue.

Drains ``_pending/actor_observations.jsonl`` into the checked-in
``defender/lessons-actor/`` corpus. The transaction envelope (queue lock → repo
lock → clean-scope → partition → curator agent → git cross-check → rotate) lives in
``_author_curator``; this module supplies the actor direction's config and the one
divergent step — ``invoke_agent``, which hands the curator agent the actor-side
forward-check commands (``verify_forward_actor.py`` / ``verify_batch.py``).

Outcome policy (see judge.md): ``caught``/``incoherent`` author pattern/tradecraft
lessons; ``survived``/``undecidable`` skip. Standing deployment facts flow to the
shared ``lessons-environment/`` corpus via ``author_actor_benign`` (issue #298), not
here. Commits carry ``Generation: N`` + ``Actor-Model:`` trailers.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Sibling modules — invoked as a script, so import by path (no package chain).
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
LESSONS_ACTOR_DIR = REPO_ROOT / "defender" / "lessons-actor"
LESSONS_ACTOR_DIR_REL = "defender/lessons-actor/"

AUTHOR_PROMPT = LEARNING_DIR / "author_actor.md"

ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")
AUTHOR_ACTOR_MODEL = os.environ.get("LEARNING_AUTHOR_ACTOR_MODEL", "claude-sonnet-4-6")
AUTHOR_ACTOR_TIMEOUT = int(os.environ.get("LEARNING_AUTHOR_ACTOR_TIMEOUT_SECONDS", "1800"))
AUTHOR_ACTOR_EFFORT = os.environ.get("LEARNING_AUTHOR_ACTOR_EFFORT", "low")

# Re-exported for callers/tests that referenced the curator's fatal error type here.
AuthorError = _curator.AuthorError


def invoke_agent(
    observations: list[dict],
    batch_id: str,
    generation: int,
    cfg: _curator.CuratorConfig,
) -> dict:
    """Spawn the actor curator agent. Returns the parsed AUTHOR_RESULT dict.

    The actor corpus forward-checks per-lesson (``verify_forward_actor.py``) with a
    batch wrapper (``verify_batch.py``), so it hands the agent both command templates
    and allows both verifier scripts."""
    verifier_py = _runner.resolve_verifier_python(REPO_ROOT)
    extra_prompt = (
        f"trailer_label: {cfg.trailer_label}\n"
        f"verify_forward_command: {verifier_py} defender/learning/verify_forward_actor.py "
        f"<lesson_path> <observation_id>\n"
        f"verify_batch_command: {verifier_py} defender/learning/verify_batch.py "
        f"defender/learning/verify_forward_actor.py "
        f"<lesson_path>=<observation_id> [<lesson_path>=<observation_id> ...]\n"
    )
    extra_tools = (
        f"Bash({verifier_py} defender/learning/verify_batch.py:*),"
        f"Bash({verifier_py} defender/learning/verify_forward_actor.py:*),"
    )
    return _curator.invoke_curator_agent(
        cfg, observations, batch_id, generation,
        extra_prompt=extra_prompt, extra_tools=extra_tools,
    )


ACTOR_CONFIG = _curator.CuratorConfig(
    corpus_dir=LESSONS_ACTOR_DIR,
    corpus_dir_rel=LESSONS_ACTOR_DIR_REL,
    pending_file=DEFAULT_PATHS.actor_observations_file,
    consumed_file=DEFAULT_PATHS.actor_observations_consumed_file,
    lock_file=DEFAULT_PATHS.actor_observations_lock_file,
    outcome_author=frozenset({"caught", "incoherent"}),
    outcome_skip=frozenset({"survived", "undecidable"}),
    trailer_label="Actor-Model",
    generation_fn=_shared.actor_generation_count,
    actor_model=ACTOR_MODEL,
    log_prefix="author_actor",
    author_prompt=AUTHOR_PROMPT,
    author_model=AUTHOR_ACTOR_MODEL,
    author_timeout=AUTHOR_ACTOR_TIMEOUT,
    author_effort=AUTHOR_ACTOR_EFFORT,
    invoke_agent=invoke_agent,
)


def run_batch(*, hold_committed: bool = False) -> int:
    return _curator.run_batch(hold_committed=hold_committed, cfg=ACTOR_CONFIG)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
