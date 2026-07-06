#!/usr/bin/env python3
"""Forward-check Haiku gate for a single candidate actor lesson.

Usage: ``verify_forward_actor.py <lesson_path> <observation_id>``

Resolves the observation row from
``defender/learning/_pending/actor_observations.jsonl`` (the active
queue — the row is still present during the author run; the queue is
rotated only on AUTHOR_RESULT post-flight). Reads the actor story
section 0 + body from ``{source_run_dir}/actor_story.md``. Runs the forward-check
IN-PROCESS on PydanticAI (GLM 5.2, Fireworks — the metered first-party path, the
mirror of the judge/actor/oracle migrations) with
``defender/learning/author/verify_forward/actor.md`` as the system prompt, via the
shared ``verify_forward/engine.forward_check``.
Prints exactly ``GOOD`` or ``BAD`` on the last line of stdout.

One rep per invocation. The author prompt allows one retry per
lesson (rewrite + re-run) before reverting and routing to
``consumed_skip``.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (it has a __main__
# block — the author drives it as a `claude -p` Bash subprocess).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from defender.learning.core.config import DEFAULT_PATHS  # noqa: E402
from defender._run_paths import resolve_run_bundle  # noqa: E402
from defender.learning.author.verify_forward.shared import (  # noqa: E402
    load_observation as _load_observation,
    data_section,
)

# Resolve the run bundle + queue off DEFAULT_PATHS (which honors
# DEFENDER_LEARNING_STATE_DIR) rather than this file's worktree ``__file__``: the
# author drains run this in a throwaway ``git worktree`` that has no runs/_pending, and
# the curator agent pins the state root in our env (curator_agent_env, #425).
PENDING_FILE = DEFAULT_PATHS.actor_observations.file
PROMPT_PATH = HERE / "actor.md"


def load_story(source_run_dir: str) -> str:
    path = (resolve_run_bundle(DEFAULT_PATHS.runs_dir, source_run_dir) / "actor_story.md").resolve()
    if not path.is_file():
        raise SystemExit(
            f"verify_forward_actor: actor_story.md missing at {path}"
        )
    return path.read_text()


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: verify_forward_actor.py <lesson_path> <observation_id>",
            file=sys.stderr,
        )
        return 64
    lesson_path = Path(argv[1]).resolve()
    observation_id = argv[2]
    if not lesson_path.is_file():
        print(
            f"verify_forward_actor: lesson not found: {lesson_path}",
            file=sys.stderr,
        )
        return 1
    row = _load_observation(
        observation_id, PENDING_FILE, error_prefix="verify_forward_actor"
    )
    observation_text = row.get("observation") or ""
    source_run_dir = row.get("source_run_dir") or ""
    if not observation_text or not source_run_dir:
        raise SystemExit(
            f"verify_forward_actor: observation row missing observation/source_run_dir: {row!r}"
        )
    story_text = load_story(source_run_dir)
    # Instructions live in actor.md (the system prompt, passed as prompt_path); the user
    # message is the case DATA only — the system/user split the sibling stages honor.
    user_prompt = "\n\n".join((
        data_section("ACTOR STORY (the original Section 0 + body the judge graded)", story_text),
        data_section("JUDGE OBSERVATION (the failure the lesson is trying to teach against)", observation_text),
        data_section("CANDIDATE LESSON", lesson_path.read_text()),
    ))
    # Lazy import: pulls the pydantic-ai graph only when a check actually runs, so this
    # module stays importable under any interpreter (the subprocess tests rely on that).
    from defender.learning.author.verify_forward.engine import forward_check

    t0 = time.monotonic()
    verdict = forward_check(
        prompt_path=PROMPT_PATH,
        user=user_prompt,
        source_run_dir=resolve_run_bundle(DEFAULT_PATHS.runs_dir, source_run_dir),
        lesson_stem=lesson_path.stem,
        error_prefix="verify_forward_actor",
    )
    elapsed = time.monotonic() - t0
    log_path = os.environ.get("VERIFY_TIMING_LOG") or str(
        HERE / "_verify_timing_actor.log"
    )
    try:
        with open(log_path, "a") as fh:
            fh.write(f"{lesson_path.name} {observation_id} {elapsed:.2f}\n")
    except OSError:
        pass
    print(verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
