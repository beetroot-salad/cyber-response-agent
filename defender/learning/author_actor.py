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

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning import _author_curator as _curator
from defender.learning import _author_runner as _runner
from defender.learning import _author_shared as _shared
from defender.learning._loop_config import DEFAULT_PATHS, LoopPaths


LESSONS_ACTOR_DIR_REL = "defender/lessons-actor/"

ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")
AUTHOR_ACTOR_MODEL = os.environ.get("LEARNING_AUTHOR_ACTOR_MODEL", "claude-sonnet-4-6")
AUTHOR_ACTOR_TIMEOUT = int(os.environ.get("LEARNING_AUTHOR_ACTOR_TIMEOUT_SECONDS", "1800"))
AUTHOR_ACTOR_EFFORT = os.environ.get("LEARNING_AUTHOR_ACTOR_EFFORT", "low")

# Re-exported for callers/tests that referenced the curator's fatal error type here.
AuthorError = _curator.AuthorError


def invoke_agent(
    observations: list[dict],
    batch_id: str,
    cfg: _curator.CuratorConfig,
) -> dict:
    """Spawn the actor curator agent. Returns the parsed AUTHOR_RESULT dict.

    The actor corpus forward-checks per-lesson (``verify_forward_actor.py``) with a
    batch wrapper (``verify_batch.py``), so it hands the agent both command templates
    and allows both verifier scripts. The commit-trailer provenance is stamped by the
    loop, not the agent, so nothing trailer-related goes in the prompt."""
    verifier_py = _runner.resolve_verifier_python(cfg.repo_root)
    extra_prompt = (
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
        cfg, observations, batch_id,
        extra_prompt=extra_prompt, extra_tools=extra_tools,
    )


def build_actor_config(paths: LoopPaths = DEFAULT_PATHS) -> _curator.CuratorConfig:
    """Build the actor-direction ``CuratorConfig`` from an injected ``LoopPaths``.

    Constructed at call time (not import) so a test rooted at a tmp tree threads one
    ``LoopPaths(repo_root=tmp)`` instead of monkeypatching module path globals."""
    return _curator.CuratorConfig(
        repo_root=paths.repo_root,
        pending_dir=paths.pending_dir,
        corpus_dir=paths.lessons_actor_dir,
        corpus_dir_rel=LESSONS_ACTOR_DIR_REL,
        pending_file=paths.actor_observations_file,
        consumed_file=paths.actor_observations_consumed_file,
        lock_file=paths.actor_observations_lock_file,
        outcome_author=frozenset({"caught", "incoherent"}),
        outcome_skip=frozenset({"survived", "undecidable"}),
        trailer_label="Actor-Model",
        generation_fn=_shared.actor_generation_count,
        actor_model=ACTOR_MODEL,
        log_prefix="author_actor",
        author_prompt=paths.learning_dir / "author_actor.md",
        author_model=AUTHOR_ACTOR_MODEL,
        author_timeout=AUTHOR_ACTOR_TIMEOUT,
        author_effort=AUTHOR_ACTOR_EFFORT,
        invoke_agent=invoke_agent,
    )


# Production default config; tests build their own via build_actor_config(tmp paths).
ACTOR_CONFIG = build_actor_config(DEFAULT_PATHS)


def run_batch(*, hold_committed: bool = False, paths: LoopPaths = DEFAULT_PATHS) -> int:
    return _curator.run_batch(hold_committed=hold_committed, cfg=build_actor_config(paths))


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
