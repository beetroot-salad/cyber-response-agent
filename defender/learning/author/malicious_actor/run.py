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

import functools
import sys
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import curator as _curator
from defender.learning.author._verifier_python import resolve_verifier_python
from defender.learning.author import shared as _shared
from defender.learning.core.config import (
    ACTOR_MODEL,
    AUTHOR_ACTOR_EFFORT,
    AUTHOR_ACTOR_MODEL,
    AUTHOR_ACTOR_REQUEST_LIMIT,
    AUTHOR_ACTOR_TIMEOUT,
    DEFAULT_PATHS,
    DefenderPaths,
    LoopPaths,
)


# All four model/wiring constants come from core.config (one source per env var,
# no duplicated defaults — cf. #449). ACTOR_MODEL is the actor *stage* model the real
# actor invocation reads (pipeline/malicious_actor/run.py); this curator only stamps
# it into the Actor-Model: commit trailer as provenance, never as authoring input.
# AUTHOR_ACTOR_* is the curator agent's own model/timeout/effort.

# Re-exported for callers/tests that referenced the curator's fatal error type here.
AuthorError = _curator.AuthorError


def invoke_agent(
    observations: list[dict],
    batch_id: str,
    cfg: _curator.CuratorConfig,
) -> dict:
    """Spawn the actor curator agent. Returns the parsed AUTHOR_RESULT dict.

    The actor corpus forward-checks per-lesson (``verify_forward/actor.py``) with a batch wrapper
    (``verify_forward/batch.py``), so it hands the agent both command templates and pins both
    verifier scripts on the in-process curator's bash lane. The commit-trailer provenance is stamped
    by the loop, not the agent, so nothing trailer-related goes in the prompt."""
    verifier_py = resolve_verifier_python(cfg.repo_root)
    rel = DefenderPaths.verify_forward_dir_rel  # repo-relative command spelling (trailing slash)
    extra_prompt = (
        f"verify_forward_command: {verifier_py} {rel}actor.py "
        f"<lesson_path> <observation_id>\n"
        f"verify_batch_command: {verifier_py} {rel}batch.py {rel}actor.py "
        f"<lesson_path>=<observation_id> [<lesson_path>=<observation_id> ...]\n"
    )
    return _curator.invoke_curator_agent(
        cfg, observations, batch_id,
        extra_prompt=extra_prompt,
        verifier_scripts=(cfg.verifier_dir / "batch.py", cfg.verifier_dir / "actor.py"),
        request_limit=AUTHOR_ACTOR_REQUEST_LIMIT,
    )


def build_actor_config(paths: LoopPaths = DEFAULT_PATHS) -> _curator.CuratorConfig:
    """Build the actor-direction ``CuratorConfig`` from an injected ``LoopPaths``.

    Constructed at call time (not import) so a test rooted at a tmp tree threads one
    ``LoopPaths(repo_root=tmp)`` instead of monkeypatching module path globals."""
    return _curator.CuratorConfig(
        repo_root=paths.repo_root,
        pending_dir=paths.pending_dir,
        runs_dir=paths.runs_dir,
        state_root=paths.state_root,
        corpus_dir=paths.lessons_actor_dir,
        corpus_dir_rel=paths.lessons_actor_dir_rel,
        verifier_dir=paths.verify_forward_dir,
        channel=paths.actor_observations,
        repo_lock_file=paths.author_lock_file,
        repo_lock_wait_seconds=_shared.REPO_LOCK_WAIT_SECONDS,
        outcome_author=frozenset({"caught", "incoherent"}),
        outcome_skip=frozenset({"survived", "undecidable"}),
        trailer_label="Actor-Model",
        generation_fn=functools.partial(_shared.actor_generation_count, paths.repo_root),
        actor_model=ACTOR_MODEL,
        log_prefix="author_actor",
        author_prompt=paths.learning_dir / "author" / "malicious_actor" / "prompt.md",
        author_model=AUTHOR_ACTOR_MODEL,
        author_timeout=AUTHOR_ACTOR_TIMEOUT,
        author_effort=AUTHOR_ACTOR_EFFORT,
        invoke_agent=invoke_agent,
    )


def run_batch(*, hold_committed: bool = False, paths: LoopPaths = DEFAULT_PATHS) -> int:
    return _curator.run_batch(hold_committed=hold_committed, cfg=build_actor_config(paths))


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
