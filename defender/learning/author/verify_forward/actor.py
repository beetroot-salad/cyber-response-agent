"""The actor-tradecraft curator's forward check, as a library (#558).

Asks whether a candidate lesson teaches against the failure the judge observed on the actor
story it was authored from. Curator B (``defender/lessons-actor/``) runs it through the
in-process ``forward_check`` tool; ``checks.py`` composes these helpers into the prompt
payload and resolves the observation row from the pending queue named on the deps.

One rep per check. The author prompt allows one retry per lesson (rewrite + re-check) before
reverting and routing to ``consumed_skip``.
"""
from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent
PROMPT_PATH = HERE / "actor.md"


def load_story(bundle: Path) -> str:
    """The actor story (section 0 + body) the judge graded, from an already-resolved source
    run bundle. The bundle is resolved by the caller off the deps' ``runs_dir`` — the shared
    state root, not the curator's throwaway worktree, whose ``runs/`` is empty (#425)."""
    path = (bundle / "actor_story.md").resolve()
    if not path.is_file():
        raise SystemExit(f"verify_forward_actor: actor_story.md missing at {path}")
    return path.read_text()
