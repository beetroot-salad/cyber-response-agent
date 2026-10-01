"""The blind lenses and the composer that review a close — confident or `inconclusive`.

The reviewer's own half of the gate: the projections each lens reads (`projector`), the role
prompts they run under, and the reading of what they return (`reply`). `challenge_gate` keeps
the harness — bounds, the review state, the stage deadline, the trace rows and the routing —
and dispatches into this package.

Two prompts, three calls: `support` (dispatched twice, once as the ablation) and `composer`.
"""

from __future__ import annotations

from pathlib import Path

from defender._io import read_text_utf8

__all__ = ["PROMPTS", "role_prompt"]

PROMPTS = Path(__file__).resolve().parent / "prompts"


def role_prompt(name: str) -> str:
    """One review role's system instruction, loaded verbatim from `prompts/<name>.md`.

    No slot substitution: per-case material arrives separately as the user message."""
    path = PROMPTS / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"no role prompt for {name!r} at {path}")
    return read_text_utf8(path)
