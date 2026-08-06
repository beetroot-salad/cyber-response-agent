"""#796 — the blind lenses and the composer that review a confident close.

The package is the reviewer's own half of the gate: the projections each lens reads
(`projector`), the role prompts they run under, and the reading of what they return
(`reply`). `challenge_gate` keeps the harness — bounds, the review state, the stage
deadline, the trace rows and the routing — and dispatches into this package.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["PROMPTS", "role_prompt"]

PROMPTS = Path(__file__).resolve().parent / "prompts"


def role_prompt(name: str) -> str:
    """One review role's system instruction, loaded whole.

    The tree's prompt-asset pattern, followed rather than reinvented: every model-facing
    `.md` here is read verbatim as an agent's `instructions`, and the per-case material
    arrives separately as the user message. Nothing substitutes slots. The one place this
    tree does substitute — the gather query templates — leaves an unfilled slot in the text
    verbatim and reports nothing, which is not a mechanism to copy into a prompt.

    The retired review stages assembled their instructions as a Python literal, so the
    wording had no home that could be read or reviewed without reading the builder, and the
    only system prompt all three shared named an issue number, which names nothing to a
    model."""
    path = PROMPTS / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"no role prompt for {name!r} at {path}")
    return path.read_text(encoding="utf-8")
