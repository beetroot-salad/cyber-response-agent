"""Canonical renderer for the gather subagent dispatch prompt.

The defender (LLM) constructs this prompt as free-form text in production;
the hooks `record_lead.py` and `inject_system_skill_description.py`
then parse and augment it. This module is the Python source of truth for the
same shape — used by the invocation test harness so tests and runtime can't
drift.

The post-hook prompt has three pieces, in order:
    1. A `Read defender/skills/gather/SKILL.md` instruction (so gather loads
       its body from disk; the dispatch doesn't inline it).
    2. A fenced ```yaml block whose keys match what `record_lead.py`
       parses: `defender_dir`, `run_dir`, `lead_id`, `system`, `goal`,
       `what_to_summarize`.
    3. A `## System {name} (auto-injected ...)` block — what
       `inject_system_skill_description.py` appends at PreToolUse time. The
       harness folds this in at render time so the test's claude -p
       invocation sees the same prompt a live Task() dispatch would after
       the hook fires.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence


# Keep in sync with hooks/inject_system_skill_description.py::build_augmented_prompt.
_INJECT_HEADER_TMPL = (
    "\n\n---\n## System `{system}` (auto-injected from SKILL frontmatter)\n\n"
    "The description below tells you what this system is for and when\n"
    "it's the right target. Use it to confirm your lead actually wants\n"
    "this system. If it does, **Read the full**\n"
    "`defender/skills/{system}/SKILL.md` before running anything — the\n"
    "body carries CLI conventions, field vocabularies, and load-bearing\n"
    "rules that the description does not.\n\n"
)


def render_dispatch_yaml(
    *,
    defender_dir: Path | str,
    run_dir: Path | str,
    lead_id: str,
    system: str,
    goal: str,
    what_to_summarize: Sequence[str],
) -> str:
    """Render the ```yaml dispatch block alone (no preamble, no injection)."""
    lines = [
        f"defender_dir: {defender_dir}",
        f"run_dir: {run_dir}",
        f"lead_id: {lead_id}",
        f"system: {system}",
        f"goal: {goal}",
        "what_to_summarize:",
    ]
    for item in what_to_summarize:
        lines.append(f"  - {item}")
    return "\n".join(lines)


def render_gather_dispatch(
    *,
    defender_dir: Path | str,
    run_dir: Path | str,
    lead_id: str,
    system: str,
    goal: str,
    what_to_summarize: Sequence[str],
    system_skill_description: str | None = None,
) -> str:
    """Render the full dispatch prompt as gather sees it post-hook.

    If `system_skill_description` is provided, the auto-inject block is
    appended (mirroring the live hook). Pass None to test the no-injection
    fallback path.
    """
    yaml_body = render_dispatch_yaml(
        defender_dir=defender_dir,
        run_dir=run_dir,
        lead_id=lead_id,
        system=system,
        goal=goal,
        what_to_summarize=what_to_summarize,
    )
    preamble = (
        f"Read {defender_dir}/skills/gather/SKILL.md and execute the dispatch below.\n\n"
        "```yaml\n"
        f"{yaml_body}\n"
        "```"
    )
    if system_skill_description is None:
        return preamble
    return preamble + _INJECT_HEADER_TMPL.format(system=system) + system_skill_description.strip() + "\n"
