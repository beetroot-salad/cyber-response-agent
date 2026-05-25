#!/usr/bin/env python3
"""PreToolUse hook: inject the system SKILL's frontmatter `description:`
into gather dispatches.

Fires on Task tool calls whose prompt dispatches the defender gather
subagent. Parses the dispatch YAML, finds `system: <name>`, reads
`defender/skills/<name>/SKILL.md`'s frontmatter `description:` field,
and appends it to the dispatch prompt as an auto-injected block.

The description is a **relevance signal**, not a rules carrier — it
tells the subagent what the system is for and when it's the right
target. When the subagent confirms the lead targets this system, it
then Reads the full SKILL.md body to pick up CLI conventions, field
vocabularies, and load-bearing rules (the "use --help, don't read
source" kind of thing). The body is where rules live; this hook just
saves the discovery turn (ls / Glob across `skills/`) by pre-naming
the relevant SKILL via its description.

Silent on every failure (missing system field, missing SKILL file,
malformed frontmatter) — the subagent then proceeds with its
un-augmented prompt and either succeeds or fails on its own. The hook
never blocks the dispatch.

Emits `hookSpecificOutput.updatedInput` to replace the tool_input with
the augmented prompt, matching the soc-agent inject_env_context.py
contract.

Exit codes:
    0 — always.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


GATHER_SKILL_MARKER = "defender/skills/gather/SKILL.md"
DEFENDER_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = DEFENDER_DIR / "skills"

FENCE_RE = re.compile(r"```ya?ml\s*\n(.*?)\n```", re.DOTALL)
SYSTEM_KEY_RE = re.compile(r"^system:\s*([A-Za-z0-9_.-]+)\s*$", re.MULTILINE)

# Capture the frontmatter block — first --- to next ---.
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*$", re.DOTALL | re.MULTILINE)
# `description:` may be a one-liner or a block scalar (`description: |\n  ...`).
# Capture everything from the colon to the next top-level key or end-of-block.
DESCRIPTION_RE = re.compile(
    r"^description:\s*(\|[+-]?\s*\n((?:[ \t]+.*\n?)+)|(.+))",
    re.MULTILINE,
)


def extract_system(prompt: str) -> str | None:
    """Find `system: <name>` in the first fenced YAML block of the prompt."""
    fence = FENCE_RE.search(prompt)
    if not fence:
        return None
    match = SYSTEM_KEY_RE.search(fence.group(1))
    if not match:
        return None
    return match.group(1)


def read_description(system: str) -> str | None:
    """Return the SKILL.md frontmatter `description:` for the named system."""
    skill_path = (SKILLS_DIR / system / "SKILL.md").resolve()
    # Path-traversal guard: must live under SKILLS_DIR.
    try:
        skill_path.relative_to(SKILLS_DIR.resolve())
    except ValueError:
        return None
    if not skill_path.is_file():
        return None

    try:
        text = skill_path.read_text()
    except OSError:
        return None

    fm = FRONTMATTER_RE.search(text)
    if not fm:
        return None
    desc = DESCRIPTION_RE.search(fm.group(1))
    if not desc:
        return None

    # Group 2 is the block-scalar body; group 3 is the one-liner.
    body = desc.group(2)
    if body is not None:
        # Strip the shared leading indent.
        lines = body.rstrip("\n").splitlines()
        if not lines:
            return None
        indent = min(
            (len(line) - len(line.lstrip())) for line in lines if line.strip()
        )
        return "\n".join(line[indent:] for line in lines).strip() or None
    return desc.group(3).strip() or None


def build_augmented_prompt(original: str, system: str, description: str) -> str:
    header = (
        f"\n\n---\n## System `{system}` (auto-injected from SKILL frontmatter)\n\n"
        f"The system you're dispatching against carries the following\n"
        f"description. It is the load-bearing reference — Read the full\n"
        f"`defender/skills/{system}/SKILL.md` only if you need detail beyond\n"
        f"what's here.\n\n"
    )
    return f"{original}{header}{description}\n"


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0

    if hook_data.get("tool_name") not in ("Task", "Agent"):
        return 0

    tool_input = hook_data.get("tool_input") or {}
    prompt = tool_input.get("prompt") or ""
    if GATHER_SKILL_MARKER not in prompt:
        return 0

    system = extract_system(prompt)
    if not system:
        return 0

    description = read_description(system)
    if not description:
        return 0

    augmented = build_augmented_prompt(prompt, system, description)
    updated = dict(tool_input)
    updated["prompt"] = augmented
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated,
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
