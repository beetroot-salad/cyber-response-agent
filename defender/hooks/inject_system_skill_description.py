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
from functools import cache
from pathlib import Path

# Workspace root on sys.path so the `defender.*` namespace imports resolve
# whether this module is imported (runtime/tools_gather.py) or run directly.
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._frontmatter import parse_frontmatter_or_none  # noqa: E402
from defender._io import read_text_soft  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402


GATHER_SKILL_MARKER = "defender/skills/gather/SKILL.md"
DEFENDER_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = DEFENDER_DIR / "skills"
ADAPTERS_DIR = DEFENDER_DIR / "scripts" / "adapters"

FENCE_RE = re.compile(r"```ya?ml\s*\n(.*?)\n```", re.DOTALL)
SYSTEM_KEY_RE = re.compile(r"^system:\s*([A-Za-z0-9_.-]+)\s*$", re.MULTILINE)


def extract_system(prompt: str) -> str | None:
    """Find `system: <name>` in the first fenced YAML block of the prompt."""
    fence = FENCE_RE.search(prompt)
    if not fence:
        return None
    match = SYSTEM_KEY_RE.search(fence.group(1))
    if not match:
        return None
    return match.group(1)


def read_description(system: str, skills_dir: Path = SKILLS_DIR) -> str | None:
    """Return the SKILL.md frontmatter `description:` for the named system.

    Routes through the canonical grammar (#591): a SKILL.md the canonical parser
    rejects — unfenced, loose opener, non-mapping — yields None rather than
    letting an interior thematic break fake a frontmatter block. Soft read: an
    unreadable or undecodable file is None, never a raised decode error into the
    gather dispatch path.
    """
    skill_path = (skills_dir / system / "SKILL.md").resolve()
    # Path-traversal guard: must live under skills_dir.
    try:
        skill_path.relative_to(skills_dir.resolve())
    except ValueError:
        return None
    if not skill_path.is_file():
        return None

    text, _reason = read_text_soft(skill_path)
    if text is None:
        return None
    front = parse_frontmatter_or_none(text)
    if front is None:
        return None
    desc = front.get("description")
    if not isinstance(desc, str):
        return None
    desc = desc.strip()
    return desc or None


@cache
def descriptor_catalog(
    skills_dir: Path = SKILLS_DIR, adapters_dir: Path = ADAPTERS_DIR
) -> str | None:
    """The progressive-disclosure index for the gather subagent: every data-source
    system + its one-line SKILL `description:`. Gather scans this to confirm its target,
    then Reads that system's full SKILL.md on demand (the skills model — descriptors
    injected, bodies loaded on decision). Static per tree; memoized — the cache keys on
    the directory arguments, so two trees in one process (a worktree run, an eval's tmp
    tree) each get their own catalog instead of the first caller's. Callers thread the
    run's tree: see ``tools_gather._run_gather`` (#551/#591).

    Scoped to systems that DECLARE VERBS (#611), not to the `*_adapter.py` files on disk. That is
    the difference between failing closed and merely looking like it: the roster used to be a
    filename GLOB that never imported the module, so a system whose module declared nothing was
    unreachable at the tool and still ADVERTISED at the prompt — gather would be told the system
    exists, spend a turn reaching for it, and be refused. Fail-closed has to hold on both
    surfaces or it holds on neither.

    The registry resolves each module per TREE (`verbs.ModuleVerbRegistry` keys on the resolved
    path, not the module name), so importing an adapter to read its roster here cannot freeze the
    first tree it saw into the second tree's run.

    Reading the roster now IMPORTS each adapter, which the filename glob never did — so one
    `*_adapter.py` that will not import (a newly onboarded system with a typo, a missing dep) would
    take down catalog construction for EVERY system, and with it every gather dispatch and the
    whole run. A system that cannot be loaded cannot be advertised; it drops out of the catalog
    alone. The tool agrees (`query_tool` files the same failure as infra against that ONE
    system), so the two surfaces stay honest with each other: unreachable, not unfiltered."""
    registry = ModuleVerbRegistry(adapters_dir)
    lines = []
    for system in registry.systems():
        try:
            verbs = registry.verbs(system)
        except Exception:  # noqa: BLE001 — a system that will not load is unreachable, not fatal
            continue
        if not verbs:
            continue
        desc = read_description(system, skills_dir)
        if desc:
            lines.append(f"- `{system}`: {desc}")
    return "\n".join(lines) or None


def build_augmented_prompt(original: str, system: str, description: str) -> str:
    header = (
        f"\n\n---\n## System `{system}` (auto-injected from SKILL frontmatter)\n\n"
        f"The description below tells you what this system is for and when\n"
        f"it's the right target. Use it to confirm your lead actually wants\n"
        f"this system. If it does, **Read the full**\n"
        f"`defender/skills/{system}/SKILL.md` before running anything — the\n"
        f"body carries the system's verb/param surface, field vocabularies, and\n"
        f"load-bearing rules that the description does not.\n\n"
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
