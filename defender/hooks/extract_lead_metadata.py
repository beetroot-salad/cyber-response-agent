#!/usr/bin/env python3
"""PreToolUse hook: persist gather lead metadata sidecar.

Fires on Task tool calls whose prompt dispatches the defender gather
subagent (identified by the literal `defender/skills/gather/SKILL.md`
in the prompt). Parses the dispatch's YAML block — `run_dir`,
`position`, `goal`, `what_to_characterize` — and writes
`{run_dir}/gather_raw/{position}.lead.json`.

This replaces the heredoc instruction that gather/SKILL.md used to
ask the model to run itself. The sidecar is the contract that
project_lead_sequence.py reads to populate `lead_description` in
`lead_sequence.yaml`; if it's missing the projection silently
degrades to the `:L findings.name` cell. Doing it here makes the
sidecar a structural side-effect of dispatching gather, not a
prompt instruction the model can forget.

The hook is silent on parse failure — the run still completes,
projection just falls back to its degraded path. Hard-failing here
would block gather dispatches over a metadata-extraction issue,
which is the wrong tradeoff for an experimental loop.

Exit codes:
    0 — always.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


GATHER_SKILL_MARKER = "defender/skills/gather/SKILL.md"

# Capture the first ```yaml ... ``` (or ```yml) fenced block in the prompt.
FENCE_RE = re.compile(r"```ya?ml\s*\n(.*?)\n```", re.DOTALL)

# Top-level key: line — `name:` or `name: value` (no leading whitespace).
# `name` is conservatively limited to identifier-shape chars so colons
# inside free-form values can't be mistaken for a new key.
_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")
# Bullet — two-or-more-space indent + dash + body. Body is taken literally,
# including any colons.
_BULLET_RE = re.compile(r"^\s{2,}-\s+(.*)$")


def extract_dispatch(prompt: str) -> dict | None:
    """Parse the dispatch block leniently.

    YAML.safe_load is unsafe here because the dispatch fields are free-form
    natural-language strings (`goal: Compare fields: user and src`,
    `- process cmdline: /bin/sh`). YAML interprets the inner colon-space
    as a nested mapping or raises, which silently drops the sidecar. We
    parse line-by-line instead: only the leading `name:` or `  - ` is
    structural; everything after is a literal string.
    """
    match = FENCE_RE.search(prompt)
    if not match:
        return None
    return _parse_block(match.group(1))


def _parse_block(text: str) -> dict | None:
    out: dict = {}
    current_list_key: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        bullet = _BULLET_RE.match(line)
        if bullet and current_list_key is not None:
            out.setdefault(current_list_key, []).append(bullet.group(1).strip())
            continue
        key = _KEY_RE.match(line)
        if not key:
            # Unrecognized continuation line — ignore rather than fail.
            continue
        name, value = key.group(1), key.group(2).strip()
        if value:
            out[name] = value
            current_list_key = None
        else:
            # Empty value → next bullets accumulate into a list.
            out[name] = []
            current_list_key = name
    return out or None


def write_sidecar(dispatch: dict) -> None:
    run_dir = dispatch.get("run_dir")
    position = dispatch.get("position")
    goal = dispatch.get("goal")
    wtc = dispatch.get("what_to_characterize") or []

    if not run_dir or position is None or not goal:
        return
    if not isinstance(wtc, list):
        return

    # Position may be int or string ("0", "0a"); the projection groups
    # files back under the int prefix, but the sidecar keys on the
    # leading integer either way.
    pos_str = str(position)
    pos_int_match = re.match(r"^(\d+)", pos_str)
    if not pos_int_match:
        return
    pos_int = pos_int_match.group(1)

    sidecar_dir = Path(run_dir) / "gather_raw"
    try:
        sidecar_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return

    sidecar_path = sidecar_dir / f"{pos_int}.lead.json"
    payload = {"goal": str(goal).strip(), "what_to_characterize": list(wtc)}
    try:
        sidecar_path.write_text(json.dumps(payload, indent=2) + "\n")
    except OSError:
        return


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

    dispatch = extract_dispatch(prompt)
    if dispatch is None:
        return 0

    write_sidecar(dispatch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
