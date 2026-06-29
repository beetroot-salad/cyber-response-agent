#!/usr/bin/env python3
"""PreToolUse hook: write the leads table + claim the lead_id.

Fires on Task tool calls whose prompt dispatches the defender gather
subagent (identified by the literal `defender/skills/gather/SKILL.md`
in the prompt). Parses the dispatch's YAML block — `run_dir`,
`lead_id`, `goal`, `what_to_summarize` — and writes the leads-table row
`{run_dir}/gather_raw/{lead_id}.lead.json` = `{goal, what_to_summarize}`.

`lead_id` is the `:L` invlang row id the defender echoes from the
already-authored `:L findings` row (e.g. `l-001`) — not a new id minted
here. It is the FK the queries table (`record_query.py`) and the read
surface (`learning/lead_repository.py`) join on.

The write is an atomic exclusive create (`O_CREAT|O_EXCL`): one syscall
that both persists the row and detects a reused id. Parallel leads
dispatch as concurrent Task calls (SKILL.md), firing this hook
concurrently — distinct ids claim distinct paths and all succeed; a
genuine reuse (same id twice in a batch, or across turns) fails the
exclusive create and the hook **exits 2**, blocking the Task so gather
never runs and no orphan query row is written. The remediation fed back
to the agent is to append a fresh `:L` findings row and echo its id (a
retry is a new lead, never a reused id — append-only invlang).

The hook stays silent (exit 0) on parse failure / missing fields /
malformed lead_id — never blocking a dispatch over an extraction issue;
only a real reuse collision blocks.

Exit codes:
    0 — claimed, or benign skip (not a gather dispatch / parse failure).
    2 — lead_id reuse collision; reason on stderr is fed back to the agent.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import sys
from pathlib import Path

from defender._run_paths import RunPaths


GATHER_SKILL_MARKER = "defender/skills/gather/SKILL.md"

# A lead_id is the `:L` row id: `l-` + alphanumerics. Grammar mirrors the
# invlang parser's lead-id grammar and scripts/gather_tools/record_query.py's --lead
# guard — keep in sync. Used verbatim as a path segment and FK.
LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")

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


def claim_lead(dispatch: dict) -> int:
    """Write the leads-table row exclusively, claiming the lead_id.

    Returns 0 on a claim or a benign skip (missing fields / malformed
    lead_id / plumbing error — never block a dispatch over these), and 2
    on a reuse collision (the id's sidecar already exists).
    """
    run_dir = dispatch.get("run_dir")
    lead_id = dispatch.get("lead_id")
    goal = dispatch.get("goal")
    wtc = dispatch.get("what_to_summarize") or []

    if not run_dir or not lead_id or not goal:
        return 0
    if not isinstance(wtc, list):
        return 0
    if not LEAD_ID_RE.match(str(lead_id)):
        return 0

    sidecar_dir = RunPaths(Path(run_dir)).gather_raw
    try:
        sidecar_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return 0

    sidecar_path = sidecar_dir / f"{lead_id}.lead.json"
    payload = json.dumps(
        {"goal": str(goal).strip(), "what_to_summarize": list(wtc)}, indent=2
    ) + "\n"

    # Atomic exclusive create: one syscall persists the row AND detects a
    # reused id. Only EEXIST is a hard error (exit 2); any other OSError
    # fails open (exit 0) — losing the sidecar is acceptable, blocking a
    # dispatch over plumbing is not.
    try:
        fd = os.open(sidecar_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except OSError as e:
        if e.errno == errno.EEXIST:
            print(
                f"lead_id {lead_id!r} already dispatched; append a new :L "
                f"findings row and echo its id (a retry is a new lead, never "
                f"a reused id).",
                file=sys.stderr,
            )
            return 2
        return 0
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
    except OSError:
        # Don't leave a 0-byte sidecar: load_leads would skip it (degrading the
        # lead to an orphan) AND it would become a false reuse token that
        # rejects a legitimate same-id retry with EEXIST. Best-effort: close a
        # leaked fd (if fdopen never took ownership) and remove the empty file.
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(sidecar_path)
        return 0
    return 0


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

    return claim_lead(dispatch)


if __name__ == "__main__":
    sys.exit(main())
