#!/usr/bin/env python3
"""CLI wrapper invoking `claude -p` with the data-source-debug SKILL.

Invoked by the gather subagent from §3.5 when a declared
`what_to_summarize` field returned a sentinel value and the system
SKILL.md doesn't already document the workaround. Takes a
natural-language question, spawns a fresh top-level claude with the
data-source-debug SKILL prompt loaded, returns the subagent's
structured verdict on stdout.

This indirection sidesteps Claude Code's subagent → subagent
restriction: `Task`/`Agent` cannot nest, but `Bash` can shell out to
`claude -p`, which spawns a fresh top-level claude with its own
context and its own permission set.

Stdout is the verdict block the data-source-debug SKILL specifies
(`## Verdict` / `## Workaround` / `## Deposited`). Anything the
spawned claude prints before that block is filtered out so the
caller can grep-parse cleanly.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_MODEL = os.environ.get("DEFENDER_DEBUG_MODEL", "claude-sonnet-4-6")


def build_prompt(skill_body: str, defender_dir: Path, system: str, payload_path: Path, question: str) -> str:
    return (
        f"{skill_body}\n\n"
        "## Dispatch\n\n"
        f"defender_dir: {defender_dir}\n"
        f"system: {system}\n"
        f"payload_path: {payload_path}\n\n"
        "question:\n"
        f"{question}\n"
    )


def extract_verdict(stdout: str) -> str:
    """Trim anything before the first `## Verdict` header.

    The data-source-debug SKILL's return contract requires emitting
    only the verdict block, but models sometimes prepend a sentence.
    Stripping the preamble keeps the gather-side grep parse clean.
    """
    match = re.search(r"^## Verdict\b", stdout, re.MULTILINE)
    if match is None:
        return stdout
    return stdout[match.start():]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--defender-dir", required=True, help="Absolute path to the defender repo root")
    p.add_argument("--system", required=True, help="System whose query produced the sentinel (e.g. elastic)")
    p.add_argument("--payload", required=True, help="Path to the raw payload file (gather_raw/{lead_id}/{seq}.json)")
    p.add_argument("--question", required=True, help="Natural-language question for the debug subagent")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"claude --model (default: {DEFAULT_MODEL})")
    args = p.parse_args()

    defender_dir = Path(args.defender_dir).resolve()
    skill_path = defender_dir / "skills" / "data-source-debug" / "SKILL.md"
    if not skill_path.is_file():
        print(f"error: data-source-debug SKILL not found at {skill_path}", file=sys.stderr)
        return 2

    payload_path = Path(args.payload).resolve()
    if not payload_path.is_file():
        print(f"error: payload not found at {payload_path}", file=sys.stderr)
        return 2

    settings_path = defender_dir / "run-settings.json"
    if not settings_path.is_file():
        print(f"error: run-settings.json not found at {settings_path}", file=sys.stderr)
        return 2

    skill_body = skill_path.read_text()
    prompt = build_prompt(skill_body, defender_dir, args.system, payload_path, args.question)

    claude_args = [
        "claude", "-p",
        "--model", args.model,
        "--permission-mode", "acceptEdits",
        "--settings", str(settings_path),
        "--add-dir", str(defender_dir),
        "--add-dir", str(payload_path.parent),
    ]

    print(f"[data_source_debug] invoking claude -p model={args.model} system={args.system}", file=sys.stderr)
    proc = subprocess.run(claude_args, input=prompt, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if proc.stderr:
        sys.stderr.write(proc.stderr)
    sys.stdout.write(extract_verdict(proc.stdout))
    sys.stdout.write("\n")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
