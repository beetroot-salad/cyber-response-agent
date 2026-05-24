#!/usr/bin/env python3
"""Emit on-disk orientation for the defender's initial prompt.

Run from `defender/run.py` (build_prompt) so the agent's message 0
already carries: run-dir contents, adapter CLI roster, system skills,
gather query templates, and which env vars are populated. The whole
point is to absorb the discovery thrash (ls/find/grep across skills,
tools, env files) observed in trace runs — every call below replaces
one or more interactive tool turns.

Stays under ~60 short lines of output. Lists paths and presence, not
file bodies — bodies are the SKILL's job. Never prints secrets;
env-var presence is a tick or a cross.

Usage:
    python3 defender/scripts/workspace_map.py <run_dir>
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

DEFENDER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DEFENDER_DIR.parent

# Env vars adapters actually consume. Presence-only — never printed.
WATCHED_ENV = ("V2_ELASTIC_PASSWORD", "V2_ELASTIC_USERNAME", "ELASTICSEARCH_URL")


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _list_dir(d: Path, suffix: str | None = None) -> list[str]:
    if not d.is_dir():
        return []
    out = []
    for child in sorted(d.iterdir()):
        if child.name.startswith(".") or child.name == "__pycache__":
            continue
        if suffix and child.is_file() and not child.name.endswith(suffix):
            continue
        out.append(child.name)
    return out


def workspace_map(run_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Workspace map")
    lines.append("")
    lines.append(
        "Generated at run start. Use this in place of `ls`/`find`/`grep` "
        "for the paths below — they are the canonical surfaces."
    )
    lines.append("")

    # Run dir
    lines.append(f"## Run dir — `{run_dir}`")
    if run_dir.is_dir():
        for child in sorted(run_dir.iterdir()):
            kind = "dir/" if child.is_dir() else ""
            lines.append(f"- {child.name}{(' ' + kind) if kind else ''}")
        gr = run_dir / "gather_raw"
        if gr.is_dir():
            kids = sorted(gr.iterdir())
            if kids:
                lines.append(f"  gather_raw/ contents: {', '.join(k.name for k in kids)}")
            else:
                lines.append("  gather_raw/ is empty")
    else:
        lines.append("- (not yet materialized)")
    lines.append("")

    # System SKILLs — these define adapter usage. Subagents should consult
    # via Skill / inlined body, not re-Read.
    skills_dir = DEFENDER_DIR / "skills"
    lines.append(f"## System skills — `{_rel(skills_dir)}/`")
    for name in _list_dir(skills_dir):
        sk = skills_dir / name / "SKILL.md"
        marker = " (SKILL.md)" if sk.is_file() else ""
        lines.append(f"- {name}{marker}")
    lines.append("")

    # Adapter CLIs
    tools_dir = DEFENDER_DIR / "scripts" / "tools"
    lines.append(f"## Adapter CLIs — `{_rel(tools_dir)}/`")
    clis = _list_dir(tools_dir, suffix="_cli.py")
    if clis:
        for name in clis:
            lines.append(f"- {name}  (run with `--help`; do not Read the source)")
    else:
        lines.append("- (none yet — v2 adapters TBD)")
    lines.append("")

    # Gather query templates — one line per system, files comma-joined.
    queries_dir = DEFENDER_DIR / "skills" / "gather" / "queries"
    lines.append(f"## Gather query templates — `{_rel(queries_dir)}/`")
    if queries_dir.is_dir():
        for system in sorted(p for p in queries_dir.iterdir() if p.is_dir()):
            files = [f.name for f in sorted(system.iterdir())
                     if f.is_file() and f.suffix == ".md"]
            drafts_dir = system / "_draft"
            drafts = [f.name for f in sorted(drafts_dir.iterdir())
                      if f.is_file() and f.suffix == ".md"] if drafts_dir.is_dir() else []
            tail = (f"  [{', '.join(files)}]" if files else "  [no published templates]")
            if drafts:
                tail += f"  _draft/[{', '.join(drafts)}]"
            lines.append(f"- {system.name}/{tail}")
    else:
        lines.append("- (no queries dir)")
    lines.append("")

    # Env-var status — presence only, no values.
    lines.append("## Environment variables")
    for name in WATCHED_ENV:
        status = "set" if os.environ.get(name) else "MISSING"
        lines.append(f"- {name}: {status}")
    lines.append("")
    lines.append(
        "If a required adapter env var is MISSING, the canonical source "
        "is `playground-v2/.env`. Source it once; do not re-grep per "
        "subagent dispatch."
    )

    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: workspace_map.py <run_dir>\n")
        return 2
    print(workspace_map(Path(argv[1])), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
