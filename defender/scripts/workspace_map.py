#!/usr/bin/env python3
"""Emit on-disk orientation for the defender's initial prompt.

Run from `defender/run.py` (build_prompt) so the agent's message 0
already carries: run-dir contents, adapter roster, system skills,
and gather query templates. The whole point is to absorb the discovery
thrash (ls/find/grep across skills and tools) observed in trace runs —
every call below replaces one or more interactive tool turns.

Stays under ~60 short lines of output. Lists paths and presence, not
file bodies — bodies are the SKILL's job. Credentials are not surfaced
here: each adapter sources them itself at call time (gather
subagent), so the orchestrator never needs them.

Usage:
    python3 defender/scripts/workspace_map.py <run_dir>
"""

from __future__ import annotations

import sys
from pathlib import Path

# Put the workspace root on sys.path so the `defender.*` import below resolves whether this file
# is imported (orient.py builds message 0 in-process) or run directly as the CLI in the usage
# above — where sys.path[0] is this script's own dir and the package would not resolve.
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_query_templates  # noqa: E402
from defender.runtime.verbs import ADAPTER_SUFFIX  # noqa: E402

DEFENDER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DEFENDER_DIR.parent


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
    # Absolute roots. Subagents spawned by Task/Agent land in a
    # Claude-Code-managed worktree whose cwd is *not* under DEFENDER_DIR;
    # relative paths in dispatch prompts (`Read defender/...`) resolve
    # against the subagent's cwd, not yours, and silently land in the
    # wrong tree. Always pass absolute paths to subagents.
    lines.append("## Absolute roots")
    lines.append(f"- DEFENDER_DIR: `{DEFENDER_DIR}`")
    lines.append(f"- REPO_ROOT: `{REPO_ROOT}`")
    lines.append(f"- RUN_DIR: `{run_dir}`")
    lines.append("")

    # Run dir
    lines.append(f"## Run dir — `{run_dir}`")
    if run_dir.is_dir():
        for child in sorted(run_dir.iterdir()):
            # gather_raw/ holds the raw query payloads + leads table — a
            # subagent-only artifact. The orchestrator reasons from gather's
            # returned summary, never the raw tree, so keep it off the map.
            if child.name == "gather_raw":
                continue
            # budget.json is the enforcement accounting state (#631): written at run
            # start (open_budget), but the orchestrator neither reads nor writes it (its
            # write scope is exactly investigation.md/report.md), so advertising it in
            # message 0 would name a file the model can't author. Off the map like
            # gather_raw — and the replayed-listing parity gate pins that it stays off.
            if child.name == "budget.json":
                continue
            kind = "dir/" if child.is_dir() else ""
            lines.append(f"- {child.name}{(' ' + kind) if kind else ''}")
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

    # Adapters
    adapters_dir = DEFENDER_DIR / "scripts" / "adapters"
    lines.append(f"## Adapters — `{_rel(adapters_dir)}/`")
    adapters = _list_dir(adapters_dir, suffix=ADAPTER_SUFFIX)
    if adapters:
        for name in adapters:
            lines.append(f"- {name}  (a VERBS registry dispatched via the query tool; do not Read the source)")
    else:
        lines.append("- (none yet — v2 adapters TBD)")
    lines.append("")

    queries_dir = DEFENDER_DIR / "skills" / "gather" / "queries"
    lines.append(f"## Gather query templates — `{_rel(queries_dir)}/`")
    lines.extend(_template_counts(queries_dir))
    lines.append("")

    return "\n".join(lines) + "\n"


def _template_counts(queries_dir: Path) -> list[str]:
    """The query-template section of the map: one line per system, COUNTS only.

    This section names no template filename, and above all no `_draft/` filename. A draft's name
    is a verb the gather LLM coined in response to alert data and `draft_synthesis` wrote to disk,
    so it is attacker-influenced text — and this map is injected verbatim into MAIN's message 0,
    where `defender/SKILL.md` forbids main the query corpus in the first place. The filenames were
    never actionable there either: main dispatches leads by SYSTEM, and it is GATHER that binds a
    template (from the index `tools_gather._template_index` injects into its dispatch prompt,
    #585). Counts keep the one fact main can use — which systems have a curated catalog behind
    them, and how deep it is.
    """
    if not queries_dir.is_dir():
        return ["- (no queries dir)"]
    rows = list(iter_query_templates(queries_dir))
    if not rows:
        # An empty walk is NOT a missing dir. Reporting one as the other would tell main the
        # catalog surface does not exist when in truth it exists and is bare (or unreadable) —
        # two different facts, and only the second is a curation defect worth seeing.
        return ["- (queries dir is present but holds no readable template)"]

    out: list[str] = []
    for system in sorted({r.system for r in rows}):
        srows = [r for r in rows if r.system == system]
        established = sum(1 for r in srows if r.status == "established")
        drafts = sum(1 for r in srows if r.status == "draft")
        line = f"- {system}/ — {established} established, {drafts} draft"
        # `status` is the frontmatter value VERBATIM and no longer defaults to "established"
        # (#585), so a template can carry neither value — an absent key, or a typo. Counting only
        # the two known buckets would drop it from both and make it vanish from the map entirely:
        # the counts would silently fail to sum to the corpus. Name the remainder instead.
        if unknown := len(srows) - established - drafts:
            line += f", {unknown} unknown status"
        out.append(line)
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: workspace_map.py <run_dir>\n")
        return 2
    print(workspace_map(Path(argv[1])), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
