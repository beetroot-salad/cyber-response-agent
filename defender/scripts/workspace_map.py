#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_query_templates  # noqa: E402
from defender.runtime.verbs import ADAPTER_SUFFIX  # noqa: E402

DEFENDER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DEFENDER_DIR.parent


def _safe_name(name: str) -> str:
    return "".join(c if c.isprintable() or c == " " else repr(c)[1:-1] for c in name)


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
    lines.append("## Absolute roots")
    lines.append(f"- DEFENDER_DIR: `{DEFENDER_DIR}`")
    lines.append(f"- REPO_ROOT: `{REPO_ROOT}`")
    lines.append(f"- RUN_DIR: `{run_dir}`")
    lines.append("")

    lines.append(f"## Run dir — `{run_dir}`")
    if run_dir.is_dir():
        for child in sorted(run_dir.iterdir()):
            if child.name == "gather_raw":
                continue
            if child.name == "budget.json":
                continue
            kind = "dir/" if child.is_dir() else ""
            lines.append(f"- {_safe_name(child.name)}{(' ' + kind) if kind else ''}")
    else:
        lines.append("- (not yet materialized)")
    lines.append("")

    skills_dir = DEFENDER_DIR / "skills"
    lines.append(f"## System skills — `{_rel(skills_dir)}/`")
    for name in _list_dir(skills_dir):
        sk = skills_dir / name / "SKILL.md"
        marker = " (SKILL.md)" if sk.is_file() else ""
        lines.append(f"- {name}{marker}")
    lines.append("")

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
    if not queries_dir.is_dir():
        return ["- (no queries dir)"]
    rows = list(iter_query_templates(queries_dir))
    if not rows:
        return ["- (queries dir is present but holds no readable template)"]

    out: list[str] = []
    for system in sorted({r.system for r in rows}):
        srows = [r for r in rows if r.system == system]
        established = sum(1 for r in srows if r.status == "established")
        drafts = sum(1 for r in srows if r.status == "draft")
        line = f"- {system}/ — {established} established, {drafts} draft"
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
