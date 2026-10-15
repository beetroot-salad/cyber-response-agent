#!/usr/bin/env python3

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_query_templates  # noqa: E402
from defender._knowledge import CHECKOUT_KNOWLEDGE  # noqa: E402
from defender._paths import adapters_under  # noqa: E402
from defender.run_repository import RUN_LAYOUT  # noqa: E402

DEFENDER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DEFENDER_DIR.parent

#: Run-dir children the map does not name. The map is inlined into MAIN's message 0 as its
#: directory view (MAIN has no `ls`), so naming a path the gate refuses only teaches it to ask
#: for one (`test_gather_raw_suppressed`). `gather_raw/` and `wire_logs/` are actually refused
#: by `permission.files`. The provenance stamp is operator infrastructure and is only hidden,
#: not out of reach: every run-root file is inside MAIN's and GATHER's
#: `under(run, SEG)` read shape.
def _unlisted() -> frozenset[str]:
    """The run-dir entries this view suppresses, asked of `RUN_LAYOUT` per call so a writer's
    rename cannot make a suppressed file silently reappear in MAIN's message 0."""
    return frozenset({
        RUN_LAYOUT.gather_raw.name, RUN_LAYOUT.wire_log_dir.name,
        RUN_LAYOUT.provenance.name,
    })


def _safe_name(name: str) -> str:
    return "".join(c if c.isprintable() or c == " " else repr(c)[1:-1] for c in name)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _list_dir(d: Path) -> list[str]:
    if not d.is_dir():
        return []
    return [
        child.name for child in sorted(d.iterdir())
        if not child.name.startswith(".") and child.name != "__pycache__"
    ]


#: No system down: the map of a run that judged none, or of a run read back by id.
NONE_DOWN: Mapping[str, str] = MappingProxyType({})

#: What the map tells MAIN beside the systems it marks DOWN (#1256 O-3): one paragraph, in the
#: same section as the marks.
DOWN_GUIDANCE = (
    "A system marked DOWN cannot be used in this run: its settings or its adapter were judged "
    "when the run started, and every dispatch or call to it is refused. Do NOT dispatch a lead "
    "to it — what it would have shown is a visibility gap: name the missing evidence in your "
    "analysis and in a `:T conclude` `ceiling_test` row (the entry price `inconclusive` owes), "
    "then escalate (inconclusive) if it blocks disposition."
)


def workspace_map(run_dir: Path, *, systems: Sequence[str],
                  down: Mapping[str, str] = NONE_DOWN) -> str:
    """The model's directory view of the run. `systems` (the Adapters section) is the run's
    roster (`read_roster(...).accepted`), never a directory listing, so the map cannot name a
    system that `query` would reject as unknown. `down` is each granted system the run judged
    down at its start, with its cause as `system_status.cause_text` names it (#1256 O-3): marked
    in the Adapters section, beside what MAIN is to do about it."""
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
            if child.name in _unlisted():
                continue
            kind = "dir/" if child.is_dir() else ""
            lines.append(f"- {_safe_name(child.name)}{(' ' + kind) if kind else ''}")
    else:
        lines.append("- (not yet materialized)")
    lines.append("")

    skills_dir = CHECKOUT_KNOWLEDGE.skills_dir
    lines.append(f"## System skills — `{_rel(skills_dir)}/`")
    for name in _list_dir(skills_dir):
        sk = skills_dir / name / "SKILL.md"
        marker = " (SKILL.md)" if sk.is_file() else ""
        lines.append(f"- {name}{marker}")
    lines.append("")

    lines.append(f"## Adapters — `{_rel(adapters_under(DEFENDER_DIR))}/`")
    if systems:
        for name in sorted(systems):
            if name in down:
                lines.append(f"- {name}  — DOWN for this run, {down[name]}")
            else:
                lines.append(f"- {name}  (a system dispatched via the query tool; do not Read the adapter source)")
    else:
        lines.append("- (none declared)")
    if down:
        lines.append("")
        lines.append(DOWN_GUIDANCE)
    lines.append("")

    queries_dir = CHECKOUT_KNOWLEDGE.catalog_dir
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
    """`workspace_map.py --tenant T <run_id>` (#1105 declared change 10, J8): the map of T's
    run, opened by id through T's repository (a path where the id belongs is refused). The
    library call (`workspace_map(run_dir, ...)`, the running investigation's) is unchanged."""
    import argparse

    p = argparse.ArgumentParser(prog="workspace_map.py")
    p.add_argument("--tenant", required=True,
                   help="the tenant whose run is mapped; required, with no default")
    p.add_argument("run_id", help="the run, by its id")
    ns = p.parse_args(argv[1:])
    # The CLI reads the checkout's roster itself; an unreadable adapters tree is a one-line
    # refusal and exit 2, not a traceback.
    from defender._command_line_run import open_command_line_run
    from defender.runtime.verbs import RegistryError, read_roster

    run = open_command_line_run(ns.tenant, ns.run_id)
    if isinstance(run, str):
        sys.stderr.write(f"workspace_map: {run}\n")
        return 2
    try:
        roster = read_roster(adapters_under(DEFENDER_DIR))
    except RegistryError as e:
        sys.stderr.write(f"workspace_map: {e}\n")
        return 2
    print(workspace_map(Path(run.run_dir), systems=tuple(roster.accepted)), end="")
    return 0


if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    sys.exit(main(sys.argv))
