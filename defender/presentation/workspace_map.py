from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from defender.knowledge._corpus import iter_query_templates
from defender.knowledge._knowledge import KnowledgePaths
from defender._paths import adapters_under
from defender.run_repository import RUN_LAYOUT
from defender.runtime.system_status import NONE_DOWN

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.runtime.model_view import ModelView

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


#: What a map with no tenant knowledge to show says in place of its skills and templates.
_NO_KNOWLEDGE = "- (no tenant knowledge in this view)"


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


#: What the map tells MAIN beside the systems it marks DOWN (#1256 O-3): one paragraph, in the
#: same section as the marks.
DOWN_GUIDANCE = (
    "A system marked DOWN cannot be used in this run — its settings or its adapter were judged "
    "unusable when the run started, or a call has shown it unusable since — and every dispatch "
    "or call to it is refused. Do NOT dispatch a lead "
    "to it — what it would have shown is a visibility gap: name the missing evidence in your "
    "analysis and in a `:T conclude` `ceiling_test` row (the entry price `inconclusive` owes), "
    "then escalate (inconclusive) if it blocks disposition."
)


def _map_roots(run_dir: Path, view: ModelView | None, agent_root: Path | None):
    """The map's code tree, the run's knowledge (`None` when it names no agent root), how a
    path is shown, and the roots it names. In a run's view the knowledge is the view's agent
    tree (the run copy, #1108 P4); on the operator's command line it is `agent_root`."""
    if view is not None:
        from defender.runtime.model_view import MODEL_AGENT

        defender_dir = view.to_host("/defender")
        assert defender_dir is not None
        agent = view.to_host(str(MODEL_AGENT))

        def shown(p: Path) -> str:
            return view.to_model(p)
        roots = [("DEFENDER_DIR", shown(defender_dir)), ("RUN_DIR", shown(run_dir))]
    else:
        defender_dir, agent, shown = DEFENDER_DIR, agent_root, _rel
        roots = [("DEFENDER_DIR", str(DEFENDER_DIR)), ("REPO_ROOT", str(REPO_ROOT)),
                 ("RUN_DIR", str(run_dir))]
        if agent is not None:
            roots.append(("AGENT_DIR", str(agent)))
    knowledge = KnowledgePaths(agent) if agent is not None else None
    return defender_dir, knowledge, shown, roots


def workspace_map(
    run_dir: Path, *, systems: Sequence[str], down: Mapping[str, str] = NONE_DOWN, view: ModelView | None = None,
    agent_root: Path | None = None,
) -> str:
    """The model's directory view of the run. `systems` (the Adapters section) is the run's
    roster (`read_roster(...).accepted`), never a directory listing, so the map cannot name a
    system that `query` would reject as unknown.

    `view` is the run's model view (#1255 P1): every root and tree the map names is the model
    path of the run's own checkout and run folder, and no host root (the repo root is the
    host's) is named. Without one — the operator's command line — the map names this host's
    paths, as it always has.

    The system skills and the query templates are the run's own tenant knowledge (#1108 P4):
    the view's agent tree (the run copy), or `agent_root` on the command line (the export the
    run was stamped with). With neither, the map says it has none to show."""
    defender_dir, knowledge, shown, roots = _map_roots(run_dir, view, agent_root)
    lines: list[str] = []
    lines.append("# Workspace map")
    lines.append("")
    lines.append(
        "Generated at run start. Use this in place of `ls`/`find`/`grep` "
        "for the paths below — they are the canonical surfaces."
    )
    lines.append("")
    lines.append("## Absolute roots")
    lines.extend(f"- {name}: `{value}`" for name, value in roots)
    lines.append("")

    lines.append(f"## Run dir — `{shown(run_dir) if view is not None else run_dir}`")
    if run_dir.is_dir():
        for child in sorted(run_dir.iterdir()):
            if child.name in _unlisted():
                continue
            kind = "dir/" if child.is_dir() else ""
            lines.append(f"- {_safe_name(child.name)}{(' ' + kind) if kind else ''}")
    else:
        lines.append("- (not yet materialized)")
    lines.append("")

    lines.extend(_skills_section(knowledge, shown))
    lines.append("")

    lines.append(f"## Adapters — `{shown(adapters_under(defender_dir))}/`")
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

    if knowledge is None:
        lines.extend(["## Gather query templates", _NO_KNOWLEDGE])
    else:
        queries_dir = knowledge.catalog_dir
        lines.append(f"## Gather query templates — `{shown(queries_dir)}/`")
        lines.extend(_template_counts(queries_dir))
    lines.append("")

    return "\n".join(lines) + "\n"


def _skills_section(knowledge: KnowledgePaths | None, shown: Callable[[Path], str]) -> list[str]:
    """The system skills of the run's agent root, by folder, each marked when it has a
    `SKILL.md`."""
    if knowledge is None:
        return ["## System skills", _NO_KNOWLEDGE]
    skills_dir = knowledge.skills_dir
    lines = [f"## System skills — `{shown(skills_dir)}/`"]
    for name in _list_dir(skills_dir):
        marker = " (SKILL.md)" if (skills_dir / name / "SKILL.md").is_file() else ""
        lines.append(f"- {name}{marker}")
    return lines


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
