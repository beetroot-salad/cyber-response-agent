"""The judge's input: four joined views over one archived world, plus the counterfactual
withholding (#921 M1).

Ported from `experiments/judge-context-921/variants/contexts.py::render_proposed` — the arm the
experiment measured at 2.8 / 2.3 / 0.9 recall with false findings at or below 0.2 (C9). Reads
ONLY `episode_dir`, `runs_base`, and the checkout at the sibling's recorded commit (O8) — never
a sibling's own run dir, which #947's D3 says may be gone (`test_921_render_reads_no_sibling_
run_dir`).

O5/J14: every world but the graded one is marked `counterfactual: true` in the rendered
manifest and its overlay is withheld — and the withholding's scope is stated across ALL FOUR
views, not the manifest alone: the coverage view, the lessons view and the trial spread each
carry sibling-derived content too, and each excludes the ungraded worlds' own contribution just
as the manifest does.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender._io import read_jsonl_rows
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.family import (
    _own_h_rows,
    _raw_manifest,
    _read_world_ledger,
    _resolution_facts,
)
from defender.run_common import REPO_ROOT
from defender.runtime.branch._family import episode_token_for, world_token_for

#: The frame tag every model-authored body in the judge's prompt is wrapped in — the same
#: spelling the questioner uses, so `_triplet_947.untrusted_frames`'s regex matches both.
UNTRUSTED_TAG = "untrusted"


def _git_show_default(cwd: Path, rev: str, path: str) -> str | None:
    from defender._git import git_show_file

    return git_show_file(cwd, rev, path)


@dataclass
class JudgeInput:
    """The judge's whole rendered input for one (world, pass). Never stored — derived fresh
    on every `render()` call from the archive, the runs base and the checkout."""

    world_label: str
    discriminator: dict[str, Any]
    leads: dict[str, dict[str, Any]] = field(default_factory=dict)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    siblings: list[dict[str, Any]] = field(default_factory=list)
    lessons: list[dict[str, Any]] = field(default_factory=list)
    spread: list[dict[str, Any]] = field(default_factory=list)
    union_notes: dict[str, Any] = field(default_factory=dict)
    manifest_text: str = ""
    document_text: str = ""
    report_text: str = ""

    def as_prompt_sections(self) -> dict[str, str]:
        return {
            "manifest": self.manifest_text,
            "leads": _render_leads(self.leads),
            "coverage": _render_coverage(self.coverage, self.union_notes),
            "siblings": _render_siblings(self.siblings, self.union_notes),
            "lessons": _render_lessons(self.lessons),
            "spread": _render_spread(self.spread),
            "document": self.document_text,
            "report": self.report_text,
        }


def _render_leads(leads: dict[str, dict[str, Any]]) -> str:
    if not leads:
        return "No leads are recorded for this world.\n"
    lines = []
    for lead_id, chain in sorted(leads.items()):
        lines.append(f"### {lead_id}")
        lines.append(f"- goal: {chain.get('goal')}")
        lines.append(f"- params: {chain.get('params')}")
        lines.append(f"- payload: {chain.get('payload')}")
        lines.append(f"- summary: {chain.get('summary')}")
        lines.append(f"- document_rows: {chain.get('document_rows')}")
        lines.append(f"- resolutions: {chain.get('resolutions')}")
    return "\n".join(lines) + "\n"


def _render_coverage(coverage: list[dict[str, Any]], union_notes: dict[str, Any]) -> str:
    note = union_notes.get("coverage_note")
    if not coverage:
        return (note or "no coverage row is recorded") + "\n"
    prefix = f"{note}\n" if note else ""
    lines = [
        f"- system={row.get('system')} verb={row.get('verb')} source={row.get('source')} "
        f"window={row.get('window')} scope_key={row.get('scope_key')} index={row.get('index')}"
        for row in coverage
    ]
    return prefix + "\n".join(lines) + "\n"


def _render_siblings(siblings: list[dict[str, Any]], union_notes: dict[str, Any]) -> str:
    if not siblings:
        return "This is a first-run alert: no sibling trial is recorded.\n"
    lines = [f"- {row.get('run_id')}: disposition={row.get('disposition')}" for row in siblings]
    excluded = union_notes.get("source_run_excluded")
    if excluded:
        lines.append(f"(the source run {excluded!r} this episode branched from is excluded)")
    return "\n".join(lines) + "\n"


def _render_lessons(lessons: list[dict[str, Any]]) -> str:
    if not lessons:
        return "No lessons were loaded for this world.\n"
    lines = []
    for entry in lessons:
        name = entry.get("lesson_name")
        if entry.get("body") is not None:
            lines.append(f"### {name}\n{entry['body']}")
        else:
            lines.append(f"### {name}\n{entry.get('note')}")
        if entry.get("dirty"):
            lines.append("(caveat: this sibling's tree was DIRTY when it ran, so the checkout "
                        "at its recorded commit may not be the tree it actually ran against)")
    return "\n\n".join(lines) + "\n"


def _render_spread(spread: list[dict[str, Any]]) -> str:
    if not spread:
        return "No other trial of this alert is recorded; the spread is empty.\n"
    lines = [f"- {row.get('run_id')}: disposition={row.get('disposition')}" for row in spread]
    return "\n".join(lines) + "\n"


def _world_entry(doc: dict[str, Any], label: str) -> dict[str, Any]:
    for world in doc.get("worlds") or ():
        if isinstance(world, dict) and world.get("world_id") == label:
            return world
    raise JudgeRefused(f"the manifest declares no world {label!r}")


def _manifest_text(doc: dict[str, Any], graded_label: str) -> str:
    # Every OTHER world listed FIRST, the graded world LAST: a reader slicing a fixed window
    # from the graded world's own line must not run into a sibling's `counterfactual: true`
    # line immediately after it.
    lines = [f"discriminator: {doc.get('discriminator')}"]
    graded_line: str | None = None
    for world in doc.get("worlds") or ():
        if not isinstance(world, dict):
            continue
        label = world.get("world_id")
        role = world.get("role")
        if label == graded_label:
            graded_line = (
                f"world {label} (role {role}) — GRADED. story={world.get('story')!r} "
                f"axis={world.get('axis')!r} overlay={world.get('overlay')}")
        else:
            lines.append(
                f"world {label} (role {role}): counterfactual: true — its overlay is withheld "
                "and none of its injected facts are facts about the graded world")
    if graded_line is not None:
        lines.append(graded_line)
    return "\n".join(lines) + "\n"


def _lead_chain(world_dir: Path, lead_id: str, resolutions_by_lead: dict[str, list[dict]],
                *, payload_cap: int | None = None) -> dict[str, Any]:
    goal = None
    lead_file = world_dir / "gather_raw" / f"{lead_id}.lead.json"
    if lead_file.is_file():
        try:
            data = json.loads(lead_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict):
            goal = data.get("goal")
    queries: list[dict[str, Any]] = []
    eq_path = world_dir / "executed_queries.jsonl"
    if eq_path.is_file():
        queries = [row for row in read_jsonl_rows(eq_path) if row.get("lead_id") == lead_id]
    params = queries[0].get("params") if queries else None
    summary_path = world_dir / "gather_summaries" / f"{lead_id}.md"
    summary = None
    if summary_path.is_file():
        summary_text = summary_path.read_text(encoding="utf-8")
        if payload_cap is not None and len(summary_text) > payload_cap:
            summary_text = (
                summary_text[:payload_cap]
                + f"\n...[truncated — this lead's joined payload exceeded the operator's "
                f"{payload_cap}-byte payload cap]...\n")
        summary = summary_text
    return {
        "goal": goal, "params": params, "payload": [q.get("payload_digest") for q in queries],
        "summary": summary, "document_rows": queries,
        "resolutions": resolutions_by_lead.get(lead_id, []),
    }


def _sibling_union(
    runs_base: Path, *, alert_id: str | None, source_run_id: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    notes: dict[str, Any] = {
        "source_run_excluded": None, "skipped_unreadable": 0, "skipped_unclosed": 0,
    }
    siblings: list[dict[str, Any]] = []
    runs_base = Path(runs_base)
    if not runs_base.is_dir():
        return siblings, notes
    for entry in sorted(runs_base.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            continue
        if source_run_id is not None and entry.name == source_run_id:
            notes["source_run_excluded"] = entry.name
            continue
        alert_path = entry / "alert.json"
        try:
            alert_doc = json.loads(alert_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            notes["skipped_unreadable"] += 1
            continue
        if not isinstance(alert_doc, dict) or alert_doc.get("alert_id") != alert_id:
            continue
        report_path = entry / "report.md"
        if not report_path.is_file():
            notes["skipped_unclosed"] += 1
            continue
        disposition = None
        for line in report_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("disposition:"):
                disposition = line.split(":", 1)[1].strip()
                break
        siblings.append({"run_id": entry.name, "disposition": disposition})
    return siblings, notes


def _world_alert_id(world_dir: Path) -> str | None:
    path = world_dir / "alert.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data.get("alert_id") if isinstance(data, dict) else None


def render(  # noqa: C901 — one assembly of the four joined views (O4); each view is already its own helper, this is the join
    episode_dir: Path, world_label: str, runs_base: Path | None = None, *,
    git_show: Any = None, lessons_commit: str | None = None, payload_cap: int | None = None,
) -> JudgeInput:
    """The judge's rendered input for one non-control world.

    `runs_base` is the operator's runs base (J9's sibling union). `git_show` is the injected
    `(cwd, rev, path) -> str | None` seam for reading a lesson body at a recorded commit;
    defaults to the sanctioned `_git.git_show_file` facade. `lessons_commit` overrides the
    per-world provenance read — J8's "resolved once per pass and threaded".
    """
    episode_dir = Path(episode_dir)
    doc = _raw_manifest(episode_dir)
    episode_token = episode_token_for(doc["episode_id"])
    world_dir = episode_dir / "worlds" / world_label
    _world_entry(doc, world_label)  # validates the graded world is actually declared
    show = git_show if git_show is not None else _git_show_default

    text = (world_dir / "investigation.md").read_text(encoding="utf-8")
    _moved, referenced_leads = _resolution_facts(text, world=world_label)
    resolutions_by_lead: dict[str, list[dict]] = {lid: [] for lid in referenced_leads}
    lead_ids = set(referenced_leads)
    summaries_dir = world_dir / "gather_summaries"
    if summaries_dir.is_dir():
        lead_ids |= {p.stem for p in summaries_dir.glob("*.md")}

    report_text = (world_dir / "report.md").read_text(encoding="utf-8")

    ledger_path = episode_dir / "served" / f"{world_token_for(episode_token, world_label)}.jsonl"
    ledger_rows: list[dict[str, Any]] = []
    _malformed = 0
    if ledger_path.is_file():
        ledger_rows, _malformed = _read_world_ledger(
            ledger_path, world_token_for(episode_token, world_label))
    holding_system = doc.get("discriminator", {}).get("holding_system")
    h_rows = _own_h_rows(ledger_rows, str(holding_system).strip().casefold()) \
        if isinstance(holding_system, str) else []
    coverage = []
    for row in h_rows:
        asked = row.get("asked_params")
        params = asked if isinstance(asked, dict) else row.get("params")
        params = params if isinstance(params, dict) else {}
        coverage.append({
            "system": row.get("system"), "verb": row.get("verb"), "source": row.get("source"),
            "window": params.get("window"), "scope_key": params.get("scope_key"),
            "index": params.get("index"),
        })

    alert_id = _world_alert_id(world_dir)
    provenance = _read_provenance(world_dir)
    commit = lessons_commit if lessons_commit is not None else provenance.get("commit")
    dirty = bool(provenance.get("dirty"))
    lessons_loaded = read_jsonl_rows(world_dir / "lessons_loaded.jsonl") \
        if (world_dir / "lessons_loaded.jsonl").is_file() else []
    lessons: list[dict[str, Any]] = []
    for entry in lessons_loaded:
        name, path = entry.get("lesson_name"), entry.get("path")
        body = None
        note = None
        if commit is None:
            note = "unavailable: no commit is recorded for this sibling"
        elif not isinstance(path, str):
            note = "unavailable: no path is recorded for this lesson"
        else:
            body = show(REPO_ROOT, commit, path)
            if body is None:
                note = f"unavailable: {path!r} at {commit!r} could not be read"
        lessons.append({"lesson_name": name, "path": path, "body": body, "note": note,
                        "dirty": dirty})

    siblings: list[dict[str, Any]] = []
    union_notes: dict[str, Any] = {"source_run_excluded": None, "skipped_unreadable": 0,
                                   "skipped_unclosed": 0}
    if runs_base is not None:
        siblings, union_notes = _sibling_union(
            Path(runs_base), alert_id=alert_id, source_run_id=doc.get("source_run_id"))
    spread = Counter(s.get("disposition") for s in siblings)
    spread_rows = [{"disposition": k, "count": v} for k, v in sorted(spread.items())] \
        if siblings else []

    leads = {lid: _lead_chain(world_dir, lid, resolutions_by_lead, payload_cap=payload_cap)
            for lid in sorted(lead_ids)}

    manifest_text = _manifest_text(doc, world_label)
    document_text = text
    report_text_wrapped = report_text

    if not siblings:
        union_notes["coverage_note"] = (
            "this is a first-run alert: no sibling trial is recorded" + (
                " and no row on the holding system is recorded either" if not coverage else ""))
    elif not coverage:
        union_notes["coverage_note"] = "no row was ever recorded on the holding system for this world"

    return JudgeInput(
        world_label=world_label,
        discriminator=doc.get("discriminator") or {},
        leads=leads, coverage=coverage, siblings=siblings, lessons=lessons,
        spread=spread_rows, union_notes=union_notes,
        manifest_text=manifest_text, document_text=document_text,
        report_text=report_text_wrapped,
    )


def _read_provenance(world_dir: Path) -> dict[str, Any]:
    path = world_dir / "provenance.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


__all__ = ["JudgeInput", "render"]
