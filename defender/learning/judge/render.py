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
from defender._report import read_report
from defender.learning.judge.family import (
    WorldFacts,
    _own_h_rows,
    _raw_manifest,
    discriminator_of,
    episode_id_of,
    read_world_facts,
    scope_params,
)
from defender.run_common import REPO_ROOT
from defender.runtime.branch._family import episode_token_for

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

    #: The operator's `JUDGE_PAYLOAD_CAP`, or `None`. Held on the input rather than applied
    #: during assembly because what it must bound is the BYTES THAT REACH THE PROMPT.
    payload_cap: int | None = None

    def as_prompt_sections(self) -> dict[str, str]:
        """Each view as the text that goes inside its frame, the SET of them under the cap.

        THE CAP IS CHARGED OVER THE WHOLE SET, not per section. It first bounded one file — a
        lead's `gather_summaries/<lead>.md` — while `document_rows` embedded every executed
        query for that lead, `_render_lessons` embedded each lesson's whole body at its recorded
        commit, and the document and report were whole files. Charging it per section instead
        fixed that and introduced its own version of it: eight sections each at the cap is eight
        times the bound, and the knob still reported success. What the operator is bounding is
        the bytes that reach the model, so that is the quantity measured."""
        return _cap_sections({
            "manifest": self.manifest_text,
            "leads": _render_leads(self.leads),
            "coverage": _render_coverage(self.coverage, self.union_notes),
            "siblings": _render_siblings(self.siblings, self.union_notes),
            "lessons": _render_lessons(self.lessons),
            "spread": _render_spread(self.spread),
            "document": self.document_text,
            "report": self.report_text,
        }, self.payload_cap)


def _cap_sections(sections: dict[str, str], payload_cap: int | None) -> dict[str, str]:
    """The rendered views, trimmed so their TOTAL length is at most `payload_cap`.

    An EQUAL SHARE of what is left, smallest section first: a view that already fits is never
    cut and hands its unused share back to the ones that do not, so the bytes come off whichever
    view is actually large. Trimming every section to `cap / 8` instead would cut the spread and
    the coverage table — the two smallest and most load-bearing views — to make room for a
    document nobody bounded."""
    if payload_cap is None or sum(len(body) for body in sections.values()) <= payload_cap:
        return sections
    remaining, left = payload_cap, len(sections)
    out: dict[str, str] = {}
    for name, body in sorted(sections.items(), key=lambda item: len(item[1])):
        share = max(remaining // left, 0)
        out[name] = body if len(body) <= share else _capped(body, share, name)
        remaining -= len(out[name])
        left -= 1
    return {name: out[name] for name in sections}


def _capped(body: str, share: int, name: str) -> str:
    """One rendered section trimmed to `share` bytes, SAYING it was cut.

    A silent truncation is a view the model reads as complete; the stamp is what makes the
    missing bytes a fact it can reason about rather than an absence it fills in (C11). The
    stamp is INSIDE the share and the result is clamped to it — a bound the returned value may
    exceed by the length of its own explanation is not a bound."""
    # SHORT ON PURPOSE. The stamp is inside the share, so a long explanation is a long
    # explanation the view's own content pays for — at a small cap it crowded out the very rows
    # it was explaining the absence of. The view is titled in the prompt already, so the stamp
    # only has to say that what is above is a prefix.
    stamp = f"\n...[{name} truncated at the payload cap]...\n"
    return (body[:max(share - len(stamp), 0)] + stamp)[:share]


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
    lines = [f"- {row.get('run_id')}: disposition={row.get('disposition')}" for row in siblings]
    if not siblings and not union_notes.get("runs_base_unset"):
        lines = ["This is a first-run alert: no sibling trial is recorded."]
    excluded = union_notes.get("source_run_excluded")
    if excluded:
        lines.append(f"(the source run {excluded!r} this episode branched from is excluded)")
    lines.extend(_exclusion_lines(union_notes))
    return "\n".join(lines) + "\n"


def _exclusion_lines(union_notes: dict[str, Any]) -> list[str]:  # noqa: D401
    """What the union DROPPED, said out loud in the view the drops belong to.

    The counts were tallied and rendered nowhere, so the model was handed a shorter sibling
    list and a smaller spread with nothing saying either had been trimmed — and then asked to
    reason about the spread. An unstated absence is what a model fills in (C11), which is the
    whole reason the empty-union case says so explicitly one line up."""
    out = []
    if union_notes.get("runs_base_unset"):
        out.append("(no runs base was named for this pass, so the sibling union was never "
                   "attempted — this is not a statement that no sibling trial exists)")
    for key, what in (("skipped_unreadable", "could not be read"),
                      ("skipped_unclosed", "never reached a close")):
        count = union_notes.get(key) or 0
        if count:
            out.append(f"({count} further trial(s) of this alert {what} and are excluded here "
                       "and from the spread below)")
    return out


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
    """The spread's own row shape — `disposition` and `count`, NOT the sibling view's
    `run_id`/`disposition`. The spread is the tally ACROSS the siblings, so the count is the
    only thing it carries that the sibling list does not; rendering it with the sibling
    formatter printed a `None` run id per line and dropped every count."""
    if not spread:
        return "No other trial of this alert is recorded; the spread is empty.\n"
    lines = [
        f"- disposition={_spread_label(row.get('disposition'))}: {row.get('count')} trial(s)"
        for row in spread
    ]
    return "\n".join(lines) + "\n"


def _spread_label(disposition: Any) -> str:
    """A spread key as text. `None` is a real member — a sibling whose report exists but
    carries no `disposition:` line — and it is named rather than printed as `None`."""
    return "(none recorded)" if disposition is None else str(disposition)


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


def _queries_by_lead(world_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """The world's whole queries table, grouped by lead, in ONE parse.

    Called once per world rather than once per lead: the per-lead chain used to re-read and
    re-parse `executed_queries.jsonl` inside its own comprehension, so a world with N leads
    parsed the same table N times."""
    eq_path = world_dir / "executed_queries.jsonl"
    if not eq_path.is_file():
        return {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in read_jsonl_rows(eq_path):
        lead_id = row.get("lead_id")
        if isinstance(lead_id, str):
            grouped.setdefault(lead_id, []).append(row)
    return grouped


def _lead_chain(world_dir: Path, lead_id: str, resolutions_by_lead: dict[str, list[dict]],
                *, queries_by_lead: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    goal = None
    lead_file = world_dir / "gather_raw" / f"{lead_id}.lead.json"
    if lead_file.is_file():
        try:
            data = json.loads(lead_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict):
            goal = data.get("goal")
    queries = queries_by_lead.get(lead_id, [])
    params = queries[0].get("params") if queries else None
    summary_path = world_dir / "gather_summaries" / f"{lead_id}.md"
    summary = None
    if summary_path.is_file():
        # `errors="replace"`, not a bare read. This is MODEL-WRITTEN text in a tree the box can
        # write, so an undecodable byte in it is an ordinary thing to meet; raising here would
        # be an unreadable summary costing the whole episode its grade, and the substitution
        # character is exactly what the judge should be shown of a byte nobody can read.
        summary = summary_path.read_text(encoding="utf-8", errors="replace")
    return {
        "goal": goal, "params": params, "payload": [q.get("payload_digest") for q in queries],
        "summary": summary, "document_rows": queries,
        "resolutions": resolutions_by_lead.get(lead_id, []),
    }


def sibling_union(
    runs_base: Path | None, *, alert_id: str | None, source_run_id: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """J9's sibling union — every finished trial of this alert under the operator's runs base.

    PUBLIC, and computed ONCE PER PASS rather than once per world: every world of one episode
    shares the alert, so the answer is identical for all of them, while the walk costs one
    `alert.json` read and one report parse per run under the runs base. `render` will compute
    it for a caller that hands over nothing, the same way it reads a world's files itself.

    `runs_base=None` is NOT an empty union. It means nobody named a runs base, which is a
    different fact from "this alert has no other trial" and is recorded as such — an
    unattempted union rendered as `no sibling trial is recorded` is the unstated absence C11
    measured a model filling in."""
    notes: dict[str, Any] = {
        "source_run_excluded": None, "skipped_unreadable": 0, "skipped_unclosed": 0,
        "runs_base_unset": runs_base is None,
    }
    if runs_base is None:
        return [], notes
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
        # THROUGH `read_report`, like every other reader of a report in this repo. It parses
        # the frontmatter the close gate writes, answers the vocabulary through
        # `normalized_disposition`, and — the part that matters at THIS call site — NEVER
        # RAISES: a bare `read_text` here made one undecodable byte in one unrelated run under
        # the operator's runs base refuse the whole grade of an episode whose own archive reads
        # perfectly. An unreadable sibling is skipped and COUNTED, the same as an unreadable
        # `alert.json` three lines up.
        read = read_report(report_path)
        if not read.text:
            notes["skipped_unreadable"] += 1
            continue
        siblings.append({"run_id": entry.name, "disposition": read.disposition})
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
    facts: WorldFacts | None = None,
    union: tuple[list[dict[str, Any]], dict[str, Any]] | None = None,
) -> JudgeInput:
    """The judge's rendered input for one non-control world.

    `runs_base` is the operator's runs base (J9's sibling union). `git_show` is the injected
    `(cwd, rev, path) -> str | None` seam for reading a lesson body at a recorded commit;
    defaults to the sanctioned `_git.git_show_file` facade. `lessons_commit` overrides the
    per-world provenance read — J8's "resolved once per pass and threaded". `facts` is this
    world's already-read archived record and `union` is the episode's sibling union: the
    mechanical pass reads the same three files immediately before this runs, and every world of
    one episode has the same union, so the orchestration hands both over and only a caller with
    nothing to hand over pays to compute them again.
    """
    episode_dir = Path(episode_dir)
    doc = _raw_manifest(episode_dir)
    episode_token = episode_token_for(episode_id_of(doc))
    world_dir = episode_dir / "worlds" / world_label
    _world_entry(doc, world_label)  # validates the graded world is actually declared
    show = git_show if git_show is not None else _git_show_default
    record = facts if facts is not None else read_world_facts(
        episode_dir, world_label, episode_token=episode_token)

    text = record.investigation_text
    resolutions_by_lead = record.resolutions_by_lead
    lead_ids = set(record.referenced_leads)
    summaries_dir = world_dir / "gather_summaries"
    if summaries_dir.is_dir():
        lead_ids |= {p.stem for p in summaries_dir.glob("*.md")}

    # The report's BYTES for the prompt, off the same read the mechanical pass made.
    report_text = record.report.text

    holding_system = discriminator_of(doc).get("holding_system")
    h_rows = _own_h_rows(record.ledger_rows, str(holding_system).strip().casefold()) \
        if isinstance(holding_system, str) else []
    coverage = []
    for row in h_rows:
        params = scope_params(row)
        coverage.append({
            "system": row.get("system"), "verb": row.get("verb"), "source": row.get("source"),
            "window": params.get("window"), "scope_key": params.get("scope_key"),
            "index": params.get("index"),
        })

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

    siblings, union_notes = union if union is not None else sibling_union(
        Path(runs_base) if runs_base is not None else None,
        # Read HERE and not above: this world's `alert.json` is opened and parsed only on the
        # path that actually needs it, and the orchestration always supplies the union.
        alert_id=_world_alert_id(world_dir), source_run_id=doc.get("source_run_id"))
    spread = Counter(s.get("disposition") for s in siblings)
    # SORTED BY A KEY, not by the values themselves. A sibling whose report exists but carries
    # no `disposition:` line contributes `None`, so the moment one such sibling shares an alert
    # with a normal one the tally holds both a string and `None` and comparing them directly
    # raises `TypeError` — out of the render, past every handler, taking the episode with it.
    spread_rows = [
        {"disposition": k, "count": v}
        for k, v in sorted(spread.items(), key=lambda kv: (kv[0] is None, str(kv[0])))
    ] if siblings else []

    queries_by_lead = _queries_by_lead(world_dir)
    leads = {lid: _lead_chain(world_dir, lid, resolutions_by_lead,
                             queries_by_lead=queries_by_lead)
            for lid in sorted(lead_ids)}

    manifest_text = _manifest_text(doc, world_label)

    # A COPY, because `union_notes` belongs to the PASS and the note below belongs to the
    # WORLD. The union is computed once and threaded to every world (J9), so writing a per-world
    # note into it left world c's "no row was ever recorded on the holding system for this
    # world" standing in world b's coverage view — above the row world b had in fact recorded.
    # That is the exact fact the lead-set and lead-quality buckets turn on.
    union_notes = dict(union_notes)
    if union_notes.get("runs_base_unset"):
        # NOT "this is a first-run alert". Nobody looked, which is a different fact from "no
        # sibling exists" — and the siblings view says so in the same prompt, so asserting the
        # absence here would hand the model two contradictory statements about one fact.
        if not coverage:
            union_notes["coverage_note"] = (
                "no row on the holding system is recorded for this world")
    elif not siblings:
        union_notes["coverage_note"] = (
            "this is a first-run alert: no sibling trial is recorded" + (
                " and no row on the holding system is recorded either" if not coverage else ""))
    elif not coverage:
        union_notes["coverage_note"] = "no row was ever recorded on the holding system for this world"

    return JudgeInput(
        world_label=world_label,
        discriminator=discriminator_of(doc),
        leads=leads, coverage=coverage, siblings=siblings, lessons=lessons,
        spread=spread_rows, union_notes=union_notes,
        manifest_text=manifest_text, document_text=text, report_text=report_text,
        payload_cap=payload_cap,
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
