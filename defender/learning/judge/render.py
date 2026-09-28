"""The judge's input: four joined views over one archived world, plus the counterfactual
withholding.

Ported from `experiments/judge-context-921/variants/contexts.py::render_proposed`, the measured
arm. Reads only `episode_dir`, `runs_base`, and the checkout at the sibling's recorded commit —
never a sibling's own run dir, which may be gone.

Every world but the graded one is marked `counterfactual: true` in the rendered manifest with
its overlay withheld, and the coverage, lessons and spread views likewise exclude the ungraded
worlds' contribution.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Any

import contextlib

from defender._io import Bound, bind
from defender._episode_paths import LAYOUT, WORLD_LEAVES
from defender._run_paths import RUN_LAYOUT
from defender.hooks.record_lesson_load import (
    EVIDENCE_INDIRECT,
    EVIDENCE_PUSH,
    EVIDENCE_READ,
    EVIDENCE_UNKNOWN,
    LessonExposure,
    exposures,
)
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.family import (
    WorldFacts,
    discriminator_of,
    episode_id_of,
    json_mapping,
    json_mapping_of,
    has_refusals,
    _repository_leads,
    lead_chain,
    own_h_rows,
    render_refused,
    read_archived_report,
    read_manifest,
    read_review_record,
    read_samples_record,
    read_world_facts,
    sample_patterns,
    scope_params,
    summary_lead_ids,
    world_review_block,
)
from defender.run_common import REPO_ROOT
from defender.runtime.branch._family import episode_token_for

#: The frame tag every model-authored body in the judge's prompt is wrapped in — the
#: questioner's spelling, so one frame regex matches both.
UNTRUSTED_TAG = "untrusted"


def _git_show_default(cwd: Path, rev: str, path: str) -> str | None:
    from defender._git import git_show_file

    return git_show_file(cwd, rev, path)


@model
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
    #: The questioner's sample(s) for this world's staged patterns, and this world's own
    #: reachability block off `review.yaml` — never a sibling's.
    sample_text: str = ""
    review_text: str = ""

    #: The operator's `JUDGE_PAYLOAD_CAP`, or `None`. Applied at `as_prompt_sections`, since
    #: what it bounds is the bytes that reach the prompt.
    payload_cap: int | None = None

    def as_prompt_sections(self) -> dict[str, str]:
        """Each view as the text that goes inside its frame, with the cap charged over the
        whole set — a per-section cap would multiply the bound by the section count."""
        return _cap_sections({
            "manifest": self.manifest_text,
            "leads": _render_leads(self.leads),
            "coverage": _render_coverage(self.coverage, self.union_notes),
            "siblings": _render_siblings(self.siblings, self.union_notes),
            "lessons": _render_lessons(self.lessons),
            "spread": _render_spread(self.spread, self.union_notes),
            "document": self.document_text,
            "report": self.report_text,
            "sample": self.sample_text,
            "review": self.review_text,
        }, self.payload_cap)


def _cap_sections(sections: dict[str, str], payload_cap: int | None) -> dict[str, str]:
    """The rendered views, trimmed so their total length is at most `payload_cap`.

    Equal share of what is left, smallest section first: a view that fits is never cut and
    hands its unused share on, so the bytes come off whichever view is actually large (not the
    small, load-bearing spread and coverage views)."""
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
    """One rendered section trimmed to `share` bytes, saying it was cut — a silent truncation
    reads as complete, and a model fills in unstated absences. The stamp counts against the
    share, so the bound holds."""
    # Short, since the stamp is paid for out of the view's own content.
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
        # Printed for every lead, `[]` included, so "refused nothing" is never ambiguous.
        lines.append(f"- refused: {render_refused(chain['refused'])}")
        lines.append(f"- summary: {chain.get('summary')}")
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
    if not siblings and _union_empty_after_a_walk(union_notes):
        lines = ["This is a first-run alert: no sibling trial is recorded."]
    excluded = union_notes.get("source_run_excluded")
    if excluded:
        lines.append(f"(the source run {excluded!r} this episode branched from is excluded)")
    lines.extend(_exclusion_lines(union_notes))
    return "\n".join(lines) + "\n"


def _union_unattempted(union_notes: dict[str, Any]) -> bool:
    """Was the sibling walk never actually made? Shared by all three union views: an
    unattempted union is not "no sibling exists"."""
    return bool(union_notes.get("runs_base_unset") or union_notes.get("runs_base_missing")
                or union_notes.get("runs_base_unreadable") or union_notes.get("alert_unidentified"))


def _union_empty_after_a_walk(union_notes: dict[str, Any]) -> bool:
    """May a view say "this is a first-run alert" — did a walk run and find nothing, with
    nothing dropped? An excluded source run or a skipped trial means something was found."""
    return not (_union_unattempted(union_notes)
                or union_notes.get("source_run_excluded")
                or union_notes.get("skipped_unreadable")
                or union_notes.get("skipped_unclosed"))


def _exclusion_lines(union_notes: dict[str, Any]) -> list[str]:  # noqa: D401
    """What the union dropped or never attempted, stated in the view — a model fills in
    unstated absences."""
    out = []
    if union_notes.get("runs_base_unset"):
        out.append("(no runs base was named for this pass, so the sibling union was never "
                   "attempted — this is not a statement that no sibling trial exists)")
    if union_notes.get("runs_base_missing"):
        out.append("(the runs base named for this pass is not a directory, so the sibling "
                   "union was never attempted — this is not a statement that no sibling "
                   "trial exists)")
    if union_notes.get("runs_base_unreadable"):
        out.append(f"(the runs base named for this pass could not be listed — "
                   f"{union_notes['runs_base_unreadable']} — so the sibling union was never "
                   "attempted — this is not a statement that no sibling trial exists)")
    if union_notes.get("alert_unidentified"):
        out.append("(this episode's own alert.json carries no alert id, so the sibling union "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
                   "had nothing to match trials against and was never attempted — this is not "
                   "a statement that no sibling trial exists)")
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
        # Required (KeyError, not silent omission): it tells the judge whether the model read
        # the body. `None` only for the unnamed-rows entry.
        exposure = entry["exposure"]
        head = f"### {name}\n({exposure})\n" if exposure is not None else f"### {name}\n"
        if entry.get("body") is not None:
            lines.append(f"{head}{entry['body']}")
        else:
            lines.append(f"{head}{entry.get('note')}")
        # `dirty` is three-valued; `None` (never measured) is not clean, so it gets a caveat.
        if entry.get("dirty") is not False:
            lines.append(
                ("(caveat: this sibling's tree was DIRTY when it ran"
                 if entry.get("dirty") else
                 "(caveat: whether this sibling's tree was dirty was never measured")
                + ", so the checkout at its recorded commit may not be the tree it actually "
                  "ran against)")
    return "\n\n".join(lines) + "\n"


def _render_spread(spread: list[dict[str, Any]], union_notes: dict[str, Any]) -> str:
    """The spread: `disposition` and `count` per row (the tally across siblings).

    An empty spread only claims "no other trial" when the walk ran and dropped nothing,
    agreeing with the siblings view."""
    if not spread:
        if not _union_empty_after_a_walk(union_notes):
            return ("The spread is empty because the sibling union it tallies is — see the "
                    "sibling view above for why; this is not a statement that no other trial "
                    "of this alert exists.\n")
        return "No other trial of this alert is recorded; the spread is empty.\n"
    lines = [
        f"- disposition={_spread_label(row.get('disposition'))}: {row.get('count')} trial(s)"
        for row in spread
    ]
    return "\n".join(lines) + "\n"


def _spread_label(disposition: Any) -> str:
    """A spread key as text; `None` (a report with no disposition) is named, not printed."""
    return "(none recorded)" if disposition is None else str(disposition)


def _world_entry(doc: dict[str, Any], label: str) -> dict[str, Any]:
    for world in doc.get("worlds") or ():
        if isinstance(world, dict) and world.get("world_id") == label:
            return world
    raise JudgeRefused(f"the manifest declares no world {label!r}")


def _manifest_text(doc: dict[str, Any], graded_label: str) -> str:
    # The graded world last, so a window sliced from its line never runs into a sibling's.
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


def _sibling_row(
    run: Bound, run_id: str, *, alert_id: str | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Classify one directory under the runs base.

    `(row, None)`: a finished trial of this alert. `(None, key)`: a skipped trial of this
    alert, `key` naming its count in `union_notes`. `(None, None)`: not a trial of this alert
    (e.g. no `alert.json`), so not counted as a skip either.

    `read_archived_report` never raises, so one bad byte in an unrelated run cannot refuse the
    grade. Both reads are no-follow."""
    alert_rec = run.read(RUN_LAYOUT.alert)
    if alert_rec.absent:
        return None, None
    alert_doc = json_mapping_of(alert_rec.text)
    if alert_doc is None:
        return None, "skipped_unreadable"
    if alert_doc.get("alert_id") != alert_id:
        return None, None
    read = read_archived_report(run, RUN_LAYOUT.report)
    if read.absent:
        return None, "skipped_unclosed"
    if not read.text:
        return None, "skipped_unreadable"
    return {"run_id": run_id, "disposition": read.disposition}, None


def sibling_union(
    runs_base: Path | None, *, alert_id: str | None, source_run_id: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The sibling union: every finished trial of this alert under the operator's runs base.

    Computed once per pass (every world shares the alert). `runs_base=None` is recorded as
    "never attempted", not rendered as an empty union."""
    notes: dict[str, Any] = {
        "source_run_excluded": None, "skipped_unreadable": 0, "skipped_unclosed": 0,
        "runs_base_unset": runs_base is None, "runs_base_missing": False,
        "runs_base_unreadable": None,
        "alert_unidentified": alert_id is None,
    }
    if runs_base is None:
        return [], notes
    siblings: list[dict[str, Any]] = []
    runs_base = Path(runs_base)
    if alert_id is None:
        # No id to match on: `None == None` would match every unrelated run lacking one.
        return siblings, notes
    # The root itself may be a link (the operator's own configuration); entries under it are
    # box-writable and judged no-follow.
    with bind(runs_base) as runs:
        listing = runs.entries()
        if listing.reason is not None:
            # Present but not listable: a different fact from missing.
            notes["runs_base_unreadable"] = listing.reason
            return siblings, notes
        if listing.absent:
            # The runs base need not exist (a tenant with no run yet, or a typo); nobody looked.
            notes["runs_base_missing"] = True
            return siblings, notes
        for run_id in listing.dirs():
            if source_run_id is not None and run_id == source_run_id:
                notes["source_run_excluded"] = run_id
                continue
            row, skipped = _sibling_row(runs.under(run_id), run_id, alert_id=alert_id)
            if row is not None:
                siblings.append(row)
            elif skipped is not None:
                notes[skipped] += 1
    return siblings, notes


def _world_alert_id(world: Bound) -> str | None:
    data = json_mapping(world, WORLD_LEAVES.alert)
    return data.get("alert_id") if data is not None else None


def episode_alert(bound: Bound, labels: list[str]) -> dict[str, Any]:
    """The alert this episode's worlds all investigate: the first world's `alert.json` that
    carries an `alert_id`, else the first that parses.

    Shared by the sibling union and the enqueue's `alert_rule_key`, so both key on the same
    world.
    """
    fallback: dict[str, Any] = {}
    for label in labels:
        # A label off box-writable `judge.yaml` may not be a path component; skip it.
        try:
            data = json_mapping(bound, LAYOUT.world(label).alert)
        except ValueError:
            continue
        if data is None:
            continue
        if data.get("alert_id") is not None:
            return data
        if not fallback:
            fallback = data
    return fallback


def _render_sample(pattern: str, samples_doc: dict[str, Any]) -> str:
    """The questioner's reference document for one staged pattern, as canonical JSON (the
    prompt carries exactly one rendering, compared canonically to the stored document).

    Absent and `null` render the same ("nothing to compare against"), matching the row's
    `sample_unavailable` predicate."""
    document = samples_doc.get(pattern)
    if document is None:
        return f"no sample was captured for {pattern!r}\n"
    # `default=str` handles YAML-typed values; non-string or mixed-type keys still raise, so the
    # dump is guarded — a damaged samples file must cost only its own claims, never the grade.
    try:
        return json.dumps(document, sort_keys=True, indent=2, default=str) + "\n"
    except (TypeError, ValueError):
        return f"the sample recorded for {pattern!r} could not be rendered\n"


def _render_samples(patterns: list[str], samples_doc: dict[str, Any]) -> str:
    """Every staged pattern's sample, one block per pattern — never reduced to one, so a
    missing sample for any pattern is visible."""
    if not patterns:
        return "no pattern is staged for this world\n"
    return "\n".join(
        f"pattern {p!r}:\n{_render_sample(p, samples_doc)}" for p in patterns)


def _render_review_block(block: dict[str, Any] | None) -> str:
    """This world's own reachability block off `review.yaml` — never the whole record, which
    would carry every other world's measurements into this world's prompt."""
    if not isinstance(block, dict):
        return "No reachability block is recorded for this world.\n"
    lines = [
        f"capture_addressed: {block.get('capture_addressed')!r}",
        f"capture_reasks_faulted: {block.get('capture_reasks_faulted')!r}",
        f"reachable_by_capture: {block.get('reachable_by_capture')!r}",
        f"injected_retrieved: {block.get('injected_retrieved')!r}",
        f"injected_present: {block.get('injected_present')!r}",
        # Accepted gap: `envelope_failed` is an adapter fault's text verbatim and can carry the
        # `wv-<world>-<stem>` staged-view names. The frame stops it being read as instruction;
        # it does not redact them.
        f"envelope_failed: {block.get('envelope_failed')!r}",
    ]
    replays = block.get("capture_replays")
    if isinstance(replays, list) and replays:
        lines.append("capture_replays:")
        for entry in replays:
            if isinstance(entry, dict):
                lines.append(f"  - key={entry.get('key')!r} differs={entry.get('differs')!r} "
                             f"faulted={entry.get('faulted')!r}")
    else:
        lines.append("capture_replays: none recorded")
    return "\n".join(lines) + "\n"


def render(  # noqa: C901, PLR0913, PLR0915 — the join of the views; the keyword tail is the per-pass hand-over that avoids re-reading what the caller has read
    episode_dir: Path, world_label: str, runs_base: Path | None = None, *,
    git_show: Any = None, lessons_commit: str | None = None, payload_cap: int | None = None,
    facts: WorldFacts | None = None, review: dict[str, Any] | None = None,
    samples: dict[str, Any] | None = None,
    union: tuple[list[dict[str, Any]], dict[str, Any]] | None = None,
    manifest: dict[str, Any] | None = None, bound: Bound | None = None,
) -> JudgeInput:
    """The judge's rendered input for one non-control world.

    `runs_base` is for the sibling union. `git_show` is the `(cwd, rev, path) -> str | None`
    seam for reading a lesson body at a recorded commit. `lessons_commit` overrides the
    per-world provenance read. `facts`, `union`, `manifest`, `review`, `samples` and `bound`
    are the caller's already-read per-pass inputs; each is read or computed here only when not
    handed over.
    """
    episode_dir = Path(episode_dir)
    with (contextlib.nullcontext(bound) if bound is not None else bind(episode_dir)) as bound:
        return _render_bound_world(bound, episode_dir, world_label, runs_base, git_show=git_show,
                       lessons_commit=lessons_commit, payload_cap=payload_cap, facts=facts,
                       review=review, samples=samples, union=union, manifest=manifest)


def _render_bound_world(  # noqa: C901, PLR0913, PLR0915 — see `render`
    bound: Bound, episode_dir: Path, world_label: str, runs_base: Path | None, *,
    git_show: Any, lessons_commit: str | None, payload_cap: int | None,
    facts: WorldFacts | None, review: dict[str, Any] | None,
    samples: dict[str, Any] | None,
    union: tuple[list[dict[str, Any]], dict[str, Any]] | None,
    manifest: dict[str, Any] | None,
) -> JudgeInput:
    doc = manifest if manifest is not None else read_manifest(bound)
    episode_token = episode_token_for(episode_id_of(doc))
    world_entry = _world_entry(doc, world_label)  # validates the graded world is actually declared
    show = git_show if git_show is not None else _git_show_default
    world = bound.under(LAYOUT.world(world_label).dir)
    # `leads_by_id` takes a path; gated as in the mechanical pass.
    record = facts if facts is not None else read_world_facts(
        bound, world_label, episode_token=episode_token,
        leads=lambda: _repository_leads(world, episode_dir, world_label))

    text = record.investigation_text
    resolutions_by_lead = record.resolutions_by_lead
    lead_ids = set(record.referenced_leads) | summary_lead_ids(world)
    # A lead whose only activity was refused may appear in neither the document nor a summary;
    # add every lead with a refusal (but not a lead with a file and nothing else).
    by_id = record.leads
    lead_ids |= {lid for lid, lead in by_id.items() if has_refusals(lead)}

    report_text = record.report.text

    # Folded exactly as `family._holding_system` does, so the patch-only pattern fallback here
    # matches the row's (samples and citations are matched by exact string).
    raw_holding_system = discriminator_of(doc).get("holding_system")
    resolved_holding_system = (
        raw_holding_system.strip().casefold()
        if isinstance(raw_holding_system, str) else "")
    h_rows = own_h_rows(record.ledger_rows, resolved_holding_system) \
        if isinstance(raw_holding_system, str) else []

    # Same helpers as `family._grade_world`, so the prompt shows the patterns and block the
    # mechanical row was computed from.
    overlay = world_entry.get("overlay")
    world_staged_patterns = sample_patterns(overlay, holding_system=resolved_holding_system)
    samples_doc = read_samples_record(bound) if samples is None else samples
    sample_text = _render_samples(world_staged_patterns, samples_doc)
    review_doc = (read_review_record(bound) or {}) if review is None else review
    review_block = world_review_block(review_doc, world_label)
    review_text = _render_review_block(review_block)
    coverage = []
    for row in h_rows:
        params = scope_params(row)
        coverage.append({
            "system": row.get("system"), "verb": row.get("verb"), "source": row.get("source"),
            "window": params.get("window"), "scope_key": params.get("scope_key"),
            "index": params.get("index"),
        })

    provenance = _read_provenance(world)
    commit = _usable_commit(
        lessons_commit if lessons_commit is not None else provenance.get("commit"))
    # Three-valued: `None` (never measured) must not collapse onto clean.
    dirty = provenance.get("dirty")
    lessons_loaded, _malformed, _rec = world.read_jsonl(WORLD_LEAVES.lessons_loaded)
    lessons: list[dict[str, Any]] = []
    # The file is an event log (a row each time a lesson reached an agent); read as a set via
    # `exposures`, so a repeatedly matched lesson's body appears once.
    read = exposures(lessons_loaded)
    for exposure in read.lessons:
        name = exposure.lesson_name
        # The writer records no path column; the name resolves to one (see `_lesson_paths_for`).
        candidates = _lesson_paths_for(name)
        path = candidates[0] if candidates else None
        body = None
        note = None
        if commit is None:
            note = "unavailable: no commit is recorded for this sibling"
        elif not candidates:
            note = "unavailable: no path is recorded for this lesson and its name names none"
        else:
            for candidate in candidates:
                body = show(REPO_ROOT, commit, candidate)
                if body is not None:
                    path = candidate
                    break
            if body is None:
                note = f"unavailable: {path!r} at {commit!r} could not be read"
        lessons.append({"lesson_name": name, "path": path, "body": body, "note": note,
                        "dirty": dirty, "exposure": _exposure_line(exposure)})
    if read.unnamed:
        # Stated, not dropped: "no lessons were loaded" would be false over a file with rows.
        lessons.append({"lesson_name": f"({read.unnamed} row(s) that named no lesson)",
                        "path": None, "body": None,
                        "note": "unavailable: the row's `lesson_name` is not a string",
                        "dirty": dirty, "exposure": None})

    siblings, union_notes = union if union is not None else sibling_union(
        Path(runs_base) if runs_base is not None else None,
        # Read only on this fallback path; the orchestration always supplies the union.
        alert_id=_world_alert_id(world), source_run_id=doc.get("source_run_id"))
    spread = Counter(s.get("disposition") for s in siblings)
    # Sorted by key: the tally can hold both strings and `None`, which do not compare.
    spread_rows = [
        {"disposition": k, "count": v}
        for k, v in sorted(spread.items(), key=lambda kv: (kv[0] is None, str(kv[0])))
    ] if siblings else []

    leads = {lid: lead_chain(world, lid, resolutions_by_lead, leads=by_id)
             for lid in sorted(lead_ids)}

    manifest_text = _manifest_text(doc, world_label)

    # A copy: the union is shared across worlds, and the note below is this world's alone.
    union_notes = dict(union_notes)
    if not _union_empty_after_a_walk(union_notes):
        # Not "first-run alert": nobody looked, or something was found and dropped.
        if not coverage:
            union_notes["coverage_note"] = (
                "no row on the holding system is recorded for this world")
    elif not siblings:
        # The empty union is stated here, the first thing the prompt says about the union.
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
        sample_text=sample_text, review_text=review_text,
        payload_cap=payload_cap,
    )


#: How a lesson reached the model, per `LessonExposure.evidence`. The body is always rendered
#: for grading, but after a `push` the model saw only the description, not the body.
_EXPOSURE_LINES = {
    EVIDENCE_READ: "read by the model",
    EVIDENCE_PUSH: "pushed by the runtime: the model saw this lesson's description and "
                   "dimensions, never the body below",
    EVIDENCE_INDIRECT: "reached another agent only, never the model",
    EVIDENCE_UNKNOWN: "in context, but the row cannot say how — it predates the read/push "
                      "distinction, or is malformed",
}


def _exposure_line(exposure: LessonExposure) -> str:
    when = f" at {exposure.evidence_at}" if exposure.evidence_at else ""
    return f"{_EXPOSURE_LINES[exposure.evidence]}{when}"


def _lesson_paths_for(lesson_name: Any) -> list[str]:
    """The repo-relative paths a runtime lesson row's `lesson_name` could name, in stable order.

    The inverse of `hooks.record_lesson_load.lesson_name` (which records the stem of
    `defender/<corpus>/<stem>.md`) over `RUNTIME_LESSON_CORPORA`. Empty for a name that is not
    a single path segment, which would build a path outside the corpus."""
    from defender.hooks.record_lesson_load import RUNTIME_LESSON_CORPORA

    if (not isinstance(lesson_name, str) or not lesson_name
            or lesson_name != Path(lesson_name).name or lesson_name in (".", "..")):
        return []
    return [f"defender/{corpus}/{lesson_name}.md"
            for corpus in sorted(RUNTIME_LESSON_CORPORA)]


def _read_provenance(world: Bound) -> dict[str, Any]:
    return json_mapping(world, WORLD_LEAVES.provenance) or {}


#: The only commit shape this pass will put in a `git show` argv. `provenance.json`'s `commit`
#: is attacker-reachable (box-writable tree), and a value starting with `-` would be parsed as
#: an option (e.g. `--output=<file>`, a host-side write outside every box). Hex only.
_COMMIT_RE = re.compile(r"\A[0-9a-fA-F]{7,40}\Z")


def _usable_commit(commit: Any) -> str | None:
    """`commit` when it is an abbreviated-or-full object name, else `None` (rendered as "no
    commit is recorded")."""
    return commit if isinstance(commit, str) and _COMMIT_RE.match(commit) else None


__all__ = ["JudgeInput", "episode_alert", "render", "sibling_union"]
