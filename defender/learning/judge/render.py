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
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths, artifact_dir, artifact_file
from defender.learning.lead_repository import JoinedLead, joined
from defender.learning.branch.archive import (
    ALERT_NAME,
    GATHER_SUMMARIES_DIRNAME,
    LESSONS_LOADED_NAME,
)
from defender.learning.judge._errors import JudgeRefused
from defender._report import read_report
from defender.learning.judge.family import (
    WorldFacts,
    _own_h_rows,
    _staged_patterns,
    _world_pattern,
    _world_review_block,
    _raw_manifest,
    discriminator_of,
    episode_id_of,
    names_one_file,
    read_review_record,
    read_samples_record,
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
    #: #1007 M4/O5: the questioner's own sample for this world's staged pattern, and this
    #: world's own reachability block off `review.yaml` — never a sibling's (S6).
    sample_text: str = ""
    review_text: str = ""

    #: The operator's `JUDGE_PAYLOAD_CAP`, or `None`. Held on the input rather than applied
    #: during assembly because what it must bound is the BYTES THAT REACH THE PROMPT.
    payload_cap: int | None = None

    def as_prompt_sections(self) -> dict[str, str]:
        """Each view as the text that goes inside its frame, the SET of them under the cap.

        THE CAP IS CHARGED OVER THE WHOLE SET, not per section. It first bounded one file — a
        lead's `gather_summaries/<lead>.md` — while the leads view embedded every executed
        query's whole row for that lead (the `document_rows` dump #1017 removed — the view now
        names `params` and the payload digests and nothing else of the row), `_render_lessons`
        embedded each lesson's whole body at its recorded commit, and the document and report
        were whole files. Charging it per section instead
        fixed that and introduced its own version of it: eight sections each at the cap is eight
        times the bound, and the knob still reported success. What the operator is bounding is
        the bytes that reach the model, so that is the quantity measured."""
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
    """Was the sibling walk never actually made? ONE predicate, because three views ask it and
    the answer must be the same in all of them: an unattempted union is not "no sibling exists",
    and only a walk that RAN over a real directory may render that sentence."""
    return bool(union_notes.get("runs_base_unset") or union_notes.get("runs_base_missing")
                or union_notes.get("alert_unidentified"))


def _union_empty_after_a_walk(union_notes: dict[str, Any]) -> bool:
    """May a view say "this is a first-run alert" — i.e. did a walk RUN and find nothing, with
    nothing dropped on the way?

    THE EXCLUSIONS COUNT TOO, not just whether the walk happened. An episode branched from a
    source run that lives under the operator's runs base excludes that run by name — so the
    alert has demonstrably been tried before, and the very next line of the view says so. The
    sentence and its own footnote contradicted each other on every ordinary branched episode.
    The same holds for a trial skipped as unreadable or unclosed: something WAS found and
    dropped, which is not "no sibling trial is recorded"."""
    return not (_union_unattempted(union_notes)
                or union_notes.get("source_run_excluded")
                or union_notes.get("skipped_unreadable")
                or union_notes.get("skipped_unclosed"))


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
    if union_notes.get("runs_base_missing"):
        out.append("(the runs base named for this pass is not a directory, so the sibling "
                   "union was never attempted — this is not a statement that no sibling "
                   "trial exists)")
    if union_notes.get("alert_unidentified"):
        out.append("(this episode's own alert.json carries no alert id, so the sibling union "
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
        if entry.get("body") is not None:
            lines.append(f"### {name}\n{entry['body']}")
        else:
            lines.append(f"### {name}\n{entry.get('note')}")
        # `is not False`, not truthiness. `dirty` is three-valued and `None` means the tree was
        # never measured, which is not a clean bill of health — the caveat belongs on that world
        # too, saying which of the two it is.
        if entry.get("dirty") is not False:
            lines.append(
                ("(caveat: this sibling's tree was DIRTY when it ran"
                 if entry.get("dirty") else
                 "(caveat: whether this sibling's tree was dirty was never measured")
                + ", so the checkout at its recorded commit may not be the tree it actually "
                  "ran against)")
    return "\n\n".join(lines) + "\n"


def _render_spread(spread: list[dict[str, Any]], union_notes: dict[str, Any]) -> str:
    """The spread's own row shape — `disposition` and `count`, NOT the sibling view's
    `run_id`/`disposition`. The spread is the tally ACROSS the siblings, so the count is the
    only thing it carries that the sibling list does not; rendering it with the sibling
    formatter printed a `None` run id per line and dropped every count.

    THE THIRD VIEW THAT ASKS `_union_unattempted` — its docstring says three do and only two
    did. The spread is derived from the same union the siblings view renders, so an empty
    spread meant "nobody looked" exactly as often as it meant "nothing is there", and the flat
    sentence below stated the absence as a fact in the same prompt whose siblings view said the
    walk was never attempted. Two contradictory statements about one fact is worse than the
    unstated absence C11 measured."""
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


def _leads_by_id(world_dir: Path) -> dict[str, JoinedLead]:
    """The world's leads off the CANONICAL surface — `lead_repository.joined` over the archived
    world dir, which has the run-dir shape it reads (C10) — indexed by lead id, in ONE parse.

    Called once per world rather than once per lead: the per-lead chain used to re-read and
    re-parse `executed_queries.jsonl` inside its own comprehension, so a world with N leads
    parsed the same table N times.

    THE SURFACE'S READING WINS (#1017 D3/N8). This module used to keep a private grouping of
    the raw rows — its own sentinel filter, its own `lead_id` check, file order for seq order,
    a raw `params` of whatever shape the row held — which is the second-reader drift
    `lead_repository` exists to end. `JoinedLead.queries` is already the sentinel-split set
    (the same `is_reserved_query_id` this module re-implemented: a `∅.`-prefixed row records
    the lead's CONDUCT — a repeat the guard refused, a call the argument schema turned back —
    and nothing it describes reached a system of record, so shown as an issued query it is a
    defender failure invented out of a call the defender was refused), seq-ordered, with the
    surface's coercions; `JoinedLead.goal` is the lead file's goal, read once for the world.

    THE LINK-REFUSING GATE STAYS AHEAD OF THE SURFACE. `artifact_file` on the table is the same
    `lstat` posture `archive.py` applies when it WRITES these names, whereas the surface's
    reader (`read_jsonl_rows_report`) follows a link. A link admitted here puts another tree's
    rows into VIEW 1 as this world's own conduct, so a world whose table is not a regular file
    renders every lead with no queries at all."""
    if not artifact_file(RunPaths(world_dir).executed_queries):
        return {}
    return {lead.lead_id: lead for lead in joined(world_dir)}


def _lead_chain(world_dir: Path, lead_id: str, resolutions_by_lead: dict[str, list[dict]],
                *, leads_by_id: dict[str, JoinedLead]) -> dict[str, Any]:
    """One lead's chain for VIEW 1: goal -> params -> payload -> summary -> resolutions.

    EVERY LINK IS NAMED FROM A `QueryRow` FIELD; no row object is stringified (#1017 D3/O3).
    The chain used to carry the lead's raw rows whole under `document_rows`, which put every
    column of every executed query — `payload_sha256`, `payload_path`, `raw_command`,
    `exit_code`, `error_class`, and since #871 `system_key` — into the prompt as bytes the
    judge cannot act on, charged against the operator's payload cap ahead of the evidence the
    cap exists to keep."""
    # THE ID IS MODEL-AUTHORED and this is where it becomes a path. `names_one_file` refuses a
    # token that would read outside the graded world — a `[../../c/report ...]` resolution row
    # otherwise put a counterfactual sibling's whole `report.md` into this world's own prompt,
    # under `- summary:`, as a fact about the world being graded (O5/J14). The surface is keyed
    # by the ids the world's OWN files and rows carry, so a token like that names no lead there.
    safe = names_one_file(lead_id)
    lead = leads_by_id.get(lead_id)
    goal = lead.goal if lead is not None else None
    queries = lead.queries if lead is not None else []
    params = queries[0].params if queries else None
    summary_path = world_dir / GATHER_SUMMARIES_DIRNAME / f"{lead_id}.md"
    summary = None
    if not safe:
        summary = ("(this lead id does not name a file inside this world, so no gather summary "
                   "was read for it)")
    elif artifact_file(summary_path):
        # `errors="replace"`, not a bare read. This is MODEL-WRITTEN text in a tree the box can
        # write, so an undecodable byte in it is an ordinary thing to meet; raising here would
        # be an unreadable summary costing the whole episode its grade, and the substitution
        # character is exactly what the judge should be shown of a byte nobody can read.
        summary = summary_path.read_text(encoding="utf-8", errors="replace")
    return {
        "goal": goal, "params": params, "payload": [q.payload_digest for q in queries],
        "summary": summary,
        "resolutions": resolutions_by_lead.get(lead_id, []),
    }


def json_mapping(path: Path) -> dict[str, Any] | None:
    """One JSON artifact as a mapping, or `None` when it is not readable as one.

    ONE HOME for the tolerance policy — which exception classes are survivable and whether a
    non-mapping counts as unreadable — because five readers in this package want the same
    answer (`alert.json` twice, `provenance.json`, a lead's `.lead.json`, and the enqueue's own
    episode alert). Spelled per site, a class that has to be added later (a `RecursionError` out
    of a deeply nested document is neither `OSError` nor `ValueError`) has to be found five
    times, and the sites are far enough apart that only a grep finds them."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _sibling_row(
    entry: Path, *, alert_id: str | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """One directory under the operator's runs base, CLASSIFIED EXHAUSTIVELY.

    `(row, None)` — a finished trial of this alert. `(None, key)` — a trial of this alert that
    was skipped, and `key` names the count in `union_notes` that says so in the view. `(None,
    None)` — not a trial of this alert at all, and so not a skip either.

    THE THIRD ANSWER IS THE POINT. `skipped_unreadable` renders as "N further trial(s) OF THIS
    ALERT could not be read", and a directory under the runs base with no `alert.json` — a
    half-created run dir, a scratch directory, a lock — is not a trial of this alert. Counted as
    one it told the model N unreadable siblings exist when none do, in the one view whose whole
    purpose is to keep an absence from being invented (C11).

    `report.md` goes THROUGH `read_report`, like every other reader of a report in this repo. It
    parses the frontmatter the close gate writes, answers the vocabulary through
    `normalized_disposition`, and — the part that matters at THIS call site — NEVER RAISES: a
    bare `read_text` here made one undecodable byte in one unrelated run under the operator's
    runs base refuse the whole grade of an episode whose own archive reads perfectly."""
    alert_path = entry / ALERT_NAME
    if not artifact_file(alert_path):
        return None, None
    alert_doc = json_mapping(alert_path)
    if alert_doc is None:
        return None, "skipped_unreadable"
    if alert_doc.get("alert_id") != alert_id:
        return None, None
    report_path = entry / "report.md"
    if not artifact_file(report_path):
        return None, "skipped_unclosed"
    read = read_report(report_path)
    if not read.text:
        return None, "skipped_unreadable"
    return {"run_id": entry.name, "disposition": read.disposition}, None


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
        "runs_base_unset": runs_base is None, "runs_base_missing": False,
        "alert_unidentified": alert_id is None,
    }
    if runs_base is None:
        return [], notes
    siblings: list[dict[str, Any]] = []
    runs_base = Path(runs_base)
    if alert_id is None:
        # NOTHING TO MATCH ON IS NOT "EVERYTHING MATCHES". `_sibling_row` selects with
        # `alert_doc.get("alert_id") != alert_id`, and a graded world whose own `alert.json` is
        # present but carries no `alert_id` (only `is_file()` is required of it) makes that
        # `None != None` — FALSE for every unrelated run under the operator's runs base whose
        # own `alert.json` also lacks the key. The union then handed the model other alerts'
        # closes as prior trials of THIS one, and the spread tallied them. Refused here rather
        # than in `_sibling_row` so the reason lands on the notes and is rendered (C11): nobody
        # could look, which is not the same fact as "no sibling trial exists".
        return siblings, notes
    if not runs_base.is_dir():  # lint-tree-read-follows-link: ok — the operator's OWN configured root, not an entry inside a box-writable tree; `defender/CLAUDE.md` documents the devcontainer pointing this knob at a path that may itself be a link, and refusing that would refuse every union
        # NAMED, not folded into the empty union. `run_common.resolve_runs_base()` returns
        # whatever `DEFENDER_RUNS_BASE` says (or its compiled default) and never checks that the
        # directory exists — `defender/CLAUDE.md` documents the devcontainer having to override
        # that knob — so a typo or an unset knob left the walk unattempted and the prompt then
        # asserted "This is a first-run alert: no sibling trial is recorded". That is the same
        # unstated absence `runs_base_unset` exists for, one step further along: nobody looked,
        # and the views must say so rather than state the absence as a fact (C11).
        notes["runs_base_missing"] = True
        return siblings, notes
    for entry in sorted(runs_base.iterdir(), key=lambda p: p.name):
        # Each ENTRY under that root is a run dir — a box's rw bind — so it is judged by `lstat`
        # even though the root above is the operator's own.
        if not artifact_dir(entry):
            continue
        if source_run_id is not None and entry.name == source_run_id:
            notes["source_run_excluded"] = entry.name
            continue
        row, skipped = _sibling_row(entry, alert_id=alert_id)
        if row is not None:
            siblings.append(row)
        elif skipped is not None:
            notes[skipped] += 1
    return siblings, notes


def _world_alert_id(world_dir: Path) -> str | None:
    data = json_mapping(world_dir / ALERT_NAME)
    return data.get("alert_id") if data is not None else None


def episode_alert(episode_dir: Path, labels: list[str]) -> dict[str, Any]:
    """The alert this episode's worlds all investigate, off the first world that names one.

    ONE RULE, because two readers want this file and they must not pick different worlds. The
    sibling union keys on the first world whose `alert.json` carries an `alert_id`; the queue
    row's `alert_rule_key` used to be derived from the first whose `alert.json` merely PARSED —
    so a family whose world b has an unkeyed alert and whose world c has a keyed one keyed the
    union on c's alert while every row landed under a rule key derived from b's document. The
    fallback (first that parses) is kept for a family where no world names an id at all, which
    is a different fact from "no world has an alert".
    """
    fallback: dict[str, Any] = {}
    for label in labels:
        data = json_mapping(Path(episode_dir) / "worlds" / label / ALERT_NAME)
        if data is None:
            continue
        if data.get("alert_id") is not None:
            return data
        if not fallback:
            fallback = data
    return fallback


def _render_sample(pattern: str, samples_doc: dict[str, Any]) -> str:
    """#1007 M4/O5: the questioner's own reference document for THIS world's staged pattern —
    the same bytes `samples.yaml` holds under `pattern`, dumped as JSON so the prompt carries
    exactly one canonical rendering of it (`test_the_judges_sample_is_byte_identical_to_the_
    questioners_within_one_attempt` re-parses whatever JSON object appears here and compares it
    canonically to the stored document — never a substring match, which a re-ordered or
    re-quoted YAML dump would fail).

    `pattern not in samples_doc` and `samples_doc[pattern] is None` render IDENTICALLY — both
    are "nothing to compare against" — which is the SAME predicate `family._grade_world`
    computes independently for `sample_unavailable` over the same file (`.get(pattern) is
    None`); this is that fact's own rendering, not a second derivation of it (H2's `family.py`
    owns the flag on the row, this owns the prompt's own sentence)."""
    document = samples_doc.get(pattern)
    if document is None:
        return f"no sample was captured for {pattern!r}\n"
    # `default=str`, the guard the questioner's own renderer of these same documents carries
    # (`branch/questioner/_corpus_section`). `samples.yaml` is read PERMISSIVELY on purpose —
    # `_default_samples_reader`'s contract is that a damaged file costs the shape-invention
    # claims their evidence and NEVER the whole grade — and a bare `json.dumps` over a value
    # `safe_load` typed as `date`/`set`/`bytes` raises `TypeError` out of `render`, a class
    # `grade_episode`'s conversion set does not name.
    #
    # AND THE DUMP ITSELF IS INSIDE THE ENVELOPE, because `default=` is never consulted for a
    # dict KEY: `{2024-01-01: ...}` still raises `TypeError: keys must be str, int, float,
    # bool or None`, and `sort_keys=True` over mixed key types raises before any conversion is
    # attempted. Both shapes are ordinary `safe_load` output from a file this reader promises
    # cannot cost more than its own claims, so an unrenderable document says so here rather
    # than escaping `render` (past `_prepare_world_prompt`'s `(JudgeRefused, OSError,
    # ValueError, TimeoutError)` arm and `grade_episode`'s conversion set alike) as a bare
    # traceback with every world's model calls already paid for.
    try:
        return json.dumps(document, sort_keys=True, indent=2, default=str) + "\n"
    except (TypeError, ValueError):
        return f"the sample recorded for {pattern!r} could not be rendered\n"


def _render_samples(patterns: list[str], samples_doc: dict[str, Any]) -> str:
    """EVERY staged pattern's own sample, one `_render_sample` block per pattern — O5's own
    domain ("per staged pattern"), never reduced to the world's single representative one.

    A world staging into two staged patterns and shown a sample for only one is O5's own
    falsifier: this function is what closes it on the RENDER side (`family._grade_world`'s
    `sample_unavailable_patterns` closes the corresponding fact side). A single-pattern world
    (every fixture in this suite until `test_a_two_pattern_world_...`) renders identically to
    the single-block output `_render_sample` alone produced before this existed — one header,
    one document — so no existing byte-identity assertion moves."""
    if not patterns:
        return "no pattern is staged for this world\n"
    return "\n".join(
        f"pattern {p!r}:\n{_render_sample(p, samples_doc)}" for p in patterns)


def _render_review_block(block: dict[str, Any] | None) -> str:
    """This world's OWN reachability block off `review.yaml` (M1/M3) — never a sibling's, and
    never the review record whole (S6 forbids a sibling's overlay reaching this prompt, and the
    review record carries no overlay itself, but rendering it whole would still carry every
    OTHER world's own measurements where this world's judge has no business reading them)."""
    if not isinstance(block, dict):
        return "No reachability block is recorded for this world.\n"
    lines = [
        f"capture_addressed: {block.get('capture_addressed')!r}",
        f"capture_reasks_faulted: {block.get('capture_reasks_faulted')!r}",
        f"reachable_by_capture: {block.get('reachable_by_capture')!r}",
        f"injected_retrieved: {block.get('injected_retrieved')!r}",
        f"injected_present: {block.get('injected_present')!r}",
        # H2/G-1, KNOWINGLY: `envelope_failed` is `str(AdapterFault.detail)` verbatim
        # (`review.py`), which can carry the `wv-<world>-<stem>` staged-view naming scheme. The
        # frame below stops this text being read as instruction; it does not redact the names.
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


def render(  # noqa: C901, PLR0913, PLR0915 — one assembly of the four joined views (O4) plus #1007's sample/review pair; each view is already its own helper, this is the join, and the keyword tail is the per-pass hand-over (facts/union/manifest/review/samples) that keeps this from re-reading what the caller has already read
    episode_dir: Path, world_label: str, runs_base: Path | None = None, *,
    git_show: Any = None, lessons_commit: str | None = None, payload_cap: int | None = None,
    facts: WorldFacts | None = None, review: dict[str, Any] | None = None,
    samples: dict[str, Any] | None = None,
    union: tuple[list[dict[str, Any]], dict[str, Any]] | None = None,
    manifest: dict[str, Any] | None = None,
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
    # THE PASS'S OWN PARSE, when the caller has one. `family.yaml` was read and YAML-parsed here
    # once per world on top of the orchestration's read and `grade_family`'s, so a two-world
    # episode parsed one file four times — and, since the episode dir is a tree a box can reach,
    # with no guarantee the four documents agreed. `facts=` and `union=` already exist for
    # exactly this hand-over; the manifest simply was not put through it.
    doc = manifest if manifest is not None else _raw_manifest(episode_dir)
    episode_token = episode_token_for(episode_id_of(doc))
    world_dir = episode_dir / "worlds" / world_label
    world_entry = _world_entry(doc, world_label)  # validates the graded world is actually declared
    show = git_show if git_show is not None else _git_show_default
    record = facts if facts is not None else read_world_facts(
        episode_dir, world_label, episode_token=episode_token)

    text = record.investigation_text
    resolutions_by_lead = record.resolutions_by_lead
    lead_ids = set(record.referenced_leads)
    summaries_dir = world_dir / GATHER_SUMMARIES_DIRNAME
    if artifact_dir(summaries_dir):
        lead_ids |= {p.stem for p in summaries_dir.glob("*.md")}

    # The report's BYTES for the prompt, off the same read the mechanical pass made.
    report_text = record.report.text

    # NORMALIZED ONCE, and the same way `family._holding_system` normalizes it — `raw.strip()
    # .casefold()`, which is the spelling every per-world fact keys on. Taken RAW for the
    # patch-only pattern fallback below while the ledger filter took it FOLDED, a manifest that
    # merely capitalised the system name made the prompt render one spelling of the pattern
    # while that world's row — its `sample_unavailable_patterns`, and its mechanical finding —
    # carried the folded one. Samples are matched by exact string on purpose, and
    # `cites_sample` compares a citation's fragment the same way, so A1(b) stopped refusing the
    # very citation the prompt had told the model to copy verbatim.
    raw_holding_system = discriminator_of(doc).get("holding_system")
    resolved_holding_system = (
        raw_holding_system.strip().casefold()
        if isinstance(raw_holding_system, str) else "")
    h_rows = _own_h_rows(record.ledger_rows, resolved_holding_system) \
        if isinstance(raw_holding_system, str) else []

    # #1007 M4/O5: this world's own sample(s) and its own reachability block — off the SAME
    # `_staged_patterns`/`_world_pattern` and `_world_review_block` helpers `family._grade_world`
    # uses, so the prompt names the same pattern(s) and the same block the mechanical row was
    # computed from. EVERY staged pattern, never just one (O5's own falsifier) — the patch-only
    # fallback (`_world_pattern`'s single holding-system name) stays for a world with no
    # staged pattern to enumerate.
    overlay = world_entry.get("overlay")
    staged_patterns = _staged_patterns(overlay) or [
        _world_pattern(overlay, holding_system=resolved_holding_system)]
    # THE PASS'S OWN PARSES, when the caller has them — the same hand-over `manifest`/`facts`/
    # `union` already take, and for the reason `read_review_record`'s own docstring gives ("the
    # episode dir is a tree a box can reach — two independent parses had no guarantee of
    # agreeing"). `render` runs once per graded world, so reading these here made 2N further
    # parses of two box-reachable files the pass had already read, and let the mechanical row
    # and the prompt section that claims to render it come off different documents.
    samples_doc = read_samples_record(episode_dir) if samples is None else samples
    sample_text = _render_samples(staged_patterns, samples_doc)
    review_doc = read_review_record(episode_dir) if review is None else review
    review_block = _world_review_block(review_doc, world_label)
    review_text = _render_review_block(review_block)
    coverage = []
    for row in h_rows:
        params = scope_params(row)
        coverage.append({
            "system": row.get("system"), "verb": row.get("verb"), "source": row.get("source"),
            "window": params.get("window"), "scope_key": params.get("scope_key"),
            "index": params.get("index"),
        })

    provenance = _read_provenance(world_dir)
    commit = _usable_commit(
        lessons_commit if lessons_commit is not None else provenance.get("commit"))
    # THREE-VALUED, and the third value is not `False`. `RunProvenance.dirty` is `None` when the
    # tree could not be measured at all — its own docstring calls collapsing that onto "clean"
    # the one error a provenance record must not make — so `bool(...)` suppressed the caveat for
    # exactly the world whose checkout is least certain to be the tree it ran against.
    dirty = provenance.get("dirty")
    lessons_loaded = read_jsonl_rows(world_dir / LESSONS_LOADED_NAME) \
        if artifact_file(world_dir / LESSONS_LOADED_NAME) else []
    lessons: list[dict[str, Any]] = []
    for entry in lessons_loaded:
        name = entry.get("lesson_name")
        # DERIVED FROM THE NAME WHEN THE ROW CARRIES NO PATH, which on a real sibling is always.
        # `lessons_loaded.jsonl` has exactly one production writer — `runtime/tools/_deps.
        # _record_lesson_load` — and it writes `{lesson_name, ts}`: no `path` column exists. Read
        # as an absent path, EVERY lesson of EVERY real archived world rendered as "unavailable:
        # no path is recorded", so VIEW 4 shipped with no bodies at all and the whole `git_show`
        # /`lessons_commit` seam below was dead in production while green against fixtures that
        # synthesise the column. The name IS the path: `hooks/record_lesson_load.lesson_name`
        # returns `p.stem` of `defender/<corpus>/<name>.md`, and the runtime corpus is one
        # directory (`RUNTIME_LESSON_CORPORA`), so the row's own name resolves it.
        recorded = entry.get("path")
        candidates = [recorded] if isinstance(recorded, str) else _lesson_paths_for(name)
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

    leads_by_id = _leads_by_id(world_dir)
    leads = {lid: _lead_chain(world_dir, lid, resolutions_by_lead, leads_by_id=leads_by_id)
             for lid in sorted(lead_ids)}

    manifest_text = _manifest_text(doc, world_label)

    # A COPY, because `union_notes` belongs to the PASS and the note below belongs to the
    # WORLD. The union is computed once and threaded to every world (J9), so writing a per-world
    # note into it left world c's "no row was ever recorded on the holding system for this
    # world" standing in world b's coverage view — above the row world b had in fact recorded.
    # That is the exact fact the lead-set and lead-quality buckets turn on.
    union_notes = dict(union_notes)
    if not _union_empty_after_a_walk(union_notes):
        # NOT "this is a first-run alert". Either nobody looked, or something WAS found and
        # dropped (the source run this episode branched from, an unreadable or unclosed trial)
        # — both different facts from "no sibling exists", and the siblings view says which in
        # the same prompt, so asserting the absence here would hand the model two contradictory
        # statements about one fact. The same predicate the siblings and spread views use, so
        # the three cannot disagree about whether the sentence may be said at all.
        if not coverage:
            union_notes["coverage_note"] = (
                "no row on the holding system is recorded for this world")
    elif not siblings:
        # THE COVERAGE VIEW IS WHERE THE EMPTY UNION IS STATED, and that is the committed spec's
        # own demand (`test_921_first_run_alert_coverage_view_states_the_empty_union`): an
        # unstated absence is what a model fills in (C11), and this note is the first thing the
        # prompt says about the union, above the coverage rows.
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


def _lesson_paths_for(lesson_name: Any) -> list[str]:
    """The repo-relative paths a runtime lesson row's `lesson_name` could name, in a stable
    order — the candidates to read a body at, empty when the name cannot become one.

    THE WRITER'S OWN INVERSE. `hooks.record_lesson_load.lesson_name` accepts
    `defender/<corpus>/<stem>.md` for a corpus in the set it is handed and returns the STEM;
    the runtime readers hand it `RUNTIME_LESSON_CORPORA`. So the stem plus that set IS the path,
    and this is the inverse of the writer rather than a second spelling of the repo layout —
    a corpus added there becomes a candidate here with no edit.

    Empty for a name that is not a single path segment: the row is model-adjacent text, and a
    name carrying a separator would build a path outside the corpus."""
    from defender.hooks.record_lesson_load import RUNTIME_LESSON_CORPORA

    if (not isinstance(lesson_name, str) or not lesson_name
            or lesson_name != Path(lesson_name).name or lesson_name in (".", "..")):
        return []
    return [f"defender/{corpus}/{lesson_name}.md"
            for corpus in sorted(RUNTIME_LESSON_CORPORA)]


def _read_provenance(world_dir: Path) -> dict[str, Any]:
    return json_mapping(world_dir / "provenance.json") or {}


#: A commit this pass will spend in a subprocess argv. Nothing else is: `provenance.json` lives
#: in the archived world dir, copied out of a tree the box has an rw bind on and screened only
#: for being a regular FILE, so its `commit` is attacker-reachable text — and the sanctioned
#: `_git.git_show_file` facade spends it as the single argv element `f"{rev}:{path}"`. A value
#: beginning with `-` is then read as an OPTION rather than a revision (`--output=<file>` is one
#: the command accepts), which turns a rendered prompt into a host-side write at a path the
#: archive chose, in the LAUNCHER's own process and outside every box. It is also never
#: type-checked upstream (`json_mapping` hands back whatever the JSON holds, and this frame's
#: own fallback does not coerce), so a non-string reached the same interpolation. An object-name
#: grammar is the whole fix: a resolvable object name is hex, and nothing else may reach an argv.
_COMMIT_RE = re.compile(r"\A[0-9a-fA-F]{7,40}\Z")


def _usable_commit(commit: Any) -> str | None:
    """`commit` when it is an abbreviated-or-full object name, `None` otherwise — see
    `_COMMIT_RE`. `None` renders as the lessons view's own "no commit is recorded" note, which
    is the honest answer for a stamp this pass will not spend."""
    return commit if isinstance(commit, str) and _COMMIT_RE.match(commit) else None


__all__ = ["JudgeInput", "episode_alert", "json_mapping", "render", "sibling_union"]
