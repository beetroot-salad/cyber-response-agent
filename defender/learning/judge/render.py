"""The judge's input (design M2): the computed context of one judged world — every run's
header, contrast row and joined call list, the fact surfaces and aligned lead rows, the judged
world's own views, the noise and the questioner inputs — derived on read (`JudgeContext`).
`layout` turns it into the prompt's sections.

The views over the judged world were ported from
`experiments/judge-context-921/variants/contexts.py::render_proposed`, the measured arm. Reads
only `episode_dir` and the checkout at the sibling's recorded commit — never a sibling's own run
dir, which may be gone, and never the tenant's runs: the judge reads only the episode it is
handed (#1105 J3 removed the same-alert sibling union and its spread).

A reference run's facts appear only in that run's own labelled blocks (M3); the lessons view
shows the judged world's own lessons alone. Every model-bound text the host did not author
arrives inside an untrusted frame (M26, A10: `RunText`).
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Annotated, Any

from pydantic import SkipValidation

import contextlib

from defender.records import _alert_input
from defender._io import Bound, bind
from defender.episodes._episode_paths import LAYOUT, WORLD_LEAVES, OracleStorePaths
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
    has_refusals,
    _repository_leads,
    lead_chain,
    render_refused,
    read_manifest,
    read_samples_record,
    read_world_facts,
    summary_lead_ids,
)
from defender.learning.branch.ledger import ORACLE, REAL_ERROR
from defender.learning.judge.calls import (
    CALL_ID,
    is_blocked_ledger_row,
    is_blocked_table_row,
    is_inherited,
    ledger_partner,
)
from defender.learning.judge.runs import RunSet, read_run_set
from defender.run_common import REPO_ROOT
from defender.runtime.branch._family import episode_token_for

#: The frame tag every model-authored body in the judge's prompt is wrapped in — the
#: questioner's spelling, so one frame regex matches both.
UNTRUSTED_TAG = "untrusted"


@dataclasses.dataclass(frozen=True)
class RunText:
    """Run- or manifest-derived text that a host-built row embeds: framed in place, inside its
    own untrusted frame, wherever the prompt shows it (A10). Host text beside it is a plain
    `str`."""

    text: str


def _git_show_default(cwd: Path, rev: str, path: str) -> str | None:
    from defender._git import git_show_file

    return git_show_file(cwd, rev, path)


@model
class JudgeInput:
    """The judged world's own views for one (world, pass) — its leads, lessons, documents,
    samples and built layer (section 6 beside the call list and answers its `RunView` holds).
    Never stored — derived fresh on every `render()` call from the archive and the checkout."""

    world_label: str
    discriminator: dict[str, Any]
    leads: dict[str, dict[str, Any]] = field(default_factory=dict)
    lessons: list[dict[str, Any]] = field(default_factory=list)
    document_text: str = ""
    report_text: str = ""
    #: The per-system samples record, one section per system (O16).
    samples_text: str = ""
    #: Served system -> where its section of real answers ends in `samples_text`: a system is
    #: shown exactly when the prompt carries `samples_text` up to there (A9 may cut the view).
    samples_ends: dict[str, int] = field(default_factory=dict)
    #: The judged world's frozen telemetry and every collision of a frozen row's identifier
    #: with this world's real data (M12=A), off its oracle-side store.
    oracle_text: str = ""


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


def _json(value: Any) -> str:
    """One value as compact canonical JSON; `default=str` so a YAML-typed value never raises."""
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(value)


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


def _world_entry(doc: dict[str, Any], label: str) -> dict[str, Any]:
    for world in doc.get("worlds") or ():
        if isinstance(world, dict) and world.get("world_id") == label:
            return world
    raise JudgeRefused(f"the manifest declares no world {label!r}")


def episode_record(bound: Bound) -> _alert_input.AlertRecord | None:
    """The record of the alert this episode's worlds all investigate: the copy launch put in the
    episode (A1), or `None` when there is none or it is not one.

    Shared by the sibling union and the enqueue's rule key, so both key on the same record."""
    read = bound.read(LAYOUT.source_record)
    return _alert_input.parse_alert_record(read.text) if read.text else None


def episode_alert(bound: Bound) -> dict[str, Any]:
    """The alert document the episode's copy holds, for display; `{}` when there is none, it is
    not one JSON object, or its bytes are not the record's digest."""
    return _alert_input.verified_document(
        bound, LAYOUT.source_alert, LAYOUT.source_record) or {}


def _render_samples(samples_doc: dict[str, Any], served: list[str]) -> tuple[str, dict[str, int]]:
    """The samples record per system (O16): each system's real example answers under its own
    name, per verb, and a system whose section is unavailable shown with its reason. A served
    system the record has no section for is named as such. Returns the text and, for each
    served system with a section of real answers, the offset its section ends at."""
    text = ""
    ends: dict[str, int] = {}
    served_set = set(served)
    for system in sorted({*map(str, samples_doc), *served}):
        section = samples_doc.get(system)
        if isinstance(section, dict) and isinstance(section.get("verbs"), dict):
            lines = [f"system {system}:"]
            for verb, answers in sorted(section["verbs"].items(), key=lambda kv: str(kv[0])):
                lines.append(f"  verb {verb}:")
                for answer in answers if isinstance(answers, list) else [answers]:
                    lines.append(f"    {answer if isinstance(answer, str) else _json(answer)}")
            text += "\n".join(lines) + "\n"
            if system in served_set:
                ends[system] = len(text)
        elif isinstance(section, dict) and "unavailable" in section:
            text += f"system {system}: unavailable — {section.get('unavailable')}\n"
        else:
            text += f"system {system}: no samples section is recorded\n"
    return (text, ends) if text else ("No samples record is archived.\n", {})


def render_oracle_store(bound: Bound, label: str) -> str:
    """The judged world's oracle-side record as the judge reads it (its built layer): every
    frozen forged row (the telemetry its facts were served through), every collision of a
    frozen row's identifier with this world's real data (M12=A — the row stayed frozen and was
    still served), and pre-flight's calibration result — the facts it recorded and its
    `preflight` rows of the oracle-side ledger."""
    paths = OracleStorePaths(Path(LAYOUT.oracle_dir(label)))
    forged, _bad, _rec = bound.read_jsonl(paths.forged.as_posix())
    collisions, _bad, _rec = bound.read_jsonl(paths.collisions.as_posix())
    lines = ["frozen telemetry (forged rows this world serves):" if forged
             else "No forged row was frozen in this world."]
    lines += [f"- {row.get('forged_id')} for fact {row.get('fact_id')} on {row.get('system')}: "
              f"{_json(row.get('row'))}" for row in forged]
    if collisions:
        lines.append("identifier collisions (a frozen row's id that this world's real data "
                     "carries too; the frozen row stayed frozen and was still served):")
        for entry in collisions:
            lines.append(f"- frozen row {entry.get('forged_id')} column {entry.get('column')} "
                         f"= {entry.get('value')}; real row(s): {_json(entry.get('real_rows'))}")
    else:
        lines.append("No frozen row's identifier collided with this world's real data.")
    # Pre-flight's calibration result (`registry.calibrate_one`): the facts it recorded, and
    # its replay, logged as `preflight` rows of the oracle-side ledger.
    recorded, _bad, _rec = bound.read_jsonl(paths.facts.as_posix())
    ledger, _bad, _rec = bound.read_jsonl(paths.ledger.as_posix())
    replayed = [row for row in ledger if row.get("actor") == "preflight"]
    lines.append("pre-flight's calibration — the facts it recorded:" if recorded
                 else "Pre-flight's calibration recorded no fact for this world.")
    lines += [f"- {_json(row)}" for row in recorded]
    lines.append("pre-flight's calibration replay (its rows of the oracle-side ledger):"
                 if replayed else "No pre-flight replay is on this world's oracle-side ledger.")
    lines += [f"- {_json(row)}" for row in replayed]
    return "\n".join(lines) + "\n"


def family_status(bound: Bound) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    """Pre-flight's outcome record (`None` when there is none to read) and every world O5
    counts as failed (`outcome.failed_worlds`) — read once per pass and shared by every
    world's prompt."""
    from defender.learning.branch import outcome as outcome_mod

    try:
        record = outcome_mod.read_outcome(bound)
    except outcome_mod.OutcomeUnreadable:
        return None, outcome_mod.failed_worlds(bound, {})
    return record, outcome_mod.failed_worlds(bound, record)


#: A run label as the manifest grammar spells one: the only run-named text that may sit in
#: host text (A10). A label read anywhere else that is not of it is framed like run text.
_LABEL = re.compile(r"[a-z0-9_]+")


def _host_label(label: Any) -> Any:
    """`label` as host text when it is of the label grammar, else framed (`RunText`)."""
    return label if isinstance(label, str) and _LABEL.fullmatch(label) else RunText(str(label))


def _run_value(value: Any) -> RunText:
    """A run- or manifest-derived value framed in place: a string verbatim, anything else as
    canonical JSON."""
    return RunText(value if isinstance(value, str) else _json(value))


def _call_parts(call: Any) -> list[Any]:
    if not isinstance(call, dict):
        return ["(no call recorded)"]
    return ["system ", _run_value(call.get("system")), " verb ", _run_value(call.get("verb")),
            " params ", _run_value(call.get("params"))]


def render_family_text(record: dict[str, Any] | None,
                       failed: dict[str, dict[str, Any]]) -> list[Any]:
    """Pre-flight's record of the family and every failed world as an explicit entry (N22):
    each world that could not be judged by its label, its reason word and the investigator's
    call it failed on; the calls pre-flight could not replay; and the calls whose live answer
    drifted from the capture. Host text, every string the record holds framed in place
    (`RunText`, A10).

    A failed world's `detail` is never shown: it is the oracle's last refusal, which can quote
    the rows it forged for that world's facts, or the verifier's reasoning about them, and this
    text reaches every judged world's prompt, where only a reference run's own labelled section
    may hold its facts."""
    if record is None:
        parts: list[Any] = ["No pre-flight outcome record is readable for this episode.\n"]
    else:
        parts = ["pre-flight outcome: ", _run_value(record.get("outcome")), " — reason: ",
                 *([_run_value(record.get("reason"))] if record.get("reason") else
                   ["(no reason given)"]), "\n"]
    if failed:
        parts.append("worlds that could not be judged (each contributes no findings):\n")
        for label, entry in sorted(failed.items()):
            parts += ["- world ", _host_label(label), ": ",
                      *([_run_value(entry.get("reason"))] if entry.get("reason") else
                        ["(no reason recorded)"]),
                      "; call: ", *_call_parts(entry.get("call")), "\n"]
    else:
        parts.append("every world could be judged\n")
    for key, what in (("not_replayable", "calls pre-flight could not replay"),
                      ("drift", "calls whose live answer drifted from the capture")):
        entries = (record or {}).get(key) or []
        if not entries:
            parts.append(f"{what}: none\n")
            continue
        parts.append(f"{what}:\n")
        for entry in entries:
            extra = (entry.get("status") or entry.get("reason")) if isinstance(entry, dict) else None
            parts += ["- ", *_call_parts(entry),
                      *([" — ", _run_value(extra)] if extra else []), "\n"]
    return parts


def render(  # noqa: PLR0913 — the keyword tail is the per-pass hand-over that avoids re-reading what the caller has read
    episode_dir: Path, world_label: str, *,
    git_show: Any = None, lessons_commit: str | None = None, payload_cap: int | None = None,
    facts: WorldFacts | None = None, samples: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None, bound: Bound | None = None,
    family_text: list[Any] | None = None, runs: RunSet | None = None,
) -> JudgeContext:
    """The judge's computed context for one planted world (design M2, derived on read, P-b):
    the computed header, contrast table, fact surfaces and aligned lead rows of the focus and
    every reference run, the reference runs' compressed sections, the focus world's own views,
    the noise, and the questioner inputs (samples record, base story).

    `git_show` is the `(cwd, rev, path) -> str | None` seam for reading a lesson body at a
    recorded commit. `lessons_commit` overrides the per-world provenance read. `facts`,
    `manifest`, `samples`, `family_text`, `runs` and `bound` are the caller's already-read
    per-pass inputs; each is read or computed here only when not handed over.
    """
    episode_dir = Path(episode_dir)
    with (contextlib.nullcontext(bound) if bound is not None else bind(episode_dir)) as bound:
        doc = manifest if manifest is not None else read_manifest(bound)
        record, failed = family_status(bound)
        if runs is None:
            runs = read_run_set(bound, doc, episode_dir=episode_dir, failed=failed)
        if family_text is None:
            family_text = render_family_text(record, failed)
        samples_doc = read_samples_record(bound) if samples is None else samples
        focus = _render_bound_world(bound, episode_dir, world_label, git_show=git_show,
                                    lessons_commit=lessons_commit,
                                    facts=facts if facts is not None else runs.usable.get(
                                        world_label),
                                    samples=samples_doc, manifest=doc)
        labels = [world_label, *runs.references(world_label)]
        views = [run_view(doc, runs, label) for label in labels]
        surfaces = fact_surfaces(doc, runs, labels)
        return JudgeContext(
            world_label=world_label, run_views=views, fact_surfaces=surfaces, focus=focus,
            noise=family_text, aligned_rows=aligned_lead_rows(views, surfaces),
            samples=samples_doc, base_story=doc.get("base_story"), payload_cap=payload_cap)


def _render_bound_world(  # noqa: C901, PLR0913, PLR0915 — see `render`
    bound: Bound, episode_dir: Path, world_label: str, *,
    git_show: Any, lessons_commit: str | None,
    facts: WorldFacts | None, samples: dict[str, Any] | None,
    manifest: dict[str, Any] | None,
) -> JudgeInput:
    from defender.learning.judge.run import served_systems_of

    doc = manifest if manifest is not None else read_manifest(bound)
    episode_token = episode_token_for(episode_id_of(doc))
    _world_entry(doc, world_label)  # validates the judged world is actually declared
    show = git_show if git_show is not None else _git_show_default
    world = bound.under(LAYOUT.world(world_label).dir)
    # `leads_by_id` takes a path; gated as in the pass's own per-world read.
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

    samples_doc = read_samples_record(bound) if samples is None else samples
    samples_text, samples_ends = _render_samples(samples_doc, served_systems_of(doc))
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

    leads = {lid: lead_chain(world, lid, resolutions_by_lead, leads=by_id)
             for lid in sorted(lead_ids)}

    return JudgeInput(
        world_label=world_label,
        discriminator=discriminator_of(doc),
        leads=leads, lessons=lessons, document_text=text,
        report_text=report_text, samples_text=samples_text, samples_ends=samples_ends,
        oracle_text=render_oracle_store(bound, world_label),
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
    from defender.knowledge._knowledge import CHECKOUT_KNOWLEDGE, RUNTIME_LESSON_CORPORA

    if (not isinstance(lesson_name, str) or not lesson_name
            or lesson_name != Path(lesson_name).name or lesson_name in (".", "..")):
        return []
    return [f"{CHECKOUT_KNOWLEDGE.rel(corpus)}{lesson_name}.md"
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


# ------------------------------------------------------------------------------------------
# The computed context (design M2): every run's header, contrast row and call list, and the
# fact surfaces — derived on read from the archive, never stored (P-b).
# ------------------------------------------------------------------------------------------

#: The words every text-matched (not established) row of the context is labelled with.
HEURISTIC = "heuristic (text-matched, not established)"


def call_list(run: WorldFacts, *, j3: frozenset[str]) -> list[dict[str, Any]]:
    """One run's calls, joined by call id (A12): every query-table row in table order, numbered
    by its 0-based line index in the table (`call`, the numbering a `#<row>` pointer cites),
    with its ledger partner's decision (`source`, `None`: inherited or unserved) and whether it is a blocked call; then every UNMAPPED ledger row (an id no table
    row carries), `call` `None`.

    @owns call — the call numbering every contrast row, call list and blocked list reads."""
    out: list[dict[str, Any]] = []
    joined_ids: set[Any] = set()
    for n, row in enumerate(run.table_rows):
        partner = ledger_partner(row, run.ledger_rows, run.token)
        if partner is not None:
            joined_ids.add(partner.get(CALL_ID))
        out.append({"call": n, "source": None if partner is None else partner.get("source"),
                    "blocked": is_blocked_table_row(row, run.ledger_rows, run.token, j3=j3),
                    "inherited": is_inherited(row, run.token), "lead": row.get("lead_id"),
                    "system": row.get("system"), "verb": row.get("verb"),
                    "params": row.get("params"), "query_id": row.get("query_id")})
    for row in run.ledger_rows:
        if row.get(CALL_ID) in joined_ids:
            continue
        out.append({"call": None, "source": row.get("source"),
                    "blocked": is_blocked_ledger_row(row), "inherited": False, "lead": None,
                    "system": row.get("system"), "verb": row.get("verb"),
                    "params": row.get("params"), CALL_ID: row.get(CALL_ID)})
    return out


def contrast_row(calls: list[dict[str, Any]], run: WorldFacts) -> dict[str, Any]:
    """One run's contrast row (M2) off its joined call list: whether it was shown its facts
    (any `oracle` ledger row), its first altered call, the leads served altered answers, its
    calls counted by system/verb, its blocked, errored, unserved and unmapped calls, and the
    shared baseline (inherited rows)."""
    altered = [c for c in calls if c["source"] == ORACLE and c["call"] is not None]
    counts: dict[str, int] = {}
    for c in calls:
        if c["call"] is not None:
            key = f"{c['system']}.{c['verb']}"
            counts[key] = counts.get(key, 0) + 1
    return {
        "shown_its_facts": any(r.get("source") == ORACLE for r in run.ledger_rows),
        "first_altered_call": altered[0]["call"] if altered else None,
        "altered_leads": sorted({str(c["lead"]) for c in altered}),
        "call_counts": counts,
        "blocked_calls": [{"call": c["call"], "source": c["source"], "system": c["system"],
                           "verb": c["verb"], "params": c["params"]}
                          for c in calls if c["blocked"]],
        "errored_calls": [c["call"] for c in calls if c["source"] == REAL_ERROR],
        "unserved_calls": [c["call"] for c in calls if c["call"] is not None
                           and not c["inherited"] and c["source"] is None],
        "unmapped_calls": [{"call": None, "source": c["source"], CALL_ID: c.get(CALL_ID)}
                           for c in calls if c["call"] is None],
        "shared_baseline": [c["call"] for c in calls if c["inherited"]],
    }


@model
class RunView:
    """One run's block of the computed context: its header facts (manifest and archived
    report), its contrast row and joined call list, and what its reference section shows (its
    leads, report and calls, A24) — each call's served answer and an altered call's claim and
    verifier verdict keyed by its call number."""

    label: str
    role: Any
    story: Any
    axis: Any
    declared: Any
    label_basis: Any
    reached: str | None
    facts: list[dict[str, Any]]
    contrast: dict[str, Any]
    calls: list[dict[str, Any]]
    #: Every lead the run's calls or gather summaries name, sorted, with its goal (`None`: the
    #: lead's record names none).
    lead_goals: dict[str, Any]
    report_text: str
    #: Call number -> the answer its ledger partner records (`payload_text`; `None`: none).
    answers: dict[int, Any] = field(default_factory=dict)
    #: Call number -> an `oracle` partner's `claim` and `verifier_verdict` (each `None` when the
    #: row stores none).
    claims: dict[int, dict[str, Any]] = field(default_factory=dict)


def run_view(doc: dict[str, Any], runs: RunSet, label: str) -> RunView:
    """`label`'s block, off the manifest entry and the run's usability read."""
    entry = _world_entry(doc, label)
    run = runs.usable[label]
    calls = call_list(run, j3=runs.j3)
    leads = sorted({str(c["lead"]) for c in calls if c["lead"] is not None} | run.summary_leads)
    answers: dict[int, Any] = {}
    claims: dict[int, dict[str, Any]] = {}
    for n, row in enumerate(run.table_rows):
        partner = ledger_partner(row, run.ledger_rows, run.token)
        if partner is None:
            continue
        answers[n] = partner.get("payload_text")
        if partner.get("source") == ORACLE:
            claims[n] = {"claim": partner.get("claim"),
                         "verifier_verdict": partner.get("verifier_verdict")}
    return RunView(
        label=label, role=entry.get("role"), story=entry.get("story"), axis=entry.get("axis"),
        declared=entry.get("disposition_declared"), label_basis=entry.get("label_basis"),
        reached=run.report.disposition,
        facts=[f for f in entry.get("facts") or () if isinstance(f, dict)],
        contrast=contrast_row(calls, run), calls=calls,
        lead_goals={lead: run.leads[lead].goal if lead in run.leads else None for lead in leads},
        report_text=run.report.text, answers=answers, claims=claims)


def fact_surfaces(doc: dict[str, Any], runs: RunSet, labels: list[str]) -> list[dict[str, Any]]:
    """Per planted fact of the runs in `labels`: the systems its forged rows were served on
    (the oracle store), its entities, and per run the leads that queried one of those systems or
    named one of those entities in their params — every hit text-matched (heuristic)."""
    out: list[dict[str, Any]] = []
    for label in labels:
        run = runs.usable[label]
        entry = _world_entry(doc, label)
        for fact in entry.get("facts") or ():
            if not isinstance(fact, dict):
                continue
            systems = sorted({str(r.get("system")) for r in run.forged_rows
                              if r.get("fact_id") == fact.get("fact_id")})
            entities = [str(e) for e in fact.get("entities") or ()]
            hits: dict[str, list[str]] = {}
            for other in labels:
                leads = sorted({str(r.get("lead_id")) for r in runs.usable[other].table_rows
                                if r.get("system") in systems
                                or any(e and e in _json(r.get("params")) for e in entities)})
                if leads:
                    hits[other] = leads
            out.append({"world": label, "fact_id": fact.get("fact_id"),
                        "statement": fact.get("statement"), "systems": systems,
                        "entities": entities, "hits": hits, "heuristic": True})
    return out


#: How an aligned row was matched (M2): through a fact surface, by system and verb, or not at
#: all (a lead with a row of its own).
MATCHED_BY_SURFACE = "fact surface"
MATCHED_BY_SYSTEM_VERB = "system and verb"
UNMATCHED = "unmatched"


def aligned_lead_rows(runs: list[RunView], surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The aligned lead view (M2, F1): leads matched across runs through the fact surfaces
    first, then by the system and verb of their first call; a lead neither pairs gets a row of
    its own. A lead is a (run, lead id) pair: one id in two runs names two leads, which only a
    surface or a system/verb match puts in one row. Every row is heuristic (text-matched, not
    established). A row holding the judged world's (`runs[0]`) leads whose calls all come before
    its first altered answer is the shared baseline (noise); with no altered answer, no row is.

    Each row: `leads` (`{"run", "lead"}` entries, in run order), `matched_by`, the `fact_id` or
    the `system`/`verb` it was matched on, `heuristic` (always `True`) and `shared_baseline`."""
    first_call, numbers, order = _lead_index(runs)
    taken: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for surface in surfaces:
        touching = [(label, str(lead)) for label, leads in surface["hits"].items()
                    for lead in leads if (label, str(lead)) in first_call]
        fresh = [key for key in touching if key not in taken]
        if len({label for label, _lead in fresh}) < 2:
            continue
        taken.update(fresh)
        rows.append({"leads": fresh, "matched_by": MATCHED_BY_SURFACE,
                     "fact_id": surface["fact_id"]})
    by_key: dict[tuple[Any, Any], list[tuple[str, str]]] = {}
    for key in order:
        if key in taken or key not in first_call:
            continue
        by_key.setdefault(first_call[key], []).append(key)
    for (system, verb), keys in by_key.items():
        if len({label for label, _lead in keys}) < 2:
            continue
        taken.update(keys)
        rows.append({"leads": keys, "matched_by": MATCHED_BY_SYSTEM_VERB, "system": system,
                     "verb": verb})
    rows += [{"leads": [key], "matched_by": UNMATCHED} for key in order if key not in taken]
    return _marked_rows(rows, runs, numbers)


_Lead = tuple[str, str]  # (run label, lead id)


def _lead_index(runs: list[RunView]) -> tuple[dict[_Lead, tuple[Any, Any]], dict[_Lead, list[int]],
                                              dict[_Lead, None]]:
    """Each lead's first call's (system, verb), its call numbers, and every lead (one with no
    call included) in run then call order."""
    first_call: dict[_Lead, tuple[Any, Any]] = {}
    numbers: dict[_Lead, list[int]] = {}
    order: dict[_Lead, None] = {}
    for run in runs:
        for c in run.calls:
            if c["lead"] is None:
                continue
            key = (run.label, str(c["lead"]))
            first_call.setdefault(key, (c["system"], c["verb"]))
            order.setdefault(key)
            if c["call"] is not None:
                numbers.setdefault(key, []).append(c["call"])
        for lead in run.lead_goals:
            order.setdefault((run.label, lead))
    return first_call, numbers, order


def _marked_rows(rows: list[dict[str, Any]], runs: list[RunView],
                 numbers: dict[_Lead, list[int]]) -> list[dict[str, Any]]:
    """`rows` with their leads in run order, each labelled heuristic and marked shared baseline
    when it holds judged-world calls all made before the judged world's first altered answer."""
    focus = runs[0].label if runs else None
    first_altered = runs[0].contrast.get("first_altered_call") if runs else None
    rank = {run.label: i for i, run in enumerate(runs)}
    out: list[dict[str, Any]] = []
    for row in rows:
        keys = sorted(row["leads"], key=lambda k: (rank.get(k[0], len(rank)), k[1]))
        own = [n for key in keys if key[0] == focus for n in numbers.get(key, [])]
        baseline = (isinstance(first_altered, int) and bool(own)
                    and all(n < first_altered for n in own))
        out.append({**row, "leads": [{"run": label, "lead": lead} for label, lead in keys],
                    "heuristic": True, "shared_baseline": baseline})
    return out


@model
class JudgeContext:
    """The judge's whole input for one planted world (design data model): the focus run's and
    every reference run's blocks (focus first), the fact surfaces and aligned lead rows, the
    focus world's own views, the noise (pre-flight's record, as host text and framed run text,
    `RunText`) and the questioner inputs (the samples record and the base story). Never
    stored — derived fresh on every `render()` call; persisted only as the prompt in the wire
    log."""

    world_label: str
    run_views: list[RunView]
    fact_surfaces: list[dict[str, Any]]
    focus: JudgeInput
    noise: Annotated[list[Any], SkipValidation]
    aligned_rows: list[dict[str, Any]] = field(default_factory=list)
    samples: dict[str, Any] = field(default_factory=dict)
    base_story: Any = None
    payload_cap: int | None = None

    @property
    def contrast_rows(self) -> dict[str, dict[str, Any]]:
        """Run label -> that run's contrast row (the focus's included)."""
        return {run.label: run.contrast for run in self.run_views}

    @property
    def focus_calls(self) -> list[dict[str, Any]]:
        """Section 6's call list: the judged world's joined calls."""
        return self.run_views[0].calls

    @property
    def reference_calls(self) -> dict[str, list[dict[str, Any]]]:
        """Section 5's call lists, by reference run."""
        return {run.label: run.calls for run in self.run_views[1:]}

    @property
    def shown_its_facts(self) -> bool:
        """Was the judged world served any altered answer (its contrast row says)?"""
        return bool(self.contrast_rows[self.world_label]["shown_its_facts"])


def excluded_text(runs: RunSet, failed: dict[str, dict[str, Any]]) -> list[Any]:
    """The worlds no reference set holds and why — cut short, missing an input, malformed —
    except the O5-failed ones, which pre-flight's record already lists (each world once). Host
    text, each reason framed in place (`RunText`)."""
    parts: list[Any] = []
    for label, reason in runs.excluded.items():
        if label not in failed:
            parts += [f"- world {label}: ", RunText(str(reason)), "\n"]
    return parts or ["Every world not failed by pre-flight is a run.\n"]


__all__ = [
    "HEURISTIC", "JudgeContext", "JudgeInput", "RunText", "RunView", "aligned_lead_rows", "call_list",
    "contrast_row", "episode_alert", "excluded_text", "fact_surfaces", "family_status", "render",
    "render_family_text", "run_view",
]
