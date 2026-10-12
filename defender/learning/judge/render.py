"""The judge's input: the joined views over one archived world, plus the withholding of every
other world's facts.

Ported from `experiments/judge-context-921/variants/contexts.py::render_proposed`, the measured
arm. Reads only `episode_dir` and the checkout at the sibling's recorded commit — never a
sibling's own run dir, which may be gone, and never the tenant's runs: the judge reads only the
episode it is handed (#1105 J3 removed the same-alert sibling union and its spread).

Every world but the judged one has its facts withheld in the rendered family, and the lessons
view likewise excludes the other worlds' contribution. Every model-bound text the
host did not author arrives inside an untrusted frame (M26).
"""

from __future__ import annotations

import json
import re
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Any

import contextlib

from defender._io import Bound, bind
from defender._episode_paths import LAYOUT, WORLD_LEAVES, OracleStorePaths
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


def _git_show_default(cwd: Path, rev: str, path: str) -> str | None:
    from defender._git import git_show_file

    return git_show_file(cwd, rev, path)


@model
class JudgeInput:
    """The judge's whole rendered input for one (world, pass). Never stored — derived fresh
    on every `render()` call from the archive and the checkout."""

    world_label: str
    discriminator: dict[str, Any]
    leads: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: Every ledger row of the judged world, in ledger order: its decision word, the call, and
    #: for an `oracle` row its claim and verifier verdict. The answers render separately.
    calls: list[dict[str, Any]] = field(default_factory=list)
    lessons: list[dict[str, Any]] = field(default_factory=list)
    manifest_text: str = ""
    document_text: str = ""
    report_text: str = ""
    #: The per-system samples record, one section per system (O16).
    samples_text: str = ""
    #: The judged world's frozen telemetry and every collision of a frozen row's identifier
    #: with this world's real data (M12=A), off its oracle-side store.
    oracle_text: str = ""

    def as_prompt_sections(self, *, cap: int | None) -> dict[str, str]:
        """Each view as the text that goes inside its frame, trimmed under `cap` (section 6's
        share of `JUDGE_PAYLOAD_CAP`, A9). The call list is never cut: under any cap the judge
        still gets each call with its decision word (N22); the bytes come off the answers and
        documents."""
        capped = _cap_sections({
            "manifest": self.manifest_text,
            "answers": _render_answers(self.calls),
            "leads": _render_leads(self.leads),
            "lessons": _render_lessons(self.lessons),
            "document": self.document_text,
            "report": self.report_text,
            "samples": self.samples_text,
            "oracle": self.oracle_text,
        }, cap)
        ordered = {"manifest": capped["manifest"], "calls": _render_calls(self.calls)}
        ordered.update((k, v) for k, v in capped.items() if k not in ordered)
        return ordered


def _cap_sections(sections: dict[str, str], payload_cap: int | None) -> dict[str, str]:
    """The rendered views, trimmed so their total length is at most `payload_cap`.

    Equal share of what is left, smallest section first: a view that fits is never cut and
    hands its unused share on, so the bytes come off whichever view is actually large (not a
    small, load-bearing one)."""
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


def _json(value: Any) -> str:
    """One value as compact canonical JSON; `default=str` so a YAML-typed value never raises."""
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(value)


def _claim_text(row: dict[str, Any]) -> str:
    """An `oracle` row's claim and verifier verdict, or the words saying either was never
    stored — a call with no stored claim is never presented as verified (N22)."""
    claim = row.get("claim")
    verdict = row.get("verifier_verdict")
    if not isinstance(claim, dict):
        return " — claim unavailable (none was stored for this call; it is not verified)"
    if not isinstance(verdict, dict):
        return (f" — claim {_json(claim)}; verifier verdict unavailable (none was stored; the "
                "claim is not verified)")
    return f" — claim {_json(claim)}; verifier verdict {_json(verdict)}"


def _render_calls(calls: list[dict[str, Any]]) -> str:
    """VIEW 1: one line per call, numbered, naming its decision word — never cut by the cap."""
    if not calls:
        return "This world's investigator made no call that reached the ledger.\n"
    lines = []
    for n, row in enumerate(calls, 1):
        line = (f"- call #{n} [{row.get('source')}] system={row.get('system')} "
                f"verb={row.get('verb')} params={_json(row.get('params'))}")
        if row.get("source") == ORACLE:
            line += _claim_text(row)
        lines.append(line)
    return "\n".join(lines) + "\n"


def _render_answers(calls: list[dict[str, Any]]) -> str:
    """VIEW 2: the answer each call was served, by call number (the bulk the cap is charged
    against)."""
    if not calls:
        return "No answer was served to this world.\n"
    return "".join(f"- call #{n} answer: {row.get('payload_text')}\n"
                   for n, row in enumerate(calls, 1))


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


def episode_alert(bound: Bound, labels: list[str]) -> dict[str, Any]:
    """The alert this episode's worlds all investigate: the first world's `alert.json` that
    carries an `alert_id`, else the first that parses.

    The enqueue's `alert_rule_key` keys on it.
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


def _render_samples(samples_doc: dict[str, Any], served: list[str]) -> str:
    """The samples record per system (O16): each system's real example answers under its own
    name, per verb, and a system whose section is unavailable shown with its reason. A served
    system the record has no section for is named as such."""
    lines: list[str] = []
    for system in sorted({*map(str, samples_doc), *served}):
        section = samples_doc.get(system)
        if isinstance(section, dict) and isinstance(section.get("verbs"), dict):
            lines.append(f"system {system}:")
            for verb, answers in sorted(section["verbs"].items(), key=lambda kv: str(kv[0])):
                lines.append(f"  verb {verb}:")
                for answer in answers if isinstance(answers, list) else [answers]:
                    lines.append(f"    {answer if isinstance(answer, str) else _json(answer)}")
        elif isinstance(section, dict) and "unavailable" in section:
            lines.append(f"system {system}: unavailable — {section.get('unavailable')}")
        else:
            lines.append(f"system {system}: no samples section is recorded")
    return "\n".join(lines) + "\n" if lines else "No samples record is archived.\n"


def render_oracle_store(bound: Bound, label: str) -> str:
    """The judged world's oracle-side record as the judge reads it: every frozen forged row
    (the telemetry its facts were served through) and every collision of a frozen row's
    identifier with this world's real data (M12=A — the row stayed frozen and was still
    served)."""
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


def _render_call(call: Any) -> str:
    if not isinstance(call, dict):
        return "(no call recorded)"
    return (f"system={call.get('system')} verb={call.get('verb')} "
            f"params={_json(call.get('params'))}")


def render_family_text(record: dict[str, Any] | None,
                       failed: dict[str, dict[str, Any]]) -> str:
    """Pre-flight's record of the family and every failed world as an explicit entry (N22):
    each world that could not be judged by its label, its reason word and the investigator's
    call it failed on; the calls pre-flight could not replay; and the calls whose live answer
    drifted from the capture.

    A failed world's `detail` is never shown: it is the oracle's last refusal, which can quote
    the rows it forged for that world's facts, or the verifier's reasoning about them, and this
    text reaches every judged world's prompt, which withholds every other world's facts."""
    if record is None:
        lines = ["No pre-flight outcome record is readable for this episode."]
    else:
        lines = [f"outcome: {record.get('outcome')} — {record.get('reason') or '(no reason given)'}"]
    if failed:
        lines.append("worlds that could not be judged (each contributes no findings):")
        for label, entry in sorted(failed.items()):
            lines.append(f"- world {label}: {entry.get('reason') or '(no reason recorded)'}; "
                         f"call: {_render_call(entry.get('call'))}")
    else:
        lines.append("every world could be judged")
    for key, what in (("not_replayable", "calls pre-flight could not replay"),
                      ("drift", "calls whose live answer drifted from the capture")):
        entries = (record or {}).get(key) or []
        if not entries:
            lines.append(f"{what}: none")
            continue
        lines.append(f"{what}:")
        for entry in entries:
            extra = (entry.get("status") or entry.get("reason")) if isinstance(entry, dict) else None
            lines.append(f"- {_render_call(entry)}" + (f" ({extra})" if extra else ""))
    return "\n".join(lines) + "\n"


def render(  # noqa: PLR0913 — the keyword tail is the per-pass hand-over that avoids re-reading what the caller has read
    episode_dir: Path, world_label: str, *,
    git_show: Any = None, lessons_commit: str | None = None, payload_cap: int | None = None,
    facts: WorldFacts | None = None, samples: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None, bound: Bound | None = None,
    family_text: str | None = None, runs: RunSet | None = None,
) -> JudgeContext:
    """The judge's computed context for one planted world (design M2, derived on read, P-b):
    the computed header, contrast table and fact surfaces of the focus and every reference run,
    the reference runs' compressed sections, the focus world's own views, and the noise.

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
        focus = _render_bound_world(bound, episode_dir, world_label, git_show=git_show,
                                    lessons_commit=lessons_commit,
                                    facts=facts if facts is not None else runs.usable.get(
                                        world_label),
                                    samples=samples, manifest=doc)
        labels = [world_label, *runs.references(world_label)]
        return JudgeContext(
            world_label=world_label, runs=[run_view(doc, runs, label) for label in labels],
            fact_surfaces=fact_surfaces(doc, runs, labels), focus=focus,
            noise_text=family_text, payload_cap=payload_cap)


def _manifest_text(doc: dict[str, Any], judged_label: str) -> str:
    """The judged world's own manifest entry: its story, axis, declared verdict and facts. Every
    other run's facts sit only in that run's labelled block of the computed header."""
    world = _world_entry(doc, judged_label)
    lines = [f"world {judged_label} (role {world.get('role')}) — JUDGED. "
             f"story={world.get('story')!r} axis={world.get('axis')!r} "
             f"declared verdict: {world.get('disposition_declared')}"]
    facts = [f for f in world.get("facts") or () if isinstance(f, dict)]
    if not facts:
        lines.append("facts: none (this world serves the capture's own answers)")
    for fact in facts:
        entities = fact.get("entities")
        lines.append(f"fact {fact.get('fact_id')}: {fact.get('statement')}"
                     + (f" (entities: {', '.join(map(str, entities))})"
                        if isinstance(entities, list) and entities else ""))
    return "\n".join(lines) + "\n"


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
    samples_text = _render_samples(samples_doc, served_systems_of(doc))
    calls = list(record.ledger_rows)

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
        leads=leads, calls=calls, lessons=lessons,
        manifest_text=_manifest_text(doc, world_label), document_text=text,
        report_text=report_text, samples_text=samples_text,
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
    from defender._knowledge import CHECKOUT_KNOWLEDGE, RUNTIME_LESSON_CORPORA

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

#: M3's section titles: host text, outside every untrusted frame (A10).
TITLE_HEADER = "COMPUTED HEADER"
TITLE_CONTRAST = "CONTRAST TABLE"
TITLE_SURFACES = "FACT SURFACES"
TITLE_ALIGNED = "ALIGNED LEAD VIEW"
TITLE_REFERENCES = "REFERENCE RUNS"
TITLE_FOCUS = "JUDGED WORLD VIEWS"
TITLE_NOISE = "NOISE CONTEXT"

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
    report), its contrast row and joined call list, and its compressed reference section."""

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
    leads_text: str
    report_text: str


def run_view(doc: dict[str, Any], runs: RunSet, label: str) -> RunView:
    """`label`'s block, off the manifest entry and the run's usability read."""
    entry = _world_entry(doc, label)
    run = runs.usable[label]
    calls = call_list(run, j3=runs.j3)
    leads = sorted({str(c["lead"]) for c in calls if c["lead"] is not None} | run.summary_leads)
    lead_lines = [f"- {lead}: goal={run.leads[lead].goal if lead in run.leads else None}"
                  for lead in leads]
    return RunView(
        label=label, role=entry.get("role"), story=entry.get("story"), axis=entry.get("axis"),
        declared=entry.get("disposition_declared"), label_basis=entry.get("label_basis"),
        reached=run.report.disposition,
        facts=[f for f in entry.get("facts") or () if isinstance(f, dict)],
        contrast=contrast_row(calls, run), calls=calls,
        leads_text="\n".join(lead_lines) + "\n" if lead_lines else "No leads are recorded.\n",
        report_text=run.report.text)


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
                        "entities": entities, "hits": hits})
    return out


@model
class JudgeContext:
    """The judge's whole input for one planted world (design data model): the focus run's and
    every reference run's blocks (focus first), the fact surfaces, the focus world's own views,
    and the noise. Never stored — derived fresh on every `render()` call; persisted only as the
    prompt in the wire log."""

    world_label: str
    runs: list[RunView]
    fact_surfaces: list[dict[str, Any]]
    focus: JudgeInput
    noise_text: str
    payload_cap: int | None = None

    @property
    def contrast_rows(self) -> dict[str, dict[str, Any]]:
        """Run label -> that run's contrast row (the focus's included)."""
        return {run.label: run.contrast for run in self.runs}

    @property
    def focus_calls(self) -> list[dict[str, Any]]:
        """Section 6's call list: the judged world's joined calls."""
        return self.runs[0].calls

    @property
    def reference_calls(self) -> dict[str, list[dict[str, Any]]]:
        """Section 5's call lists, by reference run."""
        return {run.label: run.calls for run in self.runs[1:]}

    @property
    def shown_its_facts(self) -> bool:
        """Was the judged world served any altered answer (its contrast row says)?"""
        return bool(self.contrast_rows[self.world_label]["shown_its_facts"])


def _run_header_block(run: RunView, *, served: list[str], predicate: str) -> str:
    lines = [f"role: {run.role}", f"story: {run.story}", f"axis: {run.axis}",
             f"declared verdict: {run.declared}", f"label_basis: {run.label_basis}",
             f"reached verdict (its archived {WORLD_LEAVES.report}): {run.reached}",
             f"served systems: {', '.join(served) or '(none recorded)'}",
             f"discriminator predicate: {predicate}"]
    if not run.facts:
        lines.append("facts: none (this run serves the capture's own answers)")
    for fact in run.facts:
        entities = fact.get("entities")
        lines.append(f"fact {fact.get('fact_id')}: {fact.get('statement')}"
                     + (f" (entities: {', '.join(map(str, entities))})"
                        if isinstance(entities, list) and entities else ""))
    return "\n".join(lines) + "\n"


def _contrast_block(run: RunView) -> str:
    row = run.contrast
    lines = [f"shown its facts: {'yes' if row['shown_its_facts'] else 'no'}",
             f"first altered call: {row['first_altered_call']}",
             f"leads served altered answers: {', '.join(row['altered_leads']) or 'none'}",
             f"calls by system/verb: {_json(row['call_counts'])}",
             f"blocked calls (refused, faulted, or the inherited pre-branch denial): "
             f"{_json(row['blocked_calls'])}",
             f"calls served an error (an outage, not a gap): {_json(row['errored_calls'])}",
             f"unserved calls: {_json(row['unserved_calls'])}",
             f"unmapped ledger rows: {_json(row['unmapped_calls'])}",
             f"shared baseline (inherited pre-branch calls): {_json(row['shared_baseline'])}"]
    return "\n".join(lines) + "\n"


def _calls_block(calls: list[dict[str, Any]]) -> str:
    if not calls:
        return "This run made no call.\n"
    return "".join(
        f"- call #{c['call']} lead={c['lead']} [{c['source']}]"
        f"{' BLOCKED' if c['blocked'] else ''}{' inherited' if c['inherited'] else ''} "
        f"system={c['system']} verb={c['verb']} params={_json(c['params'])}\n"
        for c in calls)


def _surfaces_block(surfaces: list[dict[str, Any]]) -> str:
    if not surfaces:
        return "No planted fact is in these runs.\n"
    lines = [f"Every hit below is {HEURISTIC}."]
    for s in surfaces:
        lines.append(f"fact {s['fact_id']} of world {s['world']}: {s['statement']}")
        lines.append(f"  served on: {', '.join(s['systems']) or 'no forged row'}; entities: "
                     f"{', '.join(s['entities']) or 'none'}")
        for run, leads in s["hits"].items():
            lines.append(f"  run {run}: leads {', '.join(leads)} ({HEURISTIC})")
    return "\n".join(lines) + "\n"


def _aligned_block(runs: list[RunView]) -> str:
    """Leads matched across runs by system/verb — each row heuristic; the focus's calls before
    its first altered answer are the shared baseline (noise)."""
    by_key: dict[str, dict[str, list[str]]] = {}
    for run in runs:
        for c in run.calls:
            if c["lead"] is None:
                continue
            key = f"{c['system']}.{c['verb']}"
            by_key.setdefault(key, {}).setdefault(run.label, [])
            if str(c["lead"]) not in by_key[key][run.label]:
                by_key[key][run.label].append(str(c["lead"]))
    if not by_key:
        return "No lead made a call in these runs.\n"
    lines = [f"Every matched row below is {HEURISTIC}; calls before the judged world's first "
             "altered answer are the shared baseline."]
    for key, per_run in sorted(by_key.items()):
        lines.append(f"{key}: " + "; ".join(f"run {run}: {', '.join(leads)}"
                                           for run, leads in per_run.items()))
    return "\n".join(lines) + "\n"


#: One prompt section: its host title, and its framed blocks — each a host label (a run's, or
#: `None`) and the non-host text that goes inside one untrusted frame (A10).
Section = tuple[str, list[tuple[str | None, str]]]


def computed_sections(doc: dict[str, Any], runs: list[RunView],
                      surfaces: list[dict[str, Any]]) -> list[Section]:
    """M3's sections 2-4 over `runs`: every run's computed header and contrast row, labelled
    by run, then the fact surfaces and the aligned lead view. Charged whole under the cap,
    never trimmed (A9)."""
    from defender.learning.judge.run import family_predicate, served_systems_of

    served, predicate = served_systems_of(doc), family_predicate(doc)
    return [
        (TITLE_HEADER, [(f"run {run.label}", _run_header_block(run, served=served,
                                                           predicate=predicate))
                        for run in runs]),
        (TITLE_CONTRAST, [(f"run {run.label}", _contrast_block(run)) for run in runs]),
        (TITLE_SURFACES, [(None, _surfaces_block(surfaces))]),
        (TITLE_ALIGNED, [(None, _aligned_block(runs))]),
    ]


def _charged(sections: list[Section]) -> int:
    return sum(len(body) for _title, blocks in sections for _label, body in blocks)


def cap_refusal(cap: int | None, fixed: int, what: str) -> str | None:
    """Why a call's whole computed context does not fit under `JUDGE_PAYLOAD_CAP` (A9), or
    `None` when it does."""
    if cap is None or fixed <= cap:
        return None
    return (f"{what}'s computed sections take {fixed} characters, over the payload cap "
            f"(JUDGE_PAYLOAD_CAP={cap}) — refused rather than sent trimmed")


def world_sections(ctx: JudgeContext, doc: dict[str, Any]) -> list[Section]:
    """Every section of the world call after the task, in M3's order, under the cap (A9):
    sections 2-4 charged whole (refused, `JudgeRefused` naming the cap, when they alone exceed
    it); then section 5 trimmed first, then 7, then section 6's views (its call list never)."""
    fixed = computed_sections(doc, ctx.runs, ctx.fact_surfaces)
    refusal = cap_refusal(ctx.payload_cap, _charged(fixed), f"world {ctx.world_label}")
    if refusal is not None:
        raise JudgeRefused(refusal)
    calls = ctx.reference_calls
    references = {f"run {run.label}": f"leads:\n{run.leads_text}\nreport:\n{run.report_text}"
                                      f"\ncalls:\n{_calls_block(calls[run.label])}"
                  for run in ctx.runs[1:]}
    # VIEW 1 is the joined call list, numbered as the contrast rows number calls (A12), so a
    # call number means one call across every section.
    focus_list = _calls_block(ctx.focus_calls)
    focus_views = {**ctx.focus.as_prompt_sections(cap=None), "calls": focus_list}
    budget = None if ctx.payload_cap is None else ctx.payload_cap - _charged(fixed)
    views_len = sum(len(v) for k, v in focus_views.items() if k != "calls")
    noise = ctx.noise_text
    if budget is not None:
        ref_budget = max(budget - views_len - len(noise), 0)
        references = _cap_sections(references, ref_budget)
        noise_budget = max(budget - views_len - sum(map(len, references.values())), 0)
        noise = _cap_sections({"noise": noise}, noise_budget)["noise"]
        view_budget = max(budget - sum(map(len, references.values())) - len(noise), 0)
        focus_views = {**ctx.focus.as_prompt_sections(cap=view_budget), "calls": focus_list}
    return [
        *fixed,
        (TITLE_REFERENCES, list(references.items()) or [(None, "No reference run.\n")]),
        (TITLE_FOCUS, [(f"world {ctx.world_label} — {_FOCUS_VIEW_TITLES.get(name, name)}", body)
                       for name, body in focus_views.items()]),
        (TITLE_NOISE, [(None, noise)]),
    ]


def family_sections(doc: dict[str, Any], runs: RunSet, noise: str, *,
                    cap: int | None) -> list[Section]:
    """The family call's sections (design M6, A22): every usable run's computed header and
    contrast row, the fact surfaces and the aligned lead view, then the noise context — no
    samples and nothing any world call answered, so the prompt is the same whatever the worlds'
    outcomes. Refused (`JudgeRefused` naming the cap) when the computed sections alone exceed
    `cap` (A9): the family call is never sent trimmed."""
    labels = list(runs.usable)
    fixed = computed_sections(doc, [run_view(doc, runs, label) for label in labels],
                              fact_surfaces(doc, runs, labels))
    refusal = cap_refusal(cap, _charged(fixed), "the family call")
    if refusal is not None:
        raise JudgeRefused(refusal)
    return [*fixed, (TITLE_NOISE, [(None, noise)])]


#: Each focus view's host label (section 6), keyed by `JudgeInput.as_prompt_sections`' names.
_FOCUS_VIEW_TITLES: dict[str, str] = {
    "manifest": "its facts and declared verdict, as the family recorded them",
    "family": "pre-flight's record of the family",
    "calls": "VIEW 1: every call its investigator made, with its decision word",
    "answers": "VIEW 2: the answers those calls were served, by call number",
    "leads": "VIEW 3: per-lead chain (goal, params, payload, refused, summary, resolutions)",
    "lessons": "VIEW 4: lessons that reached it (body at its recorded commit)",
    "document": "its own investigation.md",  # lint-run-records: ok — a label naming the record for the model
    "report": "its own report.md",  # lint-run-records: ok — a label naming the record for the model
    "oracle": "its frozen telemetry and identifier collisions (its built layer)",
    "samples": "real example answers per served system (the samples record)",
}


def excluded_text(runs: RunSet, failed: dict[str, dict[str, Any]]) -> str:
    """The worlds no reference set holds and why — cut short, missing an input, malformed —
    except the O5-failed ones, which pre-flight's record already lists (each world once)."""
    lines = [f"- world {label}: {reason}" for label, reason in runs.excluded.items()
             if label not in failed]
    return "\n".join(lines) + "\n" if lines else "Every world not failed by pre-flight is a run.\n"


__all__ = [
    "HEURISTIC", "JudgeContext", "JudgeInput", "RunView", "Section", "call_list",
    "computed_sections", "contrast_row", "episode_alert", "excluded_text", "fact_surfaces",
    "family_sections", "family_status", "render", "render_family_text", "run_view", "world_sections",
]
