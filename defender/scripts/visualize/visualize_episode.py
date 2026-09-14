"""#1025 — the episode page: `render_episode(episode_dir) -> Path` renders `learning.html`
beside `judge.yaml` from an episode directory alone, and `main(argv)` is the standalone CLI.
The launcher (`branch/cli.py::_render_document`) calls `render_episode` after the JUDGE clock frame
closes, under its own non-fatal boundary.

TWO PHASES, ONE BOUNDARY. `load_episode` reads every record the page shows — the manifest, the
six episode-level records, each world's draw documents, result event, archive and leads, the
wire logs — EXACTLY ONCE, into the typed model below (`_Episode`), and runs the findings walk
once over it. The section renderers take the model and never touch the directory. That is what
makes the page's contract hold by construction rather than by inspection: only `family.yaml`
refuses the whole page (d01); every other record a reader refuses, or a field whose shape is
not the one the writer produces, lands in ITS OWN slot at load time — a `_Record.error`, an
empty list, a `None` — and renders as that slot's own sentence. A renderer that only ever sees
values the loader has already typed cannot take the page down over one stray scalar in one
file, and no renderer can disagree with another about what a record says, because there is one
reading of it. The page always reads through the package readers rather than re-parsing any
record itself.
"""
from __future__ import annotations

import math
import re
import sys
from pathlib import Path
from typing import Any

from defender._artifact_schema import INVESTIGATION_NAME, REPORT_NAME
from defender._io import read_jsonl_rows_report, write_guarded
from defender._report import ReportRead
from defender._run_id import is_valid_run_id
from defender._run_paths import PROVENANCE, WIRE_LOG_DIR, artifact_dir, artifact_file
from defender._vocab import normalized_judge_outcome
from defender.learning.branch import archive, staging
from defender.learning.branch import timing as timing_mod
from defender.learning.branch.cli import RUNS_SUBDIR
from defender.learning.branch.steps import STEPS, Step
from defender.learning.judge import JudgeRefused, read_grade
from defender.learning.judge import family
from defender.learning.judge.enqueue import DrawsSkipReport, draws_on_disk_report
from defender.learning.judge.render import episode_alert
from defender.learning.judge.run import SUBJECT_DEFENDER, SUBJECT_WORLD
from defender.runtime.branch._family import episode_token_for
from defender.scripts import pricing
from defender.scripts.visualize.visualize_primitives import (
    CSS,
    EVENT_HANDLER_RE,
    esc,
    fmt_duration,
)

PAGE_NAME = "learning.html"

#: The run's own event stream, at the run dir's root (`_run_paths` names why it stays there).
_TOOL_TRACE_NAME = "tool_trace.jsonl"
#: The family's own draw documents live under this pseudo-label beside the worlds.
_FAMILY_LABEL = "family"

_LADDER_WORDS = ("undecidable", "caught", "survived", "discard", "corpus-contradiction")

_WITHHELD_CLASS = {
    "measured_nothing": "wh-measured-nothing",
    "capture_unaddressed": "wh-capture-unaddressed",
    "reachability_unmeasured": "wh-reachability-unmeasured",
    "episode_incomplete": "wh-episode-incomplete",
}

_BUCKET_CLASS = {
    "lead-set": "bucket-lead-set",
    "observability": "bucket-observability",
    "decision-discipline": "bucket-decision-discipline",
    "analyze-discipline": "bucket-analyze-discipline",
    "unreachable-difference": "bucket-mechanical",
    "story-overlay-gap": "bucket-story-overlay-gap",
    "lead-quality": "bucket-lead-quality",
}

_CHIP_FIELDS = ("holding_queried", "doctored_answer_served", "difference_shown",
                "injected_present", "capture_reasks_faulted", "envelope_ran")

#: The three chips that exist ONLY on a `judge.yaml` row — never on a review reachability
#: block. A world with no row (the control; any never-graded world) has nothing to name these
#: from, so they are omitted entirely rather than shown as a promise "unrecorded" makes about
#: a world that was measured (#1025 J16 c).
_ROW_ONLY_CHIP_FIELDS = frozenset({"holding_queried", "doctored_answer_served",
                                   "difference_shown"})

#: The mirror image of `_ROW_ONLY_CHIP_FIELDS`: never a row field, on any row shape — always
#: read from the review's reachability block when present, with or without a row.
_REACH_ONLY_CHIP_FIELDS = frozenset({"envelope_ran"})

_LADDER_FIELDS = ("holding_queried", "doctored_answer_served", "difference_shown",
                  "verdict", "resolution_moved")


# =========================================================================================
# Small escaping / id-safety primitives
# =========================================================================================


def _safe_id(raw: str) -> str | None:
    """`raw`, if it may safely become an html id/href/class component — grammar-gated on the
    launcher's own run-id alphabet (#1025 J5). `None` otherwise: the caller renders an
    "unnameable entry" line instead of building any attribute out of it."""
    return raw if isinstance(raw, str) and is_valid_run_id(raw) else None


def _v(x: Any) -> str:
    """A scalar rendered as text. ALIASED TO THE UNTRUSTED ESCAPE (#1025 O9): almost nothing
    on this page is a structural literal this module wrote itself — every string is a record
    field, and a record lives in a tree a box can reach. Treating `_v` as `esc()` alone would
    have made every call site a silent decision that ITS value is exempt from the event-handler
    split, which is exactly the kind of per-site judgment call this design's `esc_untrusted`
    exists to remove."""
    return _uv(x)


def _uv(x: Any) -> str:
    """`_v`, through the untrusted escape — for a value whose source is a model-authored
    record.

    The SAME event-handler predicate `visualize_primitives.esc_untrusted` splits on, imported
    rather than respelled: this page splits it across an ELEMENT boundary (`<wbr>`, a void tag
    with no text of its own), not `esc_untrusted`'s zero-width character. Both defeat a naive
    "onerror=" scan of the raw bytes, but only the element boundary survives a round trip
    through this page's own text reader: a `<wbr>` contributes nothing to `Node.text()`'s walk,
    so the two text pieces either side of it concatenate back to the ORIGINAL word exactly —
    which several of this page's own adversarial tests assert directly (`word in page.text`),
    a check a zero-width character would fail."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    escaped = esc(x if isinstance(x, str) else str(x))
    return EVENT_HANDLER_RE.sub(lambda m: m.group(0) + "<wbr>", escaped)


def _raw(x: Any) -> str:
    """`x` as plain text with no markup escaping — for building a string another function will
    escape exactly once. `None` reads as the same em dash `_v`/`_uv` show."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    return x if isinstance(x, str) else str(x)


def _unnameable(raw: str, *, what: str) -> str:
    return f'<div class="unnameable">unnameable entry ({esc(what)}): {_uv(raw)}</div>'


def _money(cost: float) -> str:
    return f"${cost:.4f}"


def _items(x: Any) -> list[Any]:
    """A record field that the writer produces as a list, or nothing: a scalar where a list
    belongs is that field's own absence, never the page's crash."""
    return x if isinstance(x, list) else []


def _mapping(x: Any) -> dict[str, Any]:
    """The mapping twin of `_items`."""
    return x if isinstance(x, dict) else {}


def _count(x: Any) -> int | None:
    """A non-negative integer field, or `None` for anything else (a bool is not a count)."""
    return x if isinstance(x, int) and not isinstance(x, bool) and x >= 0 else None


def _page_section(anchor: str, title: str, body: str) -> str:
    return f'<section id="{esc(anchor)}"><h2>{esc(title)}</h2>{body}</section>'


# =========================================================================================
# Whole-record readers — each in its own boundary, each answering (value, absent, error)
# =========================================================================================


class _Record:
    """One episode-level record's read: `value` (or `None`), `present` (was anything at all at
    the name), and `error` (the reader's refusal sentence, or `None`)."""

    __slots__ = ("value", "present", "error")

    def __init__(self, value: Any = None, *, present: bool = False, error: str | None = None):
        self.value = value
        self.present = present
        self.error = error

    @property
    def ok(self) -> bool:
        return self.error is None


def _read_review(episode_dir: Path) -> _Record:
    path = Path(episode_dir) / archive.REVIEW_NAME
    present = path.exists() or path.is_symlink()
    try:
        doc = family.read_review_record(episode_dir)
    except JudgeRefused as bad:
        return _Record(present=True, error=f"review record unreadable: {bad}")
    return _Record(doc, present=present)


def _strict_samples_reader(path: Path) -> dict[str, Any]:
    """The page's own STRICT reading of `samples.yaml` (#1025 F-4) — through `read_samples_
    record`'s `reader=` seam. The DEFAULT reader `read_samples_record` uses everywhere else
    stays permissive (#1007 M4/O5); this one refuses what it cannot read so the page's
    "unreadable" state is distinguishable from "absent". The screen itself is the package's
    one home for a YAML record read (`screened_yaml_mapping`), not a second spelling of it."""
    doc = family.screened_yaml_mapping(path, what=archive.SAMPLES_NAME)
    return doc if doc is not None else {}


def _read_samples(episode_dir: Path) -> _Record:
    path = Path(episode_dir) / archive.SAMPLES_NAME
    present = path.exists() or path.is_symlink()
    try:
        doc = family.read_samples_record(episode_dir, reader=_strict_samples_reader)
    except JudgeRefused as bad:
        return _Record(present=True, error=f"samples record unreadable: {bad}")
    if not doc and not present:
        return _Record({}, present=False)
    return _Record(doc, present=present)


def _read_staged(episode_dir: Path) -> _Record:
    path = staging.staged_path(episode_dir)
    present = path.exists() or path.is_symlink()
    try:
        rows = staging.read_staged(episode_dir)
    except staging.StagingRefused as bad:
        return _Record(present=True, error=f"staging record unreadable: {bad}")
    # `read_staged` now screens through `read_guarded`, which folds a permission-denied regular
    # file (root ignores this; a real non-root run does not, #1025) into `StagingRefused` above
    # rather than letting it escape as a bare `OSError`/`PermissionError` — this arm is kept as
    # a defensive backstop should that change, so this record's own slot still answers rather
    # than the whole page's render.
    except OSError as bad:
        return _Record(present=True, error=f"staging record unreadable: {bad}")
    if not rows and not present:
        return _Record([], present=False)
    return _Record(rows, present=present)


def _read_timing(episode_dir: Path) -> _Record:
    try:
        rows = timing_mod.read_stage_timings(episode_dir)
    except ValueError as bad:
        return _Record(present=True, error=f"timing record unreadable: {bad}")
    return _Record(rows, present=bool(rows))


def _read_family_stamp(episode_dir: Path) -> _Record:
    try:
        doc = archive.read_family_stamp(episode_dir)
    except ValueError as bad:
        return _Record(present=True, error=f"provenance record unreadable: {bad}")
    return _Record(doc, present=doc is not None)


def _read_grade(episode_dir: Path) -> _Record:
    try:
        grade = read_grade(episode_dir)
    except JudgeRefused as bad:
        return _Record(present=True, error=f"grade record unreadable: {bad}")
    return _Record(grade, present=grade is not None)


# =========================================================================================
# The model — what one read of the episode directory says
# =========================================================================================


class _ResultEvent:
    """A run's terminal `result` row off its own event stream: `(cost, wall_ms, state)`, where
    `state` is one of absent / refused / none / unusable / ok."""

    __slots__ = ("cost", "wall_ms", "state")

    def __init__(self, cost: float | None, wall_ms: float | None, state: str) -> None:
        self.cost = cost
        self.wall_ms = wall_ms
        self.state = state


class _WorldArchive:
    """What `worlds/<label>/` holds for the world section: the archived report (`None` when
    nothing is at its name), whether the investigation is archived, and the two JSON stamps."""

    __slots__ = ("report", "investigation_present", "provenance", "scrub")

    def __init__(self, *, report: ReportRead | None, investigation_present: bool,
                 provenance: dict[str, Any] | None, scrub: dict[str, Any] | None) -> None:
        self.report = report
        self.investigation_present = investigation_present
        self.provenance = provenance
        self.scrub = scrub


class _WorldLeads:
    """One world's leads block, read: the served-ledger note (or `None`), whether the world is
    archived at all, the investigation's refusal (or `None`), whether the hand-off moved, the
    gather-summary stems that could not be named, and every lead's chain in roster order —
    `None` where the lead's own read was refused."""

    __slots__ = ("ledger_note", "archived", "facts_error", "moved", "unnameable_summaries",
                 "chains")

    def __init__(self) -> None:
        self.ledger_note: str | None = None
        self.archived = False
        self.facts_error: str | None = None
        self.moved = False
        self.unnameable_summaries: list[str] = []
        self.chains: list[tuple[str, dict[str, Any] | None]] = []


class WorldEntry:
    def __init__(self, label: str) -> None:
        self.label = label
        self.in_manifest = False
        self.manifest_doc: dict[str, Any] | None = None
        self.row: dict[str, Any] | None = None  # judge.yaml row, if any
        self.role: str | None = None
        self.run_dir_name: str | None = None  # the runs/ dir that decomposed to this label
        self.result: _ResultEvent | None = None  # `None` when there is no run dir at all
        self.archive: _WorldArchive | None = None  # `None` when worlds/<label> is not a dir


class _Trace:
    """One model call's wire record, by stem (`<agent>_trace`): the plain trace file's state
    (absent / refused / ok) with its rows and unreadable-line count, and the framed twin —
    whether one is on disk, and its first row when it could be read."""

    __slots__ = ("stem", "plain", "rows", "unreadable", "framed_present", "framed")

    def __init__(self, stem: str) -> None:
        self.stem = stem
        self.plain = "absent"
        self.rows: list[dict[str, Any]] = []
        self.unreadable = 0
        self.framed_present = False
        self.framed: dict[str, Any] | None = None


class _WireLogs:
    """`wire_logs/`, read once. Every question the stages section asks of the directory — a
    role's stems, a role's priced cost, the comparator's, the unattributed judge stems — is a
    walk over `traces`, never a second glob."""

    __slots__ = ("present", "traces")

    def __init__(self) -> None:
        self.present = False
        self.traces: dict[str, _Trace] = {}

    def stems_for(self, role_prefix: str) -> set[str]:
        """Every call's own STEM for a role — the union of plain trace files and framed twins,
        since a launcher-produced episode writes only the framed one for some roles (#1025
        J13a/b): a stem with no plain trace file still gets a block, built entirely from its
        framed record."""
        return {s for s, t in self.traces.items()
                if s.startswith(role_prefix) and (t.plain != "absent" or t.framed_present)}

    def plain_stems(self, *, agent_prefix: str) -> list[str]:
        """The stems whose PLAIN trace file is on disk (readable or not), whose agent id starts
        with `agent_prefix`, in name order."""
        return sorted(s for s, t in self.traces.items()
                      if t.plain != "absent" and s[: -len("_trace")].startswith(agent_prefix))

    def role_cost(self, role_prefix: str) -> tuple[float, float, int, int]:
        """`(cost, wall_ms, priced_calls, total_calls)` for every trace file this stage's role
        owns — one call per FILE. A call is "priced" when its response row carries `usage` and a
        `model` the pricing table resolves; the wall total sums `duration_ms` only where present,
        independently of whether the call priced (#1025 J13b)."""
        agent_prefix = "questioner" if role_prefix == "questioner" else "judge_"
        total = 0.0
        wall = 0.0
        priced_calls = 0
        total_calls = 0
        for stem in self.plain_stems(agent_prefix=agent_prefix):
            trace = self.traces[stem]
            total_calls += 1
            if trace.plain != "ok":
                continue
            call_priced = False
            for row in trace.rows:
                if row.get("kind") != "response":
                    continue
                cost = _priced(row.get("model"), row.get("usage"))
                if cost is not None:
                    total += cost
                    call_priced = True
                duration = row.get("duration_ms")
                if isinstance(duration, (int, float)):
                    wall += duration
            if call_priced:
                priced_calls += 1
        return total, wall, priced_calls, total_calls

    def comparator_cost(self) -> tuple[float, int]:
        """`(cost, priced calls)` — `calls` counts response rows that actually priced, not files:
        an empty (or response-less) comparator trace contributes a file to the stream list but no
        call here, so the review row still reads "no model calls" (#1025 J13b)."""
        total = 0.0
        calls = 0
        for stem in self.plain_stems(agent_prefix="comparator_"):
            trace = self.traces[stem]
            if trace.plain != "ok":
                continue
            for row in trace.rows:
                if row.get("kind") != "response":
                    continue
                cost = _priced(row.get("model"), row.get("usage"))
                if cost is not None:
                    total += cost
                    calls += 1
        return total, calls


def _priced(model: Any, usage: Any) -> float | None:
    """This response row's bill, or `None` when it does not price: no `usage` mapping, no
    `model` string, a model the table does not know, or token counts that are not numbers — a
    wire log sits in a tree a sibling box can write, so a count spelled as text is that row's
    own unpriced state, never the page's crash."""
    if not (isinstance(usage, dict) and isinstance(model, str)):
        return None
    try:
        cost = pricing.usage_cost(model, usage)
        pricing.model_key(model)
    except (pricing.UnknownModel, TypeError, ValueError):
        return None
    return cost


class _Finding:
    __slots__ = ("row_id", "label", "draw", "index", "subject", "claim", "root_cause",
                 "anchor", "topic", "bucket", "evidence", "world_field", "disposition",
                 "reason", "stub", "recorded_id", "outcome", "raw")

    row_id: Any
    label: Any
    draw: Any
    index: Any
    subject: Any
    claim: Any
    root_cause: Any
    anchor: Any
    topic: Any
    bucket: Any
    evidence: Any
    world_field: Any
    disposition: Any
    reason: Any
    stub: Any
    recorded_id: Any
    outcome: Any
    raw: Any

    def __init__(self, **kw: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot))


class _Findings:
    """The findings walk's one answer, shared by the verdict tiles, the cards and the findings
    section: the rows, the disposition counts, each label's draw-read report, the failed draws,
    each draw's dropped count, and each heading's group number — the `fg-<n>` a card's footer
    links and the findings section renders are the SAME numbering by construction."""

    __slots__ = ("rows", "counts", "world_reports", "draw_failures", "dropped", "group_index")

    def __init__(self) -> None:
        self.rows: list[_Finding] = []
        self.counts = {"defender": 0, "world_author": 0, "withheld": 0, "unqueueable": 0,
                       "dropped": 0, "never_eligible": 0, "mappings": 0}
        self.world_reports: dict[str, DrawsSkipReport] = {}
        self.draw_failures: list[tuple[str, int, str]] = []
        self.dropped: list[tuple[str, int, int]] = []
        self.group_index: dict[str, int] = {}


class _Episode:
    """One read of the episode directory — everything a section renders, already typed."""

    def __init__(self, episode_dir: Path, manifest: dict[str, Any]) -> None:
        self.dir = episode_dir
        self.manifest = manifest
        self.episode_id = family.episode_id_of(manifest)
        try:
            self.episode_token = episode_token_for(self.episode_id)
        except Exception:  # noqa: BLE001 — a token that cannot be built names no world's ledger; every read below degrades on its own
            self.episode_token = self.episode_id
        # The manifest's world entries, as MAPPINGS: a scalar where the list belongs, or a
        # scalar among the entries, is nothing to render a section for.
        self.manifest_worlds: list[dict[str, Any]] = [
            w for w in _items(manifest.get("worlds")) if isinstance(w, dict)]
        self.control_label: str | None = next(
            (w["world_id"] for w in self.manifest_worlds
             if w.get("role") == "A" and isinstance(w.get("world_id"), str)), None)
        self.grade_rec = _Record()
        self.review_rec = _Record()
        self.samples_rec = _Record()
        self.staged_rec = _Record()
        self.stamp_rec = _Record()
        self.timing_rec = _Record()
        self.entries: dict[str, WorldEntry] = {}
        self.roster_order: list[str] = []
        self.off_roster = 0
        self.archived_world_dirs: list[str] = []
        self.alert: Any = None
        self.draws: dict[str, tuple[dict[int, dict[str, Any]], DrawsSkipReport]] = {}
        #: One leads block per ROSTER label — a `runs/` directory that decomposed to no world
        #: (J7 iv) gets one too, keyed by its full name, so the section reads the same for it.
        self.leads: dict[str, _WorldLeads] = {}
        self.wire = _WireLogs()
        self.findings = _Findings()
        self.total_cost = 0.0
        self.worlds_wall = ""
        self.lower_bound = ""

    @property
    def grade(self) -> Any:
        return self.grade_rec.value

    @property
    def not_graded(self) -> bool:
        """J14: a `not_graded` stamp voids the whole family's word."""
        return self.grade is not None and self.grade.not_graded is not None

    def manifest_world(self, label: str) -> dict[str, Any] | None:
        """The FIRST manifest entry naming `label` — the section's own; the guide renders every
        entry verbatim regardless (J7 iii)."""
        return next((w for w in self.manifest_worlds if w.get("world_id") == label), None)

    def review_block(self, label: str) -> dict[str, Any] | None:
        if not (self.review_rec.ok and isinstance(self.review_rec.value, dict)):
            return None
        return family.world_review_block(self.review_rec.value, label)


# =========================================================================================
# Loading — the one pass over the directory
# =========================================================================================


def load_episode(episode_dir: Path) -> _Episode:
    """Every record the page shows, read once. Raises `JudgeRefused` for the manifest alone
    (d01: the ONE fatal refusal); every other refusal is a slot on the model."""
    episode_dir = Path(episode_dir)
    ep = _Episode(episode_dir, family.raw_manifest(episode_dir))

    ep.grade_rec = _read_grade(episode_dir)
    ep.review_rec = _read_review(episode_dir)
    ep.samples_rec = _read_samples(episode_dir)
    ep.staged_rec = _read_staged(episode_dir)
    ep.stamp_rec = _read_family_stamp(episode_dir)
    ep.timing_rec = _read_timing(episode_dir)

    grade = ep.grade
    grade_rows = [r for r in (_items(grade.worlds) if grade is not None else [])
                  if isinstance(r, dict) and isinstance(r.get("world"), str)]
    worlds_dir = episode_dir / archive.WORLDS_DIRNAME
    if artifact_dir(worlds_dir):
        ep.archived_world_dirs = sorted(
            p.name for p in worlds_dir.iterdir() if artifact_dir(p) and p.name != _FAMILY_LABEL)
    ep.entries, ep.roster_order, ep.off_roster = _build_roster(
        ep, [r["world"] for r in grade_rows], grade_exists=grade is not None)
    for row in grade_rows:
        w = ep.entries.get(row["world"])
        if w is not None:
            w.row = row

    labels = [w["world_id"] for w in ep.manifest_worlds if isinstance(w.get("world_id"), str)]
    ep.alert = episode_alert(episode_dir, labels or ep.archived_world_dirs)

    for label in [*ep.entries, _FAMILY_LABEL]:
        ep.draws[label] = draws_on_disk_report(
            worlds_dir / label / archive.DRAWS_DIRNAME)
    for w in ep.entries.values():
        if w.run_dir_name is not None:
            w.result = _result_event(episode_dir / RUNS_SUBDIR / w.run_dir_name)
        w.archive = _load_world_archive(worlds_dir / w.label)
    for label in ep.roster_order:
        ep.leads[label] = _load_world_leads(ep, label)

    ep.wire = _load_wire_logs(episode_dir / WIRE_LOG_DIR)
    ep.findings = _walk_findings(ep)
    ep.total_cost, ep.worlds_wall, ep.lower_bound = _cost_totals(ep)
    return ep


def _decompose_run_dir(name: str, *, episode_id: str) -> str | None:
    prefix = f"{episode_id}-"
    if name.startswith(prefix) and len(name) > len(prefix):
        return name[len(prefix):]
    return None


def _build_roster(ep: _Episode, grade_row_labels: list[str],  # noqa: C901 — one union-membership decision (manifest ∪ judge.yaml rows ∪ runs/ dirs), the roster every other section keys on
                  *, grade_exists: bool) -> tuple[dict[str, WorldEntry], list[str], int]:
    """Every world label the page must give a section to: manifest worlds ∪ `judge.yaml`
    rows ∪ `runs/` directories that decompose to `<episode_id>-<label>` (#1025 J7/J8).

    Returns the entries by label (manifest order first, then extras), the list of
    undecomposable `runs/` directory FULL NAMES (each gets its own section keyed by that full
    name), and the count of `worlds/` directories that are on neither the manifest nor the
    record (reported on one templated line, never rendered)."""
    entries: dict[str, WorldEntry] = {}
    order: list[str] = []
    runs_dir = ep.dir / RUNS_SUBDIR
    # A manifest world with NEITHER a `judge.yaml` row NOR any archive evidence contributes a
    # section only once the episode has reached RUNS at all — either `runs/` still exists, or a
    # grade landed at some point (and `runs/` was pruned afterward, J8). An episode that never
    # got past REVIEW/STAGING (a rejection, an abort) has neither and has a manifest but no
    # world to show anything about yet (#1025 J7/J8).
    reached_runs = artifact_dir(runs_dir) or grade_exists
    for w in ep.manifest_worlds:
        label = w.get("world_id")
        if not isinstance(label, str):
            continue
        if label not in entries:
            if not reached_runs:
                continue
            entries[label] = WorldEntry(label)
            order.append(label)
        entries[label].in_manifest = True
        # keep the FIRST manifest entry's fields as the section's own; the guide renders every
        # entry verbatim regardless (J7 iii).
        if entries[label].manifest_doc is None:
            entries[label].manifest_doc = w
            entries[label].role = w.get("role") if isinstance(w.get("role"), str) else None

    for label in grade_row_labels:
        if label not in entries:
            entries[label] = WorldEntry(label)
            order.append(label)

    stray_run_dirs: list[str] = []
    if artifact_dir(runs_dir):
        for child in sorted(p.name for p in runs_dir.iterdir() if artifact_dir(p)):
            label = _decompose_run_dir(child, episode_id=ep.episode_id)
            if label is None:
                stray_run_dirs.append(child)
                continue
            if label not in entries:
                entries[label] = WorldEntry(label)
                order.append(label)
            entries[label].run_dir_name = child

    off_roster = sum(1 for name in ep.archived_world_dirs if name not in entries)
    return entries, [*order, *stray_run_dirs], off_roster


def _result_event(run_dir: Path) -> _ResultEvent:
    trace = run_dir / _TOOL_TRACE_NAME
    if not (trace.exists() or trace.is_symlink()):
        return _ResultEvent(None, None, "absent")
    if not artifact_file(trace):
        return _ResultEvent(None, None, "refused")
    rows, _bad = read_jsonl_rows_report(trace)
    if not rows or rows[-1].get("type") != "result":
        return _ResultEvent(None, None, "none")
    last = rows[-1]
    cost = last.get("total_cost_usd")
    duration = last.get("duration_ms")
    wall = float(duration) if isinstance(duration, (int, float)) else None
    if not isinstance(cost, (int, float)) or isinstance(cost, bool) or not math.isfinite(cost) \
            or cost < 0:
        return _ResultEvent(None, wall, "unusable")
    return _ResultEvent(float(cost), wall, "ok")


def _load_world_archive(world_dir: Path) -> _WorldArchive | None:
    if not artifact_dir(world_dir):
        return None
    report_path = world_dir / REPORT_NAME
    report = None
    if report_path.exists() or report_path.is_symlink():
        # The world-archive screen (`read_guarded`: open `O_NOFOLLOW` + `fstat`), not an lstat
        # taken ahead of a bare read — the same one reader the judge's own pass uses for these
        # bytes, so a link planted at the name is refused at the open itself.
        report = family.read_archived_report(report_path)
    inv_path = world_dir / INVESTIGATION_NAME
    return _WorldArchive(
        report=report,
        investigation_present=inv_path.exists() or inv_path.is_symlink(),
        provenance=family.json_mapping(world_dir / PROVENANCE),
        scrub=family.json_mapping(world_dir / archive.SCRUB_VERDICT_NAME))


def _load_world_leads(ep: _Episode, label: str) -> _WorldLeads:  # noqa: C901, PLR0912 — the served ledger, the archive notes and every lead's chain are one world's leads block (#1025 O3)
    leads = _WorldLeads()
    world_dir = ep.dir / archive.WORLDS_DIRNAME / label

    ledger_path = family.world_ledger_path(ep.dir, label, episode_token=ep.episode_token)
    if not (ledger_path.exists() or ledger_path.is_symlink()):
        leads.ledger_note = "served ledger: absent"
    elif not artifact_file(ledger_path):
        leads.ledger_note = "served ledger unreadable"
    else:
        try:
            # `read_jsonl_rows_report` is the shared tolerant reader's own bare `read_text` —
            # it survives a torn line or an undecodable byte but not a permission-denied
            # regular file (root ignores this; a real non-root run does not, #1025), which
            # reaches this call as an un-typed `OSError`. This world's leads block is its own
            # slot, never the whole page.
            _rows, malformed = read_jsonl_rows_report(ledger_path)
            if malformed:
                leads.ledger_note = f"{malformed} malformed row"
        except OSError:
            leads.ledger_note = "served ledger unreadable"

    leads.archived = artifact_dir(world_dir)
    if not leads.archived:
        return leads

    inv_path = world_dir / INVESTIGATION_NAME
    facts = None
    if inv_path.exists() or inv_path.is_symlink():
        try:
            facts = family.read_world_facts(ep.dir, label, episode_token=ep.episode_token)
        except JudgeRefused as bad:
            leads.facts_error = str(bad)
        except Exception as bad:  # noqa: BLE001
            leads.facts_error = str(bad)

    try:
        all_leads = family.leads_by_id(world_dir)
    except Exception:  # noqa: BLE001
        all_leads = {}

    summaries_dir = world_dir / archive.GATHER_SUMMARIES_DIRNAME
    summary_stems = set()
    if artifact_dir(summaries_dir) and not summaries_dir.is_symlink():
        for p in summaries_dir.iterdir():
            if p.suffix == ".md" and artifact_file(p):
                summary_stems.add(p.stem)
            elif not p.name.endswith(".md") and _safe_id(p.stem) is None:
                leads.unnameable_summaries.append(p.stem)

    if facts is not None:
        roster = set(facts.referenced_leads) | summary_stems
        resolutions_by_lead = facts.resolutions_by_lead
        leads.moved = bool(facts.resolution_moved)
    else:
        roster = set(all_leads) | summary_stems
        resolutions_by_lead = {}

    for lead_id in sorted(roster):
        try:
            # `lead_chain`'s own gather-summary read is `errors="replace"` for a BAD byte but
            # a bare `read_text` for a permission-denied file (root ignores this; a real
            # non-root run does not, #1025) — this one lead's row is its own slot, never the
            # whole page.
            chain = family.lead_chain(world_dir, lead_id, resolutions_by_lead, leads=all_leads)
        except OSError:
            chain = None
        leads.chains.append((lead_id, chain))
    return leads


def _load_wire_logs(wire: Path) -> _WireLogs:
    logs = _WireLogs()
    if not artifact_dir(wire):
        return logs
    logs.present = True
    for path in sorted(wire.glob("*.jsonl")):
        name = path.name
        if "_framed_trace" in name:
            if not name.endswith("_framed_trace.jsonl"):
                continue
            stem = name[: -len("_framed_trace.jsonl")] + "_trace"
            trace = logs.traces.setdefault(stem, _Trace(stem))
            trace.framed_present = True
            if artifact_file(path):
                frows, _ = read_jsonl_rows_report(path)
                if frows:
                    trace.framed = frows[0]
            continue
        if not name.endswith("_trace.jsonl"):
            continue
        stem = name[: -len(".jsonl")]
        trace = logs.traces.setdefault(stem, _Trace(stem))
        # `artifact_file` (lstat) ahead of the read: `wire_logs/` sits under the episode dir, a
        # tree a sibling box has an rw bind on (`judge.__init__._write_wire_log`'s own docstring
        # names it), and `read_jsonl_rows_report` is the shared tolerant reader's own bare
        # `is_file()` + `read_text` — unguarded on its own.
        if not artifact_file(path):
            trace.plain = "refused"
            continue
        trace.plain = "ok"
        trace.rows, trace.unreadable = read_jsonl_rows_report(path)
    return logs


def _cost_totals(ep: _Episode) -> tuple[float, str, str]:
    total = 0.0
    walls = []
    for w in ep.entries.values():
        if w.result is None:
            continue
        if w.result.cost is not None:
            total += w.result.cost
        if w.result.wall_ms:
            walls.append(w.result.wall_ms)
    q_cost, q_wall_ms, _qp, _qt = ep.wire.role_cost("questioner")
    j_cost, j_wall_ms, _jp, _jt = ep.wire.role_cost(Step.JUDGE)
    total += q_cost + j_cost
    if walls:
        wall_range = f"{fmt_duration(min(walls))}–{fmt_duration(max(walls))}"
        lower_bound = f"≈ {fmt_duration(q_wall_ms + j_wall_ms + max(walls))} lower bound on wall: model calls + longest world"
    else:
        wall_range = ""
        lower_bound = ""
    return total, wall_range, lower_bound


# =========================================================================================
# The findings walk — run once at load, read by the verdict tiles and the findings section
# =========================================================================================


def _unqueueable_lookup(grade: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in _items(getattr(grade, "unqueueable_findings", None)):
        if not isinstance(line, str) or ": " not in line:
            continue
        coord, reason = line.split(": ", 1)
        parts = coord.rsplit("/", 3)
        if len(parts) == 4:
            _prefix, label, draw, index = parts
            out[f"{label}/{draw}/{index}"] = reason
    return out


def _world_findings_lookup(grade: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in _items(getattr(grade, "world_findings", None)):
        if not isinstance(row, dict):
            continue
        fid = row.get("finding_id")
        if not isinstance(fid, str):
            continue
        parts = fid.rsplit("/", 3)
        if len(parts) == 4:
            _prefix, label, draw, index = parts
            out[f"{label}/{draw}/{index}"] = row
    return out


def _withheld_by_label(grade: Any) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for item in _items(getattr(grade, "withheld_findings", None)):
        if isinstance(item, dict) and isinstance(item.get("world"), str):
            out.setdefault(item["world"], []).append(item)
    return out


def _bump(counts: dict[str, int], disposition: str) -> None:
    key = {"defender": "defender", "world_author": "world_author", "withheld": "withheld",
          "unqueueable": "unqueueable", "never_eligible": "never_eligible"}.get(disposition)
    if key:
        counts[key] += 1


def _finding_fields(finding: dict[str, Any]) -> dict[str, Any]:
    """The row's own fields off one draw finding, as `_Finding` keyword arguments."""
    return {"claim": finding.get("claim"), "root_cause": finding.get("root_cause"),
            "anchor": finding.get("anchor"), "topic": finding.get("topic"),
            "bucket": finding.get("bucket"), "evidence": finding.get("evidence"),
            "world_field": finding.get("world"), "raw": finding}


def _walk_findings(ep: _Episode) -> _Findings:  # noqa: C901, PLR0912, PLR0915
    """Every finding row the page shows, keyed `(label, draw, index)` — the page's own
    disposition rule mirrors `enqueue_report`'s (#1025 amendment 3): the record's own signals
    (`unqueueable_findings`, a world's `withheld_reason`, the family/verdict word) decide each
    row's fate, never a re-run of the enqueue pass itself."""
    out = _Findings()
    rows = out.rows
    counts = out.counts
    grade = ep.grade
    entries = ep.entries
    roster_labels = [*entries, _FAMILY_LABEL]

    for label in roster_labels:
        docs, report = ep.draws[label]
        out.world_reports[label] = report
        for draw, doc in docs.items():
            dropped = _count(doc.get("dropped_findings"))
            if dropped is not None:
                counts["dropped"] += dropped
            if not _items(doc.get("findings")) and doc.get("failure_reason"):
                out.draw_failures.append((label, draw, doc["failure_reason"]))
            elif dropped is not None:
                out.dropped.append((label, draw, dropped))

    if grade is None:
        # No grade record at all: every on-disk finding renders under one group, undisposed.
        for label in roster_labels:
            docs, _report = ep.draws[label]
            for draw, doc in docs.items():
                for index, finding in enumerate(_items(doc.get("findings"))):
                    if not isinstance(finding, dict):
                        continue
                    counts["mappings"] += 1
                    rows.append(_Finding(
                        row_id=f"f-{label}-{draw}-{index}", label=label, draw=draw,
                        index=index, subject=finding.get("subject"),
                        disposition="no_grade", reason=None, stub=False, recorded_id=None,
                        **_finding_fields(finding)))
        out.group_index = _group_numbering(rows)
        return out

    withheld_reasons = {}
    for w in entries.values():
        if w.row is not None and w.row.get("withheld_reason") is not None:
            withheld_reasons[w.label] = w.row["withheld_reason"]
    measuring = {w.label for w in entries.values()
                if w.row is not None and not w.row.get("ungradable")
                and w.row.get("withheld_reason") is None}
    verdict_word = getattr(grade, "verdict_word", None)
    # THROUGH THE OWNER'S NORMALIZER, not a bare `in` (mirroring `enqueue.py`'s own O7 gate,
    # enqueue.py:622): a `verdict_word` that reaches this record any other way than the
    # enqueue pass's own write — case-folded, whitespace differently, a value from an older
    # writer — would otherwise be missed here while the real enqueue pass still blocks it,
    # rendering a finding "enqueued" that the record's own pass never queued (#1025).
    defender_blocked = normalized_judge_outcome(verdict_word) in ("discard", "corpus-contradiction")

    unqueueable = _unqueueable_lookup(grade)
    world_findings_by_coord = _world_findings_lookup(grade)
    seen_coords: set[str] = set()

    def _row_state_of(label: str) -> str | None:
        entry = entries.get(label)
        if label == _FAMILY_LABEL:
            return "family"
        if entry is not None and entry.row is not None:
            return "ungradable" if entry.row.get("ungradable") else "graded"
        if entry is not None and entry.in_manifest:
            return "no_grade_row"
        return None

    def _dispose(label: str, row_state: str, subject: Any, coord: str) -> tuple[str, str | None]:
        return _finding_disposition(
            row_state=row_state, entry=entries.get(label), subject=subject, coord=coord,
            unqueueable=unqueueable, withheld_reasons=withheld_reasons, measuring=measuring,
            defender_blocked=defender_blocked, verdict_word=verdict_word,
            world_findings_by_coord=world_findings_by_coord)

    for label in roster_labels:
        entry = entries.get(label)
        row_state = _row_state_of(label)
        if row_state is None:
            continue

        docs, _report = ep.draws[label]
        for draw, doc in docs.items():
            for index, finding in enumerate(_items(doc.get("findings"))):
                if not isinstance(finding, dict):
                    continue
                counts["mappings"] += 1
                coord = f"{label}/{draw}/{index}"
                seen_coords.add(coord)
                # ABSENT reads as the defender's, exactly as `enqueue_report` reads it
                # (`finding.get("subject", SUBJECT_DEFENDER)`, enqueue.py): the pre-#1007 draw
                # shape carries no `subject` at all, and the real pass queued those as defender
                # findings — a page that read the absence as "names neither channel" contradicted
                # the record's own `enqueued_rows` on the very archive it was built to explain.
                subject = finding.get("subject", SUBJECT_DEFENDER)
                disposition, reason = _dispose(label, row_state, subject, coord)
                _bump(counts, disposition)
                recorded = world_findings_by_coord.get(coord)
                recorded_id = recorded.get("finding_id") if isinstance(recorded, dict) else None
                rows.append(_Finding(
                    row_id=f"f-{label}-{draw}-{index}", label=label, draw=draw, index=index,
                    subject=subject, disposition=disposition, reason=reason, stub=False,
                    recorded_id=recorded_id, outcome=doc.get("episode_outcome"),
                    **_finding_fields(finding)))

        for mech_index, finding in enumerate(
                _items(entry.row.get("mechanical_world_findings")) if entry and entry.row
                else []):
            if not isinstance(finding, dict):
                continue
            coord = f"{label}/mechanical/{mech_index}"
            seen_coords.add(coord)
            counts["mappings"] += 1
            disposition, reason = _dispose(label, row_state, SUBJECT_WORLD, coord)
            _bump(counts, disposition)
            rows.append(_Finding(
                row_id=f"f-{label}-mechanical-{mech_index}", label=label, draw="mechanical",
                index=mech_index, subject=SUBJECT_WORLD, disposition=disposition,
                reason=reason, stub=False, recorded_id=None, **_finding_fields(finding)))

    # Record-only stubs: a recorded coordinate whose draw DOCUMENT is absent (J9b).
    present_docs = {label: set(ep.draws[label][0]) for label in roster_labels}

    for coord, row in world_findings_by_coord.items():
        label, draw_s, index_s = coord.rsplit("/", 2)
        try:
            draw_i = int(draw_s)
        except ValueError:
            draw_i = None
        if draw_i is not None and draw_i in present_docs.get(label, set()):
            continue  # a present document, no stub (the document is the grain, F-5)
        if coord in seen_coords:
            continue
        entry = entries.get(label)
        row_state = ("family" if label == _FAMILY_LABEL else
                    ("ungradable" if entry and entry.row and entry.row.get("ungradable") else
                     ("graded" if entry and entry.row else "no_grade_row")))
        disposition, reason = _dispose(label, row_state, SUBJECT_WORLD, coord)
        counts["mappings"] += 1
        _bump(counts, disposition)
        rows.append(_Finding(
            row_id=f"f-{label}-{draw_s}-{index_s}", label=label, draw=draw_s, index=index_s,
            subject=SUBJECT_WORLD, claim=row.get("finding"), disposition=disposition,
            reason=reason, stub=True, recorded_id=row.get("finding_id")))

    # A recorded withheld entry whose own draw document is present is ALREADY a row above —
    # the record carries the finding whole (`enqueue_report`'s `withheld_findings`, the same
    # mapping the draw document holds), so the join is the finding itself. Only an entry no
    # on-disk withheld row matches gets a record-only stub (J9b's grain is the DOCUMENT): a
    # world whose surviving documents carry two of its four recorded withheld findings shows
    # all four, the two without a document flagged as such, rather than the two that survive.
    on_disk_withheld: dict[str, list[dict[str, Any]]] = {}
    for f in rows:
        if f.disposition == "withheld" and not f.stub:
            on_disk_withheld.setdefault(f.label, []).append(f.raw)
    for label, wlist in _withheld_by_label(grade).items():
        unmatched = list(on_disk_withheld.get(label, []))
        for n, item in enumerate(wlist):
            finding = item.get("finding")
            if not isinstance(finding, dict):
                continue
            if finding in unmatched:
                unmatched.remove(finding)
                continue
            counts["mappings"] += 1
            counts["withheld"] += 1
            rows.append(_Finding(
                row_id=f"f-{label}-withheld-{n}", label=label, draw=None, index=None,
                subject=SUBJECT_DEFENDER, disposition="withheld", reason=item.get("reason"),
                stub=True, recorded_id=finding.get("finding_id"), **_finding_fields(finding)))

    out.group_index = _group_numbering(rows)
    return out


def _group_numbering(rows: list[_Finding]) -> dict[str, int]:
    """Each group heading's `fg-<n>`, numbered by first appearance in row order — the one
    numbering both the findings section and the cards' footers render."""
    return {h: n for n, h in enumerate(dict.fromkeys(_disposition_heading_raw(f) for f in rows),
                                       start=1)}


def _finding_disposition(  # noqa: PLR0913, C901 — the enqueue's own subject/withheld/blocked precedence (#1025 amendment 3), mirrored as one decision
    *, row_state: str, entry: WorldEntry | None, subject: Any, coord: str,
    unqueueable: dict[str, str], withheld_reasons: dict[str, str], measuring: set[str],
    defender_blocked: bool, verdict_word: Any, world_findings_by_coord: dict[str, dict],
) -> tuple[str, str | None]:
    label = coord.split("/", 1)[0]
    if row_state == "ungradable":
        reason = entry.row.get("ungradable_reason") if entry and entry.row else None
        return "world_ungradable", reason
    if row_state == "no_grade_row":
        return "no_grade_row", None
    if subject == SUBJECT_WORLD or row_state == "family":
        if coord in unqueueable:
            return "unqueueable", unqueueable[coord]
        if coord in world_findings_by_coord:
            return "world_author", None
        return "never_on_record", None
    if subject != SUBJECT_DEFENDER:
        if coord in unqueueable:
            return "unqueueable", unqueueable[coord]
        return "unqueueable", f"subject {subject!r} names neither channel"
    if coord in unqueueable:
        return "unqueueable", unqueueable[coord]
    if label in withheld_reasons:
        return "withheld", withheld_reasons[label]
    if defender_blocked and label in measuring:
        return "never_eligible", str(verdict_word)
    return "defender", None


def _disposition_heading_raw(f: _Finding) -> str:
    """The group heading's PLAIN text — never pre-escaped, so the one caller that embeds it
    can escape it exactly once. `f.reason` is a record field folded straight into the literal
    words around it; escaping happens at the render site, not here, so the two passes can
    never compound into a double escape (`&amp;#x27;`, which no HTML parser undoes back to the
    original character)."""
    if f.disposition == "defender":
        return "defender: enqueued"
    if f.disposition == "world_author":
        return "world author: enqueued"
    if f.disposition == "withheld":
        return f"defender: withheld — {_raw(f.reason)}"
    if f.disposition == "unqueueable":
        addressee = "defender" if f.subject == SUBJECT_DEFENDER else "world author"
        return f"{addressee}: unqueueable — {_raw(f.reason)}"
    if f.disposition == "never_eligible":
        return f"defender: never eligible — verdict {_raw(f.reason)}"
    if f.disposition == "world_ungradable":
        return f"not enqueued — world ungradable: {_raw(f.reason)}"
    if f.disposition == "no_grade_row":
        return "not enqueued — no grade row"
    if f.disposition == "never_on_record":
        return "not on the record — never enqueued"
    return "no grade record — not enqueued"


# =========================================================================================
# The rendered document
# =========================================================================================


def _encode_page(html_text: str) -> bytes:
    """The document's bytes (#1025 F-7): `errors="replace"` turns a lone surrogate into the
    encoder's own replacement character, but it leaves a literal NUL untouched — U+0000 encodes
    to a plain 0x00 byte under UTF-8 — so a NUL is substituted with U+FFFD FIRST, on the same
    path as a lone surrogate, and never reaches the guarded write."""
    return html_text.replace("\x00", "�").encode("utf-8", errors="replace")


def _write_page(episode_dir: Path, html_text: str) -> Path:
    page_path = Path(episode_dir) / PAGE_NAME
    write_guarded(page_path, _encode_page(html_text), mode="replace")
    return page_path


def render_episode(episode_dir: Path) -> Path:
    return _write_page(episode_dir, build_page(episode_dir))


def build_page(episode_dir: Path) -> str:
    return _render_document(load_episode(Path(episode_dir)))


def _render_document(ep: _Episode) -> str:
    body = "".join([
        _render_header(ep),
        _render_verdict(ep),
        _render_worlds(ep),
        _render_findings_section(ep),
        _render_stages(ep),
        _render_leads_section(ep),
        _render_records(ep),
    ])
    nav = _render_nav(body)

    title = f"episode — {esc(ep.episode_id)}"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>{CSS}</style></head><body id="top">
<div class="layout">
{nav}
<article class="content">
{body}
</article>
</div>
</body></html>
"""


def _render_nav(body: str) -> str:
    ids = re.findall(r'id="([^"]+)"', body)
    items = []
    for i in ids:
        if i.startswith("world-") or i.startswith("fg-") or i.startswith("sec-"):
            items.append(f'<li><a href="#{esc(i)}">{esc(i)}</a></li>')
    return f'<nav><ul>{"".join(items)}</ul></nav>'


# =========================================================================================
# Header
# =========================================================================================


def _render_header(ep: _Episode) -> str:
    manifest = ep.manifest
    grade = ep.grade
    alert = ep.alert
    rule = alert.get("rule") if isinstance(alert, dict) else None
    rule_name = rule.get("name") if isinstance(rule, dict) else None
    alert_bits = []
    if isinstance(alert, dict) and alert.get("alert_id") is not None and rule_name:
        alert_bits.append(f'<span class="hd-alert">{_uv(rule_name)}</span>')
    else:
        alert_bits.append('<span class="hd-alert">alert rule: not on the record</span>')

    source_run_id = manifest.get("source_run_id")
    branch_message_id = manifest.get("branch_message_id")
    meta_bits = list(alert_bits)
    if isinstance(source_run_id, str):
        meta_bits.append(f'<span class="hd-source">source {_v(source_run_id)}</span>')
    if branch_message_id is not None:
        meta_bits.append(f'<span class="hd-branch">branch message {_v(branch_message_id)}</span>')

    if grade is not None:
        knobs = _mapping(grade.knobs)
        draws = _mapping(grade.draws)
        model = knobs.get("model", "?")
        effort = knobs.get("effort", "?")
        cap = knobs.get("payload_cap", "?")
        configured = draws.get("configured", "?")
        completed = draws.get("completed", "?")
        knob_line = (f"{_v(model)} / {_v(effort)} / cap {_v(cap)} / "
                    f"draws {_v(configured)}/{_v(completed)}")
        meta_bits.append(f'<span class="hd-knobs">{knob_line}</span>')
        if grade.lessons_commit:
            meta_bits.append(f'<span class="hd-commit">{_v(str(grade.lessons_commit)[:8])}</span>')

    meta = '<span class="hd-sep"> · </span>'.join(meta_bits)
    return f"""
<header class="top" id="sec-case">
  <h1>episode {_v(ep.episode_id)}</h1>
  <div class="byline">{meta}</div>
</header>
"""


# =========================================================================================
# Verdict section: band, lede, tiles, cards
# =========================================================================================


def _render_verdict(ep: _Episode) -> str:  # noqa: C901, PLR0912, PLR0915 — the band, lede, four tiles and cards are one section (#1025 O1/O2)
    grade = ep.grade
    if ep.not_graded:
        stamp = grade.not_graded
        band = (f'<div class="vd-band">not graded: '
               f'<span class="vd-reason">{_uv(stamp.reason)}</span></div>')
        return _page_section("sec-verdict", "Verdict", band)

    if not ep.grade_rec.ok:
        band = f'<div class="vd-band">{esc(ep.grade_rec.error)}</div>'
        return _page_section("sec-verdict", "Verdict", band)
    if grade is None:
        band = '<div class="vd-band">no grade record</div>'
        return _page_section("sec-verdict", "Verdict", band)

    entries = ep.entries
    rows = ep.findings.rows
    counts = ep.findings.counts

    lede_parts = []
    family_groups: dict[Any, list[_Finding]] = {}
    for f in rows:
        if f.label == _FAMILY_LABEL and f.disposition != "never_on_record":
            family_groups.setdefault(f.draw, []).append(f)
    family_docs = ep.draws[_FAMILY_LABEL][0]
    for draw in sorted(family_groups, key=lambda d: (isinstance(d, str), d)):
        doc = family_docs.get(draw) if isinstance(draw, int) else None
        outcome = str(doc.get("episode_outcome", "")) if isinstance(doc, dict) else ""
        items = "".join(f'<div class="vd-family-item">{_uv(f.topic)}: {_uv(f.claim)}'
                        f' <span class="vd-outcome">{_uv(outcome)}</span></div>'
                        for f in family_groups[draw])
        lede_parts.append(f'<div class="vd-family-draw">{items}</div>')

    family_failed = getattr(grade, "family_failed_reason", None)
    if family_failed:
        lede_parts.append(f'<div class="vd-family-failed">{_uv(family_failed)}</div>')

    badge_word = getattr(grade, "family_outcome", None) or grade.verdict_word
    queued = grade.enqueued_rows + grade.world_enqueued_rows
    lede_line = (f"{_uv(grade.verdict_word)} · {queued} "
                f"findings queued · {counts['withheld']} withheld")
    if counts["withheld"]:
        first_reason = _first_withheld_reason(rows)
        if first_reason:
            lede_line += f" ({_uv(first_reason)})"
    lede_parts.append(f'<div class="vd-lede">{lede_line}</div>')

    badge = f'<span class="vd-badge">{_uv(badge_word)}</span>'
    meta = f'<span class="vd-meta">{_uv(grade.episode_outcome)} · {_uv(grade.verdict_word)}</span>'

    measuring = {w.label for w in entries.values()
                if w.row is not None and not w.row.get("ungradable")
                and w.row.get("withheld_reason") is None}
    graded = {w.label for w in entries.values()
             if w.row is not None and not w.row.get("ungradable")}
    control_world = ep.manifest_world(ep.control_label) if ep.control_label else None
    control_declared = _normalized_disposition(
        control_world.get("disposition_declared") if control_world else None)
    contrasting = 0
    agree = 0
    for label in measuring:
        row = entries[label].row
        if row is None:
            continue
        if _normalized_disposition(row.get("declared")) != control_declared:
            contrasting += 1
        if row.get("verdict") == row.get("declared"):
            agree += 1
    verdict_note = ("" if grade.verdict_word in _LADDER_WORDS
                    else ' <span class="vd-nonladder">(family outcome, not the ladder)</span>')
    tile1 = (
        f'<div class="vd-tile" id="vd-tile-1">{len(measuring)} of {len(graded)} graded '
        f'measuring · {contrasting} of {len(measuring)} contrast the control · verdict = '
        f'declared on {agree} of {len(measuring)} '
        f'<span class="vd-word">{_uv(grade.verdict_word)}</span>{verdict_note}</div>')

    withheld_captions = []
    for w in entries.values():
        if w.row is None:
            continue
        if w.row.get("ungradable"):
            withheld_captions.append(f"{_v(w.label)} — ungradable")
        elif w.row.get("withheld_reason") is not None:
            withheld_captions.append(f"{_v(w.label)} — {_v(w.row['withheld_reason'])}")
    tile2 = (
        f'<div class="vd-tile" id="vd-tile-2">{len(measuring)} of {len(graded)}'
        f'<div class="vd-caption">{"; ".join(withheld_captions)}</div></div>')

    findings_total = counts["mappings"]
    split_parts = [f"{counts['defender']} defender", f"{counts['world_author']} world author",
                  f"{counts['withheld']} withheld", f"{counts['unqueueable']} unqueueable",
                  f"{counts['dropped']} dropped"]
    if counts["never_eligible"]:
        split_parts.append(f"{counts['never_eligible']} never eligible")
    # THE WALK'S OWN COUNT (J9c) — never `grade.enqueued_rows`, which is the RECORD's figure
    # and is shown, separately, in the queue-accounting details alongside this one.
    tile_queued = counts["defender"] + counts["world_author"]
    tile3 = (
        f'<div class="vd-tile" id="vd-tile-3">{tile_queued} of '
        f'{findings_total} <div class="vd-caption">{" / ".join(split_parts)}</div></div>')

    # The lower-bound label is the STAGES header's own fallback caption — owed whenever there is
    # no REAL wall to compute from: absent (`present=False`) and present-but-unreadable
    # (`ok=False`, the STAGES table's own distinct "timing record unreadable" refusal) both
    # leave this tile with nothing better than the estimate, so both read the same here even
    # though the stage table itself tells the two apart (spec resolution, PR body). With a
    # genuinely readable, non-empty record the header carries the real figure instead, and this
    # tile must not repeat the fallback beside it.
    timing_rec = ep.timing_rec
    bound_html = f'<br>{ep.lower_bound}' if not (timing_rec.ok and timing_rec.value) else ""
    tile4 = (
        f'<div class="vd-tile" id="vd-tile-4">{_money(ep.total_cost)}'
        f'<div class="vd-caption">{ep.worlds_wall}{bound_html}</div></div>')

    cards = []
    for w in entries.values():
        if w.label == ep.control_label or w.row is None or w.row.get("ungradable"):
            continue
        row = w.row
        header = f"{_v(row.get('declared'))} → {_v(row.get('verdict'))}"
        heading = (_v(row.get("withheld_reason")) if row.get("withheld_reason") is not None
                  else _v(row.get("bucket")))
        chip_bits = "".join(f'<span class="vd-chip">{_v(k)}={_v(row.get(k))}</span>'
                           for k in _CHIP_FIELDS if k in row)
        reach = ep.review_block(w.label)
        envelope_note = ""
        if isinstance(reach, dict) and reach.get("envelope_failed"):
            first_line = str(reach["envelope_failed"]).splitlines()[0]
            envelope_note = f'<div class="vd-envelope">{_uv(first_line)}</div>'
        # The footer counts this world's DEFENDER rows and links the group its first one sits
        # in — the same rows, so the count and the anchor cannot name different things; a
        # world-author row that happens to come first in the walk is not what "N findings ·
        # enqueued" is about.
        world_group = [f for f in rows if f.label == w.label and f.subject == SUBJECT_DEFENDER]
        n_findings = len(world_group)
        if row.get("withheld_reason") is not None:
            footer_word = "withheld"
        elif world_group and all(f.disposition == "never_eligible" for f in world_group):
            footer_word = "never eligible"
        else:
            footer_word = "enqueued"
        group_n = (ep.findings.group_index.get(_disposition_heading_raw(world_group[0]), 1)
                   if world_group else 1)
        off_roster_note = ("" if w.in_manifest or w.run_dir_name is not None
                          else '<div class="vd-off-roster">not in the manifest</div>')
        cards.append(
            f'<div class="vd-cause">{_uv(w.label)} {header} {heading}{off_roster_note}'
            f'{chip_bits}{envelope_note}'
            f'<a href="#fg-{group_n}">{n_findings} findings · {footer_word}</a>'
            f'</div>')

    discard = getattr(grade, "discard_evidence", None)
    discard_html = ""
    if discard:
        pointer = discard.get("review_pointer") if isinstance(discard, dict) else None
        if pointer:
            discard_html = f'<div class="vd-discard">{_uv(pointer)}</div>'

    body = (f'<div class="vd-band">{badge}{meta}</div>'
           f'{"".join(lede_parts)}{tile1}{tile2}{tile3}{tile4}'
           f'<div class="vd-cards">{"".join(cards)}</div>{discard_html}'
           f'{_render_queue_accounting(grade, counts, rows)}')
    return _page_section("sec-verdict", "Verdict", body)


def _normalized_disposition(value: Any) -> Any:
    """A declared/verdict disposition through the vocabulary's own normalizer, for the tile's
    control-contrast count — the raw value where it is not a string the normalizer knows."""
    if not isinstance(value, str):
        return value
    try:
        from defender._vocab import normalized_disposition
        return normalized_disposition(value) or value
    except Exception:  # noqa: BLE001
        return value


def _render_queue_accounting(grade: Any, counts: dict[str, int], rows: list[_Finding]) -> str:
    lines = [
        f'defender: {grade.enqueued_rows} enqueued to {_uv(grade.enqueued_to)}',
        f'questioner: {grade.world_enqueued_rows} enqueued to {_uv(grade.world_enqueued_to)}',
        f'withheld {counts["withheld"]} ({_v(_first_withheld_reason(rows))})',
        f'unqueueable {counts["unqueueable"]}',
        f'malformed {grade.queue_malformed_rows} / {grade.world_queue_malformed_rows}',
        f'dropped {counts["dropped"]}',
        f'family malformed replies {grade.family_malformed_replies}',
    ]
    discard = getattr(grade, "discard_evidence", None)
    if discard and isinstance(discard, dict) and discard.get("review_pointer"):
        lines.append(_uv(discard["review_pointer"]))
    record_vs_page = f'record: {grade.enqueued_rows} enqueued · page found: {counts["defender"]}'
    if grade.enqueued_rows != counts["defender"]:
        record_vs_page += (f' <span class="vd-disagree">record and page disagree by '
                          f'{abs(grade.enqueued_rows - counts["defender"])}</span>')
    lines.append(record_vs_page)

    recorded_withheld = len(_items(getattr(grade, "withheld_findings", None)))
    matched = min(recorded_withheld, counts["withheld"])
    withheld_line = f'withheld list: {recorded_withheld} entries · {matched} matched'
    if recorded_withheld != counts["withheld"]:
        withheld_line += (f' <span class="vd-disagree">record and page disagree by '
                         f'{abs(recorded_withheld - counts["withheld"])}</span>')
    lines.append(withheld_line)

    for line in _items(getattr(grade, "unqueueable_findings", None)):
        lines.append(_uv(str(line)))

    return f'<details class="vd-acct"><summary>Queue accounting</summary>' \
          f'{"".join(f"<div>{line_}</div>" for line_ in lines)}</details>'


def _first_withheld_reason(rows: list[_Finding]) -> str | None:
    for f in rows:
        if f.disposition == "withheld":
            return f.reason
    return None


# =========================================================================================
# Worlds section
# =========================================================================================


def _render_worlds(ep: _Episode) -> str:
    guide_rows = []
    for w in ep.manifest_worlds:
        label = w.get("world_id")
        if not isinstance(label, str):
            guide_rows.append(_unnameable(str(label), what="world label"))
            continue
        safe = _safe_id(label)
        if safe is None:
            guide_rows.append(_unnameable(label, what="world label"))
            continue
        declared = _declared_for(label, w, ep.entries)
        if label == ep.control_label:
            guide_rows.append(f'<div class="vd-guide-row">{esc(label)} — '
                             f'the branch point untouched, not graded · {_v(declared)}</div>')
            continue
        axis = w.get("axis")
        axis_html = (f'<q class="verbatim">{_uv(axis)}</q>' if isinstance(axis, str)
                    else "<em>null</em>")
        guide_rows.append(f'<div class="vd-guide-row">{esc(label)} '
                         f'({esc(str(w.get("role")))}) {_v(declared)} {axis_html}</div>')

    sections = [_render_one_world(ep, label) for label in ep.roster_order]

    body = f'<div class="vd-guide">{"".join(guide_rows)}</div>{"".join(sections)}'
    return _page_section("sec-worlds", f"Worlds ({len(ep.entries)})", body)


def _declared_for(label: str, manifest_world: dict[str, Any],
                  entries: dict[str, WorldEntry]) -> Any:
    entry = entries.get(label)
    if entry is not None and entry.row is not None and entry.row.get("declared") is not None:
        return entry.row["declared"]
    return manifest_world.get("disposition_declared")


def _render_one_world(ep: _Episode, label: str) -> str:  # noqa: C901, PLR0912, PLR0915 — one world's whole section (state, ladder, chips, archive, review) is one demand (#1025 J7/J8/J16)
    safe = _safe_id(label)
    if safe is None:
        return _unnameable(label, what="world directory")
    entry = ep.entries.get(label)
    if entry is None:
        # A `runs/` directory whose name did not decompose into `<episode_id>-<label>` (J7
        # iv) — it is not a world at all, so it gets a minimal section keyed on its own full
        # name rather than the normal record-driven rendering.
        link = f"{RUNS_SUBDIR}/{label}/runtime.html"
        return (f'<div id="world-{esc(safe)}" class="w-section">'
               f'<span class="w-name">{_v(label)}</span>'
               f'<div class="w-state">not declared in the manifest</div>'
               f'<a href="{esc(link)}">runtime</a></div>')
    grade = ep.grade
    # J14: a `not_graded` stamp voids the whole family's word, so every world's RECORD-derived
    # state (the ladder, the bucket, the withheld reason) is exactly what an episode with no
    # grade at all shows — "not graded" — even though the row is still physically on the
    # document; the run-dir/archive-derived parts below are unaffected.
    row = None if ep.not_graded else entry.row
    bits = []
    if grade is not None and not ep.not_graded and row is None and not entry.in_manifest \
            and entry.run_dir_name is None:
        bits.append('<div class="w-state">not in the manifest</div>')

    _docs, draws_report = ep.draws[label]
    if draws_report.unreadable:
        bits.append(f'<div class="w-unreadable">{draws_report.unreadable} draw documents '
                   f'unreadable</div>')
    if draws_report.skipped:
        bits.append(f'<div class="w-skipped">{draws_report.skipped} skipped</div>')

    manifest_world = ep.manifest_world(label)
    if row is None:
        bits.append('<div class="w-state">not graded</div>')
        if manifest_world is not None:
            declared = _declared_for(label, manifest_world, ep.entries)
            bits.append(f'<div class="w-declared">{_v(declared)}</div>')
    elif row.get("ungradable"):
        bits.append('<div class="w-state">ungradable</div>')
        bits.append(f'<div class="w-reason">{_uv(row.get("ungradable_reason"))}</div>')
    elif row.get("withheld_reason") is not None:
        bits.append('<div class="w-state">withheld</div>')
        bits.append(f'<div class="w-reason">{_v(row["withheld_reason"])}</div>')
        bits.append(_ladder_html(row))
    else:
        bits.append(f'<div class="w-verdict">{_v(row.get("verdict"))}</div>')
        bits.append(_ladder_html(row))

    bits.append(_chip_html(row, ep.review_block(label)))

    if manifest_world is not None:
        axis = manifest_world.get("axis")
        if isinstance(axis, str):
            bits.append(f'<div class="w-axis"><q class="verbatim">{_uv(axis)}</q></div>')

    result = entry.result
    if result is not None:
        link = f"{RUNS_SUBDIR}/{entry.run_dir_name}/runtime.html"
        bits.append(f'<a href="{esc(link)}">runtime</a>')
        if result.state == "ok" and result.cost is not None:
            bits.append(f'<span class="w-cost">{_money(result.cost)}</span>')
            if result.wall_ms:
                bits.append(f'<span class="w-wall">{fmt_duration(result.wall_ms)}</span>')
        elif result.state == "refused":
            bits.append('<span class="w-cost">no result event (refused)</span>')
        else:
            bits.append('<span class="w-cost">no result event</span>')
    else:
        bits.append('<div class="w-archive">run directory absent</div>')

    archived = entry.archive
    if archived is None:
        bits.append('<div class="w-archive">not archived</div>')
    else:
        if archived.report is None:
            bits.append('<div class="w-archive">not archived</div>')
        else:
            headline = archived.report.disposition_or_unknown
            if archived.report.disposition is None and archived.report.reason:
                # No headline: the reader's own reason (a refused entry at the name, a
                # frontmatter that did not parse, a disposition outside the vocabulary) is the
                # slot's answer, beside the placeholder.
                headline += f" — {archived.report.reason}"
            bits.append(f'<div class="w-report">{_v(headline)}</div>')
        if not archived.investigation_present:
            bits.append('<div class="w-archive">not archived</div>')
        if archived.provenance is not None:
            bits.append(f'<div class="w-prov">{_v(archived.provenance.get("commit"))}</div>')
        else:
            bits.append('<div class="w-prov">absent</div>')
        if archived.scrub is None:
            bits.append('<div class="w-scrub">not recorded</div>')
        else:
            bits.append(f'<div class="w-scrub">{_v(archived.scrub)}</div>')

    review_rec = ep.review_rec
    review_worlds = review_rec.value.get("worlds") if review_rec.ok and isinstance(
        review_rec.value, dict) else None
    review_entry = review_worlds.get(label) if isinstance(review_worlds, dict) else None
    if not review_rec.ok:
        bits.append('<div class="w-review">review block unreadable</div>')
    elif review_entry is None:
        bits.append('<div class="w-review">no review record for this world</div>')

    return f'<div id="world-{esc(safe)}" class="w-section">{"".join(bits)}</div>'


def _ladder_html(row: dict[str, Any]) -> str:
    bits = []
    for field in _LADDER_FIELDS:
        if field == "verdict":
            bits.append(f'<span class="w-ladder">verdict = declared: '
                       f'{_v(row.get("verdict"))} == {_v(row.get("declared"))}</span>')
            continue
        if field not in row:
            continue
        val = row.get(field)
        bits.append(f'<span class="w-ladder">{esc(field)} = {_v(val)}</span>')
        if field == "doctored_answer_served" and row.get("holding_queried"):
            # `has_refused` is asked only where a world actually got a HOLDING answer (#1025
            # J16) — a withheld world never reaches this arm. The CAVEAT ("unrecorded") is the
            # not-doctored branch's own answer for a row that never stored the flag; on the
            # doctored branch the flag is not applicable and the row's own silence is never
            # invented into that caveat's wording.
            if "has_refused" in row:
                bits.append(f'<span class="w-ladder">has_refused = {_v(row["has_refused"])}</span>')
            elif val is False:
                bits.append('<span class="w-ladder">has_refused unrecorded</span>')
            else:
                bits.append('<span class="w-ladder">has_refused not applicable (doctored)</span>')
    bucket = row.get("bucket")
    if bucket:
        cls = _BUCKET_CLASS.get(bucket, "bucket-other")
        bits.append(f'<span class="w-bucket {cls}">{_v(bucket)}</span>')
    return "".join(bits)


def _chip_html(row: dict[str, Any] | None, reach: dict[str, Any] | None) -> str:
    bits = []
    for field in _CHIP_FIELDS:
        if row is not None and field in row:
            bits.append(f'<span class="w-chip">{esc(field)}: {_v(row[field])}</span>')
        elif (field in _REACH_ONLY_CHIP_FIELDS or row is None) \
                and isinstance(reach, dict) and field in reach:
            # `envelope_ran` is NEVER a row field at all, on any row shape — it is always
            # sourced from reach when present, row or no row. The other capture-measurement
            # fields fall back to reach ONLY when there is no row at all (the control; an
            # ungraded world): a row that EXISTS but omits one of THEM (a pre-#1007 shape, an
            # ungradable row's bound slots) reads "unrecorded" rather than silently falling
            # back to a different record's value (#1025 J16 d).
            bits.append(f'<span class="w-chip">{esc(field)}: {_v(reach[field])}</span>')
        elif row is None and field in _ROW_ONLY_CHIP_FIELDS:
            # No row and no review-derived source for this field either (it is never on a
            # reachability block) — there is nothing to say "unrecorded" ABOUT, so the chip is
            # simply absent rather than a promise this world was ever measured for it.
            continue
        else:
            bits.append(f'<span class="w-chip">{esc(field)}: unrecorded</span>')
    if isinstance(reach, dict) and reach.get("envelope_ran") is False and reach.get("envelope_failed"):
        first_line = str(reach["envelope_failed"]).splitlines()[0]
        bits.append(f'<div class="w-envelope">{_uv(first_line)}</div>')
    return "".join(bits)


# =========================================================================================
# Findings section
# =========================================================================================


def _finding_row_html(f: _Finding) -> str:  # noqa: C901 — one row's worth of optional fields, each independently absent
    bits = [f'<span class="fr-world">{_uv(f.label)}</span>']
    if f.bucket is not None:
        cls = _BUCKET_CLASS.get(f.bucket, "bucket-other")
        bits.append(f'<span class="fr-bucket {cls}">{_uv(f.bucket)}</span>')
    if f.subject is not None:
        bits.append(f'<span class="fr-subject">{_uv(f.subject)}</span>')
    if f.stub:
        bits.append('<div class="fr-stub">draw document absent</div>')
        if f.claim:
            bits.append(f'<div class="fr-claim">{_uv(f.claim)}</div>')
    else:
        if f.claim is not None:
            bits.append(f'<div class="fr-claim">{_uv(f.claim)}</div>')
        if f.root_cause is not None:
            bits.append(f'<div class="fr-root">{_uv(f.root_cause)}</div>')
        if f.anchor is not None:
            bits.append(f'<span class="fr-anchor">{_uv(f.anchor)}</span>')
        if f.topic is not None:
            bits.append(f'<span class="fr-topic">{_uv(f.topic)}</span>')
        for e in _items(f.evidence):
            bits.append(f'<span class="fr-evidence">{_uv(e)}</span>')
        if f.world_field is not None:
            bits.append(f'<span class="fr-world-field">{_uv(f.world_field)}</span>')
    if f.recorded_id is not None:
        bits.append(f'<span class="fr-recorded-id">{_uv(f.recorded_id)}</span>')
    if f.outcome is not None:
        # J10: the draw's own `episode_outcome` word, bound beside its findings.
        bits.append(f'<span class="fr-outcome">{_v(f.outcome)}</span>')
    # The row's own id embeds its world LABEL verbatim (`f-<label>-<draw>-<index>`); a label
    # that fails the id grammar must never reach an attribute, so such a row renders with no
    # id at all rather than the raw label smuggled into one (#1025 J5).
    id_attr = f' id="{esc(f.row_id)}"' if _safe_id(f.label) else ""
    # Joined with a real space, not "": two adjacent inline `<span>`s with nothing between them
    # let the test harness's whitespace-collapsing `text()` glue their words into one token —
    # which is how an unrelated world label ending in "...session" and a bucket value starting
    # "analyze..." produced the literal substring "nan" on the page (#1025).
    return f'<div{id_attr} class="fr-row">{" ".join(bits)}</div>'


def _render_findings_body(findings: _Findings) -> str:
    groups: dict[str, list[_Finding]] = {}
    for f in findings.rows:
        groups.setdefault(_disposition_heading_raw(f), []).append(f)

    parts = []
    for heading, group_rows in groups.items():
        rows_html = "".join(_finding_row_html(f) for f in group_rows)
        n = findings.group_index[heading]
        parts.append(f'<details id="fg-{n}" class="fg"><summary>{_uv(heading)}</summary>'
                    f'{rows_html}</details>')
    body = "".join(parts)

    dropped_bits = []
    for label, draw, dropped in findings.dropped:
        dropped_bits.append(f'<div class="fr-dropped">draw {_v(draw)} of {_v(label)}: '
                           f'{_v(dropped)} dropped</div>')
    for label, draw, failure_reason in findings.draw_failures:
        dropped_bits.append(f'<div class="fr-dropped">draw {_v(draw)} of {_v(label)}: '
                           f'{_uv(failure_reason)} —</div>')
    body += "".join(dropped_bits)

    unreadable_total = sum(r.unreadable for r in findings.world_reports.values())
    skipped_total = sum(r.skipped for r in findings.world_reports.values())
    if unreadable_total:
        body += f'<div class="fr-unreadable">{unreadable_total} draw documents unreadable</div>'
    if skipped_total:
        body += f'<div class="fr-skipped">{skipped_total} skipped</div>'
    return body


def _render_findings_section(ep: _Episode) -> str:
    if ep.not_graded:
        return _page_section("sec-findings", "Findings (0)", "")
    body = _render_findings_body(ep.findings)
    if ep.off_roster:
        body += (f'<div class="fr-off-roster">{ep.off_roster} entries under worlds/ are not on '
                f'the record</div>')
    n = len(ep.findings.rows)
    return _page_section("sec-findings", f"Findings ({n})", body)


# =========================================================================================
# Stages section
# =========================================================================================


def _render_stages(ep: _Episode) -> str:  # noqa: C901, PLR0912, PLR0915 — the stage table, the two clocks and every trace block are one section (#1025 O4)
    timing_rec = ep.timing_rec
    rows_by_step: dict[str, list[dict[str, Any]]] = {}
    if timing_rec.ok:
        for row in timing_rec.value or []:
            rows_by_step.setdefault(row["step"], []).append(row)
    q_cost, q_wall_ms, q_priced, q_calls = ep.wire.role_cost("questioner")
    j_cost, j_wall_ms, j_priced, j_calls = ep.wire.role_cost(Step.JUDGE)
    review_total, review_calls = ep.wire.comparator_cost()

    table_rows = []
    header_walls: list[tuple[str, str]] = []
    for step in STEPS:
        entries_for_step = rows_by_step.get(str(step), [])
        if timing_rec.error:
            wall_text = ""
        elif entries_for_step:
            walls = [(r, _wall_between(r["started_at"], r["ended_at"])) for r in entries_for_step]
            durations = [d for _r, d in walls if d is not None]
            # Only a NON-INVERTED pair feeds either span: an inverted row (`d < 0`,
            # `_wall_between`'s own sentinel) already shows "—" in its own cell rather than a
            # number, and letting its untrustworthy pair still widen or narrow min(start)/
            # max(end) would silently corrupt the one aggregate the row's own display just
            # refused to state (#1025 p5). A ZERO-length pair is not inverted: the clock stamps
            # whole seconds (`now_iso()`), so a step that starts and ends within one is a real
            # step whose endpoints belong in the span.
            trusted = [r for r, d in walls if d is not None and d >= 0]
            header_walls.extend((r["started_at"], r["ended_at"]) for r in trusted)
            if durations:
                # The row's own wall is its FIRST entry's start to its LAST entry's end (J15) —
                # never a sum, which double-counts a repeated step's own reported span — over
                # the same trusted pairs the header uses.
                wall_text = fmt_duration(_wall_span([r["started_at"] for r in trusted],
                                                    [r["ended_at"] for r in trusted]))
            else:
                wall_text = "—"
            if len(entries_for_step) > 1:
                wall_text += f" ({len(entries_for_step)} entries)"
        else:
            wall_text = "not on the record"
        if str(step) == "questioner":
            cost_text = _role_cost_text(q_cost, q_wall_ms, q_priced, q_calls)
        elif str(step) == Step.JUDGE:
            cost_text = _role_cost_text(j_cost, j_wall_ms, j_priced, j_calls)
        elif str(step) == "review":
            cost_text = f"{_money(review_total)}" if review_calls else "no model calls"
        elif str(step) == "runs":
            # The RUNS step's own row names no model calls — its cost lives on the per-run
            # sub-rows below, which are not "no model calls" (they are model calls the worlds
            # themselves spent); the step row itself carries only its wall.
            cost_text = ""
        else:
            cost_text = "no model calls"
        table_rows.append(f'<div class="st-row">{esc(str(step))} {esc(wall_text)} '
                         f'{esc(cost_text)}</div>')

    if timing_rec.error:
        table = (f'<div class="st-error">{esc(timing_rec.error)}</div>'
               + "".join(table_rows))
        header_wall_text = ""
    elif header_walls:
        starts = [s for s, _ in header_walls]
        ends = [e for _, e in header_walls]
        header_wall_text = fmt_duration(_wall_span(starts, ends))
        table = "".join(table_rows)
    else:
        header_wall_text = ep.lower_bound
        table = '<div class="st-caption">model-call time — no timing record</div>' + "".join(table_rows)

    # `ep.total_cost` already sums the worlds' results PLUS questioner and judge traces —
    # adding `q_cost`/`j_cost` again here would double them.
    grand_total = ep.total_cost + review_total
    # No line at all — not "$0.0000" — when nothing anywhere priced: a launcher-produced
    # episode with no trace files owes no total any more than its own rows owe one (#1025,
    # matching the runs section's own `any_costed` guard just below).
    if q_calls or j_calls or review_calls or ep.total_cost:
        table += (f'<div class="st-total">{_money(grand_total)} — excludes gather subagents and '
                f'the review gate</div>')

    runs_rows = []
    runs_total = 0.0
    any_costed = False
    for w in ep.entries.values():
        result = w.result
        if result is None:
            continue
        if result.state == "ok" and result.cost is not None:
            any_costed = True
            runs_total += result.cost
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} {_money(result.cost)} '
                            f'{fmt_duration(result.wall_ms) if result.wall_ms else ""} '
                            f'<span class="rn-launcher">result event</span></div>')
        elif result.state == "refused":
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} '
                            f'no result event (refused)</div>')
        elif result.state == "unusable":
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} '
                            f'unusable result event</div>')
        elif result.state == "absent":
            # No `tool_trace.jsonl` at all — a launcher-produced run that never wrote one, not
            # a sibling whose trace simply lacks a terminal result row (#1025). "no result
            # event" implies a trace WAS read; here nothing was there to read at all, so the
            # row reads the same words the questioner/judge steps use for the same absence.
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} no cost recorded</div>')
        else:
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} no result event</div>')
    launcher_runs_row = rows_by_step.get("runs", [])
    if launcher_runs_row:
        d = _wall_between(launcher_runs_row[0]["started_at"], launcher_runs_row[0]["ended_at"])
        if d is not None:
            runs_rows.insert(0, f'<div class="rn-launcher-wall">{fmt_duration(d)} launcher</div>')
    if any_costed:
        runs_rows.append(f'<div class="rn-total">{_money(runs_total)}</div>')

    # Only these four steps carry their own id (`stage-timing` covers the whole table already,
    # and neither `staging` nor `verify` is a surface any test — or operator — addresses on
    # its own): `staging`/`verify` render their row inline with no wrapper id.
    stages_id_map = {"questioner": "stage-questioner", "runs": "stage-runs",
                     Step.JUDGE: "stage-judge", "review": "stage-review"}
    stage_blocks = []
    for step in STEPS:
        content = table_rows[list(STEPS).index(step)]
        extra = "".join(runs_rows) if str(step) == "runs" else ""
        anchor = stages_id_map.get(str(step))
        id_attr = f' id="{esc(anchor)}"' if anchor else ""
        stage_blocks.append(f'<div{id_attr} class="stage-block">{content}{extra}'
                           f'{_transcript_blocks_for_step(ep, str(step))}'
                           f'</div>')

    timing_block = f'<div id="stage-timing" class="stage-timing">{table}</div>'
    unattributed = _unattributed_traces(ep)
    unattributed_html = ""
    if unattributed:
        unattributed_html = (f'<div class="st-unattributed">unattributed traces: '
                            f'{", ".join(esc(n) for n in unattributed)}</div>')

    if timing_rec.error or not header_walls:
        header_line = f'<div class="hd-lower-bound">{esc(ep.lower_bound)}</div>'
    else:
        header_line = (f'<div class="hd-wall">{esc(header_wall_text)} — the launcher\'s wall '
                      f'from the first step\'s start to the last step\'s end; excludes '
                      f'preflight and the prime, includes the gaps between steps</div>')

    body = f'{header_line}{timing_block}{"".join(stage_blocks)}{unattributed_html}'
    return _page_section("sec-stages", "Stages (6)", body)


def _role_cost_text(cost: float, wall_ms: float, priced: int, calls: int) -> str:
    if not calls:
        return "no cost recorded"
    if priced < calls:
        return (f"{_money(cost)} · {calls} traces · {fmt_duration(wall_ms)} · "
                f"partial — {priced} of {calls} calls priced")
    return f"{_money(cost)} · {calls} traces · {fmt_duration(wall_ms)}"


def _wall_between(start: str, end: str) -> float | None:
    """The pair's wall in ms: `None` where either stamp does not parse, `-1` where the pair is
    INVERTED (the end precedes the start), the plain delta — zero included — otherwise."""
    from defender._clock import parse_iso_utc
    a, b = parse_iso_utc(start), parse_iso_utc(end)
    if a is None or b is None:
        return None
    delta = (b - a).total_seconds() * 1000
    return delta if delta >= 0 else -1


def _wall_span(starts: list[str], ends: list[str]) -> float:
    from defender._clock import parse_iso_utc
    parsed_starts = [d for s in starts if (d := parse_iso_utc(s)) is not None]
    parsed_ends = [d for e in ends if (d := parse_iso_utc(e)) is not None]
    if not parsed_starts or not parsed_ends:
        return 0.0
    return (max(parsed_ends) - min(parsed_starts)).total_seconds() * 1000


def _unattributed_traces(ep: _Episode) -> list[str]:
    """Every `judge_*_trace.jsonl` stem that names no roster label or `family` (O4: its cost is
    still priced into the judge row; only the transcript BLOCK is withheld). Membership goes
    through `_stem_names_label`, the same digit-only-remainder check `_transcript_blocks_for_step`
    uses to route a KNOWN label's own draws — not a `range(N)`-bounded set of literal stems,
    which silently misclassified every draw at or past its bound as unattributed."""
    known_labels = [*ep.entries, _FAMILY_LABEL]
    return [stem for stem in ep.wire.plain_stems(agent_prefix="judge_")
            if not any(_stem_names_label(stem, label) for label in known_labels)]


def _transcript_blocks_for_step(ep: _Episode, step: str) -> str:  # noqa: C901 — one discovery pass per role, family-first ordering included (#1025 J13c)
    if step not in ("questioner", Step.JUDGE, "review") or not ep.wire.present:
        return ""
    blocks = []
    if step == "questioner":
        for stem in sorted(ep.wire.stems_for("questioner")):
            blocks.append(_transcript_block(ep.wire.traces[stem]))
    elif step == Step.JUDGE:
        # Family first (J13c/d29), then each roster world in numeric draw order. A launcher-
        # produced episode writes only the FRAMED twin for a judge call (no plain trace), so
        # the stem set is the union of both — never just the plain trace files' own names.
        judge_stems = ep.wire.stems_for(Step.JUDGE)
        family_stems = sorted((s for s in judge_stems if _stem_names_label(s, _FAMILY_LABEL)),
                              key=lambda s: _draw_key_stem(s, _FAMILY_LABEL))
        for stem in family_stems:
            blocks.append(_transcript_block(ep.wire.traces[stem]))
        for label in sorted(ep.entries):
            # `_stem_names_label`, not a bare `startswith`: two roster labels where one is the
            # other's own prefix (`baseline` / `baseline_2`, both legal under `is_valid_run_id`,
            # `_` included) would otherwise have `baseline`'s filter admit `baseline_2`'s own
            # stems too — the SAME transcript rendered twice, once misattributed to the wrong
            # world's block (#1025).
            label_stems = sorted((s for s in judge_stems if _stem_names_label(s, label)),
                                 key=lambda s: _draw_key_stem(s, label))
            for stem in label_stems:
                blocks.append(_transcript_block(ep.wire.traces[stem]))
    elif step == "review":
        for stem in ep.wire.plain_stems(agent_prefix="comparator_"):
            trace = ep.wire.traces[stem]
            if trace.plain != "ok":
                continue
            if trace.rows:
                blocks.append(_transcript_block(trace))
            else:
                # J13b: an empty comparator trace prices nothing and is listed by stem rather
                # than rendered as a stream with no rows.
                blocks.append(f'<div class="tx-note">{esc(stem)}: 0 rows</div>')
    return "".join(blocks)


def _stem_names_label(stem: str, label: str) -> bool:
    """Does `stem` (`judge_<label>_<n>_trace`) name a draw of `label` ITSELF — never a
    DIFFERENT label that merely has `label` as its own string prefix (#1025). `judge_baseline_`
    is a prefix of `judge_baseline_2_3_trace` too, so a bare `startswith` would have world
    `baseline`'s filter admit world `baseline_2`'s own stems — both legal labels under
    `is_valid_run_id`, `_` included. The remainder between the prefix and `_trace` must be the
    draw index's OWN digit spelling, with nothing else in it."""
    prefix = f"judge_{label}_"
    if not stem.startswith(prefix):
        return False
    return stem[len(prefix):-len("_trace")].isdigit()


def _draw_key_stem(stem: str, label: str) -> int:
    prefix = f"judge_{label}_"
    if not stem.startswith(prefix):
        return 0
    try:
        return int(stem[len(prefix):-len("_trace")])
    except ValueError:
        return 0


def _message_parts(row: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    """A wire row's `message` mapping and its `parts` list — each the empty value where the
    row does not carry that shape."""
    msg = _mapping(row.get("message"))
    return msg, _items(msg.get("parts"))


def _transcript_block(trace: _Trace) -> str:  # noqa: C901, PLR0912 — one call's request/response rendering, every response field independently absent
    rows = trace.rows
    framed = trace.framed

    agent_id = None
    if isinstance(framed, dict) and isinstance(framed.get("agent_id"), str):
        agent_id = framed["agent_id"]
    else:
        for row in rows:
            if isinstance(row.get("agent_id"), str):
                agent_id = row["agent_id"]
                break
    entries_html = [f'<div class="tx-label">{_v(agent_id)}</div>'] if agent_id else []
    has_plain_response = any(r.get("kind") == "response" for r in rows)
    # THE REQUEST HALF — the framed prompt, or (no framed twin) the plain trace's own request
    # row — is its own element, never counted among the `tx-entry` response entries below.
    if framed is not None:
        prompt = framed.get("prompt")
        failure = framed.get("failure")
        reply = framed.get("reply")
        entries_html.append(f'<div class="tx-request">{_uv(prompt)}</div>')
        if failure:
            entries_html.append(f'<div class="tx-failure">{_uv(failure)}</div>')
        elif reply and not has_plain_response:
            # A launcher-produced episode writes ONLY the framed twin for a judge call — no
            # `model`/`usage`/`duration_ms` live on this record shape (#1025), so the reply
            # renders as a bare response entry. When a plain trace's own response row is ALSO
            # on disk, that row is the metadata-bearing one the loop below renders, and the
            # framed twin's bare `reply` is the same call's text said twice — skipped here.
            entries_html.append(f'<div class="tx-entry">{_uv(reply)}</div>')
    else:
        request = next((r for r in rows if r.get("kind") == "request"), None)
        if request is not None:
            msg, parts = _message_parts(request)
            instructions = msg.get("instructions")
            prompt_text = ""
            for part in parts:
                if isinstance(part, dict) and part.get("part_kind") == "user-prompt":
                    prompt_text = part.get("content") or ""
            entries_html.append(f'<div class="tx-request">{_uv(prompt_text)}'
                               f'<details><summary>instructions</summary>'
                               f'{_uv(instructions)}</details></div>')

    for row in rows:
        if row.get("kind") != "response":
            continue
        model = row.get("model")
        usage = row.get("usage")
        duration = row.get("duration_ms")
        _msg, parts = _message_parts(row)
        text = next((p.get("content") for p in parts if isinstance(p, dict)
                    and p.get("part_kind") == "text"), "")
        priced = _priced(model, usage)
        line_bits = [f'<div class="tx-entry">{_uv(text)}']
        if model:
            line_bits.append(f'<span class="tx-model">{_v(model)}</span>')
        input_tokens = _count(usage.get("input_tokens", 0)) if isinstance(usage, dict) else None
        if input_tokens is not None:
            line_bits.append(f'<span class="tx-usage">{input_tokens:,}</span>')
        else:
            line_bits.append('<span class="tx-usage">unpriced</span>')
        if priced is not None:
            line_bits.append(f'<span class="tx-cost">{_money(priced)}</span>')
        elif isinstance(usage, dict):
            line_bits.append('<span class="tx-cost">unpriced</span>')
        if isinstance(duration, (int, float)):
            line_bits.append(f'<span class="tx-wall">{fmt_duration(duration)}</span>')
        line_bits.append('</div>')
        entries_html.append("".join(line_bits))
    framed_has_response = framed is not None and (framed.get("failure") or framed.get("reply"))
    if not framed_has_response and not has_plain_response:
        entries_html.append('<div class="tx-entry">no response recorded</div>')

    unreadable_html = (f'<div class="tx-unreadable">{trace.unreadable} unreadable rows</div>'
                       if trace.unreadable else "")
    return (f'<div id="tx-{esc(trace.stem)}" class="tx-stream">'
          f'<div class="tx-search"></div>'
          f'{"".join(entries_html)}{unreadable_html}</div>')


# =========================================================================================
# Leads section
# =========================================================================================


def _render_leads_section(ep: _Episode) -> str:
    blocks = []
    for label in ep.roster_order:
        if _safe_id(label) is None:
            continue
        blocks.append(_render_world_leads(label, ep.leads[label]))
    return _page_section("sec-leads", f"Leads ({len(ep.roster_order)})", "".join(blocks))


def _render_world_leads(label: str, leads: _WorldLeads) -> str:
    bits = []
    if leads.ledger_note is not None:
        bits.append(f'<div class="ld-served">{esc(leads.ledger_note)}</div>')

    if not leads.archived:
        return f'<div id="leads-{esc(label)}" class="leads-section">not archived' \
              f'{"".join(bits)}</div>'

    if leads.facts_error is not None:
        bits.append(f'<div class="ld-investigation">investigation record unavailable: '
                   f'{esc(leads.facts_error)}</div>')
    for stem in leads.unnameable_summaries:
        bits.append(_unnameable(stem, what="gather summary"))
    if leads.moved:
        bits.append('<div class="ld-moved">the hand-off was revisited after the branch</div>')

    for lead_id, chain in leads.chains:
        safe = _safe_id(lead_id)
        # `names_one_file` (family's own path-traversal screen) decides whether this id ever
        # reaches a real file at all — when it does not, `lead_chain` already answers safely
        # with its own descriptive sentence and nothing further needs neutralizing. Attribute
        # safety (`is_valid_run_id`) is a SEPARATE, HTML-specific concern: a stem that names a
        # real file but is not HTML-id-safe (space, `<`, `"`) is neutralized here instead,
        # discarding whatever content it would have fetched (#1025 J5).
        file_safe = isinstance(lead_id, str) and family.names_one_file(lead_id)
        if file_safe and safe is None:
            bits.append(_unnameable(lead_id, what="lead id"))
            continue
        id_attr = f' id="ld-{esc(label)}-{esc(safe)}"' if safe is not None else ""
        if chain is None:
            bits.append(f'<div{id_attr} class="ld-lead">'
                       f'<span class="ld-id">{_uv(lead_id)}</span>'
                       f'<span class="ld-summary">lead unreadable</span></div>')
            continue
        payload = _items(chain.get("payload"))
        resolutions = _items(chain.get("resolutions"))
        resolutions_html = "".join(f'<div class="ld-resolution">{_uv(r)}</div>'
                                  for r in resolutions)
        bits.append(f'<div{id_attr} class="ld-lead">'
                   f'<span class="ld-id">{_uv(lead_id)}</span>'
                   f'<span class="ld-goal">{_uv(chain.get("goal"))}</span>'
                   f'<span class="ld-params">{_uv(chain.get("params"))}</span>'
                   f'<span class="ld-payload">{"".join(_uv(str(d)) for d in payload)}</span>'
                   f'<span class="ld-summary">{_uv(chain.get("summary"))}</span>'
                   f'{resolutions_html}'
                   f'</div>')

    return f'<div id="leads-{esc(label)}" class="leads-section">{"".join(bits)}</div>'


# =========================================================================================
# Records section
# =========================================================================================


def _render_records(ep: _Episode) -> str:  # noqa: C901, PLR0912 — every episode-level record's own slot in one section (#1025 O8)
    samples_rec, staged_rec, review_rec, stamp_rec = (
        ep.samples_rec, ep.staged_rec, ep.review_rec, ep.stamp_rec)
    bits = [f'<div class="rc-story">{_uv(ep.manifest.get("base_story"))}</div>']
    discriminator = ep.manifest.get("discriminator")
    if isinstance(discriminator, dict):
        predicate = discriminator.get("predicate")
        bits.append(f'<div class="rc-predicate">{_uv(predicate)}</div>')
        params = _mapping(_mapping(discriminator.get("envelope")).get("params"))
        if "query" in params:
            bits.append(f'<div class="rc-envelope">{_uv(params["query"])}</div>')

    for w in ep.manifest_worlds:
        if isinstance(w.get("world_id"), str):
            bits.append(f'<div class="rc-world">{_uv(w["world_id"])}</div>')

    if samples_rec.error:
        bits.append(f'<div class="rc-samples">{esc(samples_rec.error)}</div>')
    elif not samples_rec.present:
        bits.append('<div class="rc-samples">absent</div>')
    else:
        for pattern in _mapping(samples_rec.value):
            bits.append(f'<div class="rc-pattern">{_uv(pattern)}</div>')

    if staged_rec.error:
        bits.append(f'<div class="rc-staged">{esc(staged_rec.error)}</div>')
    elif not staged_rec.present:
        bits.append('<div class="rc-staged">absent</div>')
    else:
        for row in _items(staged_rec.value):
            bits.append(f'<div class="rc-staged-row">{_uv(_mapping(row).get("name"))}</div>')

    if review_rec.error:
        bits.append(f'<div class="rc-review">{esc(review_rec.error)}</div>')
    elif not review_rec.present:
        bits.append('<div class="rc-review">absent</div>')
    else:
        review_doc = _mapping(review_rec.value)
        episode_block = review_doc.get("episode")
        if isinstance(episode_block, dict):
            bits.append(f'<div class="rc-review-episode">{_uv(episode_block.get("decision"))}'
                       f' {_uv(episode_block.get("outcome"))}</div>')
        else:
            bits.append('<div class="rc-review-episode">absent</div>')
        review_worlds = review_doc.get("worlds")
        if not isinstance(review_worlds, dict):
            bits.append('<div class="rc-review-worlds">absent</div>')
        teardown = review_doc.get("teardown")
        if isinstance(teardown, dict):
            bits.append(f'<div class="rc-teardown-at">{_uv(teardown.get("at"))}</div>')
            for failure in _items(teardown.get("failures")):
                if isinstance(failure, dict):
                    bits.append(f'<div class="rc-teardown-fail">{_uv(failure.get("name"))} '
                               f'{_uv(failure.get("detail"))}</div>')
        for block in _mapping(review_worlds).values():
            if isinstance(block, dict):
                for inv in _items(block.get("inventions")):
                    bits.append(f'<div class="rc-invention">{_uv(inv)}</div>')
                consistency = block.get("consistency")
                if isinstance(consistency, dict):
                    for key in _items(consistency.get("control_mismatch_keys")):
                        bits.append(f'<div class="rc-mismatch-key">{_uv(key)}</div>')

    if stamp_rec.error:
        bits.append(f'<div class="rc-provenance">{esc(stamp_rec.error)}</div>')
    elif not stamp_rec.present:
        bits.append('<div class="rc-provenance">absent</div>')
    else:
        stamp = _mapping(stamp_rec.value)
        agreed = stamp.get("agreed")
        if isinstance(agreed, dict):
            bits.append(f'<div class="rc-commit">{_v(agreed.get("commit"))}</div>')
            bits.append(f'<div class="rc-model">{_v(agreed.get("model"))}</div>')
            for path_ in _items(agreed.get("dirty_paths")):
                bits.append(f'<div class="rc-dirty">{_uv(path_)}</div>')
        bits.append(f'<div class="rc-allow-dirty">allow_dirty: '
                   f'{_v(stamp.get("allow_dirty"))}</div>')

    return _page_section("sec-records", "Records", "".join(bits))


# =========================================================================================
# CLI
# =========================================================================================


def _diagnostics(ep: _Episode) -> list[str]:
    """The stderr lines the CLI echoes beside the page path — off the MODEL's own refusal
    slots, never a scan of the rendered bytes (a model-authored claim containing the words "no
    grade record" is that finding's text, not a diagnostic)."""
    lines = []
    for name, rec in (("grade", ep.grade_rec), ("timing", ep.timing_rec),
                      ("review", ep.review_rec), ("samples", ep.samples_rec),
                      ("staging", ep.staged_rec), ("provenance", ep.stamp_rec)):
        if rec.error:
            lines.append(f"{name} record unreadable")
    if ep.grade_rec.ok and ep.grade is None:
        lines.append("no grade record")
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: visualize_episode.py <episode_dir>", file=sys.stderr)
        return 1
    episode_dir = Path(argv[0])
    # PLAIN `is_dir()`, not the lstat-screened `artifact_dir` — this is the OPERATOR's own
    # command-line argument (d11: a symlink to the episode dir is an accepted spelling, J4),
    # never an entry inside the episode tree a box could have planted.
    if not episode_dir.is_dir():  # lint-tree-read-follows-link: ok — the operator's own CLI argument, not an episode-tree entry; a symlinked episode dir is an accepted spelling (d11/J4)
        print(f"not a directory: {episode_dir}", file=sys.stderr)
        return 1
    try:
        ep = load_episode(episode_dir)
    except JudgeRefused as bad:
        # ONE LINE: the manifest's own refusal may wrap a multi-line YAML parser error, and
        # d01 promises the CLI one reason line, not the parser's whole traceback-shaped text.
        print(" ".join(str(bad).split()), file=sys.stderr)
        return 1
    try:
        page_path = _write_page(episode_dir, _render_document(ep))
    except OSError as bad:
        print(str(bad), file=sys.stderr)
        return 1
    print(page_path)
    for line in _diagnostics(ep):
        print(line, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
