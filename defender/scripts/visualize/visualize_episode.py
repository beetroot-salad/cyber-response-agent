"""The episode page: `render_episode(runs, episode_id) -> Path` renders `learning.html` beside
`judge.yaml`, the episode opened by id through the request's tenant's repository
(`runs.episode(episode_id)`, #1105 PR 2); `main(argv)` is the standalone CLI
(`--tenant T <episode_id>`). The launcher (`branch/cli.py::_render_page`) calls `render_episode`
after the judge frame closes, under its own non-fatal boundary.

The episode view judges the siblings' container record before anything else is read (G20): a
record naming another tenant, or none, refuses the page. The arm roster is the manifest's (and
the grade record's) labels, each arm opened by id through the view; an entry in `runs/` that is
no roster label is never shown. An unreadable container reads as absent.

Two phases. `load_episode` reads every record the page shows exactly once, through the package
readers, into a typed model (`_Episode`), and runs the findings walk once over it. Section
renderers take the model and never touch the directory. Only `family.yaml` refuses the whole
page; any other unreadable record or malformed field lands in its own slot (a `_Record.error`,
an empty list, a `None`) and renders as that slot's sentence, so one bad file cannot take the
page down and no two renderers can read a record differently.

The page shows the decisions passes wrote down (`judge.yaml.dispositions`, the enqueue ledger),
never a re-run of a pass's rule over the rows: re-deriving them disagrees with the pass at the
edges the page exists to explain. If a decision is not recorded, fix the writer.
"""
from __future__ import annotations

import argparse
import math
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if __name__ == "__main__" and (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _tenant
from defender._clock import parse_iso_utc
from defender._episode_handle import Episode, EpisodeRefused
from defender._paths import process_defender_dir
from defender._io import Bound, read_text_utf8
from defender._report import ReportRead
from defender._run_id import is_valid_run_id
from defender._episode_paths import LAYOUT, WORLD_LEAVES, EpisodePaths
from defender.run_repository import RUN_LAYOUT, WIRE_LOG_NAMES, RunRefused
from defender._vocab import normalized_disposition, normalized_judge_outcome
from defender.learning.branch import archive
from defender.learning.branch import outcome as outcome_mod
from defender.learning.branch import timing as timing_mod
from defender.learning.branch.steps import STEPS, Step
from defender.learning.judge import JudgeRefused, read_grade
from defender.learning.judge import family
from defender.learning.judge.enqueue import (
    LANE_DEFENDER,
    LANE_NEVER_ELIGIBLE,
    LANE_UNQUEUEABLE,
    LANE_WORLD,
    DrawsSkipReport,
    draws_on_disk_report,
)
from defender.learning.judge.render import episode_alert
from defender.learning.judge.run import SUBJECT_DEFENDER, SUBJECT_WORLD
from defender.runtime.branch._family import (
    BASE_ROLE, ManifestPredatesOracle, episode_token_for,
)
from defender._pricing import UnknownModel, model_key, usage_cost
from defender.scripts.visualize.visualize_primitives import (
    ASSETS,
    CSS,
    EVENT_HANDLER_RE,
    esc,
    fmt_duration,
)

if TYPE_CHECKING:
    from defender.run_repository import EpisodeRuns, Run, RunsRepository

#: The page's own stylesheet, inlined after the shared run-page `CSS`, which knows nothing of
#: this page's classes. `test_1025_every_class_the_page_emits_has_a_rule` keeps them in step.
EPISODE_CSS = read_text_utf8(ASSETS / "episode.css")

#: The family's own draw documents live under this pseudo-label beside the worlds.
_FAMILY_LABEL = "family"

#: The judge model's world buckets (O11, M19=A), each with its own colour; any other word (a
#: world-subject finding's free-text bucket) is `bucket-other`.
_BUCKET_CLASS = {
    "lead-set": "bucket-lead-set",
    "observability": "bucket-observability",
    "decision-discipline": "bucket-decision-discipline",
    "analyze-discipline": "bucket-analyze-discipline",
    "lead-quality": "bucket-lead-quality",
}


# =========================================================================================
# Small escaping / id-safety primitives
# =========================================================================================


def _safe_id(raw: str) -> str | None:
    """`raw` if it may become an html id/href/class component (the run-id alphabet), else
    `None`: the caller renders an "unnameable entry" line instead."""
    return raw if isinstance(raw, str) and is_valid_run_id(raw) else None


def _uv(x: Any) -> str:
    """A scalar rendered as text through the untrusted escape — the only spelling, since nearly
    every string here is a record field from a box-reachable tree; `esc()` alone is for the
    page's own literals and ids.

    Splits event-handler names with a `<wbr>` element rather than `esc_untrusted`'s zero-width
    character: both defeat a raw "onerror=" scan, but `<wbr>` contributes no text, so the page's
    text reader round-trips the original word (several adversarial tests assert this)."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    escaped = esc(x if isinstance(x, str) else str(x))
    return EVENT_HANDLER_RE.sub(lambda m: m.group(0) + "<wbr>", escaped)


def _raw(x: Any) -> str:
    """`x` as plain text, unescaped, for a string another function escapes once."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    return x if isinstance(x, str) else str(x)


def _unnameable(raw: str, *, what: str) -> str:
    return f'<div class="unnameable">unnameable entry ({esc(what)}): {_uv(raw)}</div>'


def _money(cost: float) -> str:
    """Gated at print time too: a sum of finite rows can still be `inf`."""
    return f"${cost:.4f}" if math.isfinite(cost) else "—"


def _items(x: Any) -> list[Any]:
    """A list field, or `[]` when the record holds anything else."""
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


def _read_outcome(bound: Bound) -> _Record:
    """Pre-flight's outcome record with the worlds O5 counts as failed, as
    `{"record": <record or None>, "failed": {label: entry}}`. An absent or torn record is the
    "no record" state: `error` names it, and the failed worlds' own records still show."""
    try:
        record = outcome_mod.read_outcome(bound)
    except outcome_mod.OutcomeUnreadable as missing:
        return _Record({"record": None, "failed": outcome_mod.failed_worlds(bound, {})},
                       present=True, error=f"{outcome_mod.NO_RECORD} — {missing}")
    return _Record({"record": record, "failed": outcome_mod.failed_worlds(bound, record)},
                   present=True)


def _strict_samples_reader(bound: Bound, name: str) -> dict[str, Any] | None:
    """The page's strict reading of `samples.yaml`, via `read_samples_record`'s `reader=` seam.

    The default reader stays permissive; this one refuses what it cannot read so "unreadable" is
    distinguishable from "absent" (`None`). `empty_ok=True`: an empty file means nothing
    recorded yet."""
    return family.screened_yaml_mapping(bound, name, what="the samples record", empty_ok=True)


def _read_samples(bound: Bound) -> _Record:
    try:
        doc = family.read_samples_record(bound, reader=_strict_samples_reader)
    except JudgeRefused as bad:
        return _Record(present=True, error=f"samples record unreadable: {bad}")
    return _Record(doc or {}, present=doc is not None)


def _read_timing(bound: Bound) -> _Record:
    try:
        rows = timing_mod.read_stage_timings(bound)
    except ValueError as bad:
        return _Record(present=True, error=f"timing record unreadable: {bad}")
    return _Record(rows or [], present=rows is not None)


def _read_family_stamp(bound: Bound) -> _Record:
    try:
        doc = archive.read_family_stamp(bound)
    except ValueError as bad:
        return _Record(present=True, error=f"provenance record unreadable: {bad}")
    return _Record(doc, present=doc is not None)


def _read_grade(episode_dir: Path) -> _Record:
    # `read_grade`'s refusal never quotes the root, so no scrub is needed.
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

    #: The one sentence each non-`ok` state reads as, shared by every surface showing a cost.
    TEXT = {
        # No `tool_trace.jsonl` at all: nothing was read, so it matches the questioner/judge
        # steps' wording rather than "no result event".
        "absent": "no cost recorded",
        "refused": "no result event (refused)",
        "none": "no result event",
        "unusable": "unusable result event",
        # Present so `text` never raises out of a display helper.
        "ok": "",
    }

    def __init__(self, cost: float | None, wall_ms: float | None, state: str) -> None:
        self.cost = cost
        self.wall_ms = wall_ms
        self.state = state

    @property
    def costed(self) -> bool:
        return self.state == "ok" and self.cost is not None

    @property
    def text(self) -> str:
        return self.TEXT[self.state]


class _Timing:
    """The stage clock, decided once so every surface agrees on whether the episode has a
    measured wall.

    `error` is the reader's refusal; `rows_by_step` the readable rows; `trusted_by_step` those
    whose pair is not inverted; `launcher_wall_ms` the span over every trusted pair, or `None`
    (which is what `measured` tests). `caption` is the table's fallback for an unmeasured
    clock."""

    __slots__ = ("error", "present", "rows_by_step", "trusted_by_step", "launcher_wall_ms")

    def step_wall_ms(self, step: str) -> float | None:
        """One step's wall: first trusted start to last trusted end (never a sum, which
        double-counts a repeated step), or `None` with no trusted pair."""
        trusted = self.trusted_by_step.get(step, [])
        if not trusted:
            return None
        return _wall_span([r["started_at"] for r in trusted], [r["ended_at"] for r in trusted])

    def __init__(self, rec: _Record) -> None:
        self.error = rec.error
        self.present = rec.present
        self.rows_by_step: dict[str, list[dict[str, Any]]] = {}
        self.trusted_by_step: dict[str, list[dict[str, Any]]] = {}
        if rec.ok:
            for row in rec.value or []:
                self.rows_by_step.setdefault(row["step"], []).append(row)
        # Only non-inverted pairs feed a span: an inverted row shows "—" in its own cell and
        # must not skew min(start)/max(end). A zero-length pair is valid — the clock stamps
        # whole seconds.
        for step, rows in self.rows_by_step.items():
            self.trusted_by_step[step] = [
                r for r in rows
                if (d := _wall_between(r["started_at"], r["ended_at"])) is not None and d >= 0]
        trusted = [r for rows in self.trusted_by_step.values() for r in rows]
        self.launcher_wall_ms: float | None = (
            _wall_span([r["started_at"] for r in trusted], [r["ended_at"] for r in trusted])
            if trusted else None)

    @property
    def measured(self) -> bool:
        return self.launcher_wall_ms is not None

    @property
    def caption(self) -> str | None:
        if self.measured:
            return None
        if self.error is not None:
            return None  # the table renders the refusal itself, as its own `st-error` line
        if not self.rows_by_step:
            # Absent vs present with no completed step (an early abort writes `{"steps": []}`).
            if self.present:
                return "model-call time — no completed stages"
            return "model-call time — no timing record"
        return "model-call time — the timing record has no usable span (every row inverted)"


class _WorldArchive:
    """What `worlds/<label>/` holds: the archived report, whether the investigation is
    archived, and the two JSON stamps (`None` when absent or unreadable)."""

    __slots__ = ("report", "investigation_present", "provenance", "scrub")

    def __init__(self, *, report: ReportRead, investigation_present: bool,
                 provenance: dict[str, Any] | None, scrub: dict[str, Any] | None) -> None:
        self.report = report
        self.investigation_present = investigation_present
        self.provenance = provenance
        self.scrub = scrub


class _WorldLeads:
    """One world's leads block: the served-ledger note, whether the world is archived, the
    investigation's refusal, whether the hand-off moved, and each lead's chain in roster order.

    The ledger and `investigation.md` are read and refused independently: a missing ledger costs
    only the malformed-row count."""

    __slots__ = ("ledger_note", "calls", "archived", "dir_error", "facts_error", "moved",
                 "chains")

    def __init__(self) -> None:
        self.ledger_note: str | None = None
        #: The world's own served-ledger rows (never an oracle-side store's), as the judge reads
        #: them: each call with the decision word that answered it.
        self.calls: list[dict[str, Any]] = []
        self.archived = False
        #: `worlds/<label>` exists but is not a listable real directory: the bind's refusal,
        #: said once for the block.
        self.dir_error: str | None = None
        self.facts_error: str | None = None
        self.moved = False
        self.chains: list[tuple[str, dict[str, Any]]] = []


#: The three shapes a roster item takes, decided once at load (`_build_roster`) so the worlds
#: and leads sections and their headings all count the same list.
ROSTER_WORLD = "world"
#: A label (or directory name) that cannot become an html id (`_safe_id`): rendered as one
#: "unnameable entry" line in the worlds section, and given NO section, NO leads block and
#: NO nav entry — so it is counted in neither heading.
ROSTER_UNNAMEABLE = "unnameable"


class RosterItem:
    """One line of the roster: its world label and which of the two shapes above it takes."""

    __slots__ = ("label", "kind")

    def __init__(self, label: str, kind: str) -> None:
        self.label = label
        self.kind = kind

    @property
    def sectioned(self) -> bool:
        """Does this item get a `world-<label>` section and a `leads-<label>` block?"""
        return self.kind != ROSTER_UNNAMEABLE


class WorldEntry:
    def __init__(self, label: str) -> None:
        self.label = label
        self.in_manifest = False
        self.manifest_doc: dict[str, Any] | None = None
        self.row: dict[str, Any] | None = None  # judge.yaml row, if any
        #: Whether the label may be joined into a path (`family.world_label_names_directory`):
        #: a label with `..` or a separator names a directory outside the episode, so nothing
        #: is read for it and it renders as unnameable.
        self.nameable = False
        self.run_dir_name: str | None = None  # the arm's run folder, opened by id through the view
        #: The arm's run page, relative to the episode page (`runs/<arm>/runtime.html`).
        self.run_page: str | None = None
        self.result: _ResultEvent | None = None  # `None` when there is no run dir at all
        self.archive: _WorldArchive | None = None  # `None` when nothing is at worlds/<label>


class _Trace:
    """One model call's wire record, by stem (`<agent>_trace`): the plain trace file's state
    (absent / refused / ok) with its rows and unreadable-line count, and the framed twin's
    first row when one is on disk and could be read. An entry exists only because a plain
    file or a framed twin was seen at load."""

    __slots__ = ("stem", "plain", "rows", "unreadable", "framed")

    def __init__(self, stem: str) -> None:
        self.stem = stem
        self.plain = "absent"
        self.rows: list[dict[str, Any]] = []
        self.unreadable = 0
        self.framed: dict[str, Any] | None = None


class _RoleCost:
    """One role's spend: `cost` (priced rows summed), `wall_ms` (durations summed), `priced`
    (files with at least one priced response) and `calls` (files, readable or not)."""

    __slots__ = ("cost", "wall_ms", "priced", "calls")

    def __init__(self) -> None:
        self.cost = 0.0
        self.wall_ms = 0.0
        self.priced = 0
        self.calls = 0


class _WireLogs:
    """`wire_logs/`, read once. Every question the stages section asks of the directory — a
    role's stems, a role's priced cost, the comparator's, the unattributed judge stems — is a
    walk over `traces`, never a second glob."""

    __slots__ = ("present", "traces")

    def __init__(self) -> None:
        self.present = False
        self.traces: dict[str, _Trace] = {}

    def stems_for(self, role_prefix: str) -> set[str]:
        """Every call's stem for a role — plain trace files and framed twins together, since
        some roles write only the framed record."""
        # Every entry in `traces` already has one of the two.
        return {s for s in self.traces if s.startswith(role_prefix)}

    def plain_stems(self, *, agent_prefix: str) -> list[str]:
        """The stems whose PLAIN trace file is on disk (readable or not), whose agent id starts
        with `agent_prefix`, in name order."""
        return sorted(s for s, t in self.traces.items()
                      if t.plain != "absent" and s[: -len("_trace")].startswith(agent_prefix))

    def role_cost(self, role_prefix: str) -> _RoleCost:
        """The cost of every trace file this role owns — one call per file. A call is priced
        when a response row carries `usage` and a `model` the pricing table resolves; the wall
        sums `duration_ms` wherever present, priced or not. Computed once per role at load."""
        agent_prefix = "questioner" if role_prefix == "questioner" else "judge_"
        out = _RoleCost()
        for stem in self.plain_stems(agent_prefix=agent_prefix):
            trace = self.traces[stem]
            out.calls += 1
            if trace.plain != "ok":
                continue
            call_priced = False
            for row in trace.rows:
                if row.get("kind") != "response":
                    continue
                cost = _priced(row.get("model"), row.get("usage"))
                if cost is not None:
                    out.cost += cost
                    call_priced = True
                duration = _duration(row.get("duration_ms"))
                if duration is not None:
                    out.wall_ms += duration
            if call_priced:
                out.priced += 1
        return out

    def comparator_cost(self) -> tuple[float, int]:
        """`(cost, priced calls)` — counts priced response rows, not files, so an empty
        comparator trace still reads "no model calls"."""
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
    `model`, an unknown model, or non-numeric token counts (wire logs are box-writable)."""
    # An empty `model` is unpriced here, unlike `model_key`'s absorbed case: billing an
    # unnamed model at some rate would invent a figure.
    if not (isinstance(usage, dict) and isinstance(model, str) and model):
        return None
    try:
        cost = usage_cost(model, usage)
        model_key(model)
    except (UnknownModel, TypeError, ValueError, OverflowError):
        # `OverflowError`: a 400-digit token count overflows before `_finite` sees it.
        return None
    # Usage blocks are box-writable: reject negative, NaN or infinite costs.
    priced = _finite(cost)
    return priced if priced is not None and priced >= 0 else None


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
        # Refused rather than dropped, or a misspelled keyword becomes a silent `None` field.
        unknown = set(kw) - set(self.__slots__)
        if unknown:
            raise TypeError(f"_Finding: unknown field(s) {sorted(unknown)}")
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot))


class _Findings:
    """The findings walk's one answer, shared by the verdict tiles, cards and findings section:
    rows, disposition counts, each label's draw-read report, failed draws, dropped counts, and
    each heading's group number (the `fg-<n>` cards link to)."""

    __slots__ = ("rows", "counts", "world_reports", "draw_failures", "dropped", "group_index")

    def __init__(self) -> None:
        self.rows: list[_Finding] = []
        self.counts = {"defender": 0, "world_author": 0, "unqueueable": 0,
                       "dropped": 0, "never_eligible": 0}
        self.world_reports: dict[str, DrawsSkipReport] = {}
        self.draw_failures: list[tuple[str, int, str]] = []
        self.dropped: list[tuple[str, int, int]] = []
        self.group_index: dict[str, int] = {}


class _Episode:
    """One read of the episode directory — everything a section renders, already typed."""

    def __init__(self, episode_dir: Path, manifest: dict[str, Any]) -> None:
        #: Held only for the lead repository and the draw reader, reached after the bind's
        #: listing judged the world directory real. Never formatted into the page.
        self.dir = episode_dir
        # No bound reader is stored: `load_episode` threads it through the loaders and closes
        # it, so renderers have no tree to reach for.
        self.manifest = manifest
        self.episode_id = family.episode_id_of(manifest)
        # Built or absent, never the raw id: the token is joined into
        # `served/<token>.<label>.jsonl`, and a raw `../../x` would escape the episode dir.
        try:
            self.episode_token: str | None = episode_token_for(self.episode_id)
        except Exception:  # noqa: BLE001 — a token that cannot be built names no world's ledger
            self.episode_token = None
        # Only mapping entries: scalars have nothing to render.
        self.manifest_worlds: list[dict[str, Any]] = [
            w for w in _items(manifest.get("worlds")) if isinstance(w, dict)]
        self.control_label: str | None = next(
            (w["world_id"] for w in self.manifest_worlds
             if w.get("role") == BASE_ROLE and isinstance(w.get("world_id"), str)), None)
        self.grade_rec = _Record()
        self.outcome_rec = _Record()
        self.samples_rec = _Record()
        self.stamp_rec = _Record()
        self.timing_rec = _Record()
        self.entries: dict[str, WorldEntry] = {}
        #: Every roster line in section order, classified — what the worlds and leads sections
        #: render, and what their headings count.
        self.roster: list[RosterItem] = []
        self.off_roster = 0
        self.archived_world_dirs: list[str] = []
        self.alert: Any = None
        self.draws: dict[str, tuple[dict[int, dict[str, Any]], DrawsSkipReport]] = {}
        #: One leads block per roster label.
        self.leads: dict[str, _WorldLeads] = {}
        self.wire = _WireLogs()
        self.findings = _Findings()
        self.timing = _Timing(_Record())
        self.total_cost = 0.0
        #: Did ANY run's result event price the run — the runs sub-total's own gate.
        self.runs_costed = False
        #: Did anything price this episode — the grand total's gate. A flag rather than
        #: `total_cost`'s truthiness: an all-$0.0000 episode is still priced.
        self.costed = False
        self.worlds_wall = ""
        self.lower_bound = ""
        #: Each model role's spend, decided once at load for every surface that shows it.
        self.role_costs: dict[str, _RoleCost] = {}
        self.review_cost = 0.0
        self.review_calls = 0

    @property
    def sectioned(self) -> list[RosterItem]:
        """The roster items that get a section and a leads block — what both headings count."""
        return [item for item in self.roster if item.sectioned]

    @property
    def grade(self) -> Any:
        return self.grade_rec.value

    @property
    def not_graded(self) -> bool:
        """A `not_graded` stamp voids the whole family's word."""
        return self.grade is not None and self.grade.not_graded is not None

    def manifest_world(self, label: str) -> dict[str, Any] | None:
        """The first manifest entry naming `label`; the guide still renders every entry."""
        return next((w for w in self.manifest_worlds if w.get("world_id") == label), None)

    @property
    def failed_worlds(self) -> dict[str, dict[str, Any]]:
        """Every world O5 counts as failed, by label (`outcome.failed_worlds`)."""
        return _mapping(_mapping(self.outcome_rec.value).get("failed"))


# =========================================================================================
# Loading — the one pass over the directory
# =========================================================================================


def load_episode(view: EpisodeRuns) -> _Episode:
    """Every record the page shows, read once, through `view` — the episode's view in its
    tenant's repository, whose container record was judged when it opened. Raises
    `JudgeRefused` for the manifest alone; every other refusal is a slot on the model."""
    episode = view.episode
    return _load_episode(Path(episode.dir), episode.view(), view)


def _load_episode(episode_dir: Path, bound: Bound, view: EpisodeRuns) -> _Episode:
    ep = _Episode(episode_dir, family.read_manifest(bound))

    ep.grade_rec = _read_grade(episode_dir)
    ep.outcome_rec = _read_outcome(bound)
    ep.samples_rec = _read_samples(bound)
    ep.stamp_rec = _read_family_stamp(bound)
    ep.timing_rec = _read_timing(bound)
    ep.timing = _Timing(ep.timing_rec)

    grade = ep.grade
    grade_rows = [r for r in (_items(grade.worlds) if grade is not None else [])
                  if isinstance(r, dict) and isinstance(r.get("world"), str)]
    ep.archived_world_dirs = [
        name for name in bound.under(LAYOUT.worlds).entries().dirs()
        if name != _FAMILY_LABEL]
    ep.entries, ep.roster, ep.off_roster = _build_roster(
        ep, [r["world"] for r in grade_rows], grade_present=ep.grade_rec.present,
        reached_container=view.present)
    for row in grade_rows:
        w = ep.entries.get(row["world"])
        if w is not None:
            w.row = row

    # Every path below is joined from a label, so only labels naming their own directory reach
    # the disk. Real directory names get the same gate (`..` is a name).
    nameable = [w.label for w in ep.entries.values() if w.nameable]
    labels = [w["world_id"] for w in ep.manifest_worlds
              if isinstance(w.get("world_id"), str) and w["world_id"] in nameable]
    ep.alert = episode_alert(bound, labels or [
        n for n in ep.archived_world_dirs if family.world_label_names_directory(ep.episode_id, n)])

    for label in [*ep.entries, _FAMILY_LABEL]:
        ep.draws[label] = (_load_draws(bound, label)
                           if label == _FAMILY_LABEL or ep.entries[label].nameable
                           else ({}, DrawsSkipReport()))
    for w in ep.entries.values():
        if not w.nameable:
            continue
        if view.present:
            _load_arm(w, view, episode_dir)
        w.archive = _load_world_archive(bound, w.label)
    for item in ep.sectioned:
        entry = ep.entries.get(item.label)
        ep.leads[item.label] = (_load_world_leads(ep, bound, item.label)
                                if entry is None or entry.nameable else _WorldLeads())

    ep.wire = _load_wire_logs(bound.under(RUN_LAYOUT.wire_log_dir))
    ep.findings = _walk_findings(ep)
    ep.total_cost, ep.runs_costed, ep.costed, ep.worlds_wall, ep.lower_bound = _cost_totals(ep)
    return ep


def _load_arm(w: WorldEntry, view: EpisodeRuns, episode_dir: Path) -> None:
    """World `w`'s arm, opened by id through the episode view (`view.open(view.arm_id(label))`,
    whose entry rule takes only a real directory): its run folder's name, its run page's link
    relative to the episode page, and its result event, read through the arm's own no-follow
    reader. Anything the open refuses — nothing at the id, a link or a file there, a label no
    run id can carry, a container gone since the view opened — leaves the arm absent."""
    try:
        run = view.open(view.arm_id(w.label))
        with run.reader() as reader:
            w.result = _result_event(reader)
    except (RunRefused, _tenant.TenantRefused, OSError):
        return
    w.run_dir_name = run.run_dir.name
    w.run_page = _run_page_link(run, episode_dir)


def _run_page_link(run: Run, episode_dir: Path) -> str:
    """The arm's run page (`run.observability.runtime_html`), as a link relative to the
    episode page beside `judge.yaml`."""
    return Path(run.observability.runtime_html.path).relative_to(episode_dir).as_posix()


def _load_draws(bound: Bound, label: str) -> tuple[dict[int, dict[str, Any]], DrawsSkipReport]:
    """The draws under `worlds/<label>/judge/`, through the enqueue's reader over this pass's
    root handle (a link anywhere on the way lists nothing)."""
    return draws_on_disk_report(bound, label)


def _duration(value: Any) -> float | None:
    """A showable `duration_ms`: finite and non-negative (traces are box-writable)."""
    ms = _finite(value)
    return ms if ms is not None and ms >= 0 else None


def _finite(value: Any) -> float | None:
    """`value` as a finite float, else `None`. `json.loads` admits `NaN`/`Infinity`, and a
    400-digit int makes `math.isfinite` raise, so it goes through `float(...)` first."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        as_float = float(value)
    except OverflowError:
        return None
    return as_float if math.isfinite(as_float) else None


def _build_roster(ep: _Episode, grade_row_labels: list[str], *, grade_present: bool,
                  reached_container: bool) -> tuple[dict[str, WorldEntry], list[RosterItem], int]:
    """Every world label that gets a section: manifest worlds ∪ `judge.yaml` rows. Each one's
    arm is opened by id later (`_load_arm`); an entry in `runs/` that is neither is never shown
    (#1105 J3: the roster is the manifest's, not a listing of the container).

    Returns the entries by label (manifest order first), the classified roster, and the count
    of `worlds/` dirs on neither the manifest nor the record (reported on one line, never
    rendered)."""
    entries: dict[str, WorldEntry] = {}
    order: list[str] = []

    def entry(label: str) -> WorldEntry:
        if label not in entries:
            entries[label] = WorldEntry(label)
            entries[label].nameable = family.world_label_names_directory(ep.episode_id, label)
            order.append(label)
        return entries[label]

    # A manifest world with no grade row gets a section only once the episode reached RUNS:
    # its container is there, a grade record landed, or a world was archived. An episode
    # rejected or aborted before then has no world to show.
    reached_runs = reached_container or grade_present or bool(ep.archived_world_dirs)
    # `family` is not a world: it is the reserved label for the family-level draws. The judge
    # refuses such a manifest, but the page reads whatever tree it is given, and treating it as
    # a world would walk its draws twice under duplicate ids.
    for w in ep.manifest_worlds:
        label = w.get("world_id")
        if not isinstance(label, str) or label == _FAMILY_LABEL:
            continue
        if label not in entries and not reached_runs:
            continue
        entry(label)
        entries[label].in_manifest = True
        # The first manifest entry is the section's own.
        if entries[label].manifest_doc is None:
            entries[label].manifest_doc = w

    for label in grade_row_labels:
        if label != _FAMILY_LABEL:
            entry(label)

    off_roster = sum(1 for name in ep.archived_world_dirs if name not in entries)

    roster = [RosterItem(label, ROSTER_WORLD if _safe_id(label) is not None else ROSTER_UNNAMEABLE)
              for label in order]
    return entries, roster, off_roster


def _result_event(run: Bound) -> _ResultEvent:
    # Through the arm reader's JSONL reader: absent/refused are its own states, and a link or
    # FIFO is refused at the open rather than raising `PermissionError`.
    rows, _bad, rec = run.read_jsonl(RUN_LAYOUT.tool_trace)
    if rec.absent:
        return _ResultEvent(None, None, "absent")
    if rec.refusal is not None:
        return _ResultEvent(None, None, "refused")
    if not rows or rows[-1].get("type") != "result":
        return _ResultEvent(None, None, "none")
    last = rows[-1]
    cost = _finite(last.get("total_cost_usd"))
    wall = _duration(last.get("duration_ms"))
    if cost is None or cost < 0:
        return _ResultEvent(None, wall, "unusable")
    return _ResultEvent(cost, wall, "ok")


def _load_world_archive(bound: Bound, label: str) -> _WorldArchive:
    # No pre-check of `worlds/<label>`: each leaf reads through the bind and reports its own
    # absent/refused state, whichever path component was missing or a link.
    world_rel = LAYOUT.world(label)
    report = family.read_archived_report(bound, world_rel.report)
    investigation = bound.read(world_rel.investigation)
    return _WorldArchive(
        report=report,
        investigation_present=not investigation.absent,
        provenance=family.json_mapping(bound, world_rel.provenance),
        scrub=family.json_mapping(bound, world_rel.scrub_verdict))


def _load_world_leads(ep: _Episode, bound: Bound, label: str) -> _WorldLeads:  # noqa: C901, PLR0912 — the served ledger, the archive notes and every lead's chain are one world's leads block
    leads = _WorldLeads()
    world = bound.under(LAYOUT.world(label).dir)

    # Read through the judge's own reader so `malformed_rows` matches the count on the
    # `judge.yaml` row (torn lines and out-of-vocabulary `source` values). Its refusal is the
    # ledger note only and does not affect the investigation read below.
    if ep.episode_token is None:
        leads.ledger_note = "served ledger: not readable — the episode id names no token"
    else:
        try:
            rows, malformed, ledger_read = family.read_world_ledger(
                bound, label, episode_token=ep.episode_token)
        except JudgeRefused as bad:
            leads.ledger_note = f"served ledger unreadable: {bad}"
        else:
            leads.calls = rows
            if ledger_read.absent:
                leads.ledger_note = "served ledger: absent"
            elif malformed:
                leads.ledger_note = f"{malformed} malformed row"

    # Off the bind's listing, never a stat. Wholly absent: nothing to chain. Present but not a
    # real listable directory (a link, a file): refused once here, nothing rostered. Missing
    # individual records: every other leaf still renders.
    listing = world.entries()
    leads.archived = not listing.absent
    if not leads.archived:
        return leads
    if listing.refusal is not None:
        leads.dir_error = listing.refusal
        return leads
    facts = None
    try:
        read_facts = family.read_investigation_facts(bound, world=label)
    except JudgeRefused as bad:
        leads.facts_error = str(bad)
    except Exception as bad:  # noqa: BLE001 — a model-written document is parsed here; whatever the parser raises is this slot's, never the page's
        leads.facts_error = f"{LAYOUT.world(label).investigation}: {bad!r}"
    else:
        if not read_facts.absent:
            facts = read_facts

    # `leads_by_id` takes a path, handed over only after the listing judged it a real directory.
    try:
        all_leads = family.leads_by_id(EpisodePaths(ep.dir).world(label).dir)
    except Exception:  # noqa: BLE001
        all_leads = {}

    # Only `.md` plain files are summaries; `summary_lead_ids` is shared with the judge prompt.
    summary_stems = family.summary_lead_ids(world)

    if facts is not None:
        roster = set(facts.referenced_leads) | summary_stems
        resolutions_by_lead = facts.resolutions_by_lead
        leads.moved = bool(facts.resolution_moved)
    else:
        roster = set(all_leads) | summary_stems
        resolutions_by_lead = {}

    for lead_id in sorted(roster):
        # `lead_chain` answers a refused summary as its own sentence; nothing is caught here so
        # the page and the grading pass share one reader.
        chain = family.lead_chain(world, lead_id, resolutions_by_lead, leads=all_leads)
        leads.chains.append((lead_id, chain))
    return leads


def _load_wire_logs(wire: Bound) -> _WireLogs:
    logs = _WireLogs()
    listing = wire.entries()
    if listing.entries is None:
        return logs
    logs.present = True
    for name in sorted(listing.entries):
        if not name.endswith(".jsonl"):
            continue
        # Both a trace and its framed twin take their stem from `WIRE_LOG_NAMES.trace_key`, so
        # they always pair on the same key.
        if WIRE_LOG_NAMES.is_framed(name):
            stem = WIRE_LOG_NAMES.trace_key(name)
            trace = logs.traces.setdefault(stem, _Trace(stem))
            frows, _bad, _rec = wire.read_jsonl(name)
            if frows:
                trace.framed = frows[0]
            continue
        if not WIRE_LOG_NAMES.is_agent_trace(name):
            continue
        stem = WIRE_LOG_NAMES.trace_key(name)
        trace = logs.traces.setdefault(stem, _Trace(stem))
        # `wire_logs/` is box-writable: the bound reader refuses a link or FIFO at the open and
        # answers a permission fault as a refusal.
        rows, unreadable, rec = wire.read_jsonl(name)
        if rec.text is None:
            trace.plain = "refused" if rec.refusal is not None else "absent"
            continue
        trace.plain = "ok"
        trace.rows, trace.unreadable = rows, unreadable
    return logs


def _cost_totals(ep: _Episode) -> tuple[float, bool, bool, str, str]:
    total = 0.0
    runs_costed = False
    walls = []
    for w in ep.entries.values():
        if w.result is None:
            continue
        if w.result.cost is not None and w.result.costed:
            runs_costed = True
            total += w.result.cost
        if w.result.wall_ms:
            walls.append(w.result.wall_ms)
    q = ep.role_costs["questioner"] = ep.wire.role_cost("questioner")
    j = ep.role_costs[str(Step.JUDGE)] = ep.wire.role_cost(Step.JUDGE)
    ep.review_cost, ep.review_calls = ep.wire.comparator_cost()
    total += q.cost + j.cost
    # Priced calls, not trace files: a role whose only trace is refused or unpriceable has
    # spent nothing the page can name, so it must not produce a "$0.0000" total.
    costed = runs_costed or bool(q.priced) or bool(j.priced)
    if walls:
        wall_range = f"{fmt_duration(min(walls))}–{fmt_duration(max(walls))}"
        lower_bound = f"≈ {fmt_duration(q.wall_ms + j.wall_ms + max(walls))} lower bound on wall: model calls + longest world"
    else:
        wall_range = ""
        lower_bound = ""
    return total, runs_costed, costed, wall_range, lower_bound


# =========================================================================================
# The findings walk — run once at load, read by the verdict tiles and the findings section
# =========================================================================================


def _coordinate_of(finding_id: Any) -> str | None:
    """`<label>/<draw>/<index>` from a `<run_id>/<label>/<draw>/<index>` finding id (how every
    record list keys a finding), else `None`."""
    if not isinstance(finding_id, str):
        return None
    parts = finding_id.rsplit("/", 3)
    if len(parts) != 4:
        return None
    _prefix, label, draw, index = parts
    return f"{label}/{draw}/{index}"


def _ledger_of(grade: Any) -> dict[str, dict[str, Any]] | None:
    """The record's `dispositions` ledger by coordinate, or `None` when it carries none."""
    if grade is None or grade.dispositions is None:
        return None
    out: dict[str, dict[str, Any]] = {}
    for entry in grade.dispositions:
        coord = _coordinate_of(entry["finding_id"])
        if coord is not None:
            out.setdefault(coord, entry)
    return out


def _world_findings_lookup(grade: Any) -> dict[str, dict[str, Any]]:
    """The pass's `world_findings` rows by coordinate — the stub text for a world-lane entry
    whose draw document is gone."""
    out: dict[str, dict[str, Any]] = {}
    for row in _items(grade.world_findings):
        if isinstance(row, dict):
            coord = _coordinate_of(row.get("finding_id"))
            if coord is not None:
                out.setdefault(coord, row)
    return out


def _bump(counts: dict[str, int], disposition: str) -> None:
    if disposition in counts:
        counts[disposition] += 1


def _finding_fields(finding: Any) -> dict[str, Any]:
    """One draw finding's fields as `_Finding` kwargs; a non-mapping finding has none."""
    if not isinstance(finding, dict):
        return {"raw": finding}
    return {"claim": finding.get("claim"), "root_cause": finding.get("root_cause"),
            "anchor": finding.get("anchor"), "topic": finding.get("topic"),
            "bucket": finding.get("bucket"), "evidence": finding.get("evidence"),
            "world_field": finding.get("world"), "raw": finding}


#: The ledger's lane → the page's disposition word (`_disposition_heading_raw`).
_LANE_WORD = {LANE_DEFENDER: "defender", LANE_WORLD: "world_author",
              LANE_UNQUEUEABLE: "unqueueable", LANE_NEVER_ELIGIBLE: "never_eligible"}


def _off_ledger_disposition(ep: _Episode, label: str) -> tuple[str, str | None]:
    """Why the ledger does not name a finding on disk, without re-deciding a lane: the world's
    row is ungradable, no row names the world, or the pass never saw this document (a leftover
    from an earlier attempt)."""
    entry = ep.entries.get(label)
    row = entry.row if entry is not None else None
    if label != _FAMILY_LABEL and row is None:
        return "no_grade_row", None
    if row is not None and not family.is_gradable_row(row):
        reason = row.get("ungradable_reason")
        return "world_ungradable", reason if isinstance(reason, str) else None
    return "never_on_record", None


def _walk_findings(ep: _Episode) -> _Findings:  # noqa: C901, PLR0912, PLR0915
    """Every finding row the page shows, keyed `(label, draw, index)`.

    Each row's fate is read off the record's ledger (`EpisodeGrade.dispositions`), never
    re-decided here — re-deriving the lane rule drifts from the pass at the edges. The page adds
    only what the record cannot see: documents the ledger never named
    (`_off_ledger_disposition`), and ledger entries whose document is gone (stubs)."""
    out = _Findings()
    rows = out.rows
    counts = out.counts
    grade = ep.grade
    entries = ep.entries
    roster_labels = [*entries, _FAMILY_LABEL]

    def _walked(label: str) -> bool:
        """Does the page walk this label's draws? Without a grade record, every label;
        otherwise the family lane, and worlds a grade row or manifest entry names."""
        if grade is None or label == _FAMILY_LABEL:
            return True
        entry = entries.get(label)
        return entry is not None and (entry.row is not None or entry.in_manifest)

    # Dropped/failed draws come from the same labels the findings are walked from, so the
    # counts on tile 3 share one population.
    walked_labels = [label for label in roster_labels if _walked(label)]

    # Draw-read reports for every loaded label, walked or not, so the findings section's totals
    # and each world section's line count the same directories.
    for label in roster_labels:
        out.world_reports[label] = ep.draws[label][1]

    for label in walked_labels:
        docs, _report = ep.draws[label]
        for draw, doc in docs.items():
            dropped = _count(doc.get("dropped_findings"))
            if dropped is not None:
                counts["dropped"] += dropped
            if not _items(doc.get("findings")) and doc.get("failure_reason"):
                out.draw_failures.append((label, draw, doc["failure_reason"]))
            elif dropped is not None:
                out.dropped.append((label, draw, dropped))

    ledger = _ledger_of(grade)

    def _dispose(label: str, coord: str) -> tuple[str, str | None, Any]:
        """The row's disposition word, reason and recorded id: the ledger's entry, else the
        record's account of why the pass never reached it."""
        if grade is None:
            return "no_grade", None, None
        if ledger is None:
            return "no_ledger", None, None
        entry = ledger.pop(coord, None)
        if entry is None:
            return (*_off_ledger_disposition(ep, label), None)
        return _LANE_WORD[entry["lane"]], entry.get("reason"), entry["finding_id"]

    for label in walked_labels:
        docs, _report = ep.draws[label]
        for draw, doc in docs.items():
            for index, finding in enumerate(_items(doc.get("findings"))):
                coord = f"{label}/{draw}/{index}"
                disposition, reason, recorded_id = _dispose(label, coord)
                _bump(counts, disposition)
                # A missing `subject` reads as the defender's, as the enqueue pass reads it.
                subject = (finding.get("subject", SUBJECT_DEFENDER)
                           if isinstance(finding, dict) else None)
                rows.append(_Finding(
                    row_id=f"f-{label}-{draw}-{index}", label=label, draw=draw, index=index,
                    subject=subject, disposition=disposition, reason=reason, stub=False,
                    recorded_id=recorded_id, outcome=doc.get("episode_outcome"),
                    **_finding_fields(finding)))


    # Record-only stubs: a ledger entry whose draw document is absent but whose text the
    # record still carries (`world_findings` for a world-lane entry). Defender or dropped
    # entries have no text on the record, so they only appear in the queue accounting. The grain is the document: a present document with fewer
    # findings than the ledger knew renders nothing extra.
    if ledger:
        present_docs = {label: set(ep.draws[label][0]) for label in roster_labels}
        world_rows_by_coord = _world_findings_lookup(grade)
        for coord, filed in ledger.items():
            label, draw_s, index_s = coord.rsplit("/", 2)
            try:
                draw_i: int | None = int(draw_s)
            except ValueError:
                draw_i = None
            if draw_i is not None and draw_i in present_docs.get(label, set()):
                continue
            world_row = world_rows_by_coord.get(coord)
            if filed["lane"] == LANE_WORLD and world_row is not None:
                fields: dict[str, Any] = {"claim": world_row.get("finding")}
                subject = SUBJECT_WORLD
            else:
                continue
            disposition = _LANE_WORD[filed["lane"]]
            _bump(counts, disposition)
            rows.append(_Finding(
                row_id=f"f-{label}-{draw_s}-{index_s}", label=label, draw=draw_s,
                index=index_s, subject=subject, disposition=disposition,
                reason=filed.get("reason"), stub=True, recorded_id=filed["finding_id"],
                **fields))

    out.group_index = _group_numbering(rows)
    return out


def _group_numbering(rows: list[_Finding]) -> dict[str, int]:
    """Each group heading's `fg-<n>`, by first appearance — shared by the findings section and
    the cards' footers."""
    return {h: n for n, h in enumerate(dict.fromkeys(_disposition_heading_raw(f) for f in rows),
                                       start=1)}


def _disposition_heading_raw(f: _Finding) -> str:
    """The group heading's plain text, never pre-escaped: the caller escapes it once, so a
    record-field `reason` cannot be double-escaped into an irreversible `&amp;#x27;`."""
    if f.disposition == "defender":
        return "defender: enqueued"
    if f.disposition == "world_author":
        return "world author: enqueued"
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
    if f.disposition == "no_ledger":
        return "record carries no disposition ledger — not enqueued"
    return "no grade record — not enqueued"


# =========================================================================================
# The rendered document
# =========================================================================================


def _encode_page(html_text: str) -> bytes:
    """The document's bytes. `errors="replace"` handles lone surrogates but not NUL (a plain
    0x00 in UTF-8), so NUL is replaced with U+FFFD first."""
    return html_text.replace("\x00", "�").encode("utf-8", errors="replace")


def _write_page(episode: Episode, html_text: str) -> Path:
    page = episode.learning_html
    page.write(_encode_page(html_text))
    return page.path


def render_episode(runs: RunsRepository, episode_id: str) -> Path:
    """Render episode `episode_id` of `runs`'s tenant into its own folder. The door is the
    episode view (`open_episode_view`): a missing episode, a bad id, an unusable episodes root
    or a file at the name is `JudgeRefused`, never made, and a container record naming another
    tenant, or none, refuses before anything else is read."""
    with open_episode_view(runs, episode_id) as view:
        try:
            html_text = build_page(view)
        except JudgeRefused as bad:
            # An archive of the pre-oracle design gets a page saying so; any other manifest
            # refusal stays a refusal.
            if not isinstance(bad.__cause__, ManifestPredatesOracle):
                raise
            html_text = _render_refusal(view.episode_id, bad)
        return _write_page(view.episode, html_text)


def open_episode_view(runs: RunsRepository, episode_id: str) -> EpisodeRuns:
    """`runs.episode(episode_id)`, every refusal of its door as the page's `JudgeRefused`:
    the episode owner's (a bad id, an unusable root, a missing episode, a file at the name;
    nothing is created) and the container record's (another tenant's, or none — an episode
    launched before #1078 is not supported). The caller closes the view."""
    try:
        return runs.episode(episode_id)
    except FileNotFoundError as missing:
        raise JudgeRefused(f"episode {episode_id}: no such episode directory") from missing
    except (EpisodeRefused, _tenant.TenantRefused, OSError) as refused:
        raise JudgeRefused(f"episode {episode_id}: {refused}") from refused


def build_page(view: EpisodeRuns) -> str:
    return _render_document(load_episode(view))


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
<style>{CSS}
{EPISODE_CSS}</style></head><body id="top">
<div class="layout">
{nav}
<article class="content episode">
{body}
</article>
</div>
</body></html>
"""


def _render_refusal(episode_id: str, refusal: JudgeRefused) -> str:
    """The whole page for an episode the manifest reader refused: the reason, as text, and
    nothing read from the archive."""
    title = f"episode — {esc(episode_id)}"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>{CSS}
{EPISODE_CSS}</style></head><body id="top">
<div class="layout">
<article class="content episode">
<h1>{title}</h1>
<div class="refusal">{_uv(str(refusal))}</div>
</article>
</div>
</body></html>
"""


def _render_nav(body: str) -> str:
    ids = re.findall(r'id="([^"]+)"', body)
    items = []
    for i in ids:
        if i.startswith("world-") or i.startswith("fg-") or i.startswith("sec-"):
            items.append(f'<li class="item"><a href="#{esc(i)}">{esc(i)}</a></li>')
    # The shared stylesheet's nav classes, so the sticky layout matches the run pages.
    return f'<nav class="toc"><ul>{"".join(items)}</ul></nav>'


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
        meta_bits.append(f'<span class="hd-source">source {_uv(source_run_id)}</span>')
    if branch_message_id is not None:
        meta_bits.append(f'<span class="hd-branch">branch message {_uv(branch_message_id)}</span>')

    if grade is not None:
        knobs = _mapping(grade.knobs)
        draws = _mapping(grade.draws)
        model = knobs.get("model", "?")
        effort = knobs.get("effort", "?")
        cap = knobs.get("payload_cap", "?")
        configured = draws.get("configured", "?")
        completed = draws.get("completed", "?")
        knob_line = (f"{_uv(model)} / {_uv(effort)} / cap {_uv(cap)} / "
                    f"draws {_uv(configured)}/{_uv(completed)}")
        meta_bits.append(f'<span class="hd-knobs">{knob_line}</span>')
        if grade.lessons_commit:
            meta_bits.append(f'<span class="hd-commit">{_uv(str(grade.lessons_commit)[:8])}</span>')

    meta = '<span class="hd-sep"> · </span>'.join(meta_bits)
    return f"""
<header class="top" id="sec-case">
  <h1>episode {_uv(ep.episode_id)}</h1>
  <div class="byline">{meta}</div>
</header>
"""


# =========================================================================================
# Verdict section: band, lede, tiles, cards
# =========================================================================================


def _render_verdict(ep: _Episode) -> str:  # noqa: C901, PLR0912, PLR0915 — the band, lede, four tiles and cards are one section
    grade = ep.grade
    if ep.not_graded:
        stamp = grade.not_graded
        band = (f'<div class="vd-band">not graded: {_uv(stamp.outcome)} — '
               f'<span class="vd-reason">{_uv(stamp.reason)}</span></div>')
        return _page_section("sec-verdict", "Verdict", band)

    if not ep.grade_rec.ok:
        band = f'<div class="vd-band">{_uv(ep.grade_rec.error)}</div>'
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
    # Draw keys may be `int` (document), `str` (stub) or `None`; the sort key
    # compares across them so a mixed set cannot raise `TypeError` out of the page.
    for draw in sorted(family_groups, key=_draw_sort_key):
        doc = family_docs.get(draw) if isinstance(draw, int) else None
        outcome = str(doc.get("episode_outcome", "")) if isinstance(doc, dict) else ""
        items = "".join(f'<div class="vd-family-item">{_uv(f.topic)}: {_uv(f.claim)}'
                        f' <span class="vd-outcome">{_uv(outcome)}</span></div>'
                        for f in family_groups[draw])
        lede_parts.append(f'<div class="vd-family-draw">{items}</div>')

    family_failed = getattr(grade, "family_failed_reason", None)
    if family_failed:
        lede_parts.append(f'<div class="vd-family-failed">{_uv(family_failed)}</div>')

    # `is not None`, not `or`: an empty `family_outcome` is the record's word, not an absence.
    family_outcome = getattr(grade, "family_outcome", None)
    badge_word = family_outcome if family_outcome is not None else grade.verdict_word
    queued = grade.enqueued_rows + grade.world_enqueued_rows
    lede_line = f"{_uv(grade.verdict_word)} · {queued} findings queued"
    lede_parts.append(f'<div class="vd-lede">{lede_line}</div>')

    badge = f'<span class="vd-badge">{_uv(badge_word)}</span>'
    meta = (f'<span class="vd-meta">{_uv(grade.episode_outcome)} · {_uv(grade.verdict_word)}'
            f' · validity {_uv(grade.validity)}</span>')

    # The record's own partition, never re-derived here.
    graded = grade.graded_worlds
    agree = 0
    for label in sorted(graded):
        entry = entries.get(label)
        row = entry.row if entry is not None else None
        if row is not None and _normalized_disposition(row.get("verdict")) == \
                _normalized_disposition(row.get("declared")):
            agree += 1
    # Asked of the vocabulary's own normalizer (case-insensitive, trimmed) rather than a local
    # copy of the enum.
    verdict_note = ("" if normalized_judge_outcome(grade.verdict_word) is not None
                    else ' <span class="vd-nonladder">(not a family word)</span>')
    tile1 = (
        f'<div class="vd-tile" id="vd-tile-1">{len(graded)} worlds judged · verdict = '
        f'declared on {agree} of {len(graded)} '
        f'<span class="vd-word">{_uv(grade.verdict_word)}</span>{verdict_note}</div>')

    unjudged_captions = [f"{_uv(w.label)} — {_uv(w.row.get('ungradable_reason'))}"
                         for w in entries.values()
                         if w.row is not None and w.row.get("ungradable")]
    tile2 = (
        f'<div class="vd-tile" id="vd-tile-2">{len(graded)} of '
        f'{sum(1 for w in entries.values() if w.row is not None)}'
        f'<div class="vd-caption">{"; ".join(unjudged_captions)}</div></div>')

    findings_total = len(rows)
    split_parts = [f"{counts['defender']} defender", f"{counts['world_author']} world author",
                  f"{counts['unqueueable']} unqueueable", f"{counts['dropped']} dropped"]
    if counts["never_eligible"]:
        split_parts.append(f"{counts['never_eligible']} never eligible")
    # The walk's own count, not `grade.enqueued_rows` (the record's figure, shown separately in
    # the queue accounting).
    tile_queued = counts["defender"] + counts["world_author"]
    tile3 = (
        f'<div class="vd-tile" id="vd-tile-3">{tile_queued} of '
        f'{findings_total} <div class="vd-caption">{" / ".join(split_parts)}</div></div>')

    # Without a real wall (absent, unreadable, or every row inverted) this tile shows the
    # lower-bound estimate. `measured` is decided once at load, so this agrees with the stages
    # header, which carries the figure when there is one.
    bound_html = f'<br>{ep.lower_bound}' if not ep.timing.measured else ""
    tile4 = (
        f'<div class="vd-tile" id="vd-tile-4">{_money(ep.total_cost)}'
        f'<div class="vd-caption">{ep.worlds_wall}{bound_html}</div></div>')

    cards = []
    for w in entries.values():
        if w.label == ep.control_label or w.row is None or w.row.get("ungradable"):
            continue
        row = w.row
        header = f"{_uv(row.get('declared'))} → {_uv(row.get('verdict'))}"
        heading = _bucket_html(row)
        # The footer counts this world's defender rows and links the group of the first one, so
        # the count and the anchor refer to the same rows.
        world_group = [f for f in rows if f.label == w.label and f.subject == SUBJECT_DEFENDER]
        n_findings = len(world_group)
        if world_group and all(f.disposition == "never_eligible" for f in world_group):
            footer_word = "never eligible"
        else:
            footer_word = "enqueued"
        group_n = (ep.findings.group_index.get(_disposition_heading_raw(world_group[0]), 1)
                   if world_group else 1)
        off_roster_note = ("" if w.in_manifest or w.run_dir_name is not None
                          else '<div class="vd-off-roster">not in the manifest</div>')
        cards.append(
            f'<div class="vd-cause">{_uv(w.label)} {header} {heading}{off_roster_note}'
            f'<a href="#fg-{group_n}">{n_findings} findings · {footer_word}</a>'
            f'</div>')

    body = (f'<div class="vd-band">{badge}{meta}</div>'
           f'{"".join(lede_parts)}{tile1}{tile2}{tile3}{tile4}'
           f'<div class="vd-cards">{"".join(cards)}</div>'
           f'{_render_queue_accounting(grade, counts)}')
    return _page_section("sec-verdict", "Verdict", body)


def _draw_sort_key(draw: Any) -> tuple[int, Any]:
    if isinstance(draw, int):
        return (0, draw)
    if isinstance(draw, str):
        return (1, draw)
    return (2, "")


def _normalized_disposition(value: Any) -> Any:
    """A disposition through the vocabulary's normalizer, or the raw value if it knows none."""
    if not isinstance(value, str):
        return value
    return normalized_disposition(value) or value


def _render_queue_accounting(grade: Any, counts: dict[str, int]) -> str:
    lines = [
        f'defender: {grade.enqueued_rows} enqueued to {_uv(grade.enqueued_to)}',
        f'questioner: {grade.world_enqueued_rows} enqueued to {_uv(grade.world_enqueued_to)}',
        f'unqueueable {counts["unqueueable"]}',
        f'malformed {grade.queue_malformed_rows} / {grade.world_queue_malformed_rows}',
        f'dropped {counts["dropped"]}',
        f'family malformed replies {grade.family_malformed_replies}',
    ]
    record_vs_page = f'record: {grade.enqueued_rows} enqueued · page found: {counts["defender"]}'
    if grade.enqueued_rows != counts["defender"]:
        record_vs_page += (f' <span class="vd-disagree">record and page disagree by '
                          f'{abs(grade.enqueued_rows - counts["defender"])}</span>')
    lines.append(record_vs_page)

    for line in _items(getattr(grade, "unqueueable_findings", None)):
        lines.append(_uv(str(line)))

    return f'<details class="vd-acct"><summary>Queue accounting</summary>' \
          f'{"".join(f"<div>{line_}</div>" for line_ in lines)}</details>'


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
                             f'the branch point untouched, not graded · {_uv(declared)}</div>')
            continue
        axis = w.get("axis")
        axis_html = (f'<q class="verbatim">{_uv(axis)}</q>' if isinstance(axis, str)
                    else "<em>null</em>")
        guide_rows.append(f'<div class="vd-guide-row">{esc(label)} '
                         f'({esc(str(w.get("role")))}) {_uv(declared)} {axis_html}</div>')

    # The roster as loaded: the heading counts the sectioned items; unnameable ones render one
    # line and are not counted.
    sections = [_render_roster_item(ep, item) for item in ep.roster]

    body = f'<div class="vd-guide">{"".join(guide_rows)}</div>{"".join(sections)}'
    return _page_section("sec-worlds", f"Worlds ({len(ep.sectioned)})", body)


def _declared_for(label: str, manifest_world: dict[str, Any],
                  entries: dict[str, WorldEntry]) -> Any:
    entry = entries.get(label)
    if entry is not None and entry.row is not None and entry.row.get("declared") is not None:
        return entry.row["declared"]
    return manifest_world.get("disposition_declared")


def _render_roster_item(ep: _Episode, item: RosterItem) -> str:
    """One roster line, by the shape the loader gave it."""
    if item.kind == ROSTER_UNNAMEABLE:
        return _unnameable(item.label, what="world directory")
    return _render_one_world(ep, item.label)


def _render_one_world(ep: _Episode, label: str) -> str:  # noqa: C901, PLR0912, PLR0915 — one world's whole section (state, bucket, facts, calls, archive)
    entry = ep.entries[label]
    # A `not_graded` stamp voids the family's word: every record-derived part (ladder,
    # bucket, systems) renders as "not graded" even though the row exists. Run-dir and
    # archive parts are unaffected.
    row = None if ep.not_graded else entry.row
    bits = []

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
            bits.append(f'<div class="w-declared">{_uv(declared)}</div>')
    elif row.get("ungradable"):
        bits.append('<div class="w-state">ungradable</div>')
        bits.append(f'<div class="w-reason">{_uv(row.get("ungradable_reason"))}</div>')
    else:
        bits.append(f'<div class="w-verdict">{_uv(row.get("verdict"))}</div>')
        bits.append(f'<span class="w-ladder">verdict = declared: {_uv(row.get("verdict"))} == '
                    f'{_uv(row.get("declared"))}</span>')
        bits.append(_bucket_html(row))
    failed = ep.failed_worlds.get(label)
    if isinstance(failed, dict) and row is None:
        bits.append(f'<div class="w-reason">{_uv(failed.get("reason"))} — '
                    f'{_uv(failed.get("detail"))}</div>')

    if manifest_world is not None:
        axis = manifest_world.get("axis")
        if isinstance(axis, str):
            bits.append(f'<div class="w-axis"><q class="verbatim">{_uv(axis)}</q></div>')
        bits.append(_facts_html(manifest_world))

    leads = ep.leads.get(label)
    if leads is not None and leads.calls:
        bits.append(_calls_html(leads.calls))

    result = entry.result
    # Both checked: `result` is only set alongside `run_page`, but nothing enforces that.
    if result is not None and entry.run_page is not None:
        bits.append(f'<a href="{esc(entry.run_page)}">runtime</a>')
        if result.cost is not None and result.costed:
            bits.append(f'<span class="w-cost">{_money(result.cost)}</span>')
            if result.wall_ms:
                bits.append(f'<span class="w-wall">{fmt_duration(result.wall_ms)}</span>')
        else:
            bits.append(f'<span class="w-cost">{esc(result.text)}</span>')
    else:
        bits.append('<div class="w-archive">run directory absent</div>')

    # Each archived leaf is its own line and names its leaf.
    archived = entry.archive
    if archived is None:
        bits.append('<div class="w-archive">not archived</div>')
    else:
        if archived.report.absent:
            bits.append(
                f'<div class="w-archive">{esc(str(WORLD_LEAVES.report))}: not archived</div>')
        else:
            headline = archived.report.disposition_or_unknown
            if archived.report.disposition is None and archived.report.reason:
                # No headline: show the reader's own reason beside the placeholder.
                headline += f" — {archived.report.reason}"
            bits.append(f'<div class="w-report">{_uv(headline)}</div>')
        if not archived.investigation_present:
            bits.append(
                f'<div class="w-archive">{esc(str(WORLD_LEAVES.investigation))}: '
                'not archived</div>')
        if archived.provenance is not None:
            bits.append(f'<div class="w-prov">{_uv(archived.provenance.get("commit"))}</div>')
        else:
            bits.append('<div class="w-prov">absent</div>')
        if archived.scrub is None:
            bits.append('<div class="w-scrub">not recorded</div>')
        else:
            bits.append(f'<div class="w-scrub">{_uv(archived.scrub)}</div>')

    return f'<div id="world-{esc(label)}" class="w-section">{"".join(bits)}</div>'


def _bucket_html(row: dict[str, Any]) -> str:
    """The judge model's own answer for a world: its bucket and the systems its facts touch,
    or every draw's answer where the draws disagree (never reduced to one here)."""
    bits = []
    bucket = row.get("bucket")
    if bucket:
        cls = _BUCKET_CLASS.get(bucket, "bucket-other")
        bits.append(f'<span class="w-bucket {cls}">{_uv(bucket)}</span>')
    else:
        bits.append('<span class="w-bucket bucket-other">no bucket</span>')
    systems = row.get("systems")
    if isinstance(systems, list):
        bits.append(f'<span class="w-chip">systems: {_uv(", ".join(map(str, systems)))}</span>')
    if row.get("draws_disagree"):
        for draw in _items(row.get("draws")):
            draw = _mapping(draw)
            bits.append(f'<span class="w-chip">draw {_uv(draw.get("draw"))}: '
                        f'{_uv(draw.get("bucket"))} {_uv(draw.get("systems"))}</span>')
    return " ".join(bits)


def _facts_html(manifest_world: dict[str, Any]) -> str:
    """A world's natural-language facts, each statement and its entities as text."""
    facts = [f for f in _items(manifest_world.get("facts")) if isinstance(f, dict)]
    if not facts:
        return '<div class="w-facts">no facts (the capture\'s own answers)</div>'
    items = "".join(
        f'<div class="w-fact">{_uv(f.get("fact_id"))}: {_uv(f.get("statement"))} '
        f'<span class="w-entities">{_uv(", ".join(map(str, _items(f.get("entities")))))}'
        f'</span></div>' for f in facts)
    return f'<div class="w-facts">{items}</div>'


def _calls_html(calls: list[dict[str, Any]]) -> str:
    """The world's own served-ledger rows: each call with the decision word that answered it
    (`passthrough`, `oracle`, `real-error`, `refused`, `fault`)."""
    items = "".join(
        f'<div class="w-call">[{_uv(c.get("source"))}] {_uv(c.get("system"))} '
        f'{_uv(c.get("verb"))} {_uv(c.get("params"))}</div>' for c in calls)
    return f'<div class="w-calls">{items}</div>'


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
        # The draw's own `episode_outcome`, beside its findings.
        bits.append(f'<span class="fr-outcome">{_uv(f.outcome)}</span>')
    # The row id embeds the world label, so a label failing the id grammar gets no id at all.
    id_attr = f' id="{esc(f.row_id)}"' if _safe_id(f.label) else ""
    # Joined with a space: adjacent inline spans would otherwise glue their words together in
    # whitespace-collapsing text extraction.
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
        dropped_bits.append(f'<div class="fr-dropped">draw {_uv(draw)} of {_uv(label)}: '
                           f'{_uv(dropped)} dropped</div>')
    for label, draw, failure_reason in findings.draw_failures:
        dropped_bits.append(f'<div class="fr-dropped">draw {_uv(draw)} of {_uv(label)}: '
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


def _render_stages(ep: _Episode) -> str:  # noqa: C901, PLR0912, PLR0915 — the stage table, the two clocks and every trace block are one section
    timing = ep.timing
    rows_by_step = timing.rows_by_step
    review_total, review_calls = ep.review_cost, ep.review_calls

    table_rows = []
    for step in STEPS:
        entries_for_step = rows_by_step.get(str(step), [])
        if timing.error:
            wall_text = ""
        elif entries_for_step:
            # Trusted (non-inverted) pairs only.
            step_wall = timing.step_wall_ms(str(step))
            wall_text = fmt_duration(step_wall) if step_wall is not None else "—"
            if len(entries_for_step) > 1:
                wall_text += f" ({len(entries_for_step)} entries)"
        else:
            wall_text = "not on the record"
        if str(step) in ep.role_costs:
            cost_text = _role_cost_text(ep.role_costs[str(step)])
        elif str(step) == "runs":
            # The runs step row carries only its wall; its cost is on the per-run sub-rows.
            cost_text = ""
        else:
            cost_text = "no model calls"
        table_rows.append(f'<div class="st-row">{esc(str(step))} {esc(wall_text)} '
                         f'{esc(cost_text)}</div>')

    # The caption is `_Timing`'s decision, shared with the header line and the verdict tile.
    if timing.error:
        table = f'<div class="st-error">{_uv(timing.error)}</div>' + "".join(table_rows)
    elif timing.caption is not None:
        table = f'<div class="st-caption">{esc(timing.caption)}</div>' + "".join(table_rows)
    else:
        table = "".join(table_rows)

    # `ep.total_cost` already includes the questioner and judge traces.
    grand_total = ep.total_cost + review_total
    # No total line when nothing priced; `ep.costed` rather than truthiness, since an
    # all-$0.0000 episode is still priced.
    if ep.costed or review_calls:
        table += (f'<div class="st-total">{_money(grand_total)} — excludes gather subagents</div>')

    runs_rows = []
    runs_total = 0.0
    for w in ep.entries.values():
        result = w.result
        if result is None:
            continue
        if result.cost is not None and result.costed:
            runs_total += result.cost
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} {_money(result.cost)} '
                            f'{fmt_duration(result.wall_ms) if result.wall_ms else ""} '
                            f'<span class="rn-launcher">result event</span></div>')
        else:
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} {esc(result.text)}</div>')
    runs_wall = timing.step_wall_ms("runs")
    if runs_wall is not None:
        runs_rows.insert(0, f'<div class="rn-launcher-wall">{fmt_duration(runs_wall)} launcher</div>')
    if ep.runs_costed:
        runs_rows.append(f'<div class="rn-total">{_money(runs_total)}</div>')

    # Only these steps get an id; the rest render inline.
    stages_id_map = {"questioner": "stage-questioner", "runs": "stage-runs",
                     Step.JUDGE: "stage-judge"}
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

    if not timing.measured:
        header_line = f'<div class="hd-lower-bound">{esc(ep.lower_bound)}</div>'
    else:
        header_wall_text = fmt_duration(timing.launcher_wall_ms or 0.0)
        header_line = (f'<div class="hd-wall">{esc(header_wall_text)} — the launcher\'s wall '
                      f'from the first step\'s start to the last step\'s end; excludes '
                      f'preflight and the prime, includes the gaps between steps</div>')

    body = f'{header_line}{timing_block}{"".join(stage_blocks)}{unattributed_html}'
    return _page_section("sec-stages", f"Stages ({len(STEPS)})", body)


def _role_cost_text(role: _RoleCost) -> str:
    if not role.calls:
        return "no cost recorded"
    if role.priced < role.calls:
        return (f"{_money(role.cost)} · {role.calls} traces · {fmt_duration(role.wall_ms)} · "
                f"partial — {role.priced} of {role.calls} calls priced")
    return f"{_money(role.cost)} · {role.calls} traces · {fmt_duration(role.wall_ms)}"


def _wall_between(start: str, end: str) -> float | None:
    """The pair's wall in ms: `None` if either stamp does not parse, `-1` if inverted (end
    before start), else the delta (zero included)."""
    a, b = parse_iso_utc(start), parse_iso_utc(end)
    if a is None or b is None:
        return None
    delta = (b - a).total_seconds() * 1000
    return delta if delta >= 0 else -1


def _wall_span(starts: list[str], ends: list[str]) -> float:
    parsed_starts = [d for s in starts if (d := parse_iso_utc(s)) is not None]
    parsed_ends = [d for e in ends if (d := parse_iso_utc(e)) is not None]
    if not parsed_starts or not parsed_ends:
        return 0.0
    return (max(parsed_ends) - min(parsed_starts)).total_seconds() * 1000


def _unattributed_traces(ep: _Episode) -> list[str]:
    """Every judge trace stem naming no roster label or `family`. Its cost is still in the judge
    row; only the transcript block is withheld. Uses `_stem_names_label`, the same check the
    judge block routes by."""
    known_labels = [*ep.entries, _FAMILY_LABEL]
    # `stems_for` includes framed-only twins, matching what the judge block renders.
    return [stem for stem in sorted(ep.wire.stems_for(Step.JUDGE))
            if not any(_stem_names_label(stem, label) for label in known_labels)]


def _transcript_blocks_for_step(ep: _Episode, step: str) -> str:  # noqa: C901 — one discovery pass per role, family-first ordering included
    if step not in ("questioner", Step.JUDGE, "review") or not ep.wire.present:
        return ""
    blocks = []
    if step == "questioner":
        for stem in sorted(ep.wire.stems_for("questioner")):
            blocks.append(_transcript_block(ep.wire.traces[stem]))
    elif step == Step.JUDGE:
        # Family first, then each world in numeric draw order. Stems include framed-only
        # twins, which is all some judge calls write.
        judge_stems = ep.wire.stems_for(Step.JUDGE)
        family_stems = sorted((s for s in judge_stems if _stem_names_label(s, _FAMILY_LABEL)),
                              key=lambda s: _draw_key_stem(s, _FAMILY_LABEL))
        for stem in family_stems:
            blocks.append(_transcript_block(ep.wire.traces[stem]))
        for label in sorted(ep.entries):
            # Not a bare `startswith`: `baseline` would also claim `baseline_2`'s stems.
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
                # An empty comparator trace is listed by stem rather than rendered.
                blocks.append(f'<div class="tx-note">{esc(stem)}: 0 rows</div>')
    return "".join(blocks)


def _stem_names_label(stem: str, label: str) -> bool:
    """Does `stem` (`judge_<label>_<n>_trace`) name a draw of `label` itself, rather than of a
    label that merely starts with `label` (`baseline` vs `baseline_2`)? The remainder must be
    the draw index's digits alone."""
    prefix = f"judge_{label}_"
    if not stem.startswith(prefix):
        return False
    remainder = stem[len(prefix):-len("_trace")]
    # ASCII digits only, matching `draws_on_disk_report` (`str.isdigit` admits other scripts).
    return remainder.isascii() and remainder.isdigit()


def _draw_key_stem(stem: str, label: str) -> int:
    prefix = f"judge_{label}_"
    if not stem.startswith(prefix):
        return 0
    try:
        return int(stem[len(prefix):-len("_trace")])
    except ValueError:
        return 0


def _message_parts(row: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    """A wire row's `message` mapping and `parts` list, each empty when absent."""
    msg = _mapping(row.get("message"))
    return msg, _items(msg.get("parts"))


def _no_response_html(trace: _Trace) -> str:
    """The line for a call with no response. A refused plain trace (link, FIFO, unreadable)
    says so, rather than reading like a benign empty call."""
    if trace.plain == "refused":
        return '<div class="tx-refused">trace refused — not a plain readable file at its name</div>'
    return '<div class="tx-entry">no response recorded</div>'


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
    entries_html = [f'<div class="tx-label">{_uv(agent_id)}</div>'] if agent_id else []
    has_plain_response = any(r.get("kind") == "response" for r in rows)
    # The request (framed prompt, or the plain trace's request row) is its own element, not a
    # `tx-entry`.
    if framed is not None:
        prompt = framed.get("prompt")
        failure = framed.get("failure")
        reply = framed.get("reply")
        entries_html.append(f'<div class="tx-request">{_uv(prompt)}</div>')
        if failure:
            entries_html.append(f'<div class="tx-failure">{_uv(failure)}</div>')
        elif reply and not has_plain_response:
            # Framed-only calls render the bare reply. When the plain trace has a response
            # row, that row (with model/usage/duration) is rendered below instead.
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
        duration = _duration(row.get("duration_ms"))
        _msg, parts = _message_parts(row)
        text = next((p.get("content") for p in parts if isinstance(p, dict)
                    and p.get("part_kind") == "text"), "")
        priced = _priced(model, usage)
        line_bits = [f'<div class="tx-entry">{_uv(text)}']
        if model:
            line_bits.append(f'<span class="tx-model">{_uv(model)}</span>')
        input_tokens = _count(usage.get("input_tokens", 0)) if isinstance(usage, dict) else None
        if input_tokens is not None:
            line_bits.append(f'<span class="tx-usage">{input_tokens:,}</span>')
        else:
            line_bits.append('<span class="tx-usage">unpriced</span>')
        if priced is not None:
            line_bits.append(f'<span class="tx-cost">{_money(priced)}</span>')
        elif isinstance(usage, dict):
            line_bits.append('<span class="tx-cost">unpriced</span>')
        if duration is not None:
            line_bits.append(f'<span class="tx-wall">{fmt_duration(duration)}</span>')
        line_bits.append('</div>')
        entries_html.append("".join(line_bits))
    framed_has_response = framed is not None and (framed.get("failure") or framed.get("reply"))
    if not framed_has_response and not has_plain_response:
        entries_html.append(_no_response_html(trace))

    unreadable_html = (f'<div class="tx-unreadable">{trace.unreadable} unreadable rows</div>'
                       if trace.unreadable else "")
    # The id embeds a filename stem, so it is grammar-gated, not merely escaped.
    safe = _safe_id(trace.stem)
    if safe is None:
        return _unnameable(trace.stem, what="wire log")
    return (f'<div id="tx-{esc(safe)}" class="tx-stream">'
          f'<div class="tx-search"></div>'
          f'{"".join(entries_html)}{unreadable_html}</div>')


# =========================================================================================
# Leads section
# =========================================================================================


def _render_leads_section(ep: _Episode) -> str:
    # The same sectioned roster the worlds heading counts.
    blocks = [_render_world_leads(item.label, ep.leads[item.label]) for item in ep.sectioned]
    return _page_section("sec-leads", f"Leads ({len(ep.sectioned)})", "".join(blocks))


def _render_world_leads(label: str, leads: _WorldLeads) -> str:
    bits = []
    if leads.ledger_note is not None:
        bits.append(f'<div class="ld-served">{_uv(leads.ledger_note)}</div>')

    if not leads.archived:
        return f'<div id="leads-{esc(label)}" class="leads-section">not archived' \
              f'{"".join(bits)}</div>'

    if leads.dir_error is not None:
        bits.append(f'<div class="ld-dir">world directory unreadable: {_uv(leads.dir_error)}</div>')
    if leads.facts_error is not None:
        bits.append(f'<div class="ld-investigation">investigation record unavailable: '
                   f'{_uv(leads.facts_error)}</div>')
    if leads.moved:
        bits.append('<div class="ld-moved">the hand-off was revisited after the branch</div>')

    for lead_id, chain in leads.chains:
        safe = _safe_id(lead_id)
        # `names_one_file` is the path-traversal screen; `lead_chain` already answered unsafe
        # ids. An id that names a real file but is not HTML-id-safe is neutralized here,
        # discarding its content.
        file_safe = isinstance(lead_id, str) and family.names_one_file(lead_id)
        if file_safe and safe is None:
            bits.append(_unnameable(lead_id, what="lead id"))
            continue
        id_attr = f' id="ld-{esc(label)}-{esc(safe)}"' if safe is not None else ""
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


def _render_records(ep: _Episode) -> str:  # noqa: C901, PLR0912 — every episode-level record's own slot in one section
    samples_rec, stamp_rec = ep.samples_rec, ep.stamp_rec
    bits = [f'<div class="rc-story">{_uv(ep.manifest.get("base_story"))}</div>']
    discriminator = ep.manifest.get("discriminator")
    if isinstance(discriminator, dict):
        bits.append(f'<div class="rc-predicate">{_uv(discriminator.get("predicate"))}</div>')
    served = _items(ep.manifest.get("served_systems"))
    bits.append(f'<div class="rc-served">served systems: {_uv(", ".join(map(str, served)))}'
                '</div>')

    for w in ep.manifest_worlds:
        if isinstance(w.get("world_id"), str):
            bits.append(f'<div class="rc-world">{_uv(w["world_id"])}</div>')

    bits.append(_outcome_html(ep))

    if samples_rec.error:
        bits.append(f'<div class="rc-samples">{_uv(samples_rec.error)}</div>')
    elif not samples_rec.present:
        bits.append('<div class="rc-samples">absent</div>')
    else:
        bits.append(_samples_html(_mapping(samples_rec.value)))

    if stamp_rec.error:
        bits.append(f'<div class="rc-provenance">{_uv(stamp_rec.error)}</div>')
    elif not stamp_rec.present:
        bits.append('<div class="rc-provenance">absent</div>')
    else:
        stamp = _mapping(stamp_rec.value)
        agreed = stamp.get("agreed")
        if isinstance(agreed, dict):
            bits.append(f'<div class="rc-commit">{_uv(agreed.get("commit"))}</div>')
            bits.append(f'<div class="rc-model">{_uv(agreed.get("model"))}</div>')
            for path_ in _items(agreed.get("dirty_paths")):
                bits.append(f'<div class="rc-dirty">{_uv(path_)}</div>')
        bits.append(f'<div class="rc-allow-dirty">allow_dirty: '
                   f'{_uv(stamp.get("allow_dirty"))}</div>')

    return _page_section("sec-records", "Records", "".join(bits))


def _record_call_text(call: Any) -> str:
    call = _mapping(call)
    return f'{_uv(call.get("system"))} {_uv(call.get("verb"))} {_uv(call.get("params"))}'


def _outcome_html(ep: _Episode) -> str:
    """Pre-flight's outcome record — its word and reason, the worlds it found unservable, the
    calls it could not replay and the calls that drifted — and every world's own record."""
    rec = ep.outcome_rec
    record = _mapping(_mapping(rec.value).get("record"))
    bits = []
    if rec.error:
        bits.append(f'<div class="rc-outcome">{_uv(rec.error)}</div>')
    else:
        bits.append(f'<div class="rc-outcome">outcome: {_uv(record.get("outcome"))} — '
                    f'{_uv(record.get("reason"))}</div>')
    for key, what in (("unservable_worlds", "unservable in pre-flight"),
                      ("not_replayable", "not replayable"), ("drift", "drift")):
        for entry in _items(record.get(key)):
            entry = _mapping(entry)
            extra = entry.get("world") if key == "unservable_worlds" else None
            note = entry.get("status") or entry.get("reason")
            bits.append(f'<div class="rc-outcome-call">{esc(what)}: '
                        f'{_uv(extra) + " " if extra is not None else ""}{_record_call_text(entry.get("call") if key == "unservable_worlds" else entry)}'
                        f' ({_uv(note)})</div>')
    for label, entry in sorted(ep.failed_worlds.items()):
        entry = _mapping(entry)
        bits.append(f'<div class="rc-world-record">world {_uv(label)}: {_uv(entry.get("reason"))}'
                    f' — {_record_call_text(entry.get("call"))} — {_uv(entry.get("detail"))}</div>')
    return "".join(bits)


def _samples_html(samples: dict[str, Any]) -> str:
    """The samples record, one section per system: its verbs' real example answers, or the
    reason the system has none."""
    bits = []
    for system, section in samples.items():
        section = _mapping(section)
        if "unavailable" in section:
            bits.append(f'<div class="rc-sample-system">{_uv(system)}: unavailable — '
                        f'{_uv(section.get("unavailable"))}</div>')
            continue
        answers = "".join(
            f'<div class="rc-sample">{_uv(verb)}: {_uv(answer)}</div>'
            for verb, listed in _mapping(section.get("verbs")).items()
            for answer in _items(listed))
        bits.append(f'<div class="rc-sample-system">{_uv(system)}{answers}</div>')
    return "".join(bits)


# =========================================================================================
# CLI
# =========================================================================================


def _diagnostics(ep: _Episode) -> list[str]:
    """The stderr lines the CLI echoes beside the page path, from the model's refusal slots —
    never a scan of the rendered bytes, which include model-authored text."""
    lines = []
    for name, rec in (("grade", ep.grade_rec), ("timing", ep.timing_rec),
                      ("outcome", ep.outcome_rec), ("samples", ep.samples_rec),
                      ("provenance", ep.stamp_rec)):
        if rec.error:
            lines.append(f"{name} record unreadable")
    if ep.grade_rec.ok and ep.grade is None:
        lines.append("no grade record")
    return lines


def _parse_page_args(argv: list[str]) -> argparse.Namespace:
    """`--tenant T <episode_id>` (#1105 declared change 4, J8): the tenant is required, with
    no default, and the episode is named by its id under the configured episodes root."""
    p = argparse.ArgumentParser(prog="visualize_episode.py", description=__doc__)
    p.add_argument("--tenant", required=True,
                   help="the tenant whose episode is rendered; required, with no default")
    p.add_argument("episode_id", help="the episode, by its id")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    ns = _parse_page_args(argv)
    try:
        tenant = _tenant.accept_tenant(
            _tenant.resolve_data_root(), _tenant.requested_tenant_id(ns.tenant),
            defender_dir=process_defender_dir())
        view = open_episode_view(tenant.runs_repository(), ns.episode_id)
    except (_tenant.TenantRefused, JudgeRefused) as bad:
        # One line: the refusal may wrap a multi-line YAML parser error.
        print(" ".join(str(bad).split()), file=sys.stderr)
        return 1
    with view:
        try:
            ep = load_episode(view)
        except JudgeRefused as bad:
            print(" ".join(str(bad).split()), file=sys.stderr)
            return 1
        try:
            page_path = _write_page(view.episode, _render_document(ep))
        except OSError as bad:
            print(str(bad), file=sys.stderr)
            return 1
    print(page_path)
    for line in _diagnostics(ep):
        print(line, file=sys.stderr)
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
