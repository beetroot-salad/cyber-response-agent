"""Typed episode view models and scalar normalization."""
from __future__ import annotations



import math



from pathlib import Path

from typing import Any


from defender._clock import parse_iso_utc



from defender.records._report import ReportRead










from defender.learning.judge import family

from defender.learning.judge.enqueue import (
    DrawsSkipReport,
)




from defender.episodes._family import (
    BASE_ROLE, world_id_for,
)

from defender.configuration._pricing import UnknownModel, model_key, usage_cost





def _items(x: Any) -> list[Any]:
    """A list field, or `[]` when the record holds anything else."""
    return x if isinstance(x, list) else []




def _mapping(x: Any) -> dict[str, Any]:
    """The mapping twin of `_items`."""
    return x if isinstance(x, dict) else {}




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
    """What `worlds/<world-uuid>/` holds: the archived report, whether the investigation is
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
        #: `worlds/<world-uuid>` exists but is not a listable real directory: the bind's refusal,
        #: said once for the block.
        self.dir_error: str | None = None
        self.facts_error: str | None = None
        self.moved = False
        self.chains: list[tuple[str, dict[str, Any]]] = []


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
        #: Whether the validated manifest binds this display label to a host UUID.
        self.nameable = False
        self.run_dir_name: str | None = None  # the arm's run folder, opened by id through the view
        #: The arm's run page, relative to the episode page (`runs/<arm>/runtime.html`).
        self.run_page: str | None = None
        self.result: _ResultEvent | None = None  # `None` when there is no run dir at all
        self.archive: _WorldArchive | None = None  # `None` when nothing is at worlds/<world-uuid>




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
                 "reason", "stub", "recorded_id", "raw")

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
        self.counts = {"defender": 0, "world_author": 0, "unqueueable": 0, "dropped": 0}
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
        # Only mapping entries: scalars have nothing to render.
        self.manifest_worlds: list[dict[str, Any]] = [
            w for w in _items(manifest.get("worlds")) if isinstance(w, dict)]
        self.control_label: str | None = next(
            (w["label"] for w in self.manifest_worlds
             if w.get("role") == BASE_ROLE and isinstance(w.get("label"), str)), None)
        self.grade_rec = _Record()
        self.outcome_rec = _Record()
        self.samples_rec = _Record()
        self.stamp_rec = _Record()
        self.timing_rec = _Record()
        #: Arm roster: absent before RUNS; a refusal is displayed beside the arms.
        self.roster_rec = _Record()
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


    def world_id(self, label: str) -> str:
        """The host identity for a label in this episode's validated manifest."""
        return world_id_for(self.manifest, label)

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
        return next((w for w in self.manifest_worlds if w.get("label") == label), None)

    @property
    def failed_worlds(self) -> dict[str, dict[str, Any]]:
        """Every world O5 counts as failed, by label (`outcome.failed_worlds`)."""
        return _mapping(_mapping(self.outcome_rec.value).get("failed"))




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
