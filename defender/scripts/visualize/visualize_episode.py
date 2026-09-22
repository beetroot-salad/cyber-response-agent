"""#1025 — the episode page: `render_episode(episode_dir) -> Path` renders `learning.html`
beside `judge.yaml` from an episode directory alone, and `main(argv)` is the standalone CLI.
The launcher (`branch/cli.py::_render_page`) calls `render_episode` after the JUDGE clock frame
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

A READER OF DECISIONS, NEVER A MAKER OF THEM. Where the page shows what a pass DID — which
lane a finding took, whether a world was walked — it shows what that pass wrote down
(`judge.yaml.dispositions`, the enqueue's own ledger), not a re-run of the pass's rule over
the record's rows. Two earlier shapes of this page did the latter (a copied rule, then the
borrowed rule fed with rebuilt inputs) and each disagreed with the pass at an edge the page
was built to explain. When the page needs a decision the record does not carry, the fix is to
the writer.
"""
from __future__ import annotations

import math
import re
import sys
from pathlib import Path
from typing import Any

if __name__ == "__main__" and (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._artifact_schema import INVESTIGATION_NAME, REPORT_NAME
from defender._clock import parse_iso_utc
from defender._io import Bound, bind, write_guarded
from defender._report import ReportRead
from defender._run_id import is_valid_run_id
from defender._episode_paths import LEARNING_HTML_NAME, EpisodePaths
from defender._run_paths import (
    FRAMED_TRACE_SUFFIX,
    PROVENANCE,
    REVIEW_TRACE_SUFFIX,
    RUNTIME_HTML,
    TOOL_TRACE,
    WIRE_LOG_DIR,
)
from defender._vocab import normalized_disposition, normalized_judge_outcome
from defender.learning.branch import archive, staging
from defender.learning.branch import timing as timing_mod
# `archive`, where the launcher moved it so the writer of the tree and this reader spell the
# segment once — NOT `branch.cli`, which is the launcher itself (argparse, the estate
# registry, the review runtime): imported for one constant it dragged the whole graph into a
# static renderer and, with the launcher running as a script, executed `cli.py` twice.
from defender.learning.branch.archive import RUNS_SUBDIR
from defender.learning.branch.steps import STEPS, Step
from defender.learning.judge import JudgeRefused, read_grade
from defender.learning.judge import family
from defender.learning.judge.enqueue import (
    KIND_MECHANICAL,
    LANE_DEFENDER,
    LANE_NEVER_ELIGIBLE,
    LANE_UNQUEUEABLE,
    LANE_WITHHELD,
    LANE_WORLD,
    DrawsSkipReport,
    draws_on_disk_report,
)
from defender.learning.judge.render import episode_alert
from defender.learning.judge.run import SUBJECT_DEFENDER, SUBJECT_WORLD
from defender.runtime.branch._family import BASE_ROLE, episode_token_for
from defender.scripts import pricing
from defender.scripts.visualize.visualize_primitives import (
    ASSETS,
    CSS,
    EVENT_HANDLER_RE,
    esc,
    fmt_duration,
)

#: The page's OWN stylesheet, inlined after the run pages' shared one (`CSS`: the tokens, the
#: two-column layout, the sticky header and nav, the wrapping rules). The shared sheet knows
#: nothing of this page's vocabulary — its `.tx-entry` is a two-column grid for a transcript
#: turn, which put every response's text into a 56px gutter — so every class this module
#: emits has its rule HERE, and `test_1025_every_class_the_page_emits_has_a_rule` holds the
#: two in step (#1025).
EPISODE_CSS = (ASSETS / "episode.css").read_text(encoding="utf-8")

PAGE_NAME = LEARNING_HTML_NAME

#: The run's own event stream, at the run dir's root (`_run_paths` names why it stays there).
_TOOL_TRACE_NAME = TOOL_TRACE
#: The family's own draw documents live under this pseudo-label beside the worlds.
_FAMILY_LABEL = "family"

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


def _uv(x: Any) -> str:
    """A scalar rendered as text, through the untrusted escape — THE ONE spelling (#1025 O9):
    almost nothing on this page is a structural literal this module wrote itself — every
    string is a record field, and a record lives in a tree a box can reach. A second, plainer
    alias would make every call site a silent decision that ITS value is exempt from the
    event-handler split, which is exactly the kind of per-site judgment call this design's
    `esc_untrusted` exists to remove; `esc()` alone is for the page's own literals and ids.

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
    escape exactly once. `None` reads as the same em dash `_uv` shows."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    return x if isinstance(x, str) else str(x)


def _unnameable(raw: str, *, what: str) -> str:
    return f'<div class="unnameable">unnameable entry ({esc(what)}): {_uv(raw)}</div>'


def _money(cost: float) -> str:
    """A total is gated where it is printed, not only where its addends were read: every row
    passes `_finite`, and the sum of enough finite rows is still `inf` (review of PR #1042)."""
    return f"${cost:.4f}" if math.isfinite(cost) else "—"


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


def _read_review(bound: Bound) -> _Record:
    try:
        doc = family.read_review_record(bound)
    except JudgeRefused as bad:
        return _Record(present=True, error=f"review record unreadable: {bad}")
    return _Record(doc, present=doc is not None)


def _strict_samples_reader(bound: Bound, name: str) -> dict[str, Any] | None:
    """The page's own STRICT reading of `samples.yaml` (#1025 F-4) — through `read_samples_
    record`'s `reader=` seam. The DEFAULT reader `read_samples_record` uses everywhere else
    stays permissive (#1007 M4/O5); this one refuses what it cannot read so the page's
    "unreadable" state is distinguishable from "absent", and answers `None` on absence — the
    typed answer `_read_samples` coalesces at its own read site (#1049 RF-R1). The screen
    itself is the package's one home for a YAML record read (`screened_yaml_mapping`), not a
    second spelling of it — `empty_ok=True` because a present-but-empty samples.yaml is
    "nothing recorded yet", not a reason to call the whole record unreadable (the manifest's
    own empty-document refusal is untouched)."""
    return family.screened_yaml_mapping(bound, name, what="the samples record", empty_ok=True)


def _read_samples(bound: Bound) -> _Record:
    try:
        doc = family.read_samples_record(bound, reader=_strict_samples_reader)
    except JudgeRefused as bad:
        return _Record(present=True, error=f"samples record unreadable: {bad}")
    return _Record(doc or {}, present=doc is not None)


def _read_staged(bound: Bound) -> _Record:
    try:
        rows = staging.read_staged(bound)
    except staging.StagingRefused as bad:
        return _Record(present=True, error=f"staging record unreadable: {bad}")
    return _Record(rows or [], present=rows is not None)


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
    # `read_grade` KEEPS the root and binds at entry (#1049 non-obligation) — its own refusal
    # never quotes it (RF-C3), so no scrub is needed here either.
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

    #: The ONE sentence each non-`ok` state reads as, wherever a run's cost is shown — the
    #: world section and the stages table both take it from here, so the same trace cannot
    #: read "no result event" in one and "unusable result event" in the other.
    TEXT = {
        # No `tool_trace.jsonl` at all — a launcher-produced run that never wrote one, not a
        # sibling whose trace simply lacks a terminal result row (#1025). "no result event"
        # implies a trace WAS read; here nothing was there to read, so it reads the same
        # words the questioner/judge steps use for the same absence.
        "absent": "no cost recorded",
        "refused": "no result event (refused)",
        "none": "no result event",
        "unusable": "unusable result event",
        # A priced run shows its cost, not a sentence; the key is here so `text` can never
        # raise out of a display helper (d01: only `family.yaml` is fatal).
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
    """The stage clock, DECIDED ONCE for every surface that shows it: the stages header, the
    stage table's caption and the verdict tile's fallback all read the same answer here, so
    they cannot disagree about whether the episode has a measured wall.

    `error` is the reader's refusal (present but unreadable — the table's own distinct line);
    `rows_by_step` the readable rows; `trusted_by_step` those whose pair is not inverted;
    `launcher_wall_ms` the span over every trusted pair, or `None` when there is none — the
    ONE bit `measured` turns on. `caption` is the table's fallback line for an unmeasured
    clock, `None` once there is a real wall to show instead."""

    __slots__ = ("error", "present", "rows_by_step", "trusted_by_step", "launcher_wall_ms")

    def step_wall_ms(self, step: str) -> float | None:
        """ONE step's wall: its first trusted entry's start to its last trusted entry's end
        (J15) — never a sum, which double-counts a repeated step's own reported span — or
        `None` with no trusted pair. The stage table's row and the RUNS step's launcher line
        both read this, so they cannot disagree about one step (review of PR #1042)."""
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
        # Only a NON-INVERTED pair feeds a span: an inverted row (`d < 0`, `_wall_between`'s
        # own sentinel) shows "—" in its own cell rather than a number, and letting its
        # untrustworthy pair still widen or narrow min(start)/max(end) would silently corrupt
        # the one aggregate the row's own display just refused to state (#1025 p5). A
        # ZERO-length pair is not inverted: the clock stamps whole seconds (`now_iso()`), so a
        # step that starts and ends within one is a real step whose endpoints belong in the
        # span.
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
            # ABSENT vs a present record with no completed step (an abort before the first
            # step finished leaves `{"steps": []}`, a legitimate record) — told apart by the
            # reader's own `present` (#1049 D-J7: derived from `rows is not None`, never
            # `bool(rows)`), never conflated into one caption.
            if self.present:
                return "model-call time — no completed stages"
            return "model-call time — no timing record"
        return "model-call time — the timing record has no usable span (every row inverted)"


class _WorldArchive:
    """What `worlds/<label>/` holds for the world section: the archived report (its own
    `absent` when nothing is at its name; a refused entry is its `reason`), whether the
    investigation is archived, and the two JSON stamps (`None` when absent or unreadable)."""

    __slots__ = ("report", "investigation_present", "provenance", "scrub")

    def __init__(self, *, report: ReportRead, investigation_present: bool,
                 provenance: dict[str, Any] | None, scrub: dict[str, Any] | None) -> None:
        self.report = report
        self.investigation_present = investigation_present
        self.provenance = provenance
        self.scrub = scrub


class _WorldLeads:
    """One world's leads block, read: the served-ledger note (or `None`), whether the world is
    archived at all, the investigation's refusal (or `None`), whether the hand-off moved, and
    every lead's chain in roster order (a refused gather summary is the chain's own sentence).

    The ledger and the document are TWO slots (#1025): each is read by its own package reader
    and refuses on its own, so a served ledger that is absent or unreadable costs the block its
    malformed-row count and nothing else — the resolutions, the hand-off note and the
    referenced-lead roster all come off `investigation.md`, which is read whether or not the
    ledger could be."""

    __slots__ = ("ledger_note", "archived", "dir_error", "facts_error", "moved", "chains")

    def __init__(self) -> None:
        self.ledger_note: str | None = None
        self.archived = False
        #: `worlds/<label>` is there but is not a listable real directory (a planted link, a
        #: file squatting the name, a permission fault): the bind's own refusal, said once for
        #: the block — no lead is rostered off a directory that was never listed.
        self.dir_error: str | None = None
        self.facts_error: str | None = None
        self.moved = False
        self.chains: list[tuple[str, dict[str, Any]]] = []


#: The three shapes a roster item takes — decided ONCE at load (`_build_roster`), so the
#: worlds and leads sections render the list they are handed and their headings count that
#: same list. A renderer that re-decides membership on the way through (is this label
#: nameable? is it a world at all?) is how a heading came to count a different set than the
#: sections under it (#1025).
ROSTER_WORLD = "world"
#: A `runs/` artifact dir whose name did not decompose into `<episode_id>-<label>` (J7 iv):
#: a section keyed on its full name, no record-driven parts, a leads block that reads "not
#: archived".
ROSTER_STRAY_RUN_DIR = "stray_run_dir"
#: A label (or directory name) that cannot become an html id (`_safe_id`): rendered as one
#: "unnameable entry" line in the worlds section, and given NO section, NO leads block and
#: NO nav entry — so it is counted in neither heading.
ROSTER_UNNAMEABLE = "unnameable"


class RosterItem:
    """One line of the roster: its label (a world label, or a stray run dir's full name) and
    which of the three shapes above it takes."""

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
        #: Whether the label may be joined into a path at all (`family.world_label_names_
        #: directory`): a label carrying `..` or a separator names a directory OUTSIDE the
        #: episode, so the loader reads nothing for it and the sections render it as an
        #: unnameable entry — the same grammar the grading pass refuses such a manifest on.
        self.nameable = False
        self.run_dir_name: str | None = None  # the runs/ dir that decomposed to this label
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
        """Every call's own STEM for a role — the union of plain trace files and framed twins,
        since a launcher-produced episode writes only the framed one for some roles (#1025
        J13a/b): a stem with no plain trace file still gets a block, built entirely from its
        framed record."""
        # No plainness test: an entry exists in `traces` only because a plain file or a
        # framed twin was seen at load, so every stem here already has one of the two.
        return {s for s in self.traces if s.startswith(role_prefix)}

    def plain_stems(self, *, agent_prefix: str) -> list[str]:
        """The stems whose PLAIN trace file is on disk (readable or not), whose agent id starts
        with `agent_prefix`, in name order."""
        return sorted(s for s, t in self.traces.items()
                      if t.plain != "absent" and s[: -len("_trace")].startswith(agent_prefix))

    def role_cost(self, role_prefix: str) -> _RoleCost:
        """The cost of every trace file this stage's role owns — one call per FILE. A call is
        "priced" when its response row carries `usage` and a `model` the pricing table
        resolves; the wall total sums `duration_ms` only where present, independently of
        whether the call priced (#1025 J13b). Computed ONCE per role at load (`_cost_totals`)
        and read off `_Episode.role_costs` by every surface after."""
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
    # `model` EMPTY is unpriced here, not `pricing.model_key`'s absorbed pre-provider case: a
    # wire-log row that recorded no model at all is a call the page cannot bill, and billing
    # it at the absorbed row's rate would put a figure on the stage table for a model that
    # was never named.
    if not (isinstance(usage, dict) and isinstance(model, str) and model):
        return None
    try:
        cost = pricing.usage_cost(model, usage)
        pricing.model_key(model)
    except (pricing.UnknownModel, TypeError, ValueError, OverflowError):
        # `OverflowError`: a token count spelled as a 400-digit literal is an int, and
        # int-times-rate overflows before `_finite` ever sees the product.
        return None
    # The same gate `_result_event` puts on `total_cost_usd`: a usage block is box-writable,
    # and a negative, NaN or overflowing token count priced straight into the verdict tile
    # and the stages total as `$-146.7500` / `$inf` (#1025).
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
        # REFUSED, not dropped: a misspelled keyword at any construction site would otherwise
        # become a silent `None` field on every row.
        unknown = set(kw) - set(self.__slots__)
        if unknown:
            raise TypeError(f"_Finding: unknown field(s) {sorted(unknown)}")
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
                       "dropped": 0, "never_eligible": 0}
        self.world_reports: dict[str, DrawsSkipReport] = {}
        self.draw_failures: list[tuple[str, int, str]] = []
        self.dropped: list[tuple[str, int, int]] = []
        self.group_index: dict[str, int] = {}


class _Episode:
    """One read of the episode directory — everything a section renders, already typed."""

    def __init__(self, episode_dir: Path, manifest: dict[str, Any]) -> None:
        #: Held for EXACTLY two readers that are not this page's to rewrite — the lead
        #: repository (`family.leads_by_id`, the run dir's own surface) and the draw reader
        #: (`draws_on_disk_report`) — and reached only past the bind's own listing having
        #: judged the world directory real. Never formatted into the page.
        self.dir = episode_dir
        # NO bound reader is stored here (#1049 D-V2): `load_episode` binds once, threads the
        # handle through every loader as an argument, and closes it when it returns — every
        # read the page makes happens at load, and a renderer has no tree to reach for.
        self.manifest = manifest
        self.episode_id = family.episode_id_of(manifest)
        # BUILT OR ABSENT, never the raw id in its place: the token is joined into
        # `served/<token>.<label>.jsonl`, and an id the builder refuses (`../../x`) joined raw
        # would name a file OUTSIDE the episode dir this page promises to read from alone.
        # With no token there is no ledger to read, and the leads block says so.
        try:
            self.episode_token: str | None = episode_token_for(self.episode_id)
        except Exception:  # noqa: BLE001 — a token that cannot be built names no world's ledger
            self.episode_token = None
        # The manifest's world entries, as MAPPINGS: a scalar where the list belongs, or a
        # scalar among the entries, is nothing to render a section for.
        self.manifest_worlds: list[dict[str, Any]] = [
            w for w in _items(manifest.get("worlds")) if isinstance(w, dict)]
        self.control_label: str | None = next(
            (w["world_id"] for w in self.manifest_worlds
             if w.get("role") == BASE_ROLE and isinstance(w.get("world_id"), str)), None)
        self.grade_rec = _Record()
        self.review_rec = _Record()
        self.samples_rec = _Record()
        self.staged_rec = _Record()
        self.stamp_rec = _Record()
        self.timing_rec = _Record()
        self.entries: dict[str, WorldEntry] = {}
        #: Every roster line in section order, classified — what the worlds and leads sections
        #: render, and what their headings count.
        self.roster: list[RosterItem] = []
        self.off_roster = 0
        #: `runs/` directories whose full name is already a roster label — not sectioned a
        #: second time under the same ids; named on the off-roster line.
        self.shadowed_run_dirs: list[str] = []
        self.archived_world_dirs: list[str] = []
        self.alert: Any = None
        self.draws: dict[str, tuple[dict[int, dict[str, Any]], DrawsSkipReport]] = {}
        #: One leads block per ROSTER label — a `runs/` directory that decomposed to no world
        #: (J7 iv) gets one too, keyed by its full name, so the section reads the same for it.
        self.leads: dict[str, _WorldLeads] = {}
        self.wire = _WireLogs()
        self.findings = _Findings()
        self.timing = _Timing(_Record())
        self.total_cost = 0.0
        #: Did ANY run's result event price the run — the runs sub-total's own gate.
        self.runs_costed = False
        #: Did anything at all price this episode (a run, a questioner call, a judge call) —
        #: the grand total's gate. A flag, not `total_cost`'s truthiness: an episode whose
        #: every run cost $0.0000 is priced, and owes its total line, exactly as the runs
        #: sub-total below it does.
        self.costed = False
        self.worlds_wall = ""
        self.lower_bound = ""
        #: Each model role's spend, decided ONCE at load and read by the verdict tile, the
        #: stages header and the stage table alike — never re-walked at a render site.
        self.role_costs: dict[str, _RoleCost] = {}
        self.review_cost = 0.0
        self.review_calls = 0

    @property
    def sectioned(self) -> list[RosterItem]:
        """The roster items that get a section and a leads block — the count both headings
        show, by construction the same list the sections are rendered from."""
        return [item for item in self.roster if item.sectioned]

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
    with bind(episode_dir) as bound:
        return _load_episode(episode_dir, bound)


def _load_episode(episode_dir: Path, bound: Bound) -> _Episode:
    ep = _Episode(episode_dir, family.read_manifest(bound))

    ep.grade_rec = _read_grade(episode_dir)
    ep.review_rec = _read_review(bound)
    ep.samples_rec = _read_samples(bound)
    ep.staged_rec = _read_staged(bound)
    ep.stamp_rec = _read_family_stamp(bound)
    ep.timing_rec = _read_timing(bound)
    ep.timing = _Timing(ep.timing_rec)

    grade = ep.grade
    grade_rows = [r for r in (_items(grade.worlds) if grade is not None else [])
                  if isinstance(r, dict) and isinstance(r.get("world"), str)]
    ep.archived_world_dirs = [
        name for name in bound.under(archive.WORLDS_DIRNAME).entries().dirs()
        if name != _FAMILY_LABEL]
    ep.entries, ep.roster, ep.off_roster = _build_roster(
        ep, bound, [r["world"] for r in grade_rows], grade_present=ep.grade_rec.present)
    for row in grade_rows:
        w = ep.entries.get(row["world"])
        if w is not None:
            w.row = row

    # EVERY path below is joined from a label; only a label that names a directory of its
    # own reaches the disk. `archived_world_dirs` are real directory names, but a name is not
    # a label (`..` is a name) — the same gate applies.
    nameable = [w.label for w in ep.entries.values() if w.nameable]
    labels = [w["world_id"] for w in ep.manifest_worlds
              if isinstance(w.get("world_id"), str) and w["world_id"] in nameable]
    ep.alert = episode_alert(bound, labels or [
        n for n in ep.archived_world_dirs if family.world_label_names_directory(ep.episode_id, n)])

    for label in [*ep.entries, _FAMILY_LABEL]:
        ep.draws[label] = (_load_draws(ep, bound, label)
                           if label == _FAMILY_LABEL or ep.entries[label].nameable
                           else ({}, DrawsSkipReport()))
    for w in ep.entries.values():
        if not w.nameable:
            continue
        if w.run_dir_name is not None:
            w.result = _result_event(bound, f"{RUNS_SUBDIR}/{w.run_dir_name}")
        w.archive = _load_world_archive(bound, w.label)
    for item in ep.sectioned:
        entry = ep.entries.get(item.label)
        ep.leads[item.label] = (_load_world_leads(ep, bound, item.label)
                                if entry is None or entry.nameable else _WorldLeads())

    ep.wire = _load_wire_logs(bound.under(WIRE_LOG_DIR))
    ep.findings = _walk_findings(ep)
    ep.total_cost, ep.runs_costed, ep.costed, ep.worlds_wall, ep.lower_bound = _cost_totals(ep)
    return ep


def _load_draws(ep: _Episode, bound: Bound, label: str) -> tuple[dict[int, dict[str, Any]], DrawsSkipReport]:
    """The draws under `worlds/<label>/judge/` through the enqueue's own reader — which takes
    a path — reached ONLY when the bind's listing of `worlds/<label>` says the draw directory
    is a real one (never a link the page would otherwise hand the reader to follow)."""
    world = bound.under(f"{archive.WORLDS_DIRNAME}/{label}").entries()
    if not world.has_dir(archive.DRAWS_DIRNAME):
        return {}, DrawsSkipReport()
    return draws_on_disk_report(ep.dir / archive.WORLDS_DIRNAME / label / archive.DRAWS_DIRNAME)


def _duration(value: Any) -> float | None:
    """A `duration_ms` that can be shown: finite AND non-negative — the same gate
    `_result_event` puts on `total_cost_usd`. A negative wall off a box-writable trace made
    the worlds' wall range and the lower-bound estimate count backwards (review of PR #1042)."""
    ms = _finite(value)
    return ms if ms is not None and ms >= 0 else None


def _finite(value: Any) -> float | None:
    """`value` as a float when it is a real, finite number — `json.loads` admits `NaN` and
    `Infinity`, and `fmt_duration`'s `int(...)` rejects both — else `None`. The coercion goes
    through `float(...)` first: a 400-digit literal is an int, not `inf`, and `math.isfinite`
    on it raises `OverflowError` rather than answering (review of PR #1042)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        as_float = float(value)
    except OverflowError:
        return None
    return as_float if math.isfinite(as_float) else None


def _decompose_run_dir(name: str, *, episode_id: str) -> str | None:
    prefix = f"{episode_id}-"
    if name.startswith(prefix) and len(name) > len(prefix):
        return name[len(prefix):]
    return None


def _build_roster(ep: _Episode, bound: Bound, grade_row_labels: list[str],  # noqa: C901 — one union-membership decision (manifest ∪ judge.yaml rows ∪ runs/ dirs), the roster every other section keys on
                  *, grade_present: bool) -> tuple[dict[str, WorldEntry], list[RosterItem], int]:
    """Every world label the page must give a section to: manifest worlds ∪ `judge.yaml`
    rows ∪ `runs/` directories that decompose to `<episode_id>-<label>` (#1025 J7/J8).

    Returns the entries by label (manifest order first, then extras), the roster — each label
    in section order, then each undecomposable `runs/` directory by its FULL NAME, every item
    classified once here (`ROSTER_WORLD` / `ROSTER_STRAY_RUN_DIR` / `ROSTER_UNNAMEABLE`) — and
    the count of `worlds/` directories that are on neither the manifest nor the record
    (reported on one templated line, never rendered)."""
    entries: dict[str, WorldEntry] = {}
    order: list[str] = []
    runs = bound.under(RUNS_SUBDIR).entries()
    run_dirs = runs.dirs()

    def entry(label: str) -> WorldEntry:
        if label not in entries:
            entries[label] = WorldEntry(label)
            entries[label].nameable = family.world_label_names_directory(ep.episode_id, label)
            order.append(label)
        return entries[label]

    # A manifest world with no `judge.yaml` row contributes a section only once the episode
    # has reached RUNS at all — `runs/` still exists, a grade record landed at some point
    # (readable or not; `runs/` is disposable after it, J8), or a world was archived under
    # `worlds/`. An episode that never got past REVIEW/STAGING (a rejection, an abort) has none
    # of these: a manifest but no world to show anything about yet (#1025 J7/J8).
    # (`run_dirs` non-empty implies `runs/` listed — it is listed from it — so the rule is
    # these three, not four.)
    reached_runs = runs.entries is not None or grade_present or bool(ep.archived_world_dirs)
    # `family` IS NOT A WORLD. It is the reserved label the family-level call's draws live under
    # (`worlds/family/judge/`), and the judge refuses a manifest that spells a world with it —
    # but the page reads whatever tree it is given, and a manifest row, a grade row or a
    # `runs/<ep>-family` directory carrying the name would otherwise make the family lane a
    # world entry as well, walking its draws twice under duplicate `f-family-*` ids.
    for w in ep.manifest_worlds:
        label = w.get("world_id")
        if not isinstance(label, str) or label == _FAMILY_LABEL:
            continue
        if label not in entries and not reached_runs:
            continue
        entry(label)
        entries[label].in_manifest = True
        # keep the FIRST manifest entry's fields as the section's own; the guide renders every
        # entry verbatim regardless (J7 iii).
        if entries[label].manifest_doc is None:
            entries[label].manifest_doc = w

    for label in grade_row_labels:
        if label != _FAMILY_LABEL:
            entry(label)

    stray_run_dirs: list[str] = []
    for child in run_dirs:
        label = _decompose_run_dir(child, episode_id=ep.episode_id)
        if label is None or label == _FAMILY_LABEL:
            stray_run_dirs.append(child)
            continue
        entry(label).run_dir_name = child

    # ONE ITEM PER LABEL. A stray directory's roster label is its full name, and a name that is
    # already a world's label (`runs/<label>/` beside `runs/<ep>-<label>/`) would be a second
    # item with the same `world-<label>`/`leads-<label>` ids, silently overwriting the world's
    # leads block. It is reported on the off-roster line instead, beside the `worlds/` entries
    # the roster does not carry.
    shadowed = [name for name in stray_run_dirs if name in entries]
    stray_run_dirs = [name for name in stray_run_dirs if name not in entries]

    off_roster = sum(1 for name in ep.archived_world_dirs if name not in entries)
    ep.shadowed_run_dirs = shadowed

    def classify(label: str, kind: str) -> RosterItem:
        return RosterItem(label, kind if _safe_id(label) is not None else ROSTER_UNNAMEABLE)

    roster = [*(classify(label, ROSTER_WORLD) for label in order),
              *(classify(name, ROSTER_STRAY_RUN_DIR) for name in stray_run_dirs)]
    return entries, roster, off_roster


def _result_event(bound: Bound, run_dir_name: str) -> _ResultEvent:
    # THE EPISODE BIND, WALKED THROUGH THE JSONL TWIN (#1049) — absent/refused are the
    # primitive's own states, never an `entry_present` stat ahead of the read; a link or a
    # FIFO at the name is refused at the open itself rather than crashing the page with a
    # bare `PermissionError` (root ignores mode 000; a real non-root run does not, #1025).
    rows, _bad, rec = bound.read_jsonl(f"{run_dir_name}/{_TOOL_TRACE_NAME}")
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
    # NO PRE-CHECK OF `worlds/<label>` (#1049 D-36): each leaf below reads for itself, through
    # the episode bind, and answers its own absent/refused/present state — a world with no
    # `worlds/<label>` directory at all reads every leaf absent exactly as one with the
    # directory but no file at a leaf does, because the walk's own ENOENT does not care which
    # component was missing; a LINK at `worlds/<label>` is every leaf's own refusal.
    name = f"{archive.WORLDS_DIRNAME}/{label}"
    report = family.read_archived_report(bound, f"{name}/{REPORT_NAME}")
    investigation = bound.read(f"{name}/{INVESTIGATION_NAME}")
    return _WorldArchive(
        report=report,
        investigation_present=not investigation.absent,
        provenance=family.json_mapping(bound, f"{name}/{PROVENANCE}"),
        scrub=family.json_mapping(bound, f"{name}/{archive.SCRUB_VERDICT_NAME}"))


def _load_world_leads(ep: _Episode, bound: Bound, label: str) -> _WorldLeads:  # noqa: C901, PLR0912 — the served ledger, the archive notes and every lead's chain are one world's leads block (#1025 O3)
    leads = _WorldLeads()
    world = bound.under(f"{archive.WORLDS_DIRNAME}/{label}")

    # The served ledger is read ONCE, through the judge's own reader (`read_world_ledger`) —
    # its `malformed_rows` is the judge's own count (a torn line AND a row whose `source` is
    # outside the ledger's vocabulary), the number that lands on the `judge.yaml` row. A second
    # read here through the bare tolerant reader counted only the torn lines and disagreed with
    # the record. ITS OWN SLOT: the ledger's refusal is the ledger note, and never reaches the
    # investigation read below.
    if ep.episode_token is None:
        leads.ledger_note = "served ledger: not readable — the episode id names no token"
    else:
        try:
            _rows, malformed, ledger_read = family.read_world_ledger(
                bound, label, episode_token=ep.episode_token)
        except JudgeRefused as bad:
            leads.ledger_note = f"served ledger unreadable: {bad}"
        else:
            if ledger_read.absent:
                leads.ledger_note = "served ledger: absent"
            elif malformed:
                leads.ledger_note = f"{malformed} malformed row"

    # DIRECTORY-LEVEL, OFF THE BIND'S OWN LISTING (#1049 D-36) — never a stat: a world whose
    # `worlds/<label>` is wholly absent has nothing this block can chain leads over; one whose
    # entry is there but is not a real, listable directory (a planted link, a file at the
    # name) is refused ONCE, here, and nothing below it is rostered — a link is never a way to
    # another tree's leads; one that exists but is missing individual records
    # (investigation.md, a lead's summary) still renders every leaf it can, each its own arm.
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
        leads.facts_error = f"{archive.WORLDS_DIRNAME}/{label}/{INVESTIGATION_NAME}: {bad!r}"
    else:
        if not read_facts.absent:
            facts = read_facts

    # `leads_by_id` is the lead repository's own surface and takes the world's directory — the
    # one path this block hands anyone, and only now that the listing above judged
    # `worlds/<label>` a real directory.
    try:
        all_leads = family.leads_by_id(ep.dir / archive.WORLDS_DIRNAME / label)
    except Exception:  # noqa: BLE001
        all_leads = {}

    # A summary is a `.md` plain file; anything else in the directory is invisible here — its
    # stem is a lead id the roster below neutralizes on its own if it cannot be named. The
    # judge prompt's roster and this one come off one spelling (`summary_lead_ids`).
    summary_stems = family.summary_lead_ids(world)

    if facts is not None:
        roster = set(facts.referenced_leads) | summary_stems
        resolutions_by_lead = facts.resolutions_by_lead
        leads.moved = bool(facts.resolution_moved)
    else:
        roster = set(all_leads) | summary_stems
        resolutions_by_lead = {}

    for lead_id in sorted(roster):
        # `lead_chain` reads the gather summary through the world's derived sub-bind and
        # answers a refusal as the summary's own sentence; nothing is caught here, so the page
        # and the grading pass see one and the same reader.
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
        if "_framed_trace" in name:
            if not name.endswith(FRAMED_TRACE_SUFFIX):
                continue
            stem = name[: -len(FRAMED_TRACE_SUFFIX)] + "_trace"
            trace = logs.traces.setdefault(stem, _Trace(stem))
            frows, _bad, _rec = wire.read_jsonl(name)
            if frows:
                trace.framed = frows[0]
            continue
        if not name.endswith(REVIEW_TRACE_SUFFIX):
            continue
        stem = name[: -len(".jsonl")]
        trace = logs.traces.setdefault(stem, _Trace(stem))
        # `wire_logs/` sits under the episode dir, a tree a sibling box has an rw bind on
        # (`judge.__init__._write_wire_log`'s own docstring names it): the bound reader
        # refuses a link or a FIFO at the name at the open itself and answers a permission
        # fault as a refusal rather than an exception.
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
    # PRICED calls, not trace files: a role whose only trace is refused, unreadable or priced
    # by no known model has spent nothing the page can name, and a "$0.0000" grand total over
    # it is the line the stages table promises not to print (review of PR #1042).
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
    """`<label>/<draw>/<index>` off a `build_finding_row` id (`<run_id>/<label>/<draw>/
    <index>`) — the spelling every record list keys a finding by. `None` for anything else."""
    if not isinstance(finding_id, str):
        return None
    parts = finding_id.rsplit("/", 3)
    if len(parts) != 4:
        return None
    _prefix, label, draw, index = parts
    return f"{label}/{draw}/{index}"


def _ledger_of(grade: Any) -> dict[str, dict[str, Any]] | None:
    """The record's ledger by coordinate (`EpisodeGrade.dispositions`, validated on read —
    every entry names its finding and a lane), or `None` for a record that carries none."""
    if grade is None or grade.dispositions is None:
        return None
    out: dict[str, dict[str, Any]] = {}
    for entry in grade.dispositions:
        coord = _coordinate_of(entry["finding_id"])
        if coord is not None:
            out.setdefault(coord, entry)
    return out


def _world_findings_lookup(grade: Any) -> dict[str, dict[str, Any]]:
    """The questioner rows the pass built (`world_findings`), by coordinate — the J9b stub's
    text for a world-lane entry whose draw document is gone."""
    out: dict[str, dict[str, Any]] = {}
    for row in _items(grade.world_findings):
        if isinstance(row, dict):
            coord = _coordinate_of(row.get("finding_id"))
            if coord is not None:
                out.setdefault(coord, row)
    return out


def _withheld_lookup(grade: Any) -> dict[str, dict[str, Any]]:
    """The findings the pass withheld, whole (`withheld_findings`), by coordinate — the J9b
    stub's text for a withheld entry whose draw document is gone."""
    out: dict[str, dict[str, Any]] = {}
    for item in _items(grade.withheld_findings):
        if isinstance(item, dict) and isinstance(item.get("finding"), dict):
            coord = _coordinate_of(item.get("finding_id"))
            if coord is not None:
                out.setdefault(coord, item)
    return out


def _bump(counts: dict[str, int], disposition: str) -> None:
    if disposition in counts:
        counts[disposition] += 1


def _finding_fields(finding: Any) -> dict[str, Any]:
    """The row's own fields off one draw finding, as `_Finding` keyword arguments. A finding
    that is not a mapping (the ledger names those too — dropped, "not a mapping") has none."""
    if not isinstance(finding, dict):
        return {"raw": finding}
    return {"claim": finding.get("claim"), "root_cause": finding.get("root_cause"),
            "anchor": finding.get("anchor"), "topic": finding.get("topic"),
            "bucket": finding.get("bucket"), "evidence": finding.get("evidence"),
            "world_field": finding.get("world"), "raw": finding}


#: The ledger's lane → the page's disposition word (`_disposition_heading_raw`).
_LANE_WORD = {LANE_DEFENDER: "defender", LANE_WORLD: "world_author", LANE_WITHHELD: "withheld",
              LANE_UNQUEUEABLE: "unqueueable", LANE_NEVER_ELIGIBLE: "never_eligible"}


def _off_ledger_disposition(ep: _Episode, label: str) -> tuple[str, str | None]:
    """A finding on disk that the ledger does not name: the pass never walked it, and the
    record says why without any lane being re-decided here — the world's own row is
    `ungradable` (its draws are never walked), no row names the world at all, or the pass
    simply did not see this document (a leftover from an earlier, wider attempt)."""
    entry = ep.entries.get(label)
    row = entry.row if entry is not None else None
    if label != _FAMILY_LABEL and row is None:
        return "no_grade_row", None
    if row is not None and not family.is_gradable_row(row):
        reason = row.get("ungradable_reason")
        return "world_ungradable", reason if isinstance(reason, str) else None
    return "never_on_record", None


def _walk_findings(ep: _Episode) -> _Findings:  # noqa: C901, PLR0912, PLR0915
    """Every finding row the page shows, keyed `(label, draw, index)`. Each row's fate is READ
    OFF THE RECORD'S LEDGER (`EpisodeGrade.dispositions` — what the enqueue pass did with
    that coordinate, written where it was decided) and never re-decided here: the page
    carried first a copy of the lane rule and then the rule itself fed with inputs rebuilt
    from the rows, and both drifted from the pass on the edges (#1025 amendment 3, and the
    #1042 review's duplicate-label case). What the page adds is only what it can see and the
    record cannot: a document on disk the ledger never named (`_off_ledger_disposition`), and
    a ledger entry whose document is gone (a J9b stub)."""
    out = _Findings()
    rows = out.rows
    counts = out.counts
    grade = ep.grade
    entries = ep.entries
    roster_labels = [*entries, _FAMILY_LABEL]

    def _walked(label: str) -> bool:
        """Does the page walk this label's draws at all? With no grade record, every roster
        label; otherwise the family lane always, and a world once a grade row or a manifest
        entry names it (a bare `runs/` directory is a section with no findings)."""
        if grade is None or label == _FAMILY_LABEL:
            return True
        entry = entries.get(label)
        return entry is not None and (entry.row is not None or entry.in_manifest)

    # ONE population for every count tile 3 shows: the dropped/failed draws are read off the
    # same labels the findings below are walked from, so "queued of N · M dropped" cannot
    # add a draw the walk never opened to a split it does not appear in.
    walked_labels = [label for label in roster_labels if _walked(label)]

    # The draw-read reports of EVERY label the loader read, walked or not: the findings
    # section's "N draw documents unreadable / skipped" totals and each world section's own
    # line count the same directories (review of PR #1042).
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
        """The row's disposition word, its reason and the record's id for it: the ledger's
        entry where there is one; otherwise the record's own account of why the pass never
        reached it — or, with no ledger at all, that fact alone."""
        if grade is None:
            return "no_grade", None, None
        if ledger is None:
            return "no_ledger", None, None
        entry = ledger.pop(coord, None)
        if entry is None:
            return (*_off_ledger_disposition(ep, label), None)
        return _LANE_WORD[entry["lane"]], entry.get("reason"), entry["finding_id"]

    for label in walked_labels:
        entry = entries.get(label)
        docs, _report = ep.draws[label]
        for draw, doc in docs.items():
            for index, finding in enumerate(_items(doc.get("findings"))):
                coord = f"{label}/{draw}/{index}"
                disposition, reason, recorded_id = _dispose(label, coord)
                _bump(counts, disposition)
                # `subject` ABSENT reads as the defender's, as the enqueue pass reads it (the
                # pre-#1007 draw shape); the row shows the same reading.
                subject = (finding.get("subject", SUBJECT_DEFENDER)
                           if isinstance(finding, dict) else None)
                rows.append(_Finding(
                    row_id=f"f-{label}-{draw}-{index}", label=label, draw=draw, index=index,
                    subject=subject, disposition=disposition, reason=reason, stub=False,
                    recorded_id=recorded_id, outcome=doc.get("episode_outcome"),
                    **_finding_fields(finding)))

        for mech_index, finding in enumerate(
                _items(entry.row.get("mechanical_world_findings")) if entry and entry.row
                else []):
            coord = f"{label}/{KIND_MECHANICAL}/{mech_index}"
            disposition, reason, recorded_id = _dispose(label, coord)
            _bump(counts, disposition)
            rows.append(_Finding(
                row_id=f"f-{label}-{KIND_MECHANICAL}-{mech_index}", label=label,
                draw=KIND_MECHANICAL, index=mech_index, subject=SUBJECT_WORLD,
                disposition=disposition, reason=reason, stub=False, recorded_id=recorded_id,
                **_finding_fields(finding)))

    # Record-only stubs (J9b): a ledger entry whose draw DOCUMENT is absent and whose text the
    # record itself still carries — the questioner row the pass built for a world-lane entry
    # (`world_findings`), the finding carried whole for a withheld one (`withheld_findings`).
    # A defender or dropped entry with no document has no text anywhere on the record (its
    # row went to the queue file, or nowhere), so it is a line in the queue accounting and
    # not a row. THE GRAIN IS THE DOCUMENT (F-5): an entry naming a PRESENT document with
    # fewer findings than the ledger knew renders no stub and no row.
    if ledger:
        present_docs = {label: set(ep.draws[label][0]) for label in roster_labels}
        world_rows_by_coord = _world_findings_lookup(grade)
        withheld_by_coord = _withheld_lookup(grade)
        for coord, filed in ledger.items():
            label, draw_s, index_s = coord.rsplit("/", 2)
            try:
                draw_i: int | None = int(draw_s)
            except ValueError:
                draw_i = None
            if draw_i is not None and draw_i in present_docs.get(label, set()):
                continue
            if draw_s == KIND_MECHANICAL and label in entries and entries[label].row:
                continue  # its row is on the record; the walk above rendered it
            world_row = world_rows_by_coord.get(coord)
            withheld = withheld_by_coord.get(coord)
            if filed["lane"] == LANE_WORLD and world_row is not None:
                fields: dict[str, Any] = {"claim": world_row.get("finding")}
                subject = SUBJECT_WORLD
            elif filed["lane"] == LANE_WITHHELD and withheld is not None:
                fields = _finding_fields(withheld["finding"])
                subject = SUBJECT_DEFENDER
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
    """Each group heading's `fg-<n>`, numbered by first appearance in row order — the one
    numbering both the findings section and the cards' footers render."""
    return {h: n for n, h in enumerate(dict.fromkeys(_disposition_heading_raw(f) for f in rows),
                                       start=1)}


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
    if f.disposition == "no_ledger":
        return "record carries no disposition ledger — not enqueued"
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
    page_path = EpisodePaths(Path(episode_dir)).learning_html
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


def _render_nav(body: str) -> str:
    ids = re.findall(r'id="([^"]+)"', body)
    items = []
    for i in ids:
        if i.startswith("world-") or i.startswith("fg-") or i.startswith("sec-"):
            items.append(f'<li class="item"><a href="#{esc(i)}">{esc(i)}</a></li>')
    # `nav.toc` / `li.item`: the shared stylesheet's own nav vocabulary, so the sticky
    # left-column layout is the run pages' rule and not a second spelling of it.
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


def _render_verdict(ep: _Episode) -> str:  # noqa: C901, PLR0912, PLR0915 — the band, lede, four tiles and cards are one section (#1025 O1/O2)
    grade = ep.grade
    if ep.not_graded:
        stamp = grade.not_graded
        band = (f'<div class="vd-band">not graded: '
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
    # Draw keys come in three shapes — a document's `int`, a record-only stub's `str`, a
    # withheld entry's `None` — and a key that compares across them is what keeps one
    # `withheld_findings` entry tagged `world: family` from raising `TypeError` out of the
    # whole page (d01: only `family.yaml` is fatal).
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

    # `is not None`, not `or` (CLAUDE.md, "anchor a default in one place"): `family_outcome`
    # is the record's own `str | None`, and an empty string on it is the record's word, not
    # an absence to fall through.
    family_outcome = getattr(grade, "family_outcome", None)
    badge_word = family_outcome if family_outcome is not None else grade.verdict_word
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

    # The record's OWN partition (`_grade_from_document` derives both off the rows with
    # `is_gradable_row`, the one predicate), never a third spelling of it here.
    measuring = grade.measuring_worlds
    graded = grade.graded_worlds
    control_world = ep.manifest_world(ep.control_label) if ep.control_label else None
    control_declared = _normalized_disposition(
        control_world.get("disposition_declared") if control_world else None)
    contrasting = 0
    agree = 0
    for label in sorted(measuring):
        entry = entries.get(label)
        row = entry.row if entry is not None else None
        if row is None:
            continue
        declared = _normalized_disposition(row.get("declared"))
        if declared != control_declared:
            contrasting += 1
        # The same normalizer as the contrast count beside it on this tile — a case or
        # whitespace variant of one word must not agree on one figure and differ on the other.
        if _normalized_disposition(row.get("verdict")) == declared:
            agree += 1
    # The ladder's vocabulary is `_vocab.JUDGE_OUTCOME_ENUM`'s, asked of its own normalizer
    # (case-insensitive, trimmed — a bare `in` over a local copy would call ` Survived` off
    # the ladder, and would go stale the day the enum grows).
    verdict_note = ("" if normalized_judge_outcome(grade.verdict_word) is not None
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
            withheld_captions.append(f"{_uv(w.label)} — ungradable")
        elif w.row.get("withheld_reason") is not None:
            withheld_captions.append(f"{_uv(w.label)} — {_uv(w.row['withheld_reason'])}")
    tile2 = (
        f'<div class="vd-tile" id="vd-tile-2">{len(measuring)} of {len(graded)}'
        f'<div class="vd-caption">{"; ".join(withheld_captions)}</div></div>')

    findings_total = len(rows)
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
    # no REAL wall to compute from: absent, present-but-unreadable (the STAGES table's own
    # distinct "timing record unreadable" refusal) and readable-but-every-row-inverted all
    # leave this tile with nothing better than the estimate, so all read the same here even
    # though the stage table itself tells them apart (spec resolution, PR body). `measured` is
    # the header's OWN decision, taken once at load, so the two cannot disagree: with a real
    # wall the header carries the figure and this tile must not repeat the fallback beside it.
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
        heading = (_uv(row.get("withheld_reason")) if row.get("withheld_reason") is not None
                  else _uv(row.get("bucket")))
        chip_bits = "".join(f'<span class="vd-chip">{_uv(k)}={_uv(row.get(k))}</span>'
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


def _draw_sort_key(draw: Any) -> tuple[int, Any]:
    if isinstance(draw, int):
        return (0, draw)
    if isinstance(draw, str):
        return (1, draw)
    return (2, "")


def _normalized_disposition(value: Any) -> Any:
    """A declared/verdict disposition through the vocabulary's own normalizer, for the tile's
    control-contrast count — the raw value where it is not a string the normalizer knows."""
    if not isinstance(value, str):
        return value
    return normalized_disposition(value) or value


def _render_queue_accounting(grade: Any, counts: dict[str, int], rows: list[_Finding]) -> str:
    lines = [
        f'defender: {grade.enqueued_rows} enqueued to {_uv(grade.enqueued_to)}',
        f'questioner: {grade.world_enqueued_rows} enqueued to {_uv(grade.world_enqueued_to)}',
        f'withheld {counts["withheld"]} ({_uv(_first_withheld_reason(rows))})',
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
                             f'the branch point untouched, not graded · {_uv(declared)}</div>')
            continue
        axis = w.get("axis")
        axis_html = (f'<q class="verbatim">{_uv(axis)}</q>' if isinstance(axis, str)
                    else "<em>null</em>")
        guide_rows.append(f'<div class="vd-guide-row">{esc(label)} '
                         f'({esc(str(w.get("role")))}) {_uv(declared)} {axis_html}</div>')

    # The roster AS LOADED: each item already classified, so the heading counts the very list
    # the sections below are rendered from — the sectioned items — and an unnameable label
    # renders its one line without being counted as a section it never gets.
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
    if item.kind == ROSTER_STRAY_RUN_DIR:
        # A `runs/` directory whose name did not decompose into `<episode_id>-<label>` (J7
        # iv) — it is not a world at all, so it gets a minimal section keyed on its own full
        # name rather than the normal record-driven rendering.
        link = f"{RUNS_SUBDIR}/{item.label}/{RUNTIME_HTML}"
        return (f'<div id="world-{esc(item.label)}" class="w-section">'
               f'<span class="w-name">{_uv(item.label)}</span>'
               f'<div class="w-state">not declared in the manifest</div>'
               f'<a href="{esc(link)}">runtime</a></div>')
    return _render_one_world(ep, item.label)


def _render_one_world(ep: _Episode, label: str) -> str:  # noqa: C901, PLR0912, PLR0915 — one world's whole section (state, ladder, chips, archive, review) is one demand (#1025 J7/J8/J16)
    entry = ep.entries[label]
    # J14: a `not_graded` stamp voids the whole family's word, so every world's RECORD-derived
    # state (the ladder, the bucket, the withheld reason) is exactly what an episode with no
    # grade at all shows — "not graded" — even though the row is still physically on the
    # document; the run-dir/archive-derived parts below are unaffected. (The "not in the
    # manifest" note is the verdict CARD's, `_render_verdict`: a world reaches the roster only
    # through the manifest, a grade row or a `runs/` dir, so no section could ever have shown
    # it here.)
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
    elif row.get("withheld_reason") is not None:
        bits.append('<div class="w-state">withheld</div>')
        bits.append(f'<div class="w-reason">{_uv(row["withheld_reason"])}</div>')
        bits.append(_ladder_html(row))
    else:
        bits.append(f'<div class="w-verdict">{_uv(row.get("verdict"))}</div>')
        bits.append(_ladder_html(row))

    bits.append(_chip_html(row, ep.review_block(label)))

    if manifest_world is not None:
        axis = manifest_world.get("axis")
        if isinstance(axis, str):
            bits.append(f'<div class="w-axis"><q class="verbatim">{_uv(axis)}</q></div>')

    result = entry.result
    if result is not None:
        link = f"{RUNS_SUBDIR}/{entry.run_dir_name}/{RUNTIME_HTML}"
        bits.append(f'<a href="{esc(link)}">runtime</a>')
        if result.cost is not None and result.costed:
            bits.append(f'<span class="w-cost">{_money(result.cost)}</span>')
            if result.wall_ms:
                bits.append(f'<span class="w-wall">{fmt_duration(result.wall_ms)}</span>')
        else:
            bits.append(f'<span class="w-cost">{esc(result.text)}</span>')
    else:
        bits.append('<div class="w-archive">run directory absent</div>')

    # Each archived leaf is its own arm (d: "each missing piece renders its own absent arm"),
    # and each arm names its leaf — two bare "not archived" lines in one section said the
    # same words about two different files.
    archived = entry.archive
    if archived is None:
        bits.append('<div class="w-archive">not archived</div>')
    else:
        if archived.report.absent:
            bits.append(f'<div class="w-archive">{esc(REPORT_NAME)}: not archived</div>')
        else:
            headline = archived.report.disposition_or_unknown
            if archived.report.disposition is None and archived.report.reason:
                # No headline: the reader's own reason (a refused entry at the name, a
                # frontmatter that did not parse, a disposition outside the vocabulary) is the
                # slot's answer, beside the placeholder.
                headline += f" — {archived.report.reason}"
            bits.append(f'<div class="w-report">{_uv(headline)}</div>')
        if not archived.investigation_present:
            bits.append(f'<div class="w-archive">{esc(INVESTIGATION_NAME)}: not archived</div>')
        if archived.provenance is not None:
            bits.append(f'<div class="w-prov">{_uv(archived.provenance.get("commit"))}</div>')
        else:
            bits.append('<div class="w-prov">absent</div>')
        if archived.scrub is None:
            bits.append('<div class="w-scrub">not recorded</div>')
        else:
            bits.append(f'<div class="w-scrub">{_uv(archived.scrub)}</div>')

    review_rec = ep.review_rec
    review_worlds = review_rec.value.get("worlds") if review_rec.ok and isinstance(
        review_rec.value, dict) else None
    review_entry = review_worlds.get(label) if isinstance(review_worlds, dict) else None
    if not review_rec.ok:
        bits.append('<div class="w-review">review block unreadable</div>')
    elif review_entry is None:
        bits.append('<div class="w-review">no review record for this world</div>')

    return f'<div id="world-{esc(label)}" class="w-section">{"".join(bits)}</div>'


def _ladder_html(row: dict[str, Any]) -> str:
    bits = []
    for field in _LADDER_FIELDS:
        if field == "verdict":
            bits.append(f'<span class="w-ladder">verdict = declared: '
                       f'{_uv(row.get("verdict"))} == {_uv(row.get("declared"))}</span>')
            continue
        if field not in row:
            continue
        val = row.get(field)
        bits.append(f'<span class="w-ladder">{esc(field)} = {_uv(val)}</span>')
        if field == "doctored_answer_served" and row.get("holding_queried"):
            # `has_refused` is asked only where a world actually got a HOLDING answer (#1025
            # J16) — a withheld world never reaches this arm. The CAVEAT ("unrecorded") is the
            # not-doctored branch's own answer for a row that never stored the flag; on the
            # doctored branch the flag is not applicable and the row's own silence is never
            # invented into that caveat's wording.
            if "has_refused" in row:
                bits.append(f'<span class="w-ladder">has_refused = {_uv(row["has_refused"])}</span>')
            elif val is False:
                bits.append('<span class="w-ladder">has_refused unrecorded</span>')
            else:
                bits.append('<span class="w-ladder">has_refused not applicable (doctored)</span>')
    bucket = row.get("bucket")
    if bucket:
        cls = _BUCKET_CLASS.get(bucket, "bucket-other")
        bits.append(f'<span class="w-bucket {cls}">{_uv(bucket)}</span>')
    return "".join(bits)


def _chip_html(row: dict[str, Any] | None, reach: dict[str, Any] | None) -> str:
    bits = []
    for field in _CHIP_FIELDS:
        if row is not None and field in row:
            bits.append(f'<span class="w-chip">{esc(field)}: {_uv(row[field])}</span>')
        elif (field in _REACH_ONLY_CHIP_FIELDS or row is None) \
                and isinstance(reach, dict) and field in reach:
            # `envelope_ran` is NEVER a row field at all, on any row shape — it is always
            # sourced from reach when present, row or no row. The other capture-measurement
            # fields fall back to reach ONLY when there is no row at all (the control; an
            # ungraded world): a row that EXISTS but omits one of THEM (a pre-#1007 shape, an
            # ungradable row's bound slots) reads "unrecorded" rather than silently falling
            # back to a different record's value (#1025 J16 d).
            bits.append(f'<span class="w-chip">{esc(field)}: {_uv(reach[field])}</span>')
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
        bits.append(f'<span class="fr-outcome">{_uv(f.outcome)}</span>')
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
    if ep.shadowed_run_dirs:
        body += (f'<div class="fr-shadowed-runs">{len(ep.shadowed_run_dirs)} entries under '
                f'{esc(RUNS_SUBDIR)}/ wear a world\'s own label and are not sectioned twice: '
                f'{", ".join(_uv(n) for n in ep.shadowed_run_dirs)}</div>')
    n = len(ep.findings.rows)
    return _page_section("sec-findings", f"Findings ({n})", body)


# =========================================================================================
# Stages section
# =========================================================================================


def _render_stages(ep: _Episode) -> str:  # noqa: C901, PLR0912, PLR0915 — the stage table, the two clocks and every trace block are one section (#1025 O4)
    timing = ep.timing
    rows_by_step = timing.rows_by_step
    review_total, review_calls = ep.review_cost, ep.review_calls

    table_rows = []
    for step in STEPS:
        entries_for_step = rows_by_step.get(str(step), [])
        if timing.error:
            wall_text = ""
        elif entries_for_step:
            # `trusted` (the clock's own non-inverted pairs), not every row — a step whose
            # only rows are inverted read "—" only because `fmt_duration(0)` happens to spell
            # zero as the dash.
            step_wall = timing.step_wall_ms(str(step))
            wall_text = fmt_duration(step_wall) if step_wall is not None else "—"
            if len(entries_for_step) > 1:
                wall_text += f" ({len(entries_for_step)} entries)"
        else:
            wall_text = "not on the record"
        if str(step) in ep.role_costs:
            cost_text = _role_cost_text(ep.role_costs[str(step)])
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

    # The table's own caption is the clock's decision (`_Timing.caption`): the refusal line
    # for an unreadable record, the fallback sentence for an unmeasured one, nothing once
    # there is a real wall — the same `measured` bit the header line and the verdict tile key
    # on, so no surface can call a present record absent while another shows its figure.
    if timing.error:
        table = f'<div class="st-error">{_uv(timing.error)}</div>' + "".join(table_rows)
    elif timing.caption is not None:
        table = f'<div class="st-caption">{esc(timing.caption)}</div>' + "".join(table_rows)
    else:
        table = "".join(table_rows)

    # `ep.total_cost` already sums the worlds' results PLUS questioner and judge traces —
    # adding `q_cost`/`j_cost` again here would double them.
    grand_total = ep.total_cost + review_total
    # No line at all — not "$0.0000" — when nothing anywhere priced: a launcher-produced
    # episode with no trace files owes no total any more than its own rows owe one (#1025).
    # `ep.costed`, the model's own flag, not the float's truthiness: an episode whose every
    # run cost $0.0000 is priced, and the runs sub-total below already says so.
    if ep.costed or review_calls:
        table += (f'<div class="st-total">{_money(grand_total)} — excludes gather subagents and '
                f'the review gate</div>')

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
    """The pair's wall in ms: `None` where either stamp does not parse, `-1` where the pair is
    INVERTED (the end precedes the start), the plain delta — zero included — otherwise."""
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
    """Every `judge_*_trace.jsonl` stem that names no roster label or `family` (O4: its cost is
    still priced into the judge row; only the transcript BLOCK is withheld). Membership goes
    through `_stem_names_label`, the same digit-only-remainder check `_transcript_blocks_for_step`
    uses to route a KNOWN label's own draws — not a `range(N)`-bounded set of literal stems,
    which silently misclassified every draw at or past its bound as unattributed."""
    known_labels = [*ep.entries, _FAMILY_LABEL]
    # `stems_for` — plain trace files AND framed-only twins — the census the JUDGE block itself
    # renders from; walked off the plain files alone, a framed-only trace naming no roster
    # label was neither rendered nor listed (review of PR #1042).
    return [stem for stem in sorted(ep.wire.stems_for(Step.JUDGE))
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
    remainder = stem[len(prefix):-len("_trace")]
    # ASCII digits only — the same alphabet `draws_on_disk_report` holds a draw stem to, so
    # the two readers of one name agree: a stem spelled with an Arabic-Indic or superscript
    # digit (`str.isdigit` admits both) is unattributed here and unreadable there, never a
    # draw of this world on one surface and a fault on the other.
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
    """A wire row's `message` mapping and its `parts` list — each the empty value where the
    row does not carry that shape."""
    msg = _mapping(row.get("message"))
    return msg, _items(msg.get("parts"))


def _no_response_html(trace: _Trace) -> str:
    """The line a call with no response reads as. A REFUSED plain trace (a link, a FIFO or an
    unreadable file at its own name, tracked at load) is said as such: "no response recorded"
    is a benign empty call's sentence, and a planted alias must not read the same as one
    (review of PR #1042)."""
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
    # The id embeds the wire-log FILENAME's stem: grammar-gated like every other
    # filename-derived id on the page (`world-`/`leads-`/`f-`), never merely escaped — a stem
    # outside the run-id alphabet renders as an unnameable entry with no id at all (J5).
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
    # The same sectioned roster the worlds heading counts: one block per item, no re-deciding
    # here which labels can be named.
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
        bits.append(f'<div class="rc-samples">{_uv(samples_rec.error)}</div>')
    elif not samples_rec.present:
        bits.append('<div class="rc-samples">absent</div>')
    else:
        for pattern in _mapping(samples_rec.value):
            bits.append(f'<div class="rc-pattern">{_uv(pattern)}</div>')

    if staged_rec.error:
        bits.append(f'<div class="rc-staged">{_uv(staged_rec.error)}</div>')
    elif not staged_rec.present:
        bits.append('<div class="rc-staged">absent</div>')
    else:
        for row in _items(staged_rec.value):
            bits.append(f'<div class="rc-staged-row">{_uv(_mapping(row).get("name"))}</div>')

    if review_rec.error:
        bits.append(f'<div class="rc-review">{_uv(review_rec.error)}</div>')
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
    # The standalone spelling the docstring promises — `python defender/scripts/visualize/
    # visualize_episode.py <dir>` from anywhere — has no package on `sys.path` until it is put
    # there, the same bootstrap `visualize_run.py` carries (#1025 F14). Under `-m` or an
    # import the module-level imports above have already resolved and this is inert.
    sys.exit(main(sys.argv[1:]))
