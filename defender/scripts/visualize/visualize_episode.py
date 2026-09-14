"""#1025 — the episode page: `render_episode(episode_dir) -> Path` renders `learning.html`
beside `judge.yaml` from an episode directory alone, and `main(argv)` is the standalone CLI.
The launcher (`branch/cli.py::_render_page`) calls `render_episode` after the JUDGE clock frame
closes, under its own non-fatal boundary.

Only `family.yaml` refuses the whole page (d01) — every other record a reader refuses renders
that reader's refusal sentence, escaped, in its own slot, and the page always reads through the
package readers below rather than re-parsing any record itself.
"""
from __future__ import annotations

import math
import re
import sys
from pathlib import Path
from typing import Any

from defender._io import read_guarded, read_jsonl_rows_report, write_guarded
from defender._report import read_report
from defender._run_id import is_valid_run_id
from defender._run_paths import PROVENANCE, artifact_dir, artifact_file
from defender._vocab import normalized_judge_outcome
from defender.learning.branch import archive, staging
from defender.learning.branch import timing as timing_mod
from defender.learning.branch.steps import STEPS, Step
from defender.learning.judge import JudgeRefused, read_grade
from defender.learning.judge import family
from defender.learning.judge.enqueue import draws_on_disk, draws_on_disk_report
from defender.runtime.branch._family import episode_token_for
from defender.scripts import pricing
from defender.scripts.visualize.visualize_primitives import esc, fmt_duration

PAGE_NAME = "learning.html"

_ASSETS = Path(__file__).resolve().parent / "assets"
CSS = (_ASSETS / "styles.css").read_text(encoding="utf-8")

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


#: The same event-handler predicate `visualize_primitives.esc_untrusted` splits on (an
#: `on<word>=`-shaped attribute, case-insensitive), spelled once here rather than imported: this
#: page splits it across an ELEMENT boundary (`<wbr>`, a void tag with no text of its own), not
#: `esc_untrusted`'s zero-width character. Both defeat a naive "onerror=" scan of the raw bytes,
#: but only the element boundary survives a round trip through this page's own text reader: a
#: `<wbr>` contributes nothing to `Node.text()`'s walk, so the two text pieces either side of it
#: concatenate back to the ORIGINAL word exactly — which several of this page's own adversarial
#: tests assert directly (`word in page.text`), a check a zero-width character would fail.
_EVENT_HANDLER_RE = re.compile(r"\bon(?=[a-zA-Z]\w*\s*=)", re.IGNORECASE)


def _uv(x: Any) -> str:
    """`_v`, through the untrusted escape — for a value whose source is a model-authored
    record."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    escaped = esc(x if isinstance(x, str) else str(x))
    return _EVENT_HANDLER_RE.sub(lambda m: m.group(0) + "<wbr>", escaped)


def _unnameable(raw: str, *, what: str) -> str:
    return f'<div class="unnameable">unnameable entry ({esc(what)}): {_uv(raw)}</div>'


def _money(cost: float) -> str:
    return f"${cost:.4f}"


# =========================================================================================
# Section / block chrome
# =========================================================================================


def _page_section(anchor: str, title: str, body: str) -> str:
    return f'<section id="{esc(anchor)}"><h2>{esc(title)}</h2>{body}</section>'


def _block(anchor: str, title: str, body: str, *, cls: str = "") -> str:
    id_attr = f' id="{esc(anchor)}"' if anchor else ""
    cls_attr = f' class="{esc(cls)}"' if cls else ""
    return (f'<div{id_attr}{cls_attr}><h3>{esc(title)}</h3>'
            f'<div class="body">{body}</div></div>')


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
    "unreadable" state is distinguishable from "absent"."""
    if not (path.exists() or path.is_symlink()):
        return {}
    text, refusal = read_guarded(path)
    if text is None:
        raise JudgeRefused(f"{path} could not be read: {refusal}")
    import yaml

    from defender._yaml import safe_load
    try:
        doc = safe_load(text) or {}
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"{path} could not be read: {bad}") from bad
    if not isinstance(doc, dict):
        raise JudgeRefused(f"{path} is not a mapping")
    return doc


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
    # `read_staged` is `artifact_file`-screened against a PLANTED alias but still opens the
    # plain file it confirms is there with a bare `read_text` — a permission-denied regular
    # file (root ignores this; a real non-root run does not, #1025) reaches this call as an
    # un-typed `OSError`/`PermissionError`, which is this record's own slot's business, never
    # the whole page's.
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
# Roster and per-world facts
# =========================================================================================


class WorldEntry:
    def __init__(self, label: str) -> None:
        self.label = label
        self.in_manifest = False
        self.manifest_doc: dict[str, Any] | None = None
        self.row: dict[str, Any] | None = None  # judge.yaml row, if any
        self.role: str | None = None
        self.run_dir_name: str | None = None  # the runs/ dir that decomposed to this label


def _decompose_run_dir(name: str, *, episode_id: str) -> str | None:
    prefix = f"{episode_id}-"
    if name.startswith(prefix) and len(name) > len(prefix):
        return name[len(prefix):]
    return None


def _build_roster(episode_dir: Path, manifest: dict[str, Any], grade_row_labels: list[str],  # noqa: C901, PLR0912 — one union-membership decision (manifest ∪ judge.yaml rows ∪ runs/ dirs), the roster every other section keys on
                   *, episode_id: str, grade_exists: bool) -> tuple[dict[str, WorldEntry], list[str], int]:
    """Every world label the page must give a section to: manifest worlds ∪ `judge.yaml`
    rows ∪ `runs/` directories that decompose to `<episode_id>-<label>` (#1025 J7/J8).

    Returns the entries by label (manifest order first, then extras), the list of
    undecomposable `runs/` directory FULL NAMES (each gets its own section keyed by that full
    name), and the count of `worlds/` directories that are on neither the manifest nor the
    record (reported on one templated line, never rendered)."""
    entries: dict[str, WorldEntry] = {}
    order: list[str] = []
    # A manifest world with NEITHER a `judge.yaml` row NOR any archive evidence contributes a
    # section only once the episode has reached RUNS at all — either `runs/` still exists, or a
    # grade landed at some point (and `runs/` was pruned afterward, J8). An episode that never
    # got past REVIEW/STAGING (a rejection, an abort) has neither and has a manifest but no
    # world to show anything about yet (#1025 J7/J8).
    reached_runs = artifact_dir(episode_dir / "runs") or grade_exists
    raw_worlds = manifest.get("worlds")
    for w in raw_worlds if isinstance(raw_worlds, list) else []:
        if not isinstance(w, dict):
            continue
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
        if not isinstance(label, str):
            continue
        if label not in entries:
            entries[label] = WorldEntry(label)
            order.append(label)

    stray_run_dirs: list[str] = []
    runs_dir = episode_dir / "runs"
    off_roster_run_dirs = 0
    if artifact_dir(runs_dir):
        for child in sorted(p.name for p in runs_dir.iterdir() if artifact_dir(p)):
            label = _decompose_run_dir(child, episode_id=episode_id)
            if label is None:
                stray_run_dirs.append(child)
                continue
            if label not in entries:
                entries[label] = WorldEntry(label)
                order.append(label)
            entries[label].run_dir_name = child

    worlds_dir = episode_dir / "worlds"
    if artifact_dir(worlds_dir):
        for wchild in worlds_dir.iterdir():
            if not artifact_dir(wchild):
                continue
            if wchild.name == "family":
                continue
            if wchild.name not in entries:
                off_roster_run_dirs += 1

    return entries, [*order, *stray_run_dirs], off_roster_run_dirs


# =========================================================================================
# The rendered document
# =========================================================================================


def _encode_page(html_text: str) -> bytes:
    """The document's bytes (#1025 F-7): `errors="replace"` turns a lone surrogate into the
    encoder's own replacement character, but it leaves a literal NUL untouched — U+0000 encodes
    to a plain 0x00 byte under UTF-8 — so a NUL is substituted with U+FFFD FIRST, on the same
    path as a lone surrogate, and never reaches the guarded write."""
    return html_text.replace("\x00", "�").encode("utf-8", errors="replace")


def render_episode(episode_dir: Path) -> Path:
    episode_dir = Path(episode_dir)
    html_text = build_page(episode_dir)
    page_path = episode_dir / PAGE_NAME
    write_guarded(page_path, _encode_page(html_text), mode="replace")
    return page_path


def build_page(episode_dir: Path) -> str:
    manifest = family.raw_manifest(episode_dir)  # d01: the ONE fatal refusal
    episode_id = family.episode_id_of(manifest)
    try:
        episode_token = episode_token_for(episode_id)
    except Exception:  # noqa: BLE001 — a token that cannot be built names no world's ledger; every read below degrades on its own
        episode_token = episode_id

    grade_rec = _read_grade(episode_dir)
    grade = grade_rec.value
    grade_row_labels: list[str] = []
    for r in (grade.worlds if grade else []):
        if isinstance(r, dict):
            w = r.get("world")
            if isinstance(w, str):
                grade_row_labels.append(w)
    review_rec = _read_review(episode_dir)
    samples_rec = _read_samples(episode_dir)
    staged_rec = _read_staged(episode_dir)
    stamp_rec = _read_family_stamp(episode_dir)
    timing_rec = _read_timing(episode_dir)

    entries, roster_order, off_roster = _build_roster(
        episode_dir, manifest, grade_row_labels, episode_id=episode_id,
        grade_exists=grade is not None)
    if grade is not None:
        for row in grade.worlds:
            if isinstance(row, dict) and isinstance(row.get("world"), str):
                w = entries.get(row["world"])
                if w is not None:
                    w.row = row

    control_label = _control_label(manifest)

    body = "".join([
        _render_header(episode_dir, manifest, grade, episode_id, samples_rec),
        _render_verdict(episode_dir, manifest, grade, grade_rec, entries, roster_order,
                        control_label, episode_id, episode_token, review_rec, timing_rec),
        _render_worlds(episode_dir, manifest, entries, roster_order, control_label,
                       review_rec, grade, episode_id),
        _render_findings(episode_dir, manifest, grade, grade_rec, entries, roster_order,
                         episode_id, off_roster),
        _render_stages(episode_dir, manifest, grade, timing_rec, entries,
                       roster_order, episode_id, episode_token),
        _render_leads(episode_dir, entries, roster_order, review_rec, episode_id,
                     episode_token),
        _render_records(episode_dir, manifest, review_rec, samples_rec, staged_rec, stamp_rec,
                        episode_id),
    ])
    nav = _render_nav(body)

    title = f"episode — {esc(episode_id)}"
    doc = f"""<!doctype html>
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
    return doc


def _control_label(manifest: dict[str, Any]) -> str | None:
    worlds = manifest.get("worlds")
    if not isinstance(worlds, list):
        return None
    for w in worlds:
        if isinstance(w, dict) and w.get("role") == "A" and isinstance(w.get("world_id"), str):
            return w["world_id"]
    return None


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


def _render_header(episode_dir: Path, manifest: dict[str, Any], grade: Any, episode_id: str,
                   samples_rec: _Record) -> str:
    from defender.learning.judge.render import episode_alert

    labels: list[str] = []
    for w in (manifest.get("worlds") or []):
        if isinstance(w, dict):
            wid = w.get("world_id")
            if isinstance(wid, str):
                labels.append(wid)
    if not labels:
        worlds_dir = episode_dir / "worlds"
        labels = sorted(p.name for p in worlds_dir.iterdir()
                        if artifact_dir(p) and p.name != "family") if artifact_dir(worlds_dir) else []
    alert = episode_alert(episode_dir, labels)
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
        knobs = grade.knobs if isinstance(grade.knobs, dict) else {}
        draws = grade.draws if isinstance(grade.draws, dict) else {}
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
  <h1>episode {_v(episode_id)}</h1>
  <div class="byline">{meta}</div>
</header>
"""


# =========================================================================================
# The findings walk — shared by the verdict tiles and the findings section
# =========================================================================================


class _Finding:
    __slots__ = ("row_id", "label", "draw", "index", "subject", "claim", "root_cause",
                 "anchor", "topic", "bucket", "evidence", "world_field", "disposition",
                 "reason", "stub", "recorded_id", "dropped", "outcome")

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
    dropped: Any
    outcome: Any

    def __init__(self, **kw: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot))


def _unqueueable_lookup(grade: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in getattr(grade, "unqueueable_findings", None) or []:
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
    for row in getattr(grade, "world_findings", None) or []:
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


def _walk_findings(  # noqa: C901, PLR0912, PLR0915
    episode_dir: Path, entries: dict[str, WorldEntry], grade: Any, grade_ok: bool,
    *, episode_id: str,
) -> tuple[list[_Finding], dict[str, int], dict[str, Any], list[tuple[str, int, str]]]:
    """Every finding row the page shows, keyed `(label, draw, index)` — the page's own
    disposition rule mirrors `enqueue_report`'s (#1025 amendment 3): the record's own signals
    (`unqueueable_findings`, a world's `withheld_reason`, the family/verdict word) decide each
    row's fate, never a re-run of the enqueue pass itself."""
    rows: list[_Finding] = []
    counts = {"defender": 0, "world_author": 0, "withheld": 0, "unqueueable": 0, "dropped": 0,
              "never_eligible": 0, "mappings": 0}
    world_reports: dict[str, Any] = {}
    draw_failures: list[tuple[str, int, str]] = []

    roster_labels = list(entries) + ["family"]

    def _draws_for(label: str) -> tuple[dict[int, dict[str, Any]], Any]:
        from defender.learning.judge.enqueue import draws_on_disk_report
        d = Path(episode_dir) / archive.WORLDS_DIRNAME / label / archive.DRAWS_DIRNAME
        docs, report = draws_on_disk_report(d)
        world_reports[label] = report
        return docs, report

    if not grade_ok:
        # No grade record at all: every on-disk finding renders under one group, undisposed.
        for label in roster_labels:
            docs, _report = _draws_for(label)
            for draw, doc in docs.items():
                findings = doc.get("findings") if isinstance(doc, dict) else None
                for index, finding in enumerate(findings or []):
                    if not isinstance(finding, dict):
                        continue
                    counts["mappings"] += 1
                    rows.append(_Finding(
                        row_id=f"f-{label}-{draw}-{index}", label=label, draw=draw,
                        index=index, subject=finding.get("subject"),
                        claim=finding.get("claim"), root_cause=finding.get("root_cause"),
                        anchor=finding.get("anchor"), topic=finding.get("topic"),
                        bucket=finding.get("bucket"), evidence=finding.get("evidence"),
                        world_field=finding.get("world"), disposition="no_grade",
                        reason=None, stub=False, recorded_id=None))
        return rows, counts, world_reports, draw_failures

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

    for label in roster_labels:
        entry = entries.get(label)
        row_state: str
        if label == "family":
            row_state = "family"
        elif entry is not None and entry.row is not None:
            row_state = "ungradable" if entry.row.get("ungradable") else "graded"
        elif entry is not None and entry.in_manifest:
            row_state = "no_grade_row"
        else:
            continue

        docs, _report = _draws_for(label)
        for draw, doc in docs.items():
            findings = doc.get("findings") if isinstance(doc, dict) else None
            if not findings and isinstance(doc, dict) and doc.get("failure_reason"):
                draw_failures.append((label, draw, doc["failure_reason"]))
            for index, finding in enumerate(findings or []):
                if not isinstance(finding, dict):
                    continue
                counts["mappings"] += 1
                coord = f"{label}/{draw}/{index}"
                seen_coords.add(coord)
                subject = finding.get("subject")
                disposition, reason = _finding_disposition(
                    row_state=row_state, entry=entry, subject=subject, coord=coord,
                    unqueueable=unqueueable, withheld_reasons=withheld_reasons,
                    measuring=measuring, defender_blocked=defender_blocked,
                    verdict_word=verdict_word, world_findings_by_coord=world_findings_by_coord)
                _bump(counts, disposition)
                dropped = doc.get("dropped_findings") if isinstance(doc, dict) else None
                outcome = doc.get("episode_outcome") if isinstance(doc, dict) else None
                recorded = world_findings_by_coord.get(coord)
                recorded_id = recorded.get("finding_id") if isinstance(recorded, dict) else None
                rows.append(_Finding(
                    row_id=f"f-{label}-{draw}-{index}", label=label, draw=draw, index=index,
                    subject=subject, claim=finding.get("claim"), dropped=dropped,
                    root_cause=finding.get("root_cause"), anchor=finding.get("anchor"),
                    topic=finding.get("topic"), bucket=finding.get("bucket"),
                    evidence=finding.get("evidence"), world_field=finding.get("world"),
                    disposition=disposition, reason=reason, stub=False,
                    recorded_id=recorded_id, outcome=outcome))

        for mech_index, finding in enumerate(
                (entry.row.get("mechanical_world_findings") if entry and entry.row else None)
                or []):
            if not isinstance(finding, dict):
                continue
            coord = f"{label}/mechanical/{mech_index}"
            seen_coords.add(coord)
            counts["mappings"] += 1
            disposition, reason = _finding_disposition(
                row_state=row_state, entry=entry, subject="world", coord=coord,
                unqueueable=unqueueable, withheld_reasons=withheld_reasons, measuring=measuring,
                defender_blocked=defender_blocked, verdict_word=verdict_word,
                world_findings_by_coord=world_findings_by_coord)
            _bump(counts, disposition)
            rows.append(_Finding(
                row_id=f"f-{label}-mechanical-{mech_index}", label=label, draw="mechanical",
                index=mech_index, subject="world", claim=finding.get("claim"),
                root_cause=finding.get("root_cause"), anchor=finding.get("anchor"),
                topic=finding.get("topic"), bucket=finding.get("bucket"),
                evidence=finding.get("evidence"), world_field=finding.get("world"),
                disposition=disposition, reason=reason, stub=False, recorded_id=None))

    # Record-only stubs: a recorded coordinate whose draw DOCUMENT is absent (J9b).
    present_docs: dict[str, set[int]] = {}
    for label in roster_labels:
        docs, _report = _draws_for(label)
        present_docs[label] = set(docs)

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
        row_state = ("family" if label == "family" else
                    ("ungradable" if entry and entry.row and entry.row.get("ungradable") else
                     ("graded" if entry and entry.row else "no_grade_row")))
        disposition, reason = _finding_disposition(
            row_state=row_state, entry=entry, subject="world", coord=coord,
            unqueueable=unqueueable, withheld_reasons=withheld_reasons, measuring=measuring,
            defender_blocked=defender_blocked, verdict_word=verdict_word,
            world_findings_by_coord=world_findings_by_coord)
        counts["mappings"] += 1
        _bump(counts, disposition)
        rows.append(_Finding(
            row_id=f"f-{label}-{draw_s}-{index_s}", label=label, draw=draw_s, index=index_s,
            subject="world", claim=row.get("finding"), root_cause=None, anchor=None, topic=None,
            bucket=None, evidence=None, world_field=None, disposition=disposition, reason=reason,
            stub=True, recorded_id=row.get("finding_id")))

    already_withheld_labels = {f.label for f in rows if f.disposition == "withheld"}
    for label, wlist in _withheld_by_label(grade).items():
        if label in already_withheld_labels:
            # The on-disk walk already produced this world's withheld rows from its own draw
            # documents — a second, record-only stub per entry would double it (J9b's grain is
            # the DOCUMENT, and a present document needs no stub).
            continue
        entry = entries.get(label)
        docs, _report = _draws_for(label)
        for n, item in enumerate(wlist):
            finding = item.get("finding") if isinstance(item, dict) else None
            if not isinstance(finding, dict):
                continue
            counts["mappings"] += 1
            counts["withheld"] += 1
            reason = item.get("reason") if isinstance(item, dict) else None
            rows.append(_Finding(
                row_id=f"f-{label}-withheld-{n}", label=label, draw=None, index=None,
                subject="defender", claim=finding.get("claim"),
                root_cause=finding.get("root_cause"), anchor=finding.get("anchor"),
                topic=finding.get("topic"), bucket=finding.get("bucket"),
                evidence=finding.get("evidence"), world_field=finding.get("world"),
                disposition="withheld", reason=reason, stub=True,
                recorded_id=finding.get("finding_id")))

    return rows, counts, world_reports, draw_failures


def _withheld_by_label(grade: Any) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for item in getattr(grade, "withheld_findings", None) or []:
        if isinstance(item, dict) and isinstance(item.get("world"), str):
            out.setdefault(item["world"], []).append(item)
    return out


def _bump(counts: dict[str, int], disposition: str) -> None:
    key = {"defender": "defender", "world_author": "world_author", "withheld": "withheld",
          "unqueueable": "unqueueable", "never_eligible": "never_eligible"}.get(disposition)
    if key:
        counts[key] += 1


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
    if subject == "world" or row_state == "family":
        if coord in unqueueable:
            return "unqueueable", unqueueable[coord]
        if coord in world_findings_by_coord:
            return "world_author" if row_state != "family" else "world_author", None
        return "never_on_record", None
    if subject != "defender":
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


_DISPOSITION_HEADING = {
    "defender": "defender: enqueued",
    "world_author": "world author: enqueued",
}


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
        addressee = "defender" if f.subject == "defender" else "world author"
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


def _raw(x: Any) -> str:
    """`x` as plain text with no markup escaping — for building a string another function will
    escape exactly once. `None` reads as the same em dash `_v`/`_uv` show."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    return x if isinstance(x, str) else str(x)


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
        if isinstance(f.evidence, list):
            for e in f.evidence:
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


def _render_findings_body(rows: list[_Finding], grade: Any, grade_ok: bool, episode_id: str,
                          world_reports: dict[str, Any],
                          draw_failures: list[tuple[str, Any, str]] | None = None) -> str:
    groups: dict[str, list[_Finding]] = {}
    for f in rows:
        heading = _disposition_heading_raw(f)
        groups.setdefault(heading, []).append(f)

    parts = []
    for n, (heading, group_rows) in enumerate(groups.items(), start=1):
        rows_html = "".join(_finding_row_html(f) for f in group_rows)
        parts.append(f'<details id="fg-{n}" class="fg"><summary>{_uv(heading)}</summary>'
                    f'{rows_html}</details>')
    body = "".join(parts)

    dropped_seen: set[tuple[str, Any]] = set()
    dropped_bits = []
    for f in rows:
        key = (f.label, f.draw)
        if key in dropped_seen or f.dropped is None:
            continue
        dropped_seen.add(key)
        dropped_bits.append(f'<div class="fr-dropped">draw {_v(f.draw)} of {_v(f.label)}: '
                           f'{_v(f.dropped)} dropped</div>')
    for label, draw, failure_reason in draw_failures or []:
        dropped_seen.add((label, draw))
        dropped_bits.append(f'<div class="fr-dropped">draw {_v(draw)} of {_v(label)}: '
                           f'{_uv(failure_reason)} —</div>')
    body += "".join(dropped_bits)

    unreadable_total = sum(r.unreadable for r in world_reports.values())
    skipped_total = sum(r.skipped for r in world_reports.values())
    if unreadable_total:
        body += f'<div class="fr-unreadable">{unreadable_total} draw documents unreadable</div>'
    if skipped_total:
        body += f'<div class="fr-skipped">{skipped_total} skipped</div>'
    return body


# =========================================================================================
# Verdict section: band, lede, tiles, cards
# =========================================================================================


def _render_verdict(episode_dir: Path, manifest: dict[str, Any], grade: Any, grade_rec: _Record,  # noqa: C901, PLR0912, PLR0913, PLR0915 — the band, lede, four tiles and cards are one section (#1025 O1/O2), each reading its own record fields
                    entries: dict[str, WorldEntry], roster_order: list[str],
                    control_label: str | None, episode_id: str, episode_token: str,
                    review_rec: _Record, timing_rec: _Record) -> str:
    if grade is not None and grade.not_graded is not None:
        stamp = grade.not_graded
        band = (f'<div class="vd-band">not graded: '
               f'<span class="vd-reason">{_uv(stamp.reason)}</span></div>')
        return _page_section("sec-verdict", "Verdict", band)

    if not grade_rec.ok:
        band = f'<div class="vd-band">{esc(grade_rec.error)}</div>'
        return _page_section("sec-verdict", "Verdict", band)
    if grade is None:
        band = '<div class="vd-band">no grade record</div>'
        return _page_section("sec-verdict", "Verdict", band)

    rows, counts, _world_reports, _draw_failures = _walk_findings(
        episode_dir, entries, grade, True, episode_id=episode_id)

    lede_parts = []
    family_groups: dict[Any, list[_Finding]] = {}
    for f in rows:
        if f.label == "family" and f.disposition != "never_on_record":
            family_groups.setdefault(f.draw, []).append(f)
    for draw in sorted(family_groups, key=lambda d: (isinstance(d, str), d)):
        outcome = _family_draw_outcome(episode_dir, draw)
        items = "".join(f'<div class="vd-family-item">{_uv(f.topic)}: {_uv(f.claim)}'
                        f' <span class="vd-outcome">{esc(outcome)}</span></div>'
                        for f in family_groups[draw])
        lede_parts.append(f'<div class="vd-family-draw">{items}</div>')

    family_failed = getattr(grade, "family_failed_reason", None)
    if family_failed:
        lede_parts.append(f'<div class="vd-family-failed">{_uv(family_failed)}</div>')

    badge_word = getattr(grade, "family_outcome", None) or grade.verdict_word
    queued = grade.enqueued_rows + grade.world_enqueued_rows
    lede_line = (f"{esc(grade.verdict_word)} · {queued} "
                f"findings queued · {counts['withheld']} withheld")
    if counts["withheld"]:
        first_reason = next((f.reason for f in rows if f.disposition == "withheld"), None)
        if first_reason:
            lede_line += f" ({esc(str(first_reason))})"
    lede_parts.append(f'<div class="vd-lede">{lede_line}</div>')

    badge = f'<span class="vd-badge">{esc(str(badge_word))}</span>'
    meta = f'<span class="vd-meta">{esc(grade.episode_outcome)} · {esc(grade.verdict_word)}</span>'

    measuring = {w.label for w in entries.values()
                if w.row is not None and not w.row.get("ungradable")
                and w.row.get("withheld_reason") is None}
    graded = {w.label for w in entries.values()
             if w.row is not None and not w.row.get("ungradable")}
    control_declared = _normalized(_control_declared(manifest, control_label))
    contrasting = 0
    agree = 0
    for label in measuring:
        row = entries[label].row
        if row is None:
            continue
        if _normalized(row.get("declared")) != control_declared:
            contrasting += 1
        if row.get("verdict") == row.get("declared"):
            agree += 1
    verdict_note = ("" if grade.verdict_word in _LADDER_WORDS
                    else ' <span class="vd-nonladder">(family outcome, not the ladder)</span>')
    tile1 = (
        f'<div class="vd-tile" id="vd-tile-1">{len(measuring)} of {len(graded)} graded '
        f'measuring · {contrasting} of {len(measuring)} contrast the control · verdict = '
        f'declared on {agree} of {len(measuring)} '
        f'<span class="vd-word">{esc(grade.verdict_word)}</span>{verdict_note}</div>')

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
                  "0 dropped"]
    if counts["never_eligible"]:
        split_parts.append(f"{counts['never_eligible']} never eligible")
    # THE WALK'S OWN COUNT (J9c) — never `grade.enqueued_rows`, which is the RECORD's figure
    # and is shown, separately, in the queue-accounting details alongside this one.
    tile_queued = counts["defender"] + counts["world_author"]
    tile3 = (
        f'<div class="vd-tile" id="vd-tile-3">{tile_queued} of '
        f'{findings_total} <div class="vd-caption">{" / ".join(split_parts)}</div></div>')

    total_cost, worlds_wall, lower_bound = _cost_totals(episode_dir, manifest, entries)
    # The lower-bound label is the STAGES header's own fallback caption — owed whenever there is
    # no REAL wall to compute from: absent (`present=False`) and present-but-unreadable
    # (`ok=False`, the STAGES table's own distinct "timing record unreadable" refusal) both
    # leave this tile with nothing better than the estimate, so both read the same here even
    # though the stage table itself tells the two apart (spec resolution, PR body). With a
    # genuinely readable, non-empty record the header carries the real figure instead, and this
    # tile must not repeat the fallback beside it.
    bound_html = f'<br>{lower_bound}' if not (timing_rec.ok and timing_rec.value) else ""
    tile4 = (
        f'<div class="vd-tile" id="vd-tile-4">{_money(total_cost)}'
        f'<div class="vd-caption">{worlds_wall}{bound_html}</div></div>')

    cards = []
    for w in entries.values():
        if w.label == control_label or w.row is None or w.row.get("ungradable"):
            continue
        row = w.row
        header = f"{_v(row.get('declared'))} → {_v(row.get('verdict'))}"
        heading = (_v(row.get("withheld_reason")) if row.get("withheld_reason") is not None
                  else _v(row.get("bucket")))
        chip_bits = "".join(f'<span class="vd-chip">{_v(k)}={_v(row.get(k))}</span>'
                           for k in _CHIP_FIELDS if k in row)
        reach = (family.world_review_block(review_rec.value, w.label)
                if review_rec.ok and isinstance(review_rec.value, dict) else None)
        envelope_note = ""
        if isinstance(reach, dict) and reach.get("envelope_failed"):
            first_line = str(reach["envelope_failed"]).splitlines()[0]
            envelope_note = f'<div class="vd-envelope">{_uv(first_line)}</div>'
        world_group = [f for f in rows if f.label == w.label and f.subject == "defender"]
        n_findings = len(world_group)
        footer_word = "withheld" if row.get("withheld_reason") is not None else "enqueued"
        group_id = f"fg-{_group_index_for(w.label, rows)}"
        off_roster_note = ("" if w.in_manifest or w.run_dir_name is not None
                          else '<div class="vd-off-roster">not in the manifest</div>')
        cards.append(
            f'<div class="vd-cause">{_uv(w.label)} {header} {heading}{off_roster_note}'
            f'{chip_bits}{envelope_note}'
            f'<a href="#{esc(group_id)}">{n_findings} findings · {footer_word}</a>'
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


def _group_index_for(label: str, rows: list[_Finding]) -> int:
    groups: dict[str, int] = {}
    n = 0
    for f in rows:
        h = _disposition_heading_raw(f)
        if h not in groups:
            n += 1
            groups[h] = n
        if f.label == label:
            return groups[h]
    return 1


def _control_declared(manifest: dict[str, Any], control_label: str | None) -> Any:
    for w in manifest.get("worlds") or []:
        if isinstance(w, dict) and w.get("world_id") == control_label:
            return w.get("disposition_declared")
    return None


def _normalized(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        from defender._vocab import normalized_disposition
        return normalized_disposition(value) or value
    except Exception:  # noqa: BLE001
        return value


def _family_draw_outcome(episode_dir: Path, draw: Any) -> str:
    d = Path(episode_dir) / archive.WORLDS_DIRNAME / "family" / archive.DRAWS_DIRNAME
    docs = draws_on_disk(d)
    doc = docs.get(draw) if isinstance(draw, int) else None
    if isinstance(doc, dict):
        return str(doc.get("episode_outcome", ""))
    return ""


def _cost_totals(episode_dir: Path, manifest: dict[str, Any],
                 entries: dict[str, WorldEntry]) -> tuple[float, str, str]:
    total = 0.0
    walls = []
    for w in entries.values():
        run_dir = _run_dir_path(episode_dir, w)
        if run_dir is None:
            continue
        cost, wall_ms, _state = _result_event(run_dir)
        if cost is not None:
            total += cost
        if wall_ms:
            walls.append(wall_ms)
    q_cost, q_wall_ms, _qp, _qt = _trace_cost(episode_dir, "questioner")
    j_cost, j_wall_ms, _jp, _jt = _trace_cost(episode_dir, Step.JUDGE)
    total += q_cost + j_cost
    if walls:
        wall_range = f"{fmt_duration(min(walls))}–{fmt_duration(max(walls))}"
        lower_bound = f"≈ {fmt_duration(q_wall_ms + j_wall_ms + max(walls))} lower bound on wall: model calls + longest world"
    else:
        wall_range = ""
        lower_bound = ""
    return total, wall_range, lower_bound


def _run_dir_path(episode_dir: Path, w: WorldEntry) -> Path | None:
    p = episode_dir / "runs"
    if w.run_dir_name:
        return p / w.run_dir_name
    return None


def _result_event(run_dir: Path) -> tuple[float | None, float | None, str]:
    trace = run_dir / "tool_trace.jsonl"
    if not (trace.exists() or trace.is_symlink()):
        return None, None, "absent"
    if not artifact_file(trace):
        return None, None, "refused"
    rows, _bad = read_jsonl_rows_report(trace)
    if not rows or rows[-1].get("type") != "result":
        return None, None, "none"
    last = rows[-1]
    cost = last.get("total_cost_usd")
    duration = last.get("duration_ms")
    if not isinstance(cost, (int, float)) or isinstance(cost, bool) or not math.isfinite(cost) \
            or cost < 0:
        return None, duration if isinstance(duration, (int, float)) else None, "unusable"
    return float(cost), float(duration) if isinstance(duration, (int, float)) else None, "ok"


def _trace_cost(episode_dir: Path, role_prefix: str) -> tuple[float, float, int, int]:  # noqa: C901 — the priced/wall-time split per call, one pass over one stream
    """`(cost, wall_ms, priced_calls, total_calls)` for every trace file this stage's role
    owns — one call per FILE. A call is "priced" when its response row carries `usage` and a
    `model` the pricing table resolves; the wall total sums `duration_ms` only where present,
    independently of whether the call priced (#1025 J13b)."""
    total = 0.0
    wall = 0.0
    priced_calls = 0
    total_calls = 0
    wire = episode_dir / "wire_logs"
    if not artifact_dir(wire):
        return 0.0, 0.0, 0, 0
    for path in sorted(wire.glob("*.jsonl")):
        if "_framed_trace" in path.name or not path.name.endswith("_trace.jsonl"):
            continue
        agent = path.name[: -len("_trace.jsonl")]
        if role_prefix == "questioner" and not agent.startswith("questioner"):
            continue
        if role_prefix == Step.JUDGE and not agent.startswith("judge_"):
            continue
        total_calls += 1
        rows, _bad = read_jsonl_rows_report(path)
        call_priced = False
        for row in rows:
            if row.get("kind") != "response":
                continue
            usage = row.get("usage")
            model = row.get("model")
            duration = row.get("duration_ms")
            if isinstance(usage, dict) and isinstance(model, str):
                try:
                    total += pricing.usage_cost(model, usage)
                    pricing.model_key(model)
                    call_priced = True
                except pricing.UnknownModel:
                    pass
            if isinstance(duration, (int, float)):
                wall += duration
        if call_priced:
            priced_calls += 1
    return total, wall, priced_calls, total_calls


def _render_queue_accounting(grade: Any, counts: dict[str, int], rows: list[_Finding]) -> str:
    lines = [
        f'defender: {grade.enqueued_rows} enqueued to {_uv(grade.enqueued_to)}',
        f'questioner: {grade.world_enqueued_rows} enqueued to {_uv(grade.world_enqueued_to)}',
        f'withheld {counts["withheld"]} ({_v(_first_withheld_reason(rows))})',
        f'unqueueable {counts["unqueueable"]}',
        f'malformed {grade.queue_malformed_rows} / {grade.world_queue_malformed_rows}',
        'dropped 0',
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

    recorded_withheld = len(getattr(grade, "withheld_findings", None) or [])
    matched = min(recorded_withheld, counts["withheld"])
    withheld_line = f'withheld list: {recorded_withheld} entries · {matched} matched'
    if recorded_withheld != counts["withheld"]:
        withheld_line += (f' <span class="vd-disagree">record and page disagree by '
                         f'{abs(recorded_withheld - counts["withheld"])}</span>')
    lines.append(withheld_line)

    for line in getattr(grade, "unqueueable_findings", None) or []:
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


def _render_worlds(episode_dir: Path, manifest: dict[str, Any], entries: dict[str, WorldEntry],
                   roster_order: list[str], control_label: str | None, review_rec: _Record,
                   grade: Any, episode_id: str) -> str:
    guide_rows = []
    for w in manifest.get("worlds") or []:
        if not isinstance(w, dict):
            continue
        label = w.get("world_id")
        if not isinstance(label, str):
            guide_rows.append(_unnameable(str(label), what="world label"))
            continue
        safe = _safe_id(label)
        if safe is None:
            guide_rows.append(_unnameable(label, what="world label"))
            continue
        declared = _declared_for(label, w, entries)
        if label == control_label:
            guide_rows.append(f'<div class="vd-guide-row">{esc(label)} — '
                             f'the branch point untouched, not graded · {_v(declared)}</div>')
            continue
        axis = w.get("axis")
        axis_html = (f'<q class="verbatim">{_uv(axis)}</q>' if isinstance(axis, str)
                    else "<em>null</em>")
        guide_rows.append(f'<div class="vd-guide-row">{esc(label)} '
                         f'({esc(str(w.get("role")))}) {_v(declared)} {axis_html}</div>')

    sections = []
    for label in roster_order:
        sections.append(_render_one_world(episode_dir, manifest, entries, label, control_label,
                                          review_rec, grade, episode_id))

    body = f'<div class="vd-guide">{"".join(guide_rows)}</div>{"".join(sections)}'
    return _page_section("sec-worlds", f"Worlds ({len(entries)})", body)


def _declared_for(label: str, manifest_world: dict[str, Any],
                  entries: dict[str, WorldEntry]) -> Any:
    entry = entries.get(label)
    if entry is not None and entry.row is not None and entry.row.get("declared") is not None:
        return entry.row["declared"]
    return manifest_world.get("disposition_declared")


def _render_one_world(  # noqa: C901, PLR0912, PLR0915 — one world's whole section (state, ladder, chips, archive, review) is one demand (#1025 J7/J8/J16)
                      episode_dir: Path, manifest: dict[str, Any],
                      entries: dict[str, WorldEntry], label: str, control_label: str | None,
                      review_rec: _Record, grade: Any, episode_id: str) -> str:
    safe = _safe_id(label)
    if safe is None:
        return _unnameable(label, what="world directory")
    entry = entries.get(label)
    if entry is None:
        # A `runs/` directory whose name did not decompose into `<episode_id>-<label>` (J7
        # iv) — it is not a world at all, so it gets a minimal section keyed on its own full
        # name rather than the normal record-driven rendering.
        run_dir = episode_dir / "runs" / label
        if artifact_dir(run_dir):
            link = f"runs/{label}/runtime.html"
            return (f'<div id="world-{esc(safe)}" class="w-section">'
                   f'<span class="w-name">{_v(label)}</span>'
                   f'<div class="w-state">not declared in the manifest</div>'
                   f'<a href="{esc(link)}">runtime</a></div>')
        entry = WorldEntry(label)
    # J14: a `not_graded` stamp voids the whole family's word, so every world's RECORD-derived
    # state (the ladder, the bucket, the withheld reason) is exactly what an episode with no
    # grade at all shows — "not graded" — even though the row is still physically on the
    # document; the run-dir/archive-derived parts below are unaffected.
    not_graded = grade is not None and grade.not_graded is not None
    row = None if not_graded else entry.row
    bits = []
    if grade is not None and not not_graded and row is None and not entry.in_manifest \
            and entry.run_dir_name is None:
        bits.append('<div class="w-state">not in the manifest</div>')

    draws_dir = episode_dir / archive.WORLDS_DIRNAME / label / archive.DRAWS_DIRNAME
    _docs, draws_report = draws_on_disk_report(draws_dir)
    if draws_report.unreadable:
        bits.append(f'<div class="w-unreadable">{draws_report.unreadable} draw documents '
                   f'unreadable</div>')
    if draws_report.skipped:
        bits.append(f'<div class="w-skipped">{draws_report.skipped} skipped</div>')

    if row is None:
        bits.append('<div class="w-state">not graded</div>')
        manifest_world = next((w for w in manifest.get("worlds") or []
                              if isinstance(w, dict) and w.get("world_id") == label), None)
        if manifest_world is not None:
            declared = _declared_for(label, manifest_world, entries)
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

    bits.append(_chip_html(row, review_rec, label))

    manifest_world = next((w for w in manifest.get("worlds") or []
                          if isinstance(w, dict) and w.get("world_id") == label), None)
    if manifest_world is not None:
        axis = manifest_world.get("axis")
        if isinstance(axis, str):
            bits.append(f'<div class="w-axis"><q class="verbatim">{_uv(axis)}</q></div>')

    run_dir = episode_dir / "runs" / f"{episode_id}-{label}"
    if artifact_dir(run_dir):
        cost, wall_ms, state = _result_event(run_dir)
        link = f"runs/{episode_id}-{label}/runtime.html"
        bits.append(f'<a href="{esc(link)}">runtime</a>')
        if state == "ok" and cost is not None:
            bits.append(f'<span class="w-cost">{_money(cost)}</span>')
            if wall_ms:
                bits.append(f'<span class="w-wall">{fmt_duration(wall_ms)}</span>')
        elif state == "refused":
            bits.append('<span class="w-cost">no result event (refused)</span>')
        else:
            bits.append('<span class="w-cost">no result event</span>')
    else:
        bits.append('<div class="w-archive">run directory absent</div>')

    world_dir = episode_dir / "worlds" / label
    if not artifact_dir(world_dir):
        bits.append('<div class="w-archive">not archived</div>')
    else:
        report_path = world_dir / "report.md"
        if not (report_path.exists() or report_path.is_symlink()):
            bits.append('<div class="w-archive">not archived</div>')
        elif artifact_file(report_path):
            # Screened: this world's own archived report, through the package reader — a
            # symlink at the name is refused above rather than followed here.
            report = read_report(report_path)
            bits.append(f'<div class="w-report">{_v(report.disposition_or_unknown)}</div>')
        else:
            bits.append('<div class="w-archive">report record unreadable</div>')
        if (not (world_dir / "investigation.md").exists()
                and not (world_dir / "investigation.md").is_symlink()):
            bits.append('<div class="w-archive">not archived</div>')
        prov = family.json_mapping(world_dir / PROVENANCE)
        if prov is not None:
            bits.append(f'<div class="w-prov">{_v(prov.get("commit"))}</div>')
        else:
            bits.append('<div class="w-prov">absent</div>')
        scrub = family.json_mapping(world_dir / archive.SCRUB_VERDICT_NAME)
        if scrub is None:
            bits.append('<div class="w-scrub">not recorded</div>')
        else:
            bits.append(f'<div class="w-scrub">{_v(scrub)}</div>')

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


def _chip_html(row: dict[str, Any] | None, review_rec: _Record, label: str) -> str:
    bits = []
    reach = (family.world_review_block(review_rec.value, label)
            if review_rec.ok and isinstance(review_rec.value, dict) else None)
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


def _render_findings(episode_dir: Path, manifest: dict[str, Any], grade: Any, grade_rec: _Record,
                     entries: dict[str, WorldEntry], roster_order: list[str],
                     episode_id: str, off_roster: int) -> str:
    if grade is not None and grade.not_graded is not None:
        return _page_section("sec-findings", "Findings (0)", "")
    grade_ok = grade is not None
    rows, _walk_counts, world_reports, draw_failures = _walk_findings(
        episode_dir, entries, grade, grade_ok, episode_id=episode_id)
    body = _render_findings_body(rows, grade, grade_ok, episode_id, world_reports,
                                 draw_failures)
    if off_roster:
        body += (f'<div class="fr-off-roster">{off_roster} entries under worlds/ are not on '
                f'the record</div>')
    n = len(rows)
    return _page_section("sec-findings", f"Findings ({n})", body)


# =========================================================================================
# Stages section
# =========================================================================================


def _render_stages(episode_dir: Path, manifest: dict[str, Any], grade: Any, timing_rec: _Record,  # noqa: C901, PLR0912, PLR0915 — the stage table, the two clocks and every trace block are one section (#1025 O4)
                   entries: dict[str, WorldEntry], roster_order: list[str], episode_id: str,
                   episode_token: str) -> str:
    rows_by_step: dict[str, list[dict[str, Any]]] = {}
    if timing_rec.ok:
        for row in timing_rec.value or []:
            rows_by_step.setdefault(row["step"], []).append(row)

    total_cost, worlds_wall, lower_bound = _cost_totals(episode_dir, manifest, entries)
    q_cost, q_wall_ms, q_priced, q_calls = _trace_cost(episode_dir, "questioner")
    j_cost, j_wall_ms, j_priced, j_calls = _trace_cost(episode_dir, Step.JUDGE)

    table_rows = []
    header_walls = []
    for step in STEPS:
        entries_for_step = rows_by_step.get(str(step), [])
        if timing_rec.error:
            wall_text = ""
        elif entries_for_step:
            starts = [r["started_at"] for r in entries_for_step]
            ends = [r["ended_at"] for r in entries_for_step]
            durations = []
            for r in entries_for_step:
                d = _wall_between(r["started_at"], r["ended_at"])
                if d is not None:
                    durations.append(d)
                    # Only a POSITIVE duration feeds the header span: an inverted row (`d <= 0`,
                    # `_wall_between`'s own negative-duration sentinel) already shows "—" in its
                    # own cell rather than a number, and letting its untrustworthy pair still
                    # widen or narrow min(start)/max(end) would silently corrupt the one
                    # aggregate the row's own display just refused to state (#1025 p5).
                    if d > 0:
                        header_walls.append((r["started_at"], r["ended_at"]))
            if durations:
                # The row's own wall is its FIRST entry's start to its LAST entry's end (J15) —
                # never a sum, which double-counts a repeated step's own reported span.
                span_starts = [r["started_at"] for r in entries_for_step
                              if _wall_between(r["started_at"], r["ended_at"]) is not None]
                span_ends = [r["ended_at"] for r in entries_for_step
                            if _wall_between(r["started_at"], r["ended_at"]) is not None]
                wall_text = fmt_duration(_wall_span(span_starts, span_ends))
            else:
                wall_text = "—"
            if len(entries_for_step) > 1:
                wall_text += f" ({len(entries_for_step)} entries)"
        else:
            wall_text = "not on the record"
        if str(step) == "questioner":
            if not q_calls:
                cost_text = "no cost recorded"
            elif q_priced < q_calls:
                cost_text = (f"{_money(q_cost)} · {q_calls} traces · {fmt_duration(q_wall_ms)} · "
                            f"partial — {q_priced} of {q_calls} calls priced")
            else:
                cost_text = f"{_money(q_cost)} · {q_calls} traces · {fmt_duration(q_wall_ms)}"
        elif str(step) == Step.JUDGE:
            if not j_calls:
                cost_text = "no cost recorded"
            elif j_priced < j_calls:
                cost_text = (f"{_money(j_cost)} · {j_calls} traces · {fmt_duration(j_wall_ms)} · "
                            f"partial — {j_priced} of {j_calls} calls priced")
            else:
                cost_text = f"{_money(j_cost)} · {j_calls} traces · {fmt_duration(j_wall_ms)}"
        elif str(step) == "review":
            comp_cost, comp_calls = _comparator_cost(episode_dir)
            cost_text = f"{_money(comp_cost)}" if comp_calls else "no model calls"
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
        header_wall_text = lower_bound
        table = '<div class="st-caption">model-call time — no timing record</div>' + "".join(table_rows)

    review_total, review_calls = _comparator_cost(episode_dir)
    # `total_cost` (from `_cost_totals`) already sums the worlds' results PLUS questioner and
    # judge traces — adding `q_cost`/`j_cost` again here would double them.
    grand_total = total_cost + review_total
    # No line at all — not "$0.0000" — when nothing anywhere priced: a launcher-produced
    # episode with no trace files owes no total any more than its own rows owe one (#1025,
    # matching the runs section's own `any_costed` guard just below).
    if q_calls or j_calls or review_calls or total_cost:
        table += (f'<div class="st-total">{_money(grand_total)} — excludes gather subagents and '
                f'the review gate</div>')

    runs_rows = []
    runs_total = 0.0
    any_costed = False
    for w in entries.values():
        run_dir = episode_dir / "runs" / f"{episode_id}-{w.label}"
        if not artifact_dir(run_dir):
            continue
        cost, wall_ms, state = _result_event(run_dir)
        if state == "ok" and cost is not None:
            any_costed = True
            runs_total += cost
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} {_money(cost)} '
                            f'{fmt_duration(wall_ms) if wall_ms else ""} '
                            f'<span class="rn-launcher">result event</span></div>')
        elif state == "refused":
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} '
                            f'no result event (refused)</div>')
        elif state == "unusable":
            runs_rows.append(f'<div class="rn-row">{esc(str(w.label))} '
                            f'unusable result event</div>')
        elif state == "absent":
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
                           f'{_transcript_blocks_for_step(episode_dir, str(step), episode_id, entries)}'
                           f'</div>')

    timing_block = f'<div id="stage-timing" class="stage-timing">{table}</div>'
    unattributed = _unattributed_traces(episode_dir, entries)
    unattributed_html = ""
    if unattributed:
        unattributed_html = (f'<div class="st-unattributed">unattributed traces: '
                            f'{", ".join(esc(n) for n in unattributed)}</div>')

    if timing_rec.error or not header_walls:
        header_line = f'<div class="hd-lower-bound">{esc(lower_bound)}</div>'
    else:
        header_line = (f'<div class="hd-wall">{esc(header_wall_text)} — the launcher\'s wall '
                      f'from the first step\'s start to the last step\'s end; excludes '
                      f'preflight and the prime, includes the gaps between steps</div>')

    body = f'{header_line}{timing_block}{"".join(stage_blocks)}{unattributed_html}'
    return _page_section("sec-stages", "Stages (6)", body)


def _wall_between(start: str, end: str) -> float | None:
    from defender._clock import parse_iso_utc
    a, b = parse_iso_utc(start), parse_iso_utc(end)
    if a is None or b is None:
        return None
    delta = (b - a).total_seconds() * 1000
    return delta if delta > 0 else -1


def _wall_span(starts: list[str], ends: list[str]) -> float:
    from defender._clock import parse_iso_utc
    parsed_starts = [d for s in starts if (d := parse_iso_utc(s)) is not None]
    parsed_ends = [d for e in ends if (d := parse_iso_utc(e)) is not None]
    if not parsed_starts or not parsed_ends:
        return 0.0
    return (max(parsed_ends) - min(parsed_starts)).total_seconds() * 1000


def _comparator_cost(episode_dir: Path) -> tuple[float, int]:
    """`(cost, priced calls)` — `calls` counts response rows that actually priced, not files:
    an empty (or response-less) comparator trace contributes a file to the stream list but no
    call here, so the review row still reads "no model calls" (#1025 J13b)."""
    wire = episode_dir / "wire_logs"
    total = 0.0
    calls = 0
    if not artifact_dir(wire):
        return 0.0, 0
    for path in sorted(wire.glob("comparator_*_trace.jsonl")):
        rows, _bad = read_jsonl_rows_report(path)
        for row in rows:
            if row.get("kind") == "response" and isinstance(row.get("usage"), dict) \
                    and isinstance(row.get("model"), str):
                total += pricing.usage_cost(row["model"], row["usage"])
                calls += 1
    return total, calls


def _unattributed_traces(episode_dir: Path, entries: dict[str, WorldEntry]) -> list[str]:
    wire = episode_dir / "wire_logs"
    if not artifact_dir(wire):
        return []
    known = {f"judge_{label}_{n}" for label in [*entries, "family"] for n in range(50)}
    out = []
    for path in sorted(wire.glob("judge_*_trace.jsonl")):
        if "_framed_trace" in path.name:
            continue
        stem = path.name[: -len("_trace.jsonl")]
        if stem not in known:
            out.append(path.name[: -len(".jsonl")])
    return out


def _transcript_blocks_for_step(episode_dir: Path, step: str, episode_id: str,  # noqa: C901 — one discovery pass per role, family-first ordering included (#1025 J13c)
                                entries: dict[str, WorldEntry]) -> str:
    if step not in ("questioner", Step.JUDGE, "review"):
        return ""
    wire = episode_dir / "wire_logs"
    if not artifact_dir(wire):
        return ""
    blocks = []
    if step == "questioner":
        for stem in sorted(_trace_stems(wire, "questioner")):
            blocks.append(_transcript_block(episode_dir, stem))
    elif step == Step.JUDGE:
        # Family first (J13c/d29), then each roster world in numeric draw order. A launcher-
        # produced episode writes only the FRAMED twin for a judge call (no plain trace), so
        # the stem set is the union of both — never just the plain trace files' own names.
        judge_stems = _trace_stems(wire, Step.JUDGE)
        family_stems = sorted((s for s in judge_stems if s.startswith("judge_family_")),
                              key=lambda s: _draw_key_stem(s, "family"))
        for stem in family_stems:
            blocks.append(_transcript_block(episode_dir, stem))
        for label in sorted(entries):
            prefix = f"judge_{label}_"
            label_stems = sorted((s for s in judge_stems if s.startswith(prefix)),
                                 key=lambda s: _draw_key_stem(s, label))
            for stem in label_stems:
                blocks.append(_transcript_block(episode_dir, stem))
    elif step == "review":
        for path in sorted(wire.glob("comparator_*_trace.jsonl")):
            comp_rows, _bad = read_jsonl_rows_report(path)
            if comp_rows:
                blocks.append(_transcript_block(episode_dir, path.name[: -len(".jsonl")]))
            else:
                # J13b: an empty comparator trace prices nothing and is listed by stem rather
                # than rendered as a stream with no rows.
                stem = path.name[: -len(".jsonl")]
                blocks.append(f'<div class="tx-note">{esc(stem)}: 0 rows</div>')
    return "".join(blocks)


def _draw_key_stem(stem: str, label: str) -> int:
    prefix = f"judge_{label}_"
    if not stem.startswith(prefix):
        return 0
    try:
        return int(stem[len(prefix):-len("_trace")])
    except ValueError:
        return 0


def _trace_stems(wire: Path, role_prefix: str) -> set[str]:
    """Every call's own STEM (`<agent>_trace`, never `..._framed_trace`) for a role — the
    union of plain trace files and framed twins, since a launcher-produced episode writes only
    the framed one for some roles (#1025 J13a/b): a stem with no plain trace file still gets a
    block, built entirely from its framed record."""
    stems: set[str] = set()
    for path in wire.glob(f"{role_prefix}*_trace.jsonl"):
        if "_framed_trace" in path.name:
            continue
        stems.add(path.name[: -len(".jsonl")])
    for path in wire.glob(f"{role_prefix}*_framed_trace.jsonl"):
        stems.add(path.name[: -len("_framed_trace.jsonl")] + "_trace")
    return stems


def _transcript_block(episode_dir: Path, stem: str) -> str:  # noqa: C901, PLR0912, PLR0915 — one call's request/response rendering, every response field independently absent
    path = episode_dir / "wire_logs" / f"{stem}.jsonl"
    rows, unreadable = read_jsonl_rows_report(path)
    framed_path = episode_dir / "wire_logs" / f"{stem[:-len('_trace')]}_framed_trace.jsonl"
    framed = None
    if artifact_file(framed_path):
        frows, _ = read_jsonl_rows_report(framed_path)
        if frows:
            framed = frows[0]

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
            msg = request.get("message") or {}
            instructions = msg.get("instructions")
            prompt_text = ""
            for part in msg.get("parts") or []:
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
        parts = (row.get("message") or {}).get("parts") or []
        text = next((p.get("content") for p in parts if isinstance(p, dict)
                    and p.get("part_kind") == "text"), "")
        priced = None
        if isinstance(usage, dict) and isinstance(model, str):
            try:
                priced = pricing.usage_cost(model, usage)
                pricing.model_key(model)
            except pricing.UnknownModel:
                priced = None
        line_bits = [f'<div class="tx-entry">{_uv(text)}']
        if model:
            line_bits.append(f'<span class="tx-model">{_v(model)}</span>')
        if isinstance(usage, dict):
            line_bits.append(f'<span class="tx-usage">{usage.get("input_tokens", 0):,}</span>')
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
    if not framed_has_response and not any(r.get("kind") == "response" for r in rows):
        entries_html.append('<div class="tx-entry">no response recorded</div>')

    unreadable_html = f'<div class="tx-unreadable">{unreadable} unreadable rows</div>' if unreadable else ""
    return (f'<div id="tx-{esc(stem)}" class="tx-stream">'
          f'<div class="tx-search"></div>'
          f'{"".join(entries_html)}{unreadable_html}</div>')


# =========================================================================================
# Leads section
# =========================================================================================


def _render_leads(episode_dir: Path, entries: dict[str, WorldEntry], roster_order: list[str],
                  review_rec: _Record, episode_id: str, episode_token: str) -> str:
    blocks = []
    for label in roster_order:
        safe = _safe_id(label)
        if safe is None:
            continue
        blocks.append(_render_world_leads(episode_dir, label, episode_token))
    return _page_section("sec-leads", f"Leads ({len(roster_order)})", "".join(blocks))


def _render_world_leads(episode_dir: Path, label: str, episode_token: str) -> str:  # noqa: C901, PLR0912, PLR0915 — the served ledger, the archive notes and every lead's chain are one world's leads block (#1025 O3)
    world_dir = episode_dir / "worlds" / label
    bits = []

    ledger_path = family.world_ledger_path(episode_dir, label, episode_token=episode_token)
    if not (ledger_path.exists() or ledger_path.is_symlink()):
        bits.append('<div class="ld-served">served ledger: absent</div>')
    elif not artifact_file(ledger_path):
        bits.append('<div class="ld-served">served ledger unreadable</div>')
    else:
        try:
            # `read_jsonl_rows_report` is the shared tolerant reader's own bare `read_text` —
            # it survives a torn line or an undecodable byte but not a permission-denied
            # regular file (root ignores this; a real non-root run does not, #1025), which
            # reaches this call as an un-typed `OSError`. This world's leads block is its own
            # slot, never the whole page.
            _rows, malformed = read_jsonl_rows_report(ledger_path)
            if malformed:
                bits.append(f'<div class="ld-served">{malformed} malformed row</div>')
        except OSError:
            bits.append('<div class="ld-served">served ledger unreadable</div>')

    if not artifact_dir(world_dir):
        return f'<div id="leads-{esc(label)}" class="leads-section">not archived' \
              f'{"".join(bits)}</div>'

    inv_path = world_dir / "investigation.md"
    facts = None
    facts_error = None
    if not (inv_path.exists() or inv_path.is_symlink()):
        pass
    else:
        try:
            facts = family.read_world_facts(episode_dir, label, episode_token=episode_token)
        except JudgeRefused as bad:
            facts_error = str(bad)
        except Exception as bad:  # noqa: BLE001
            facts_error = str(bad)

    if facts_error is not None:
        bits.append(f'<div class="ld-investigation">investigation record unavailable: '
                   f'{esc(facts_error)}</div>')

    try:
        all_leads = family.leads_by_id(world_dir)
    except Exception:  # noqa: BLE001
        all_leads = {}

    summaries_dir = world_dir / "gather_summaries"
    summary_stems = set()
    if artifact_dir(summaries_dir) and not summaries_dir.is_symlink():
        for p in summaries_dir.iterdir():
            if p.suffix == ".md" and artifact_file(p):
                summary_stems.add(p.stem)
            elif not p.name.endswith(".md"):
                s = _safe_id(p.stem)
                if s is None:
                    bits.append(_unnameable(p.stem, what="gather summary"))

    if facts is not None:
        referenced = set(facts.referenced_leads)
        roster = referenced | summary_stems
    else:
        roster = set(all_leads) | summary_stems

    resolutions_by_lead = facts.resolutions_by_lead if facts is not None else {}
    if facts is not None and facts.resolution_moved:
        bits.append('<div class="ld-moved">the hand-off was revisited after the branch</div>')

    for lead_id in sorted(roster):
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
        try:
            # `lead_chain`'s own gather-summary read is `errors="replace"` for a BAD byte but
            # a bare `read_text` for a permission-denied file (root ignores this; a real
            # non-root run does not, #1025) — this one lead's row is its own slot, never the
            # whole page.
            chain = family.lead_chain(world_dir, lead_id, resolutions_by_lead, leads=all_leads)
        except OSError:
            id_attr = f' id="ld-{esc(label)}-{esc(safe)}"' if safe is not None else ""
            bits.append(f'<div{id_attr} class="ld-lead">'
                       f'<span class="ld-id">{_uv(lead_id)}</span>'
                       f'<span class="ld-summary">lead unreadable</span></div>')
            continue
        goal = chain.get("goal")
        params = chain.get("params")
        summary = chain.get("summary")
        payload = chain.get("payload") or []
        resolutions = chain.get("resolutions") or []
        resolutions_html = "".join(f'<div class="ld-resolution">{_uv(r)}</div>'
                                  for r in resolutions)
        id_attr = f' id="ld-{esc(label)}-{esc(safe)}"' if safe is not None else ""
        bits.append(f'<div{id_attr} class="ld-lead">'
                   f'<span class="ld-id">{_uv(lead_id)}</span>'
                   f'<span class="ld-goal">{_uv(goal)}</span>'
                   f'<span class="ld-params">{_uv(params)}</span>'
                   f'<span class="ld-payload">{"".join(_uv(str(d)) for d in payload)}</span>'
                   f'<span class="ld-summary">{_uv(summary)}</span>'
                   f'{resolutions_html}'
                   f'</div>')

    return f'<div id="leads-{esc(label)}" class="leads-section">{"".join(bits)}</div>'


# =========================================================================================
# Records section
# =========================================================================================


def _render_records(episode_dir: Path, manifest: dict[str, Any], review_rec: _Record,  # noqa: C901, PLR0912 — every episode-level record's own slot in one section (#1025 O8)
                    samples_rec: _Record, staged_rec: _Record, stamp_rec: _Record,
                    episode_id: str) -> str:
    bits = []
    base_story = manifest.get("base_story")
    bits.append(f'<div class="rc-story">{_uv(base_story)}</div>')
    discriminator = manifest.get("discriminator")
    if isinstance(discriminator, dict):
        predicate = discriminator.get("predicate")
        bits.append(f'<div class="rc-predicate">{_uv(predicate)}</div>')
        envelope = discriminator.get("envelope")
        if isinstance(envelope, dict):
            params = envelope.get("params")
            if isinstance(params, dict) and "query" in params:
                bits.append(f'<div class="rc-envelope">{_uv(params["query"])}</div>')

    for w in manifest.get("worlds") or []:
        if isinstance(w, dict) and isinstance(w.get("world_id"), str):
            bits.append(f'<div class="rc-world">{_uv(w["world_id"])}</div>')

    if samples_rec.error:
        bits.append(f'<div class="rc-samples">{esc(samples_rec.error)}</div>')
    elif not samples_rec.present:
        bits.append('<div class="rc-samples">absent</div>')
    else:
        for pattern in samples_rec.value or {}:
            bits.append(f'<div class="rc-pattern">{_uv(pattern)}</div>')

    if staged_rec.error:
        bits.append(f'<div class="rc-staged">{esc(staged_rec.error)}</div>')
    elif not staged_rec.present:
        bits.append('<div class="rc-staged">absent</div>')
    else:
        for row in staged_rec.value or []:
            bits.append(f'<div class="rc-staged-row">{_uv(row.get("name"))}</div>')

    if review_rec.error:
        bits.append(f'<div class="rc-review">{esc(review_rec.error)}</div>')
    elif not review_rec.present:
        bits.append('<div class="rc-review">absent</div>')
    else:
        review_doc = review_rec.value if isinstance(review_rec.value, dict) else {}
        episode_block = review_doc.get("episode")
        if isinstance(episode_block, dict):
            bits.append(f'<div class="rc-review-episode">{_uv(episode_block.get("decision"))}'
                       f' {_uv(episode_block.get("outcome"))}</div>')
        else:
            bits.append('<div class="rc-review-episode">absent</div>')
        if not isinstance(review_doc.get("worlds"), dict):
            bits.append('<div class="rc-review-worlds">absent</div>')
        teardown = review_doc.get("teardown")
        if isinstance(teardown, dict):
            bits.append(f'<div class="rc-teardown-at">{_uv(teardown.get("at"))}</div>')
            for failure in teardown.get("failures") or []:
                if isinstance(failure, dict):
                    bits.append(f'<div class="rc-teardown-fail">{_uv(failure.get("name"))} '
                               f'{_uv(failure.get("detail"))}</div>')
        for _label, block in (review_doc.get("worlds") or {}).items() if isinstance(
                review_doc.get("worlds"), dict) else []:
            if isinstance(block, dict):
                for inv in block.get("inventions") or []:
                    bits.append(f'<div class="rc-invention">{_uv(inv)}</div>')
                consistency = block.get("consistency")
                if isinstance(consistency, dict):
                    for key in consistency.get("control_mismatch_keys") or []:
                        bits.append(f'<div class="rc-mismatch-key">{_uv(key)}</div>')

    if stamp_rec.error:
        bits.append(f'<div class="rc-provenance">{esc(stamp_rec.error)}</div>')
    elif not stamp_rec.present:
        bits.append('<div class="rc-provenance">absent</div>')
    else:
        agreed = stamp_rec.value.get("agreed") if isinstance(stamp_rec.value, dict) else {}
        if isinstance(agreed, dict):
            bits.append(f'<div class="rc-commit">{_v(agreed.get("commit"))}</div>')
            bits.append(f'<div class="rc-model">{_v(agreed.get("model"))}</div>')
            for path_ in agreed.get("dirty_paths") or []:
                bits.append(f'<div class="rc-dirty">{_uv(path_)}</div>')
        bits.append(f'<div class="rc-allow-dirty">allow_dirty: '
                   f'{_v(stamp_rec.value.get("allow_dirty"))}</div>')

    return _page_section("sec-records", "Records", "".join(bits))


# =========================================================================================
# CLI
# =========================================================================================


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
        html_text = build_page(episode_dir)
    except JudgeRefused as bad:
        # ONE LINE: the manifest's own refusal may wrap a multi-line YAML parser error, and
        # d01 promises the CLI one reason line, not the parser's whole traceback-shaped text.
        print(" ".join(str(bad).split()), file=sys.stderr)
        return 1
    try:
        page_path = episode_dir / PAGE_NAME
        write_guarded(page_path, _encode_page(html_text), mode="replace")
    except OSError as bad:
        print(str(bad), file=sys.stderr)
        return 1
    print(page_path)
    for sentence in ("grade record unreadable", "timing record unreadable",
                     "review record unreadable", "samples record unreadable",
                     "staging record unreadable", "provenance record unreadable",
                     "no grade record"):
        if sentence in html_text:
            print(sentence, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
