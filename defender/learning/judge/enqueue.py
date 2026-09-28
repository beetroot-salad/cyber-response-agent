"""The judge's appender: thirteen-key finding rows onto the defender and questioner queues.

Refuses a row missing `finding_id`/`run_id`/`direction` before it reaches the shared findings
gate (where it would raise a bare `KeyError` and stuck-record the whole keyed batch), and
refuses `discard`/`corpus-contradiction` outright: for those outcomes the family record is the
whole artifact, and no row of such an episode may ever be authored from.

The refusal is the appender's, for rows handed in from anywhere. `enqueue_report` asks the same
rule one row at a time and drops (and names) only the findings that fail it, so one unusable
finding never costs the other worlds theirs.
"""

from __future__ import annotations

import json
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Any

import yaml

from defender._io import (
    ENTRY_FILE, Bound, bind, guarded_mkdir, read_jsonl_rows_report, write_guarded)
from defender._run_paths import artifact_dir, artifact_file
from defender._yaml import safe_load as _yaml_safe_load
from defender._text import is_content_less
from defender._vocab import normalized_judge_outcome
from defender._episode_paths import LAYOUT, EpisodePaths
from defender.learning.core.config import (
    QUEUEABLE_FINDING_TYPES,
    learning_state_root,
    loop_paths,
)
from defender.learning.core.persist import derive_alert_rule_key, queue_lock
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.family import is_gradable_row
from defender.learning.judge.render import episode_alert
#: Imported, not re-spelled, so the appender's guard and `run.py`'s selector cannot drift.
from defender.learning.judge.run import SUBJECT_DEFENDER, SUBJECT_WORLD, cites_sample

#: Outcomes whose episode is never a defender failure to author from.
_UNQUEUEABLE_VERDICTS = frozenset({"discard", "corpus-contradiction"})


def _queue_paths_for(channel: Any, queue_dir: Path | None) -> tuple[Path, Path]:
    """One channel's `(file, append_lock)`, relocated under `queue_dir` when given.

    Names come from the `QueueChannel` the drain reads through, so a rename cannot leave the
    appender writing files nothing reads; only the directory is overridable."""
    if queue_dir is None:
        return channel.file, channel.append_lock
    queue_dir = Path(queue_dir)
    return queue_dir / channel.file.name, queue_dir / channel.append_lock.name


def _queue_paths(queue_dir: Path | None) -> tuple[Path, Path]:
    """The defender findings queue's file and its append lock.

    Resolved per call (not the import-frozen `DEFAULT_PATHS`) so the environment's state root
    wins. Never derived from `episode_dir`, or rows could land where no drain reads.
    """
    return _queue_paths_for(loop_paths().findings, queue_dir)


def _questioner_queue_paths(queue_dir: Path | None) -> tuple[Path, Path]:
    """The questioner channel's file and its own append lock, resolved as `_queue_paths`."""
    return _queue_paths_for(loop_paths().questioner_findings, queue_dir)


def _validate_row(row: dict[str, Any], *, episode_dir: Path | None = None) -> None:
    """The rule for what may go on the defender queue — per row, so the producer can drop one
    row alone while the appender refuses outright."""
    where = f"episode {Path(episode_dir).name}: " if episode_dir is not None else ""
    # `_gate_findings` indexes all three unguarded (`finding_id` first).
    for key in ("finding_id", "run_id", "direction"):
        if key not in row:
            raise JudgeRefused(
                f"{where}a family finding row is missing {key!r} — a row missing it raises a "
                "bare KeyError inside the shared findings gate and stuck-records the whole "
                "keyed batch (P6); refused at the appender instead")
    # Exact match, no case-fold and no trim: this is the last screen before the defender curator.
    subject = row.get("subject")
    if subject != SUBJECT_DEFENDER:
        raise JudgeRefused(
            f"{where}a row bound for the defender findings channel must carry "
            f"subject={SUBJECT_DEFENDER!r}, not {subject!r}")
    # `build_finding_row` keeps the two consistent, but hand-fed rows may not.
    if row.get("direction") == SUBJECT_WORLD:
        raise JudgeRefused(
            f"{where}a row bound for the defender findings channel must carry "
            f"direction={SUBJECT_WORLD!r} nowhere near subject={SUBJECT_DEFENDER!r} — the two "
            "fields disagree")
    row_type = row.get("type")
    # `isinstance` first: an unhashable value (e.g. a list off a draw file) would raise
    # `TypeError` from the set test, which the per-row drop arm does not catch.
    if not isinstance(row_type, str) or row_type not in QUEUEABLE_FINDING_TYPES:
        raise JudgeRefused(
            f"{where}a family finding row's type={row_type!r} is not one of the queueable "
            f"finding types {sorted(QUEUEABLE_FINDING_TYPES)}")
    for key in ("subject_anchor", "subject_topic"):
        value = row.get(key)
        if not isinstance(value, str) or is_content_less(value):
            raise JudgeRefused(
                f"{where}a family finding row's {key} must be a non-empty string")
    outcome = normalized_judge_outcome(row.get("judge_outcome"))
    if outcome is None:
        raise JudgeRefused(
            f"{where}a family finding row's judge_outcome={row.get('judge_outcome')!r} is not "
            "a member of the judge outcome vocabulary")
    if outcome in _UNQUEUEABLE_VERDICTS:
        # Checked here, not only in the producer: downstream nothing skips or holds such a row,
        # so it would go straight to the curator.
        raise JudgeRefused(
            f"{where}a family finding row's judge_outcome={outcome!r} is a word the family "
            "record is the whole artifact for — such an episode is never a defender failure to "
            "author from, so no row of it may reach the queue (O7)")


def _validate_world_row(row: dict[str, Any], *, episode_dir: Path | None = None) -> None:
    """The rule for what may go on the questioner channel. The bucket (`type`) is an open
    vocabulary, but `pattern`, `holding_system` and `subject` are required: this is the last
    screen, as the questioner curator's gate is idempotency-only."""
    where = f"episode {Path(episode_dir).name}: " if episode_dir is not None else ""
    for key in ("finding_id", "run_id", "direction"):
        if key not in row:
            raise JudgeRefused(
                f"{where}a questioner finding row is missing {key!r} — a row missing it raises "
                "a bare KeyError inside the shared drain machinery")
    if row.get("direction") != SUBJECT_WORLD:
        raise JudgeRefused(
            f"{where}a row bound for the questioner findings channel must carry "
            f"direction={SUBJECT_WORLD!r}, not {row.get('direction')!r}")
    subject = row.get("subject")
    if subject != SUBJECT_WORLD:
        raise JudgeRefused(
            f"{where}a row bound for the questioner findings channel must carry "
            f"subject={SUBJECT_WORLD!r}, not {subject!r}")
    for key in ("pattern", "holding_system"):
        value = row.get(key)
        if not isinstance(value, str) or is_content_less(value):
            raise JudgeRefused(
                f"{where}a questioner finding row's {key} must be a non-empty string")
    # Open, not untyped. A bare re-enqueue reads draw YAML unvalidated, so e.g. a date arrives
    # as `datetime.date` and would raise `TypeError` in `json.dumps` inside the queue lock.
    row_type = row.get("type")
    if not isinstance(row_type, str) or is_content_less(row_type):
        raise JudgeRefused(
            f"{where}a questioner finding row's type must be a non-empty string, not "
            f"{type(row_type).__name__}")
    # Same hazard for the anchor columns, which would fail mid-append.
    for key in ("subject_anchor", "subject_topic"):
        value = row.get(key)
        if not isinstance(value, str) or is_content_less(value):
            raise JudgeRefused(
                f"{where}a questioner finding row's {key} must be a non-empty string")


def _append_validated_rows(
    rows: list[dict[str, Any]], *, pending_file: Path, lock_file: Path,
    dedup_key: str | None = None,
) -> tuple[int, int]:
    """The one write under one lock hold that every channel appender shares. Rows must already
    be validated.

    The malformed count is taken inside the same hold, so a concurrent appender cannot tear the
    read that measures tearing.

    `dedup_key` makes the append idempotent on that field, checked against this channel's own
    file only — an id consumed on the defender channel must not suppress a world row."""
    if not rows:
        # No lock and no mkdir: a pass that enqueued nothing must not create the queue. The
        # count is best-effort here for that reason.
        return 0, read_jsonl_rows_report(pending_file)[1]
    # Anchored at the state root, not the queue dir itself: with `base=path` no component is
    # judged and the guard degenerates into a plain `mkdir(parents=True)`.
    guarded_mkdir(pending_file.parent, base=_queue_trust_root(pending_file))
    with queue_lock(lock_file):
        # A torn trailing row must not be concatenated onto; a leading newline (below) closes
        # its line without touching its bytes.
        existing, malformed = read_jsonl_rows_report(pending_file)
        to_write = rows
        if dedup_key is not None:
            # String ids only on both sides: an unhashable id off the shared file would raise
            # `TypeError` inside the lock. Every id minted here is a string, and a non-string
            # id can only fail to suppress a write, which is the safe direction.
            seen = {r[dedup_key] for r in existing
                    if isinstance(r, dict) and isinstance(r.get(dedup_key), str)}
            to_write = [r for r in rows
                        if not (isinstance(r.get(dedup_key), str) and r[dedup_key] in seen)]
        if not to_write:
            return 0, malformed
        text = "".join(json.dumps(row) + "\n" for row in to_write)
        if artifact_file(pending_file) and pending_file.stat().st_size > 0:
            with pending_file.open("rb") as fh:
                fh.seek(-1, 2)
                if fh.read(1) != b"\n":
                    text = "\n" + text
        write_guarded(pending_file, text, mode="append")
    return len(to_write), malformed


def append_rows(episode_dir: Path, rows: list[dict[str, Any]], *,
                queue_dir: Path | None = None) -> int:
    """How many of `rows` were appended. See `append_rows_report` for the rest of the answer."""
    return append_rows_report(episode_dir, rows, queue_dir=queue_dir)[0]


def append_rows_report(episode_dir: Path, rows: list[dict[str, Any]], *,
                       queue_dir: Path | None = None) -> tuple[int, int]:
    """Append `rows` to the defender findings channel; return `(appended, malformed lines seen
    on the queue)`. `episode_dir` is only for refusal text; the queue is never derived from it."""
    rows = list(rows)
    for row in rows:
        _validate_row(row, episode_dir=episode_dir)
    pending_file, lock_file = _queue_paths(queue_dir)
    return _append_validated_rows(rows, pending_file=pending_file, lock_file=lock_file)


def append_world_rows(episode_dir: Path, rows: list[dict[str, Any]], *,
                      queue_dir: Path | None = None) -> int:
    """How many of `rows` were appended to the questioner channel."""
    return append_world_rows_report(episode_dir, rows, queue_dir=queue_dir)[0]


def append_world_rows_report(episode_dir: Path, rows: list[dict[str, Any]], *,
                             queue_dir: Path | None = None) -> tuple[int, int]:
    """Append `rows` to the questioner findings channel; return `(appended, malformed lines
    seen on the queue)`.

    `judge_outcome` is forced to `None`: a defender verdict word on a world row would invite the
    questioner curator to author a lesson about the defender."""
    validated = list(rows)
    for row in validated:
        _validate_world_row(row, episode_dir=episode_dir)
    pending_file, lock_file = _questioner_queue_paths(queue_dir)
    sanitized = [{**row, "judge_outcome": None} for row in validated]
    return _append_validated_rows(sanitized, pending_file=pending_file, lock_file=lock_file,
                                  dedup_key="finding_id")


def _queue_trust_root(pending_file: Path) -> Path:
    """The tree `guarded_mkdir` is anchored at: the learning state root for a queue inside it,
    else the queue dir's parent (the most that can be claimed about a caller-chosen location)."""
    state_root = learning_state_root()
    queue_dir = pending_file.parent
    return state_root if state_root in queue_dir.parents else queue_dir.parent


def _resolving_citations(finding: dict[str, Any]) -> list[str]:
    """A finding's evidence pointers minus the ones `_draw_document` recorded as not resolving.

    The unresolved ones stay off the row (the queue shape is fixed at thirteen keys) and remain
    readable on the draw document `source_run_dir` names."""
    # Model-authored YAML: neither key is known to be a list, and a bare string would iterate
    # into one-character citations. `str()` because YAML scalars like dates are not
    # JSON-serialisable and would raise inside the queue lock.
    raw = finding.get("evidence")
    evidence = [str(p) for p in raw] if isinstance(raw, list) else []
    raw_unresolved = finding.get("unresolved_evidence")
    unresolved = (
        {str(p) for p in raw_unresolved} if isinstance(raw_unresolved, list) else set())
    return [p for p in evidence if p not in unresolved]


def build_finding_row(  # noqa: PLR0913 — the FindingRow's own inputs, one keyword each
    *, run_id: str, label: str, draw: str, index: int, subject: str, finding: dict[str, Any],
    alert_rule_key: str, judge_outcome: str, provenance: str = "model",
    pattern: str | None = None, holding_system: str | None = None,
) -> dict[str, Any]:
    """The thirteen-key `FindingRow` for one finding of one draw of one world, plus
    `world`/`pattern`/`holding_system`/`provenance` for `subject: world`.

    @owns finding_id
    @owns source_run_dir
    @owns direction

    `finding_id` is `{run_id}/{label}/{draw}/{index}`: deterministic across retries over the
    same draw files, since queue idempotency keys on it alone. `label="family"` keys a
    family-level finding; `_check_world_labels` refuses a world labeled `family` so the two
    cannot collide.

    `direction` is derived from `subject` so the two cannot disagree. `world` is the pass's
    stamp (`None` for family-level), never the model's claim.

    `source_run_dir` is `episodes/{run_id}/worlds/{label}`, or `episodes/{run_id}` for a
    family-level finding. One `run_id` feeds both it and `finding_id` so they always name the
    same episode."""
    direction = SUBJECT_WORLD if subject == SUBJECT_WORLD else "family"
    row: dict[str, Any] = {
        "schema_version": 1,
        "finding_id": f"{run_id}/{label}/{draw}/{index}",
        "run_id": run_id,
        "alert_rule_key": alert_rule_key,
        "direction": direction,
        "subject": subject,
        "type": finding.get("bucket"),
        "subject_anchor": finding.get("anchor"),
        "subject_topic": finding.get("topic"),
        "finding": f"{finding.get('claim', '')} — {finding.get('root_cause', '')}",
        "judge_outcome": judge_outcome,
        "citations": _resolving_citations(finding),
        "source_run_dir": (
            f"episodes/{run_id}" if label == "family" else f"episodes/{run_id}/worlds/{label}"),
    }
    if subject == SUBJECT_WORLD:
        row["world"] = None if label == "family" else label
        # The pass's stamp first; the model's value only where the pass has none. `pattern` is
        # the questioner corpus's only selection key, so a model-chosen string that is not a
        # real staged pattern would make the lesson silently unselectable.
        row["pattern"] = _first_nonempty(pattern, finding.get("pattern"))
        row["holding_system"] = _first_nonempty(holding_system, finding.get("holding_system"))
        row["provenance"] = provenance
    return row


def _first_nonempty(*values: Any) -> Any:
    """The first argument that is a non-blank string, else the last one (so an absent value
    still reaches the validator that refuses it)."""
    for value in values:
        if isinstance(value, str) and not is_content_less(value):
            return value
    return values[-1] if values else None


@model
class DrawsSkipReport:
    """What `draws_on_disk_report` did not turn into a draw document.

    `unreadable` is a fault: torn, undecodable, linked, or a stem outside the ASCII-digit
    alphabet (a non-ASCII digit like `'١'` counts here). `skipped` is a non-canonical spelling of
    an index (`01.yaml`), ignored by design and reported separately from faults."""

    unreadable: int = 0
    skipped: int = 0


def draws_on_disk_report(draw_dir: Path) -> tuple[dict[int, dict[str, Any]], DrawsSkipReport]:
    """`draws_on_disk` plus what it skipped, classified."""
    report = DrawsSkipReport()
    # `artifact_dir`, not `is_dir()`: a planted link would queue another tree's draws as ours.
    if not artifact_dir(draw_dir):
        return {}, report
    out: dict[int, dict[str, Any]] = {}
    with bind(Path(draw_dir)) as bound:
        listed = bound.entries().entries or {}
        for name in sorted(n for n in listed if n.endswith(".yaml")):
            text = _draw_text(bound, name, listed[name], report)
            if text is None:
                continue
            try:
                # `_yaml.safe_load` converts a deep-nesting `RecursionError` into a handled class.
                doc = _yaml_safe_load(text) or {}
            except (ValueError, yaml.YAMLError):
                report.unreadable += 1
                continue
            if isinstance(doc, dict):
                out[int(Path(name).stem)] = doc
            else:
                report.unreadable += 1
    return dict(sorted(out.items())), report


def _draw_text(bound: Bound, name: str, kind: str, report: DrawsSkipReport) -> str | None:
    """One listed `<n>.yaml`'s text, or `None` with the reason counted on `report`."""
    stem = Path(name).stem
    # `isdigit()` alone admits superscripts and non-ASCII digits, which `int()` rejects.
    if not (stem.isascii() and stem.isdigit()):
        report.unreadable += 1
        return None
    # Canonical spelling only: `01.yaml` and `1.yaml` would collapse onto one key over an
    # unordered listing, making `finding_id` (the idempotency key) nondeterministic.
    if stem != str(int(stem)):
        report.skipped += 1
        return None
    # A link, directory or other non-file entry is unreadable, judged without following it;
    # the no-follow read then refuses a hard link and undecodable bytes.
    text = bound.read(name).text if kind == ENTRY_FILE else None
    if text is None:
        report.unreadable += 1
    return text


def draws_on_disk(draw_dir: Path) -> dict[int, dict[str, Any]]:
    """Every draw document in `draw_dir`, keyed by draw index, in numeric order.

    The one reader of `worlds/<X>/judge/<n>.yaml`, shared with the episode page so both join
    the same rows. Used when the caller did not just produce the draws; one that did passes them
    as `drawn=` so no file this pass did not write is picked up."""
    return draws_on_disk_report(draw_dir)[0]


def enqueue(episode_dir: Path, grade: Any, *, queue_dir: Path | None = None,
            drawn: dict[str, dict[int, dict[str, Any]]] | None = None,
            family_drawn: dict[int, dict[str, Any]] | None = None) -> int:
    """How many defender rows this pass enqueued (`enqueue_report` has the rest)."""
    return enqueue_report(episode_dir, grade, queue_dir=queue_dir, drawn=drawn,
                          family_drawn=family_drawn).appended


#: `route_finding`'s answers — where one finding goes before any row is built or validated.
#: Internal: the decision is written per finding to the ledger (`LANE_*`), and readers show
#: the ledger rather than re-deriving the route, which would be a second decision that drifts.
ROUTE_DEFENDER = "defender"
"""A defender row is built and validated against `_validate_row`."""
ROUTE_WORLD = "world"
"""A world row is built and validated against `_validate_world_row` (the questioner channel)."""
ROUTE_WITHHELD = "withheld"
"""Recorded whole on `withheld_findings` with the world's own reason; never a row."""
ROUTE_NEVER_ELIGIBLE = "never_eligible"
"""The family's verdict word blocks the whole defender lane; not counted anywhere."""
ROUTE_NO_CHANNEL = "no_channel"
"""`subject` names neither channel: dropped and named on `unqueueable_findings`."""
ROUTE_UNGRADABLE = "ungradable"
"""The world's row is `ungradable`: its draws are never walked, so nothing is queued."""
ROUTE_NO_ROW = "no_row"
"""No grade row names this world: its draws are never walked."""

#: The three shapes a finding coordinate takes — a per-world draw (`<label>/<n>/<i>`), the
#: family-level call's draw (`family/<n>/<i>`) and a mechanical finding
#: (`<label>/mechanical/<i>`).
KIND_DRAW = "draw"
KIND_FAMILY = "family"
KIND_MECHANICAL = "mechanical"

#: The ledger: what this pass did with every finding coordinate it touched, written to the
#: record as `EpisodeGrade.dispositions`. A lane is the decision after validation (a defender
#: route that `_validate_row` refused is `LANE_UNQUEUEABLE`), so each entry answers "did this
#: reach a queue, and if not, why" without the reader re-deriving anything.
LANE_DEFENDER = ROUTE_DEFENDER
"""A defender row was built, validated and handed to the defender appender."""
LANE_WORLD = ROUTE_WORLD
"""A world row was built, validated and handed to the questioner appender."""
LANE_WITHHELD = ROUTE_WITHHELD
"""Recorded whole on `withheld_findings`; `reason` is the world row's `withheld_reason`."""
LANE_NEVER_ELIGIBLE = ROUTE_NEVER_ELIGIBLE
"""The defender lane was closed by the family's word; `reason` is that `verdict_word`."""
LANE_UNQUEUEABLE = "unqueueable"
"""Never a row: `reason` is the same line `unqueueable_findings` carries, minus the id."""
LEDGER_LANES = frozenset({LANE_DEFENDER, LANE_WORLD, LANE_WITHHELD, LANE_NEVER_ELIGIBLE,
                          LANE_UNQUEUEABLE})


def disposition_entry(finding_id: str, lane: str, reason: str | None = None) -> dict[str, Any]:
    """One ledger entry: the finding's id (`build_finding_row`'s spelling, whether or not a row
    was built), its lane, and the reason where the lane is a refusal."""
    return check_disposition_entry({"finding_id": finding_id, "lane": lane, "reason": reason})


def check_disposition_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Check a ledger entry names its finding and one of the lanes above; `ValueError`
    otherwise (a writer mistake, or a planted record read back)."""
    if not isinstance(entry.get("finding_id"), str):
        raise ValueError(f"a ledger entry does not name its finding: {entry!r}")
    if entry.get("lane") not in LEDGER_LANES:
        raise ValueError(f"a ledger entry names no lane ({sorted(LEDGER_LANES)}): {entry!r}")
    return entry


def unqueueable_lines_of(dispositions: list[dict[str, Any]]) -> list[str]:
    """`unqueueable_findings`, one line per dropped finding, derived from the ledger."""
    return [f"{e['finding_id']}: {e['reason']}" for e in dispositions
            if e["lane"] == LANE_UNQUEUEABLE]


def withheld_reasons_of(world_rows: list[dict[str, Any]]) -> dict[str, str]:
    """`{label: withheld_reason}` for every world row carrying one.

    `is not None`, the same predicate that partitions `measuring_worlds`; truthiness would let
    a `""` reason be withheld there and enqueued here."""
    return {
        w["world"]: w["withheld_reason"] for w in world_rows
        if isinstance(w, dict) and "world" in w and w.get("withheld_reason") is not None}


def defender_lane_blocked(verdict_word: Any) -> bool:
    """Does the family's word close the defender lane? Through the normalizer, since the word
    may come off a box-reachable `judge.yaml` as an unhashable or differently-cased value."""
    return normalized_judge_outcome(verdict_word) in _UNQUEUEABLE_VERDICTS


def route_finding(  # noqa: PLR0911, PLR0913 — one decision, one return per lane; the inputs are the record's own signals
    *, label: str, finding: dict[str, Any], kind: str, world_row: dict[str, Any] | None,
    withheld_reasons: dict[str, str], defender_blocked: bool,
) -> tuple[str, str | None]:
    """Which lane one finding takes, and the reason where the lane is a refusal.

    Decided from the record's signals alone (the world's row, withheld reasons, whether the
    defender lane is blocked, the finding's `subject`); validation is separate. An absent
    `subject` is the defender's — older draws carry none and were queued as defender findings.
    """
    if kind in (KIND_FAMILY, KIND_MECHANICAL):
        # Always the world lane; mechanical findings are walked for every row, ungradable ones
        # included (the finding is the record of why the world could not be graded).
        return ROUTE_WORLD, None
    if world_row is None:
        return ROUTE_NO_ROW, None
    if not is_gradable_row(world_row):
        reason = world_row.get("ungradable_reason")
        return ROUTE_UNGRADABLE, reason if isinstance(reason, str) else None
    subject = finding.get("subject", SUBJECT_DEFENDER)
    if subject == SUBJECT_WORLD:
        return ROUTE_WORLD, None
    if subject != SUBJECT_DEFENDER:
        return ROUTE_NO_CHANNEL, (
            f"subject={subject!r} names neither channel ({SUBJECT_DEFENDER!r}/"
            f"{SUBJECT_WORLD!r}) — no case-fold and no trim, so it is dropped rather than "
            "routed by guesswork")
    if label in withheld_reasons:
        return ROUTE_WITHHELD, withheld_reasons[label]
    if defender_blocked:
        return ROUTE_NEVER_ELIGIBLE, None
    return ROUTE_DEFENDER, None


@model(frozen=True)
class EnqueueReport:
    """What one enqueue did on both channels: rows appended, findings it could not make a row
    of, and the malformed lines already on each queue."""

    appended: int = 0
    queue_malformed_rows: int = 0
    world_appended: int = 0
    world_queue_malformed_rows: int = 0
    #: The world rows this pass built — not appended: the channel dedups on `finding_id`, so a
    #: re-grade builds every row and appends none. `world_appended` is the count.
    world_rows: list[dict[str, Any]] = field(default_factory=list)
    #: `{finding, world, reason}` for every withheld defender finding — the whole finding, as
    #: its only surviving record. Distinct from `unqueueable` (could not be made a valid row).
    withheld_findings: list[dict[str, Any]] = field(default_factory=list)
    #: The ledger: every finding coordinate touched and its lane, in walk order.
    dispositions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def unqueueable(self) -> list[str]:
        """Findings this pass could not make a row of, as `<finding_id>: <reason>`."""
        return unqueueable_lines_of(self.dispositions)


def _add_row(  # noqa: PLR0913 — the sink dispatch's own inputs
    row: dict[str, Any], *, validator: Any, sink: list[dict[str, Any]], lane: str,
    ledger: list[dict[str, Any]], episode_dir: Path,
) -> None:
    """Validate one row against its channel's rule and file it, or record the drop — so an
    invalid finding costs only itself. The ledger gets an entry either way."""
    try:
        validator(row, episode_dir=episode_dir)
    except JudgeRefused as refused:
        ledger.append(disposition_entry(row["finding_id"], LANE_UNQUEUEABLE, str(refused)))
        return
    ledger.append(disposition_entry(row["finding_id"], lane))
    sink.append(row)


def enqueue_report(  # noqa: C901, PLR0912, PLR0915 — one pass over one set of findings; splitting it would re-derive `graded_labels`/`alert_rule_key` per lane
    episode_dir: Path, grade: Any, *, queue_dir: Path | None = None,
    drawn: dict[str, dict[int, dict[str, Any]]] | None = None,
    family_drawn: dict[int, dict[str, Any]] | None = None,
) -> EnqueueReport:
    """Every finding of every completed draw -> one `FindingRow`, partitioned by `subject`
    onto the defender channel or the questioner channel.

    `grade` carries the family's `verdict_word` (every defender row's `judge_outcome`) and the
    per-world rows. `drawn`/`family_drawn` are the draws the caller just produced; `None` falls
    back to the draw directories on disk (a bare re-enqueue).

    A blocked defender lane (`discard`/`corpus-contradiction`) does not stop the world lane,
    whose findings are about the instrument, not the defender."""
    episode_dir = Path(episode_dir)
    verdict_word = grade["verdict_word"] if isinstance(grade, dict) else grade.verdict_word
    world_rows = grade["worlds"] if isinstance(grade, dict) else grade.worlds
    # Deduped: a box-writable `judge.yaml` can name a world on two rows, which would file every
    # finding twice.
    graded_labels = list(dict.fromkeys(w["world"] for w in world_rows if is_gradable_row(w)))
    withheld_reasons = withheld_reasons_of(world_rows)
    #: Each world's row by label: the pass's `pattern`/`holding_system` stamp and
    #: `sample_unavailable_patterns`, needed per finding on the world lane.
    row_of = {w["world"]: w for w in world_rows if isinstance(w, dict) and "world" in w}
    run_id = episode_dir.name
    # The one rule for which world's alert is the episode's, shared with the orchestration so
    # the rule key and the sibling union agree.
    with bind(episode_dir) as bound:
        alert_rule_key = derive_alert_rule_key(episode_alert(bound, graded_labels))
    defender_blocked = defender_lane_blocked(verdict_word)

    defender_rows: list[dict[str, Any]] = []
    world_rows_out: list[dict[str, Any]] = []
    ledger: list[dict[str, Any]] = []

    def _drop(finding_id: str, reason: str) -> None:
        ledger.append(disposition_entry(finding_id, LANE_UNQUEUEABLE, reason))
    #: The whole finding: a re-grade may not reproduce the same model draw, so this is its only
    #: surviving record.
    withheld_findings: list[dict[str, Any]] = []

    #: Every world row carries the family's holding system, ungradable ones included.
    family_holding_system = _first_nonempty(
        *(w.get("holding_system") for w in world_rows if isinstance(w, dict)), "")
    #: A real staged pattern for the family lane: `pattern` is the questioner corpus's only
    #: selection key, and the holding system's name is never a stageable pattern, so a
    #: family-level lesson stamped with it could never be selected again.
    family_pattern = _first_nonempty(
        *(w.get("pattern") for w in world_rows if isinstance(w, dict)), family_holding_system)

    # Family-level draws first, so a per-world finding sharing its (open-vocabulary) bucket
    # never shadows it in the channel's written order. `is None`, not truthiness: an empty map
    # means this pass produced no family draw, and must not fall back to leftovers on disk.
    family_documents = (
        draws_on_disk(EpisodePaths(episode_dir).world("family").draws)
        if family_drawn is None else family_drawn)
    for draw, draw_doc in family_documents.items():
        findings = draw_doc.get("findings") or []
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                _drop(f"{run_id}/family/{draw}/{index}",
                      f"the family draw's finding[{index}] is {type(finding).__name__}, "
                      "not a mapping")
                continue
            # No sample-citation gate needed: the family call is shown no sample, so evidence
            # resolution already refuses a `samples.yaml` pointer for it.
            row = build_finding_row(
                run_id=run_id, label="family", draw=str(draw), index=index,
                subject=SUBJECT_WORLD, finding=finding, alert_rule_key=alert_rule_key,
                judge_outcome=verdict_word, provenance="model",
                pattern=family_pattern, holding_system=family_holding_system)
            _add_row(row, validator=_validate_world_row, sink=world_rows_out,
                     lane=LANE_WORLD, ledger=ledger, episode_dir=episode_dir)

    for label in graded_labels:
        # Only `drawn is None` falls back to disk: an empty or label-less map means this pass
        # produced no draw, and an earlier attempt's leftovers must not be queued as its own.
        documents = (drawn.get(label) or {}) if drawn is not None else draws_on_disk(
            EpisodePaths(episode_dir).world(label).draws)
        for draw, draw_doc in documents.items():
            findings = draw_doc.get("findings") or []
            for index, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    # Model-authored YAML can hold scalars here; named, like every drop.
                    _drop(f"{run_id}/{label}/{draw}/{index}",
                          f"the draw's finding[{index}] is {type(finding).__name__}, "
                          "not a mapping")
                    continue
                # A `subject` naming neither channel is dropped, not routed to the defender lane
                # (where `build_finding_row` would re-stamp it and bypass the exact-match guard).
                route, route_reason = route_finding(
                    label=label, finding=finding, kind=KIND_DRAW, world_row=row_of.get(label),
                    withheld_reasons=withheld_reasons, defender_blocked=defender_blocked)
                if route == ROUTE_WORLD:
                    world_row = row_of.get(label) or {}
                    # Refuse a finding citing a sample the judge was never shown — here, on the
                    # path that feeds the queue. No `or []`: `None` (never recorded) is
                    # `cites_sample`'s blanket refusal, while `[]` screens per pattern.
                    if cites_sample(
                        finding,
                        unavailable_patterns=world_row.get("sample_unavailable_patterns"),
                    ):
                        _drop(f"{run_id}/{label}/{draw}/{index}",
                              f"cites `{LAYOUT.samples}` for a pattern this world had no sample "
                              "for (A1(b))")
                        continue
                    row = build_finding_row(
                        run_id=run_id, label=label, draw=str(draw), index=index,
                        subject=SUBJECT_WORLD, finding=finding, alert_rule_key=alert_rule_key,
                        judge_outcome=verdict_word, provenance="model",
                        pattern=world_row.get("pattern"),
                        holding_system=world_row.get("holding_system"))
                    _add_row(row, validator=_validate_world_row, sink=world_rows_out,
                             lane=LANE_WORLD, ledger=ledger, episode_dir=episode_dir)
                    continue
                if route == ROUTE_NO_CHANNEL:
                    _drop(f"{run_id}/{label}/{draw}/{index}", route_reason or "")
                    continue
                if route == ROUTE_WITHHELD:
                    # The world's difference was never measured: recorded whole, with reason.
                    finding_id = f"{run_id}/{label}/{draw}/{index}"
                    withheld_findings.append(
                        {"finding": finding, "world": label, "reason": route_reason,
                         "finding_id": finding_id})
                    ledger.append(disposition_entry(finding_id, LANE_WITHHELD, route_reason))
                    continue
                if route == ROUTE_NEVER_ELIGIBLE:
                    # Never eligible: not counted as unqueueable or withheld, but on the ledger.
                    ledger.append(disposition_entry(
                        f"{run_id}/{label}/{draw}/{index}", LANE_NEVER_ELIGIBLE,
                        str(verdict_word)))
                    continue
                if route != ROUTE_DEFENDER:
                    # Residue, e.g. a world named on two rows (`graded_labels` takes the first
                    # gradable one, `row_of` the last) reaching here as ungradable.
                    _drop(f"{run_id}/{label}/{draw}/{index}",
                          f"routed `{route}`{' (' + route_reason + ')' if route_reason else ''}"
                          " — the label's row is not one this pass queues from; the record "
                          "names the world on more than one row")
                    continue
                row = build_finding_row(
                    run_id=run_id, label=label, draw=str(draw), index=index,
                    subject=SUBJECT_DEFENDER, finding=finding, alert_rule_key=alert_rule_key,
                    judge_outcome=verdict_word)
                _add_row(row, validator=_validate_row, sink=defender_rows,
                         lane=LANE_DEFENDER, ledger=ledger, episode_dir=episode_dir)

    # Mechanical findings get a fixed coordinate per world, so a re-grade dedups. Every row,
    # ungradable ones included.
    for row_dict in world_rows:
        label = row_dict.get("world")
        for mech_index, finding in enumerate(row_dict.get("mechanical_world_findings") or []):
            wrow = build_finding_row(
                run_id=run_id, label=label, draw="mechanical", index=mech_index,
                subject=SUBJECT_WORLD, finding=finding, alert_rule_key=alert_rule_key,
                judge_outcome=verdict_word, provenance=finding.get("provenance", "mechanical"))
            _add_row(wrow, validator=_validate_world_row, sink=world_rows_out,
                     lane=LANE_WORLD, ledger=ledger, episode_dir=episode_dir)

    if defender_blocked:
        defender_appended, defender_malformed = 0, 0
    else:
        defender_appended, defender_malformed = append_rows_report(
            episode_dir, defender_rows, queue_dir=queue_dir)
    world_appended, world_malformed = append_world_rows_report(
        episode_dir, world_rows_out, queue_dir=queue_dir)
    reported_world_rows = [{**row, "judge_outcome": None} for row in world_rows_out]
    return EnqueueReport(
        appended=defender_appended,
        queue_malformed_rows=defender_malformed, world_appended=world_appended,
        world_queue_malformed_rows=world_malformed, world_rows=reported_world_rows,
        withheld_findings=withheld_findings, dispositions=ledger)


__all__ = [
    "DrawsSkipReport", "EnqueueReport", "KIND_DRAW", "KIND_FAMILY", "KIND_MECHANICAL",
    "LANE_DEFENDER", "LANE_NEVER_ELIGIBLE", "LANE_UNQUEUEABLE", "LANE_WITHHELD", "LANE_WORLD",
    "LEDGER_LANES", "ROUTE_DEFENDER", "ROUTE_NEVER_ELIGIBLE", "ROUTE_NO_CHANNEL", "ROUTE_NO_ROW",
    "ROUTE_UNGRADABLE", "ROUTE_WITHHELD", "ROUTE_WORLD", "append_rows", "append_rows_report",
    "append_world_rows", "append_world_rows_report", "build_finding_row",
    "defender_lane_blocked", "draws_on_disk", "draws_on_disk_report", "enqueue",
    "check_disposition_entry", "disposition_entry", "enqueue_report", "route_finding",
    "unqueueable_lines_of",
    "withheld_reasons_of",
]
