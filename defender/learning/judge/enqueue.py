"""The judge's appenders: finding rows onto the defender and questioner queues, and the one
builder of those rows.

A defender row is an investigator finding of a measured, unanimous, non-`none` world (A7,
A13); a questioner row is a design world finding (A1: not gap-only, with a resolving plan
pointer). Which finding goes where is `route.fate`'s decision; this module builds the row,
screens it one last time against its channel's rule, and appends through the pass's `state=`
handle — never a queue path of its own.

Each appender refuses a row of the wrong shape outright (a row missing `finding_id`/`run_id`/
`direction` would raise a bare `KeyError` inside the shared findings gate and stuck-record the
whole keyed batch; a row carrying a retired name is refused by that name, A4). A world's rows are
appended once, by its `queueing` -> `queued` commit (A6). Both channels drop a row whose
`finding_id` they already hold, including an earlier row in one append, so re-appending one
pass's rows adds none. The pass names, on its ledger, any new finding whose id a row of an
earlier pass already holds, so dedup never loses one silently (A25; `_Pass._place`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Any

import yaml

from defender._io import ENTRY_FILE, Bound
from defender._yaml import safe_load as _yaml_safe_load
from defender._text import is_content_less
from defender.episodes._episode_paths import LAYOUT
from defender.records import _alert_input
from defender.learning.core.config import QUEUEABLE_FINDING_TYPES
from defender.learning.core.retired import retired_keys
from defender.learning.core.state import (
    FINDINGS,
    QUESTIONER_FINDINGS,
    LearningState,
    names_systems,
)
from defender.learning.judge._errors import JudgeRefused
from defender.learning.judge.route import (
    LANE_DEFENDER,
    LANE_QUESTIONER,
    LANE_UNQUEUEABLE,
    LEDGER_LANES,
    defender_lane_blocked,
)
#: Imported, not re-spelled, so the appender's guard and the reply model cannot drift.
from defender.learning.judge.run import (
    CONTRAST_EVIDENCE,
    DIRECTION_FAMILY,
    ON_VERDICT_PATH,
    SUBJECT_DEFENDER,
    SUBJECT_WORLD,
    WORLD_FINDING_BUCKETS,
    is_world_finding_bucket,
)

#: The doubt mark a defender row carries (design data model, I6).
WORLD_LABEL_DOUBTED = "world_label_doubted"
#: The questioner channel's lane, under the name the page reads.
LANE_WORLD = LANE_QUESTIONER
#: The prefix of a plan-class citation (A1): what makes a world row design.
_PLAN_PREFIX = str(LAYOUT.family) + "#"


def rule_key_of(record: _alert_input.AlertRecord | None) -> str:
    """The recorded signature verbatim, or the explicit unkeyed fallback."""
    signature = None if record is None else record.facts.signature
    return signature if signature is not None else "unkeyed"


def no_record_reason() -> str:
    """Refuse an episode with no readable source alert record, without echoing its content."""
    return (f"the episode holds no readable record of the alert it investigates "
            f"({LAYOUT.source_record}) — it was launched before the alert's record existed, or "
            "the record is damaged")


def _refusal_prefix(episode_dir: Path | None) -> str:
    return f"episode {Path(episode_dir).name}: " if episode_dir is not None else ""


def _require_keys(row: dict[str, Any], where: str, channel: str) -> None:
    """The keys the shared drain machinery indexes unguarded, and no retired name (A4)."""
    for key in ("finding_id", "run_id", "direction"):
        if key not in row:
            raise JudgeRefused(
                f"{where}a {channel} finding row is missing {key!r} — a row missing it raises a "
                "bare KeyError inside the shared findings gate and stuck-records the whole "
                "keyed batch (P6); refused at the appender instead")
    retired = retired_keys(row)
    if retired:
        raise JudgeRefused(f"{where}a {channel} finding row carries the retired "
                           f"{', '.join(retired)} — refused by name, never read as the old "
                           "design meant it")
    for key in ("subject_anchor", "subject_topic"):
        value = row.get(key)
        if not isinstance(value, str) or is_content_less(value):
            raise JudgeRefused(f"{where}a {channel} finding row's {key} must be a non-empty "
                               "string")


def _validate_row(row: dict[str, Any], *, episode_dir: Path | None = None) -> None:
    """The rule for what may go on the defender queue: an investigator finding's row, typed
    with one of the queueable defender types, carrying `contrast_evidence`, a boolean
    `on_verdict_path` and a boolean `world_label_doubted` (design M7)."""
    where = _refusal_prefix(episode_dir)
    _require_keys(row, where, "defender")
    # Exact match, no case-fold and no trim: this is the last screen before the curator.
    if row.get("subject") != SUBJECT_DEFENDER or row.get("direction") != DIRECTION_FAMILY:
        raise JudgeRefused(
            f"{where}a row bound for the defender findings channel must carry "
            f"subject={SUBJECT_DEFENDER!r} and direction={DIRECTION_FAMILY!r}, not "
            f"subject={row.get('subject')!r} direction={row.get('direction')!r}")
    row_type = row.get("type")
    # `isinstance` first: an unhashable value would raise `TypeError` from the set test.
    if not isinstance(row_type, str) or row_type not in QUEUEABLE_FINDING_TYPES:
        raise JudgeRefused(
            f"{where}a defender finding row's type={row_type!r} is not one of the queueable "
            f"finding types {sorted(QUEUEABLE_FINDING_TYPES)}")
    contrast = row.get(CONTRAST_EVIDENCE)
    if not isinstance(contrast, list) or not contrast \
            or not all(isinstance(p, str) for p in contrast):
        raise JudgeRefused(f"{where}a defender finding row carries no {CONTRAST_EVIDENCE} — "
                           "every queued investigator finding rests on a stated contrast (I1)")
    for key in (ON_VERDICT_PATH, WORLD_LABEL_DOUBTED):
        if not isinstance(row.get(key), bool):
            raise JudgeRefused(f"{where}a defender finding row's {key}={row.get(key)!r} must be "
                               "a boolean")


def _validate_world_row(row: dict[str, Any], *, episode_dir: Path | None = None) -> None:
    """The rule for what may go on the questioner channel: a design world finding's row — a
    world-finding bucket, its own `systems`, and a plan-class citation (A1) — the last screen
    before the questioner curator."""
    where = _refusal_prefix(episode_dir)
    _require_keys(row, where, "questioner")
    if row.get("direction") != SUBJECT_WORLD or row.get("subject") != SUBJECT_WORLD:
        raise JudgeRefused(
            f"{where}a row bound for the questioner findings channel must carry "
            f"direction={SUBJECT_WORLD!r} and subject={SUBJECT_WORLD!r}, not "
            f"direction={row.get('direction')!r} subject={row.get('subject')!r}")
    row_type = row.get("type")
    if not is_world_finding_bucket(row_type):
        raise JudgeRefused(f"{where}a questioner finding row's type={row_type!r} is not one of "
                           f"{sorted(WORLD_FINDING_BUCKETS)}")
    if not names_systems(row.get("systems")):
        raise JudgeRefused(
            f"{where}a questioner finding row's systems={row.get('systems')!r} name no system, "
            "so no lesson authored from it could be selected for a tenant")
    citations = row.get("citations")
    if not isinstance(citations, list) or not any(
            isinstance(p, str) and p.startswith(_PLAN_PREFIX) for p in citations):
        raise JudgeRefused(f"{where}a questioner finding row cites no plan pointer "
                           f"({_PLAN_PREFIX}...) — only a design finding reaches the questioner")


def append_rows(episode_dir: Path, rows: list[dict[str, Any]], *,
                state: LearningState) -> int:
    """Append `rows` to the defender findings channel through `state`; how many were appended
    (`append_rows_report` without its malformed count)."""
    return append_rows_report(episode_dir, rows, state=state)[0]


def append_rows_report(episode_dir: Path, rows: list[dict[str, Any]], *,
                       state: LearningState) -> tuple[int, int]:
    """Append `rows` to the defender findings channel through `state`; return `(appended,
    malformed lines seen)` — the unreadable lines `state.append` counted on the queue under its
    append lock (a torn trailing row is one, closed rather than concatenated onto). Every row
    is screened first, so one bad row refuses the whole append before any write. `episode_dir`
    is only for refusal text; the queue is never derived from it."""
    rows = list(rows)
    for row in rows:
        _validate_row(row, episode_dir=episode_dir)
    return state.append(FINDINGS, rows, dedup_key="finding_id")


def append_world_rows(episode_dir: Path, rows: list[dict[str, Any]], *,
                      state: LearningState) -> int:
    """Append `rows` to the questioner findings channel through `state`; how many were
    appended (`append_world_rows_report` without its malformed count)."""
    return append_world_rows_report(episode_dir, rows, state=state)[0]


def append_world_rows_report(episode_dir: Path, rows: list[dict[str, Any]], *,
                             state: LearningState) -> tuple[int, int]:
    """Append `rows` to the questioner findings channel through `state`; return `(appended,
    malformed lines seen)` on that queue, as `append_rows_report` does. A row whose
    `finding_id` the queue already holds is not appended again."""
    rows = list(rows)
    for row in rows:
        _validate_world_row(row, episode_dir=episode_dir)
    return state.append(QUESTIONER_FINDINGS, rows, dedup_key="finding_id")


@model
class DrawnRows:
    """The rows one A6 commit appends, built by the pass (`build_finding_row`) from the replies
    it just drew for that world (or the family call) — never read back from draw files on disk
    (A8). `defender` rows go to the defender channel, `world` rows to the questioner's."""

    defender: list[dict[str, Any]] = field(default_factory=list)
    world: list[dict[str, Any]] = field(default_factory=list)


@model
class EnqueueReport:
    """What one `enqueue_report` call appended: rows on the defender channel (`appended`) and
    on the questioner channel (`world_appended`), with the unreadable lines each append saw on
    its queue (`malformed`, `world_malformed`; `None` where that channel had no rows to append,
    so its queue was not read)."""

    appended: int = 0
    world_appended: int = 0
    malformed: int | None = None
    world_malformed: int | None = None


def enqueue_report(episode_dir: Path, record: dict[str, Any], *, state: LearningState,
                   drawn: DrawnRows) -> EnqueueReport:
    """Append one commit's rows: `drawn`, the rows the pass built from the replies it drew for
    `record` — the world row (or the family row) being committed `queueing` -> `queued` (A6).

    `drawn` is required and must be the pass's own `DrawnRows`: there is no path that rebuilds
    rows from draw files on disk (A8), so `drawn=None` is refused by name and nothing is
    appended. Every row must belong to `record` (its `finding_id`'s world half is the row's
    `world`, `family` for the family row), so one commit never appends another world's rows.
    Both channels' rows are screened before either is written."""
    where = _refusal_prefix(episode_dir)
    if not isinstance(drawn, DrawnRows):
        raise JudgeRefused(
            f"{where}enqueue_report takes drawn=, the rows the pass built from the replies it "
            f"just drew, not {type(drawn).__name__}: rows are never rebuilt from draw files on "
            "disk (A8)")
    label = record.get("world") or "family"
    for row in (*drawn.defender, *drawn.world):
        parts = str(row.get("finding_id")).rsplit("/", 3)
        if len(parts) != 4 or parts[1] != label:
            raise JudgeRefused(
                f"{where}finding row {row.get('finding_id')!r} is not one of {label!r}'s: one "
                "commit appends only its own world's rows (A6)")
    for row in drawn.defender:
        _validate_row(row, episode_dir=episode_dir)
    for row in drawn.world:
        _validate_world_row(row, episode_dir=episode_dir)
    report = EnqueueReport()
    if drawn.defender:
        report.appended, report.malformed = append_rows_report(
            episode_dir, drawn.defender, state=state)
    if drawn.world:
        report.world_appended, report.world_malformed = append_world_rows_report(
            episode_dir, drawn.world, state=state)
    return report


def build_finding_row(  # noqa: PLR0913 — the FindingRow's own inputs, one keyword each
    *, run_id: str, label: str, world_id: str | None, draw: str, index: int, subject: str, finding: dict[str, Any],
    alert_rule_key: str | None, citations: Sequence[str] = (), contrast: Sequence[str] = (),
    world_label_doubted: bool = False, provenance: str = "model",
    recorded_signature: str | None = None,
) -> dict[str, Any]:
    """The `FindingRow` for one finding of one draw of one world (`label="family"`: the family
    call's).

    @owns finding_id
    @owns source_run_dir
    @owns direction
    @owns recorded_signature
    @owns contrast_evidence
    @owns world_label_doubted

    `finding_id` is `{run_id}/{label}/{draw}/{index}`, the index the finding's place in the
    draw's three filed lists (A13): deterministic across retries over the same draw files.
    `citations` are the finding's resolving pointers (A1). A defender row (`subject:
    defender`) carries `contrast_evidence` (the resolving conduct pointers of its two-run
    contrast), `on_verdict_path` as filed and `world_label_doubted` (the world's own draws'
    doubt mark); a world row carries `world` (the pass's stamp, `None` for the family call),
    the finding's own `systems` (A5) and `provenance`. `direction` is derived from `subject`
    so the two cannot disagree."""
    if (label == "family") != (world_id is None):
        raise ValueError("a world finding needs its host UUID; only the family call has none")
    source = f"episodes/{run_id}"
    if world_id is not None:
        source += f"/{LAYOUT.world(world_id).dir}"
    direction = SUBJECT_WORLD if subject == SUBJECT_WORLD else DIRECTION_FAMILY
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
        "citations": list(citations),
        "source_run_dir": source,
    }
    if recorded_signature is not None:
        row["recorded_signature"] = recorded_signature
    if subject == SUBJECT_WORLD:
        row["world"] = None if label == "family" else label
        row["systems"] = _row_systems(finding.get("systems"))
        row["provenance"] = provenance
    else:
        row[CONTRAST_EVIDENCE] = list(contrast)
        row[ON_VERDICT_PATH] = finding.get(ON_VERDICT_PATH)
        row[WORLD_LABEL_DOUBTED] = world_label_doubted
    return row


def _row_systems(systems: Any) -> Any:  # lint-owns: ok — the questioner queue row's `systems`; `tenant_settings.read_systems` owns a different record's field of the same name
    """@owns systems — a questioner-channel row's `systems` is its world finding's own list
    (A5: never the manifest's served systems), copied here and nowhere else;
    `_validate_world_row` refuses anything but a list of names."""
    return list(systems) if isinstance(systems, list) else systems


@model
class DrawsSkipReport:
    """What `draws_on_disk_report` did not turn into a draw document.

    `unreadable` is a fault: torn, undecodable, linked, or a stem outside the ASCII-digit
    alphabet (a non-ASCII digit like `'١'` counts here). `skipped` is a non-canonical spelling of
    an index (`01.yaml`), ignored by design and reported separately from faults. `retired` names
    each document refused for carrying a name #1234 retired (A4), as `<file>: <names>`: never
    read as the old design meant it."""

    unreadable: int = 0
    skipped: int = 0
    retired: list[str] = field(default_factory=list)


def draws_on_disk_report(
    view: Bound, world_id: str | None,
) -> tuple[dict[int, dict[str, Any]], DrawsSkipReport]:
    """Every draw document of world `label` (`worlds/<world-uuid>/judge/`) under the episode root
    `view` reads, keyed by draw index in numeric order, plus what it skipped or refused — the
    episode page's reader. The grading pass never reads a draw back: it routes the documents it just
    produced."""
    report = DrawsSkipReport()
    # Walked no-follow from the episode root: a link at `worlds/`, `worlds/<world-uuid>` or `judge/`
    # lists nothing, so another tree's draws are never read as ours.
    bound = view.under(LAYOUT.family_draws if world_id is None else LAYOUT.world(world_id).draws)
    listed = bound.entries().entries or {}
    out: dict[int, dict[str, Any]] = {}
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
        if not isinstance(doc, dict):
            report.unreadable += 1
        elif names := retired_keys(doc):
            report.retired.append(f"{name}: {', '.join(names)}")
        else:
            out[int(Path(name).stem)] = doc
    return dict(sorted(out.items())), report


def _draw_text(bound: Bound, name: str, kind: str, report: DrawsSkipReport) -> str | None:
    """One listed `<n>.yaml`'s text, or `None` with the reason counted on `report`."""
    stem = Path(name).stem
    # `isdigit()` alone admits superscripts and non-ASCII digits, which `int()` rejects.
    if not (stem.isascii() and stem.isdigit()):
        report.unreadable += 1
        return None
    # Canonical spelling only: `01.yaml` and `1.yaml` would collapse onto one key.
    if stem != str(int(stem)):
        report.skipped += 1
        return None
    # A link, directory or other non-file entry is unreadable, judged without following it;
    # the no-follow read then refuses a hard link and undecodable bytes.
    text = bound.read(name).text if kind == ENTRY_FILE else None
    if text is None:
        report.unreadable += 1
    return text


def draws_on_disk(view: Bound, world_id: str | None) -> dict[int, dict[str, Any]]:
    """`draws_on_disk_report` without the skip report: every readable draw document of world
    `label`, by index."""
    return draws_on_disk_report(view, world_id)[0]


def disposition_entry(finding_id: str, lane: str, reason: str | None = None) -> dict[str, Any]:
    """One ledger entry: the finding's id (`build_finding_row`'s spelling, whether or not a row
    was built), its lane, and the reason where the lane is a refusal."""
    return check_disposition_entry({"finding_id": finding_id, "lane": lane, "reason": reason})


def check_disposition_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Check a ledger entry names its finding and one of the lanes (`route.LEDGER_LANES`);
    `ValueError` otherwise (a writer mistake, or a planted record read back)."""
    if not isinstance(entry.get("finding_id"), str):
        raise ValueError(f"a ledger entry does not name its finding: {entry!r}")
    if entry.get("lane") not in LEDGER_LANES:
        raise ValueError(f"a ledger entry names no lane ({sorted(LEDGER_LANES)}): {entry!r}")
    return entry


__all__ = [
    "DrawnRows", "DrawsSkipReport", "EnqueueReport", "LANE_DEFENDER", "LANE_UNQUEUEABLE",
    "LANE_WORLD", "LEDGER_LANES", "WORLD_LABEL_DOUBTED", "append_rows", "append_rows_report",
    "append_world_rows", "append_world_rows_report", "build_finding_row", "check_disposition_entry", "defender_lane_blocked",
    "disposition_entry", "draws_on_disk", "draws_on_disk_report", "enqueue_report",
]
