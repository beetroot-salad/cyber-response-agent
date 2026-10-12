"""The judge's appenders: finding rows onto the defender and questioner queues, and the one
builder of those rows.

A defender row is an investigator finding of a measured, unanimous, non-`none` world (A7,
A13); a questioner row is a design world finding (A1: not gap-only, with a resolving plan
pointer). Which finding goes where is `route.fate`'s decision; this module builds the row,
screens it one last time against its channel's rule, and appends through the pass's `state=`
handle — never a queue path of its own.

Each appender refuses a row of the wrong shape outright (a row missing `finding_id`/`run_id`/
`direction` would raise a bare `KeyError` inside the shared findings gate and stuck-record the
whole keyed batch; a row carrying a retired name is refused by that name, A4). Nothing here is
deduplicated: a world's rows are appended exactly once, by its `queueing` -> `queued` commit
(A6), so an id already on a queue never silently suppresses a new finding (A25).
"""

from __future__ import annotations

from collections.abc import Sequence
from defender._model import model
from pathlib import Path
from typing import Any

import yaml

from defender._io import ENTRY_FILE, Bound
from defender._yaml import safe_load as _yaml_safe_load
from defender._text import is_content_less
from defender._episode_paths import LAYOUT
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
    if row.get("subject") != SUBJECT_DEFENDER or row.get("direction") == SUBJECT_WORLD:
        raise JudgeRefused(
            f"{where}a row bound for the defender findings channel must carry "
            f"subject={SUBJECT_DEFENDER!r} and a direction other than {SUBJECT_WORLD!r}, not "
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
    """Append `rows` to the defender findings channel through `state`; how many were appended.
    Every row is screened first, so one bad row refuses the whole append before any write.
    `episode_dir` is only for refusal text; the queue is never derived from it."""
    rows = list(rows)
    for row in rows:
        _validate_row(row, episode_dir=episode_dir)
    return state.append(FINDINGS, rows)[0]


def append_world_rows(episode_dir: Path, rows: list[dict[str, Any]], *,
                      state: LearningState) -> int:
    """Append `rows` to the questioner findings channel through `state`; how many were
    appended."""
    rows = list(rows)
    for row in rows:
        _validate_world_row(row, episode_dir=episode_dir)
    return state.append(QUESTIONER_FINDINGS, rows)[0]


def build_finding_row(  # noqa: PLR0913 — the FindingRow's own inputs, one keyword each
    *, run_id: str, label: str, draw: str, index: int, subject: str, finding: dict[str, Any],
    alert_rule_key: str | None, citations: Sequence[str] = (), contrast: Sequence[str] = (),
    world_label_doubted: bool = False, provenance: str = "model",
) -> dict[str, Any]:
    """The `FindingRow` for one finding of one draw of one world (`label="family"`: the family
    call's).

    @owns finding_id
    @owns source_run_dir
    @owns direction
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
        "citations": list(citations),
        "source_run_dir": (
            f"episodes/{run_id}" if label == "family" else f"episodes/{run_id}/worlds/{label}"),
    }
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
    an index (`01.yaml`), ignored by design and reported separately from faults."""

    unreadable: int = 0
    skipped: int = 0


def draws_on_disk_report(
    view: Bound, label: str,
) -> tuple[dict[int, dict[str, Any]], DrawsSkipReport]:
    """Every draw document of world `label` (`worlds/<label>/judge/`) under the episode root
    `view` reads, keyed by draw index in numeric order, plus what it skipped — the episode
    page's reader. The grading pass never reads a draw back: it routes the documents it just
    produced."""
    report = DrawsSkipReport()
    # Walked no-follow from the episode root: a link at `worlds/`, `worlds/<label>` or `judge/`
    # lists nothing, so another tree's draws are never read as ours.
    bound = view.under(LAYOUT.world(label).draws)
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


def draws_on_disk(view: Bound, label: str) -> dict[int, dict[str, Any]]:
    """`draws_on_disk_report` without the skip report: every readable draw document of world
    `label`, by index."""
    return draws_on_disk_report(view, label)[0]


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
    "DrawsSkipReport", "LANE_DEFENDER", "LANE_UNQUEUEABLE", "LANE_WORLD", "LEDGER_LANES",
    "WORLD_LABEL_DOUBTED", "append_rows", "append_world_rows", "build_finding_row",
    "check_disposition_entry", "defender_lane_blocked", "disposition_entry",
    "draws_on_disk", "draws_on_disk_report",
]
