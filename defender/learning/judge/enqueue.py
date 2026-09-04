"""The judge's own appender: twelve-key rows into the existing findings queue (#921 M5).

Never `persist.append_findings` — that writer's `_outcome_keyword` gates on the OLD pipeline's
`OUTCOME_ENUM`, which this design's words (`survived`/`caught`/`undecidable`/`discard`/
`corpus-contradiction`) are not all members of. Refuses a row missing `run_id`/`direction`
BEFORE it reaches the shared findings gate (P6: such a row raises a bare `KeyError` inside
`_gate_findings` and stuck-records the WHOLE keyed batch), and refuses `discard`/
`corpus-contradiction` outright — the family record is the artifact for those two (O7).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from defender._io import guarded_mkdir, write_guarded
from defender._text import is_content_less
from defender._vocab import normalized_judge_outcome
from defender.learning.core.config import DEFAULT_PATHS, QUEUEABLE_FINDING_TYPES
from defender.learning.core.persist import derive_alert_rule_key, queue_lock
from defender.learning.judge._errors import JudgeRefused

#: `discard` and `corpus-contradiction` are members of `JUDGE_OUTCOME_ENUM` and ARE the
#: family's `verdict_word` when they apply — never a defender failure to author from (O7).
_UNQUEUEABLE_VERDICTS = frozenset({"discard", "corpus-contradiction"})


def _default_queue_dir(episode_dir: Path) -> Path:
    """Where the findings queue lives when the caller names no `queue_dir`.

    The REAL shared production queue (`DEFAULT_PATHS.pending_dir`, `learning/_pending/` — the
    EXISTING findings channel O6 names) when `episode_dir` actually lives directly under the
    CONFIGURED episodes root (`DEFENDER_EPISODES_BASE`) — the one real launcher path
    (`cli.episode_dir_for`) ever produces, so a real family judge pass drains through the same
    queue every other direction does.

    Derived from `episode_dir`'s own ancestry otherwise: an episode built at an ad-hoc root
    (every hand-built fixture in this suite) is NOT a fact about the configured deployment, and
    sharing the one real queue across every such fixture is what produced 139 rows for an
    assertion of 8 — two unrelated episodes' finding ids collide by construction (both name
    the same fixed `EPISODE_ID`), and no test in this suite ever names a `queue_dir` to avoid
    it.
    """
    import os

    episode_dir = Path(episode_dir).resolve()
    episodes_base = os.environ.get("DEFENDER_EPISODES_BASE")
    if episodes_base and episode_dir.parent == Path(episodes_base).resolve():
        return DEFAULT_PATHS.pending_dir
    return episode_dir.parent.parent / "_pending"


def _queue_paths(queue_dir: Path | None, episode_dir: Path) -> tuple[Path, Path]:
    queue_dir = Path(queue_dir) if queue_dir is not None else _default_queue_dir(episode_dir)
    return queue_dir / "findings.jsonl", queue_dir / ".findings.lock"


def _validate_row(row: dict[str, Any]) -> None:
    for key in ("run_id", "direction"):
        if key not in row:
            raise JudgeRefused(
                f"a family finding row is missing {key!r} — a row missing it raises a bare "
                "KeyError inside the shared findings gate and stuck-records the whole keyed "
                "batch (P6); refused at the appender instead")
    row_type = row.get("type")
    if row_type not in QUEUEABLE_FINDING_TYPES:
        raise JudgeRefused(
            f"a family finding row's type={row_type!r} is not one of the queueable finding "
            f"types {sorted(QUEUEABLE_FINDING_TYPES)}")
    for key in ("subject_anchor", "subject_topic"):
        value = row.get(key)
        if not isinstance(value, str) or is_content_less(value):
            raise JudgeRefused(f"a family finding row's {key} must be a non-empty string")
    if normalized_judge_outcome(row.get("judge_outcome")) is None:
        raise JudgeRefused(
            f"a family finding row's judge_outcome={row.get('judge_outcome')!r} is not a "
            "member of the judge outcome vocabulary")


def append_rows(episode_dir: Path, rows: list[dict[str, Any]], *,
                queue_dir: Path | None = None) -> int:
    """Append `rows` under the queue's append lock, ONE write, ONE lock hold (P3) — through
    `write_guarded(..., mode="append")` so the write lint sees the guarded spelling (J7's
    survivor)."""
    rows = list(rows)
    for row in rows:
        _validate_row(row)
    if not rows:
        return 0
    pending_file, lock_file = _queue_paths(queue_dir, episode_dir)
    guarded_mkdir(pending_file.parent, base=pending_file.parent)
    text = "".join(json.dumps(row) + "\n" for row in rows)
    with queue_lock(lock_file):
        # F-11: a torn trailing row (no closing newline) already on the queue must not be
        # concatenated onto — that turns both the fragment AND this pass's first row into one
        # unreadable line. A leading newline closes the fragment's own line without touching
        # its bytes; the fragment stays exactly as unreadable as it already was.
        if pending_file.is_file() and pending_file.stat().st_size > 0:
            with pending_file.open("rb") as fh:
                fh.seek(-1, 2)
                if fh.read(1) != b"\n":
                    text = "\n" + text
        write_guarded(pending_file, text, mode="append")
    return len(rows)


def _episode_alert(episode_dir: Path, worlds: list[str]) -> dict[str, Any]:
    for label in worlds:
        path = episode_dir / "worlds" / label / "alert.json"
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                return data
    return {}


def _build_row(
    *, run_id: str, label: str, draw: str, index: int, finding: dict[str, Any],
    alert_rule_key: str, judge_outcome: str, episode_name: str,
) -> dict[str, Any]:
    """The twelve-key `FindingRow` for one finding of one draw of one world.

    @owns finding_id
    @owns source_run_dir

    `finding_id` is `f"{run_id}/{label}/{draw}/{index}"` — deterministic across a retried
    `enqueue()` call over the SAME on-disk draw files (P5's idempotency guard keys on this
    value alone, so a fresh id per retry would defeat it, and a reused id across two distinct
    findings would suppress a real one), and it is the ONLY place in this module that mints
    one — `enqueue()`'s own loop calls this rather than interpolating the f-string itself.

    `source_run_dir` is `f"episodes/{episode_name}/worlds/{label}"` — the archived world dir a
    row's evidence is scoped to (F-3: a value the last-segment `resolve_run_bundle` resolver
    can honour, never a value shaped like a run id it could collide with)."""
    return {
        "schema_version": 1,
        "finding_id": f"{run_id}/{label}/{draw}/{index}",
        "run_id": run_id,
        "alert_rule_key": alert_rule_key,
        "direction": "family",
        "type": finding.get("bucket"),
        "subject_anchor": finding.get("anchor"),
        "subject_topic": finding.get("topic"),
        "finding": f"{finding.get('claim', '')} — {finding.get('root_cause', '')}",
        "judge_outcome": judge_outcome,
        "citations": finding.get("evidence") or [],
        "source_run_dir": f"episodes/{episode_name}/worlds/{label}",
    }


def enqueue(episode_dir: Path, grade: Any, *, queue_dir: Path | None = None) -> int:
    """Every finding of every completed draw of every graded world -> one `FindingRow`.

    `grade` carries the family's `verdict_word` (the word every row's `judge_outcome` takes)
    and the per-world rows that name which worlds are graded; the findings themselves are read
    back off `worlds/<X>/judge/<n>.yaml`, so a retried call re-derives the SAME rows rather
    than minting fresh ids (P5's idempotency key is `finding_id` alone)."""
    episode_dir = Path(episode_dir)
    verdict_word = grade["verdict_word"] if isinstance(grade, dict) else grade.verdict_word
    if verdict_word in _UNQUEUEABLE_VERDICTS:
        return 0
    world_rows = grade["worlds"] if isinstance(grade, dict) else grade.worlds
    graded_labels = [
        (w["world"] if isinstance(w, dict) else w.world)
        for w in world_rows
        if not (w.get("ungradable") if isinstance(w, dict) else getattr(w, "ungradable", False))
    ]
    run_id = episode_dir.name
    alert_rule_key = derive_alert_rule_key(_episode_alert(episode_dir, graded_labels))

    rows: list[dict[str, Any]] = []
    for label in graded_labels:
        draw_dir = episode_dir / "worlds" / label / "judge"
        if not draw_dir.is_dir():
            continue
        for draw_path in sorted(draw_dir.glob("*.yaml"), key=lambda p: p.stem):
            try:
                draw_doc = yaml.safe_load(draw_path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                continue
            findings = draw_doc.get("findings") or []
            for index, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    continue
                rows.append(_build_row(
                    run_id=run_id, label=label, draw=draw_path.stem, index=index,
                    finding=finding, alert_rule_key=alert_rule_key,
                    judge_outcome=verdict_word, episode_name=episode_dir.name))
    return append_rows(episode_dir, rows, queue_dir=queue_dir)


__all__ = ["append_rows", "enqueue"]
