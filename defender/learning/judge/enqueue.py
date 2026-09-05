"""The judge's own appender: twelve-key rows into the existing findings queue (#921 M5).

Never `persist.append_findings` — that writer's `_outcome_keyword` gates on the OLD pipeline's
`OUTCOME_ENUM`, which this design's words (`survived`/`caught`/`undecidable`/`discard`/
`corpus-contradiction`) are not all members of. Refuses a row missing `run_id`/`direction`
BEFORE it reaches the shared findings gate (P6: such a row raises a bare `KeyError` inside
`_gate_findings` and stuck-records the WHOLE keyed batch), and refuses `discard`/
`corpus-contradiction` outright — the family record is the artifact for those two (O7).

The refusal is the APPENDER's, for rows handed in from anywhere. The producer below
(`enqueue_report`) asks the same rule one row at a time and DROPS the findings that fail it,
naming them on its report: a model-authored finding with an empty anchor is one unusable
finding, not a reason to discard every other world's good ones.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from defender._io import guarded_mkdir, read_jsonl_rows_report, write_guarded
from defender._yaml import safe_load as _yaml_safe_load
from defender._text import is_content_less
from defender._vocab import normalized_judge_outcome
from defender.learning.core.config import (
    QUEUEABLE_FINDING_TYPES,
    learning_state_root,
    loop_paths,
)
from defender.learning.core.persist import derive_alert_rule_key, queue_lock
from defender.learning.judge._errors import JudgeRefused

#: `discard` and `corpus-contradiction` are members of `JUDGE_OUTCOME_ENUM` and ARE the
#: family's `verdict_word` when they apply — never a defender failure to author from (O7).
_UNQUEUEABLE_VERDICTS = frozenset({"discard", "corpus-contradiction"})


def _queue_paths(queue_dir: Path | None) -> tuple[Path, Path]:
    """The findings queue's file and its append lock — `(pending_file, lock_file)`.

    BOTH NAMES COME FROM THE CHANNEL THAT OWNS THEM. `LoopPaths.findings` is the `QueueChannel`
    the drain and `persist.append_findings` both reach the queue through; spelling
    `"findings.jsonl"` and `".findings.lock"` a third time here is how a rename or a lock-role
    change leaves this appender writing files nothing reads. Only the DIRECTORY is overridable
    — `queue_dir` relocates the channel, it does not rename it.

    Resolved through `config.loop_paths()` rather than the import-frozen `DEFAULT_PATHS` so a
    process pointed at a different learning state root by its environment writes where that
    root says, which is also how a test isolates itself from the real queue. It does NOT fork
    on where `episode_dir` happens to live: a production path that picks a different sink when
    an env var is unset is a pass whose rows can land in a directory no drain reads, with the
    family record's `enqueued_to` as the only trace.
    """
    channel = loop_paths().findings
    if queue_dir is None:
        return channel.file, channel.append_lock
    queue_dir = Path(queue_dir)
    return queue_dir / channel.file.name, queue_dir / channel.append_lock.name


def _validate_row(row: dict[str, Any], *, episode_dir: Path | None = None) -> None:
    """THE rule for what may go on the queue. One function, so the producer below can ask it
    about a single row (and drop that row alone) while the appender still refuses outright for
    a caller handing rows in from anywhere else."""
    where = f"episode {Path(episode_dir).name}: " if episode_dir is not None else ""
    # `finding_id` FIRST, because `_gate_findings` indexes it FIRST — `fid = entry["finding_id"]`
    # opens its per-row loop, before `skips_forward_check` and before the deliberate
    # `entry["run_id"]` probe. A row missing it therefore raises exactly the bare `KeyError` this
    # guard exists to keep off the queue, one line earlier than the two keys that were listed.
    for key in ("finding_id", "run_id", "direction"):
        if key not in row:
            raise JudgeRefused(
                f"{where}a family finding row is missing {key!r} — a row missing it raises a "
                "bare KeyError inside the shared findings gate and stuck-records the whole "
                "keyed batch (P6); refused at the appender instead")
    row_type = row.get("type")
    # `isinstance` FIRST: `QUEUEABLE_FINDING_TYPES` is a `set`, so an UNHASHABLE value here
    # (`bucket: [lead-set]` read back off a draw file) raises `TypeError` out of a function whose
    # whole contract is to answer with this design's refusal — and `enqueue_report`'s
    # drop-and-name arm catches `JudgeRefused` only, so one unusable finding took the whole
    # append down. `_vocab.normalized_disposition` names the same hazard for the disposition
    # vocabulary, and `run._parse_finding` already asks it of the reply's own bucket.
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
        # AT THE APPENDER, which is where this module's docstring has always said the refusal
        # is. Only the producer checked it, so a row handed in from anywhere else — and a
        # producer that stopped checking — put a `discard` row on the shared queue, where
        # `_gate_family` neither skips nor holds it and the subtraction routes it straight to
        # the curator. An episode whose whole point is that it must train nothing then trains
        # something (O7).
        raise JudgeRefused(
            f"{where}a family finding row's judge_outcome={outcome!r} is a word the family "
            "record is the whole artifact for — such an episode is never a defender failure to "
            "author from, so no row of it may reach the queue (O7)")


def append_rows(episode_dir: Path, rows: list[dict[str, Any]], *,
                queue_dir: Path | None = None) -> int:
    """How many of `rows` were appended. See `append_rows_report` for the rest of the answer."""
    return append_rows_report(episode_dir, rows, queue_dir=queue_dir)[0]


def append_rows_report(episode_dir: Path, rows: list[dict[str, Any]], *,
                       queue_dir: Path | None = None) -> tuple[int, int]:
    """Append `rows`, and report `(appended, malformed lines seen on the queue)`.

    ONE write, ONE lock hold (P3) — through `write_guarded(..., mode="append")` so the write
    lint sees the guarded spelling (J7's survivor). The malformed count is taken INSIDE that
    same hold: it is a fact about the queue as this pass found it (F-11's evidence that some
    writer left a row half-written), and read outside the lock a concurrent appender can tear
    the very read that is supposed to measure tearing.

    `episode_dir` names the pass, for the refusal text; the queue itself is a shared sink whose
    location is `queue_dir` or the configured default, never derived from the episode.
    """
    rows = list(rows)
    for row in rows:
        _validate_row(row, episode_dir=episode_dir)
    pending_file, lock_file = _queue_paths(queue_dir)
    if not rows:
        # Nothing to append means no lock to take and no directory to create — a pass that
        # enqueued nothing must not bring a queue into existence. The count is therefore
        # BEST-EFFORT here and the locked read below is not: the hazard the lock answers is
        # another appender tearing OUR read, which an unlocked read is exposed to whether or
        # not we are writing. Taking the lock only to count would create the queue directory
        # this branch exists to avoid creating.
        return 0, read_jsonl_rows_report(pending_file)[1]
    # The TRUST ROOT is the learning state root the queue lives under, not the queue directory
    # itself: `base=path` makes `path.relative_to(base)` yield `.`, so zero components are
    # judged and the alias-refusing guard degenerates into a plain `mkdir(parents=True)`.
    guarded_mkdir(pending_file.parent, base=_queue_trust_root(pending_file))
    text = "".join(json.dumps(row) + "\n" for row in rows)
    with queue_lock(lock_file):
        # F-11: a torn trailing row (no closing newline) already on the queue must not be
        # concatenated onto — that turns both the fragment AND this pass's first row into one
        # unreadable line. A leading newline closes the fragment's own line without touching
        # its bytes; the fragment stays exactly as unreadable as it already was.
        _existing, malformed = read_jsonl_rows_report(pending_file)
        if pending_file.is_file() and pending_file.stat().st_size > 0:
            with pending_file.open("rb") as fh:
                fh.seek(-1, 2)
                if fh.read(1) != b"\n":
                    text = "\n" + text
        write_guarded(pending_file, text, mode="append")
    return len(rows), malformed


def _queue_trust_root(pending_file: Path) -> Path:
    """The tree `guarded_mkdir` is anchored at when it creates the queue's directory.

    The learning state root for the default queue — the host-controlled tree the queue is a
    directory INSIDE, which is exactly what the anchor is for. For a queue the caller named
    somewhere else, its own parent, which is the most that can honestly be claimed about a
    location this module did not choose."""
    state_root = learning_state_root()
    queue_dir = pending_file.parent
    return state_root if state_root in queue_dir.parents else queue_dir.parent


def _episode_alert(episode_dir: Path, worlds: list[str]) -> dict[str, Any]:
    """The alert this episode's worlds investigate, off the first world that carries one.

    THROUGH `render.json_mapping`, which is the one home for this tolerance policy and names
    this very reader as one of its five. The copy that used to live here caught `(OSError,
    ValueError)` and dropped `RecursionError` — the class that docstring says it was centralised
    to stop having to fix five times, and one that is neither in this module's handlers nor in
    `grade_episode`'s conversion set, so a deeply nested `alert.json` took the whole pass down
    as a bare traceback after every draw had already been made."""
    from defender.learning.branch.archive import ALERT_NAME
    from defender.learning.judge.render import json_mapping

    for label in worlds:
        data = json_mapping(episode_dir / "worlds" / label / ALERT_NAME)
        if data is not None:
            return data
    return {}


def _resolving_citations(finding: dict[str, Any]) -> list[str]:
    """A finding's evidence pointers MINUS the ones `_draw_document` recorded as not resolving.

    O1 keeps a finding when at least one pointer resolves inside the graded world's own subtree
    and records the rest; citing all of them anyway handed the curator pointers already known
    not to resolve, with nothing on the row distinguishing them. The unresolved ones stay off
    the row rather than riding under a thirteenth key — the queue's shape is twelve keys the
    shared validator reads — and remain readable in full on the draw document the row's own
    `source_run_dir` names."""
    unresolved = set(finding.get("unresolved_evidence") or [])
    return [p for p in (finding.get("evidence") or []) if p not in unresolved]


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
        # ONLY THE POINTERS THAT RESOLVED. `_draw_document` keeps a finding when at least one
        # of its pointers resolves inside the graded world's own subtree and records the rest
        # on `unresolved_evidence`; copying the whole list into `citations` handed the curator
        # pointers already known not to resolve, with nothing on the row distinguishing them —
        # O1's grounding claim, lost one hop downstream. The unresolved ones stay OFF the row
        # rather than riding under a thirteenth key — the queue's shape is twelve keys the
        # shared validator reads — and they remain readable in full on the draw document the
        # row's own `source_run_dir` names.
        "citations": _resolving_citations(finding),
        "source_run_dir": f"episodes/{episode_name}/worlds/{label}",
    }


def _draws_on_disk(draw_dir: Path) -> dict[int, dict[str, Any]]:
    """Every draw document in `draw_dir`, keyed by draw index, in draw order.

    The fallback for a caller that did not just produce them — a bare re-enqueue over an
    episode's existing draws. Ordered NUMERICALLY: `sorted` on the file stem is lexicographic,
    which puts draw 10 between 1 and 2 the moment an operator asks for ten draws. A caller that
    DID produce them passes them in (`drawn=`) rather than having them read back, which is both
    the cheaper path and the only one that cannot pick up a file this pass did not write."""
    if not draw_dir.is_dir():
        return {}
    out: dict[int, dict[str, Any]] = {}
    for path in draw_dir.glob("*.yaml"):
        # `isascii()` AND `isdigit()`: `str.isdigit()` is true for superscripts and every
        # non-ASCII digit script, and `int()` accepts neither — so `'²'.yaml` in a directory the
        # box can reach passed the filter and raised `ValueError` out of the whole pass. The two
        # tests have to answer the same question about the same string.
        if not (path.stem.isascii() and path.stem.isdigit()):
            continue
        try:
            # `_yaml.safe_load` for the same reason every other parse in this package uses it:
            # a `RecursionError` out of a deeply nested draw file is neither a `ValueError` nor
            # a `YAMLError`, so it escaped this handler and every one above it.
            doc = _yaml_safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if isinstance(doc, dict):
            out[int(path.stem)] = doc
    return dict(sorted(out.items()))


def enqueue(episode_dir: Path, grade: Any, *, queue_dir: Path | None = None,
            drawn: dict[str, dict[int, dict[str, Any]]] | None = None) -> int:
    """How many rows this pass enqueued. See `enqueue_report` for the rest of the answer."""
    return enqueue_report(episode_dir, grade, queue_dir=queue_dir, drawn=drawn).appended


@dataclass(frozen=True)
class EnqueueReport:
    """What one enqueue did: rows appended, findings it could not make a row of, and the
    malformed lines already on the queue when it appended."""

    appended: int = 0
    unqueueable: list[str] = field(default_factory=list)
    queue_malformed_rows: int = 0


def enqueue_report(episode_dir: Path, grade: Any, *, queue_dir: Path | None = None,
                   drawn: dict[str, dict[int, dict[str, Any]]] | None = None) -> EnqueueReport:
    """Every finding of every completed draw of every graded world -> one `FindingRow`.

    `grade` carries the family's `verdict_word` (the word every row's `judge_outcome` takes)
    and the per-world rows that name which worlds are graded. `drawn` is what the pass just
    produced, per world and keyed by draw index; a caller that has it hands it over rather than
    having every file it wrote read and parsed back, and a caller that does not (a bare
    re-enqueue) falls back to the directory. Either way a retried call re-derives the SAME rows
    rather than minting fresh ids (P5's idempotency key is `finding_id` alone).

    A finding that cannot become a valid row is DROPPED AND NAMED, not raised on. The rule it
    is judged by is `_validate_row` itself, asked one row at a time, so there is still exactly
    one definition of what the queue accepts — but the blast radius is that finding rather than
    the episode: a model emitting one finding with an empty anchor used to refuse the whole
    append, discarding every other world's good findings and (because the record is written
    after the enqueue, J11) leaving no `judge.yaml` to say what had been graded at all."""
    episode_dir = Path(episode_dir)
    verdict_word = grade["verdict_word"] if isinstance(grade, dict) else grade.verdict_word
    if verdict_word in _UNQUEUEABLE_VERDICTS:
        return EnqueueReport()
    world_rows = grade["worlds"] if isinstance(grade, dict) else grade.worlds
    graded_labels = [
        (w["world"] if isinstance(w, dict) else w.world)
        for w in world_rows
        if not (w.get("ungradable") if isinstance(w, dict) else getattr(w, "ungradable", False))
    ]
    run_id = episode_dir.name
    alert_rule_key = derive_alert_rule_key(_episode_alert(episode_dir, graded_labels))

    rows: list[dict[str, Any]] = []
    unqueueable: list[str] = []
    for label in graded_labels:
        # "THE CALLER HANDED NOTHING OVER" IS `drawn is None`, and nothing else. `(drawn or
        # {})` folded an EMPTY map — and a map simply missing this label — back onto the disk
        # fallback, which is the one thing `drawn` exists to avoid: a pass that produced no
        # draw for a world would then queue whatever an earlier, wider attempt left in that
        # world's draw directory as its own findings (P4: a retry clobbers, it cleans nothing
        # up), under THIS pass's `verdict_word`.
        if drawn is not None:
            documents = drawn.get(label) or {}
        else:
            documents = _draws_on_disk(episode_dir / "worlds" / label / "judge")
        for draw, draw_doc in documents.items():
            findings = draw_doc.get("findings") or []
            for index, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    # NAMED, like every other drop in this loop. `_draws_on_disk` parses
                    # model-authored draw YAML off a tree a box can reach, where `findings:` can
                    # legitimately be a list of scalars — dropped in silence those vanished with
                    # no line on `unqueueable_findings`, whose whole job is that a drop is said
                    # out loud instead of read later as a finding the model never emitted.
                    unqueueable.append(
                        f"{run_id}/{label}/{draw}/{index}: the draw's finding[{index}] is "
                        f"{type(finding).__name__}, not a mapping")
                    continue
                row = _build_row(
                    run_id=run_id, label=label, draw=str(draw), index=index,
                    finding=finding, alert_rule_key=alert_rule_key,
                    judge_outcome=verdict_word, episode_name=episode_dir.name)
                try:
                    _validate_row(row, episode_dir=episode_dir)
                except JudgeRefused as refused:
                    unqueueable.append(f"{row['finding_id']}: {refused}")
                    continue
                rows.append(row)
    appended, malformed = append_rows_report(episode_dir, rows, queue_dir=queue_dir)
    return EnqueueReport(appended=appended, unqueueable=unqueueable,
                         queue_malformed_rows=malformed)


__all__ = ["EnqueueReport", "append_rows", "append_rows_report", "enqueue", "enqueue_report"]
