"""The judge's own appender: thirteen-key rows into the existing findings queue (#921 M5).

Its own, and not the shared appender the old pipeline used: that writer gated the outcome word
against the pipeline's own enum, which this design's words (`survived`/`caught`/`undecidable`/
`discard`/`corpus-contradiction`) are not all members of. #922 deleted it; this is what is left. Refuses a row missing `run_id`/`direction`
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
from defender._run_paths import artifact_dir, artifact_file
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
from defender.learning.judge.family import is_gradable_row
from defender.learning.judge.render import episode_alert
#: The two `subject` literals (#1007 O1/M6) — re-exported here rather than a second literal
#: pair, so the appender's own guard and `run.py`'s selector cannot drift apart.
from defender.learning.judge.run import SUBJECT_DEFENDER, SUBJECT_WORLD

#: `discard` and `corpus-contradiction` are members of `JUDGE_OUTCOME_ENUM` and ARE the
#: family's `verdict_word` when they apply — never a defender failure to author from (O7).
_UNQUEUEABLE_VERDICTS = frozenset({"discard", "corpus-contradiction"})


def _queue_paths_for(channel: Any, queue_dir: Path | None) -> tuple[Path, Path]:
    """One channel's `(file, append_lock)`, relocated under `queue_dir` when given.

    BOTH NAMES COME FROM THE CHANNEL THAT OWNS THEM — `LoopPaths.findings` /
    `.questioner_findings` are the `QueueChannel`s the drain reaches each queue through, so
    spelling a filename a third time here is how a rename or a lock-role change leaves an
    appender writing files nothing reads. Only the DIRECTORY is overridable — `queue_dir`
    relocates the channel, it does not rename it."""
    if queue_dir is None:
        return channel.file, channel.append_lock
    queue_dir = Path(queue_dir)
    return queue_dir / channel.file.name, queue_dir / channel.append_lock.name


def _queue_paths(queue_dir: Path | None) -> tuple[Path, Path]:
    """The DEFENDER findings queue's file and its append lock.

    Resolved through `config.loop_paths()` rather than the import-frozen `DEFAULT_PATHS` so a
    process pointed at a different learning state root by its environment writes where that
    root says, which is also how a test isolates itself from the real queue. It does NOT fork
    on where `episode_dir` happens to live: a production path that picks a different sink when
    an env var is unset is a pass whose rows can land in a directory no drain reads, with the
    family record's `enqueued_to` as the only trace.
    """
    return _queue_paths_for(loop_paths().findings, queue_dir)


def _questioner_queue_paths(queue_dir: Path | None) -> tuple[Path, Path]:
    """The QUESTIONER channel's file and its OWN append lock (#1007 M6) — see `_queue_paths`'s
    docstring; the two channels share every reasoning point above except which channel."""
    return _queue_paths_for(loop_paths().questioner_findings, queue_dir)


def _validate_row(row: dict[str, Any], *, episode_dir: Path | None = None) -> None:
    """THE rule for what may go on the DEFENDER queue. One function, so the producer below can
    ask it about a single row (and drop that row alone) while the appender still refuses
    outright for a caller handing rows in from anywhere else."""
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
    # `subject` (#1007 O1/M6), NO CASE-FOLD AND NO TRIM — a row bound for the DEFENDER channel
    # must carry EXACTLY `subject: defender`; a `subject: world` row (or a near-miss, or an
    # absent one) is refused here, at the last screen before the shared findings gate and the
    # defender curator.
    subject = row.get("subject")
    if subject != SUBJECT_DEFENDER:
        raise JudgeRefused(
            f"{where}a row bound for the defender findings channel must carry "
            f"subject={SUBJECT_DEFENDER!r}, not {subject!r}")
    # SYMMETRIC WITH `_validate_world_row`'s own `direction` screen (#1007, claims-adversary
    # finding): `build_finding_row` derives `direction` from `subject` so the two can never
    # disagree from the pass's own producer, but this appender also takes rows handed in from
    # anywhere (its own docstring above) — a hand-fed row whose two fields DO disagree must be
    # refused here too, not just on the questioner lane, or a `subject: defender` row carrying
    # `direction: world` would still land on this channel unnoticed.
    if row.get("direction") == SUBJECT_WORLD:
        raise JudgeRefused(
            f"{where}a row bound for the defender findings channel must carry "
            f"direction={SUBJECT_WORLD!r} nowhere near subject={SUBJECT_DEFENDER!r} — the two "
            "fields disagree")
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


def _validate_world_row(row: dict[str, Any], *, episode_dir: Path | None = None) -> None:
    """THE rule for what may go on the QUESTIONER channel (#1007 M6). The bucket (`type`) is
    NEVER gated against `QUEUEABLE_FINDING_TYPES` — R2's open vocabulary — but `pattern`,
    `holding_system` and `subject` are required here because this appender is the LAST screen:
    the questioner curator's own gate is idempotency-only (M7)."""
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


def _append_validated_rows(
    rows: list[dict[str, Any]], *, pending_file: Path, lock_file: Path,
    dedup_key: str | None = None,
) -> tuple[int, int]:
    """The one write, one lock hold every channel appender shares (P3) — through
    `write_guarded(..., mode="append")` so the write lint sees the guarded spelling (J7's
    survivor). The malformed count is taken INSIDE that same hold: it is a fact about the queue
    as this pass found it (F-11's evidence that some writer left a row half-written), and read
    outside the lock a concurrent appender can tear the very read that is supposed to measure
    tearing. Rows are assumed ALREADY VALIDATED — each channel's own rule runs before this.

    `dedup_key`, when given, makes the append IDEMPOTENT on that field: a row whose value is
    already present on THIS channel's own file is dropped rather than written a second time.
    Read under the SAME lock hold as the write, off THIS channel alone — never another
    channel's file or its `consumed` sidecar, so a finding id already consumed on the defender
    channel does not suppress a world row sharing that id
    (`test_a_world_row_reusing_a_consumed_defender_finding_id_still_reaches_its_own_curator`)."""
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
    with queue_lock(lock_file):
        # F-11: a torn trailing row (no closing newline) already on the queue must not be
        # concatenated onto — that turns both the fragment AND this pass's first row into one
        # unreadable line. A leading newline closes the fragment's own line without touching
        # its bytes; the fragment stays exactly as unreadable as it already was.
        existing, malformed = read_jsonl_rows_report(pending_file)
        to_write = rows
        if dedup_key is not None:
            seen = {r.get(dedup_key) for r in existing if isinstance(r, dict)}
            to_write = [r for r in rows if r.get(dedup_key) not in seen]
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
    """Append `rows` to the DEFENDER findings channel, and report `(appended, malformed lines
    seen on the queue)`. `episode_dir` names the pass, for the refusal text; the queue itself is
    a shared sink whose location is `queue_dir` or the configured default, never derived from
    the episode."""
    rows = list(rows)
    for row in rows:
        _validate_row(row, episode_dir=episode_dir)
    pending_file, lock_file = _queue_paths(queue_dir)
    return _append_validated_rows(rows, pending_file=pending_file, lock_file=lock_file)


def append_world_rows(episode_dir: Path, rows: list[dict[str, Any]], *,
                      queue_dir: Path | None = None) -> int:
    """How many of `rows` were appended to the QUESTIONER channel. See
    `append_world_rows_report` for the rest of the answer."""
    return append_world_rows_report(episode_dir, rows, queue_dir=queue_dir)[0]


def append_world_rows_report(episode_dir: Path, rows: list[dict[str, Any]], *,
                             queue_dir: Path | None = None) -> tuple[int, int]:
    """Append `rows` to the QUESTIONER findings channel (#1007 M6), and report `(appended,
    malformed lines seen on the queue)`.

    `judge_outcome` is FORCED to `None` on every row this writes, whatever the caller handed
    in: a world row is about the world, and a defender verdict word on it (`caught`/`survived`/
    `undecidable`) is the category error O1 exists to prevent — it would invite the questioner
    curator to author a lesson about the DEFENDER into the corpus the questioner reads back."""
    validated = list(rows)
    for row in validated:
        _validate_world_row(row, episode_dir=episode_dir)
    pending_file, lock_file = _questioner_queue_paths(queue_dir)
    sanitized = [{**row, "judge_outcome": None} for row in validated]
    return _append_validated_rows(sanitized, pending_file=pending_file, lock_file=lock_file,
                                  dedup_key="finding_id")


def _queue_trust_root(pending_file: Path) -> Path:
    """The tree `guarded_mkdir` is anchored at when it creates the queue's directory.

    The learning state root for the default queue — the host-controlled tree the queue is a
    directory INSIDE, which is exactly what the anchor is for. For a queue the caller named
    somewhere else, its own parent, which is the most that can honestly be claimed about a
    location this module did not choose."""
    state_root = learning_state_root()
    queue_dir = pending_file.parent
    return state_root if state_root in queue_dir.parents else queue_dir.parent


def _resolving_citations(finding: dict[str, Any]) -> list[str]:
    """A finding's evidence pointers MINUS the ones `_draw_document` recorded as not resolving.

    O1 keeps a finding when at least one pointer resolves inside the graded world's own subtree
    and records the rest; citing all of them anyway handed the curator pointers already known
    not to resolve, with nothing on the row distinguishing them. The unresolved ones stay off
    the row rather than riding under a fourteenth key — the queue's shape is thirteen keys the
    shared validator reads — and remain readable in full on the draw document the row's own
    `source_run_dir` names."""
    # EVERY VALUE HERE IS MODEL-AUTHORED YAML off a tree a box can reach (`_draws_on_disk`), so
    # neither key is a list until this frame has looked. `set(3)` raises `TypeError`, `set([[a]])`
    # raises `TypeError: unhashable`, and a bare string `evidence` iterates into one-character
    # citations — none of which `enqueue_report`'s per-row drop arm (which catches `JudgeRefused`
    # alone) or `grade_episode`'s conversion set names, so the whole append died as a bare
    # traceback with zero rows written. `str()` for the same reason `run._draw_document` coerces:
    # a YAML-native scalar (`evidence: [2026-01-01]` -> `datetime.date`) is not JSON-serialisable,
    # and `json.dumps` raises inside the queue's own lock hold.
    raw = finding.get("evidence")
    evidence = [str(p) for p in raw] if isinstance(raw, list) else []
    raw_unresolved = finding.get("unresolved_evidence")
    unresolved = (
        {str(p) for p in raw_unresolved} if isinstance(raw_unresolved, list) else set())
    return [p for p in evidence if p not in unresolved]


def build_finding_row(  # noqa: PLR0913 — the FindingRow's own inputs, one keyword each
    *, run_id: str, label: str, draw: str, index: int, subject: str, finding: dict[str, Any],
    alert_rule_key: str, judge_outcome: str, provenance: str = "model",
) -> dict[str, Any]:
    """The thirteen-key `FindingRow` for one finding of one draw of one world — PLUS, for
    `subject: world` (#1007 M6), `world`/`pattern`/`holding_system`/`provenance`.

    @owns finding_id
    @owns source_run_dir
    @owns direction

    `finding_id` is `f"{run_id}/{label}/{draw}/{index}"` — deterministic across a retried
    `enqueue()` call over the SAME on-disk draw files (P5's idempotency guard keys on this
    value alone, so a fresh id per retry would defeat it, and a reused id across two distinct
    findings would suppress a real one), and it is the ONLY place in this module that mints
    one — `enqueue()`'s own loop calls this rather than interpolating the f-string itself.
    `label="family"` (M5, `family` a reserved world label) keys a family-level finding as
    `<run_id>/family/<draw>/<index>` — a coordinate that collides with a per-world one only if
    a graded world is itself labeled `"family"`, which `family._check_world_labels` refuses
    before `grade_episode` builds any row (mirroring the launcher's own `RESERVED_WORLD_LABELS`
    check, independently, since `grade_episode` is directly callable without the launcher).

    `direction` is DERIVED FROM `subject`, never taken as a separate argument (#1007
    `test_direction_is_derived_from_subject_so_disagreement_is_unrepresentable`): a row whose
    two fields could disagree is a row the defender curator's gate and the appender's own guard
    could each read differently. `world` is likewise the PASS's own stamp — `None` for a
    family-level finding (`label == "family"`), the draw's own world label otherwise — never
    the model's own `finding["world"]` claim (A3: identity belongs to the pass).

    `source_run_dir` is `f"episodes/{run_id}/worlds/{label}"` for a per-world finding, or
    `f"episodes/{run_id}"` for a family-level one (there is no `worlds/family/` archive). ONE
    parameter carries the episode's name for both keys: as two (`run_id=` and `episode_name=`,
    which the single call site filled from one value), nothing held them in agreement, and a
    caller taking one from a manifest field and the other from the directory would mint rows
    whose `finding_id` and `source_run_dir` name different episodes — which P5's idempotency
    guard, keyed on `finding_id` alone, cannot notice (F-3: a value the last-segment
    `resolve_run_bundle` resolver can honour, never a value shaped like a run id it could
    collide with)."""
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
        # ONLY THE POINTERS THAT RESOLVED. `_draw_document` keeps a finding when at least one
        # of its pointers resolves inside the graded world's own subtree and records the rest
        # on `unresolved_evidence`; copying the whole list into `citations` handed the curator
        # pointers already known not to resolve, with nothing on the row distinguishing them —
        # O1's grounding claim, lost one hop downstream. The unresolved ones stay OFF the row
        # rather than riding under a fourteenth key — the queue's shape is thirteen keys the
        # shared validator reads — and they remain readable in full on the draw document the
        # row's own `source_run_dir` names.
        "citations": _resolving_citations(finding),
        "source_run_dir": (
            f"episodes/{run_id}" if label == "family" else f"episodes/{run_id}/worlds/{label}"),
    }
    if subject == SUBJECT_WORLD:
        row["world"] = None if label == "family" else label
        row["pattern"] = finding.get("pattern")
        row["holding_system"] = finding.get("holding_system")
        row["provenance"] = provenance
    return row


def _draws_on_disk(draw_dir: Path) -> dict[int, dict[str, Any]]:
    """Every draw document in `draw_dir`, keyed by draw index, in draw order.

    The fallback for a caller that did not just produce them — a bare re-enqueue over an
    episode's existing draws. Ordered NUMERICALLY: `sorted` on the file stem is lexicographic,
    which puts draw 10 between 1 and 2 the moment an operator asks for ten draws. A caller that
    DID produce them passes them in (`drawn=`) rather than having them read back, which is both
    the cheaper path and the only one that cannot pick up a file this pass did not write."""
    # `artifact_dir`, not `is_dir()`: the draw directory lives under the episode dir, and a
    # link planted at its name would have the TARGET's `<n>.yaml` files read back as this
    # episode's own draws and queued as its findings.
    if not artifact_dir(draw_dir):
        return {}
    out: dict[int, dict[str, Any]] = {}
    for path in draw_dir.glob("*.yaml"):
        # `isascii()` AND `isdigit()`: `str.isdigit()` is true for superscripts and every
        # non-ASCII digit script, and `int()` accepts neither — so `'²'.yaml` in a directory the
        # box can reach passed the filter and raised `ValueError` out of the whole pass. The two
        # tests have to answer the same question about the same string.
        if not (path.stem.isascii() and path.stem.isdigit()):
            continue
        # AND THE STEM MUST BE THE INT'S OWN SPELLING. `int("01") == int("1")`, so `01.yaml` and
        # `1.yaml` — this design writes only the second, but P4 says a retry clobbers and cleans
        # nothing up, and the directory is a tree a box can write — collapse onto one key over an
        # UNORDERED `glob`, so which document becomes `<run>/<label>/1/<index>` differs between
        # runs. `finding_id` is P5's sole idempotency key, so that either suppresses a real
        # finding or gives two different ones the same id.
        if path.stem != str(int(path.stem)):
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
            drawn: dict[str, dict[int, dict[str, Any]]] | None = None,
            family_drawn: dict[int, dict[str, Any]] | None = None) -> int:
    """How many DEFENDER rows this pass enqueued. See `enqueue_report` for the rest of the
    answer, including the questioner channel's own count."""
    return enqueue_report(episode_dir, grade, queue_dir=queue_dir, drawn=drawn,
                          family_drawn=family_drawn).appended


@dataclass(frozen=True)
class EnqueueReport:
    """What one enqueue did, on BOTH channels (#1007 M6): rows appended, findings it could not
    make a row of, and the malformed lines already on each queue when it appended."""

    appended: int = 0
    unqueueable: list[str] = field(default_factory=list)
    queue_malformed_rows: int = 0
    world_appended: int = 0
    world_queue_malformed_rows: int = 0
    #: The world rows this pass actually appended — handed on so an in-process caller
    #: (`EpisodeGrade.world_findings`) can see them without re-reading the queue file.
    world_rows: list[dict[str, Any]] = field(default_factory=list)
    #: O4/F7: `{finding, world, reason}` for every defender finding this pass withheld rather
    #: than enqueued — the whole finding, the ONLY surviving record of one that never became a
    #: queue row. Distinct from `unqueueable` (could not be made a valid row at all).
    withheld_findings: list[dict[str, Any]] = field(default_factory=list)


def _add_row(  # noqa: PLR0913 — the sink dispatch's own inputs
    row: dict[str, Any], *, validator: Any, sink: list[dict[str, Any]],
    unqueueable: list[str], episode_dir: Path,
) -> None:
    """Validate one row against its OWN channel's rule and file it — or name the drop. ONE
    dispatcher for both channels, so a finding that cannot become a valid row costs only that
    finding (never the episode): the blast radius `_validate_row`'s docstring has always
    promised, now shared by the world lane too."""
    try:
        validator(row, episode_dir=episode_dir)
    except JudgeRefused as refused:
        unqueueable.append(f"{row['finding_id']}: {refused}")
        return
    sink.append(row)


def enqueue_report(  # noqa: C901, PLR0912, PLR0915 — the two-channel partition (M6) and the mechanical/family draws (M3/M5) are one pass over one set of findings; splitting it would re-derive `graded_labels`/`alert_rule_key` per lane
    episode_dir: Path, grade: Any, *, queue_dir: Path | None = None,
    drawn: dict[str, dict[int, dict[str, Any]]] | None = None,
    family_drawn: dict[int, dict[str, Any]] | None = None,
) -> EnqueueReport:
    """Every finding of every completed draw -> one `FindingRow`, partitioned by `subject`
    (#1007 O1/M6) onto the defender channel or the questioner channel.

    `grade` carries the family's `verdict_word` (the word every DEFENDER row's `judge_outcome`
    takes; a world row's is always blanked at the questioner appender) and the per-world rows
    that name which worlds are graded, their `withheld_reason` (O4) and their own mechanical
    `world_findings` (M3). `drawn` is what the pass just produced, per world and keyed by draw
    index; `family_drawn` is likewise the family-level call's own draws (M5). A caller that has
    them hands them over rather than having every file it wrote read back, and one that does
    not (a bare re-enqueue) falls back to the world draw directories on disk — the family call
    has no such directory and is `family_drawn=None` on that path (nothing to re-derive).

    THE TWO LANES DO NOT SHARE ONE EARLY RETURN. A `discard`/`corpus-contradiction`
    `verdict_word` (O7) means no DEFENDER row may reach the queue — that episode's whole
    artifact is the family record — but it says nothing about the WORLD lane, whose findings
    are about the instrument, not the defender's conduct (`test_an_unqueueable_defender_finding_
    does_not_suppress_the_world_findings`)."""
    episode_dir = Path(episode_dir)
    verdict_word = grade["verdict_word"] if isinstance(grade, dict) else grade.verdict_word
    world_rows = grade["worlds"] if isinstance(grade, dict) else grade.worlds
    # `family.is_gradable_row`, the ONE predicate — see its docstring: this site and
    # `grade_family`'s own answered the same question two ways.
    graded_labels = [w["world"] for w in world_rows if is_gradable_row(w)]
    # `str`-keyed, not a set: O4's own reason (one of the four `WITHHELD_*` values on the row)
    # is what F7's resolution asks `withheld_findings` to carry alongside each dropped finding
    # — a bare membership set can say a world was withheld but not why.
    withheld_reasons = {
        w["world"]: w["withheld_reason"] for w in world_rows if w.get("withheld_reason")}
    withheld_labels = set(withheld_reasons)
    run_id = episode_dir.name
    # `render.episode_alert`, the ONE rule for which world's `alert.json` this episode's alert
    # comes off. A local copy taking the first world whose file merely PARSED disagreed with
    # `__init__._pass_alert_id`, which takes the first that carries an `alert_id`: the sibling
    # union was then keyed on one world's alert while every row landed under a rule key derived
    # from another's document.
    alert_rule_key = derive_alert_rule_key(episode_alert(episode_dir, graded_labels))
    # THROUGH THE OWNER'S NORMALIZER, not a bare `in` — the same rule `_validate_row` states.
    # `grade` may be built from `judge.yaml` off a tree a box can reach (`_grade_from_document`),
    # so `verdict_word: [discard]` raises `TypeError: unhashable type` out of a function whose
    # contract is this design's refusal, and `verdict_word: Discard` misses the O7 gate entirely.
    defender_blocked = normalized_judge_outcome(verdict_word) in _UNQUEUEABLE_VERDICTS

    defender_rows: list[dict[str, Any]] = []
    world_rows_out: list[dict[str, Any]] = []
    unqueueable: list[str] = []
    #: O4/F7: the whole finding, since this row is the ONLY surviving record of a defender
    #: finding that never became a queue row — the draw document it came off is not part of
    #: this design's write set and a later re-grade may not reproduce the same model draw.
    withheld_findings: list[dict[str, Any]] = []

    # M5's family-level draws FIRST — always `subject: world`, `world: None`, keyed under the
    # reserved `family` label so the coordinate can never collide with a per-world one. Ordered
    # ahead of the per-world walk so a family-level finding is never shadowed, on the channel's
    # own written order, by a per-world finding that happens to share its bucket string (the
    # vocabulary is open — R2 — so nothing else distinguishes them positionally).
    for draw, draw_doc in (family_drawn or {}).items():
        findings = draw_doc.get("findings") or []
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                unqueueable.append(
                    f"{run_id}/family/{draw}/{index}: the family draw's finding[{index}] is "
                    f"{type(finding).__name__}, not a mapping")
                continue
            row = build_finding_row(
                run_id=run_id, label="family", draw=str(draw), index=index,
                subject=SUBJECT_WORLD, finding=finding, alert_rule_key=alert_rule_key,
                judge_outcome=verdict_word, provenance="model")
            _add_row(row, validator=_validate_world_row, sink=world_rows_out,
                     unqueueable=unqueueable, episode_dir=episode_dir)

    for label in graded_labels:
        # "THE CALLER HANDED NOTHING OVER" IS `drawn is None`, and nothing else. `(drawn or
        # {})` folded an EMPTY map — and a map simply missing this label — back onto the disk
        # fallback, which is the one thing `drawn` exists to avoid: a pass that produced no
        # draw for a world would then queue whatever an earlier, wider attempt left in that
        # world's draw directory as its own findings (P4: a retry clobbers, it cleans nothing
        # up), under THIS pass's `verdict_word`.
        documents = (drawn.get(label) or {}) if drawn is not None else _draws_on_disk(
            episode_dir / "worlds" / label / "judge")
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
                subject = finding.get("subject")
                if subject == SUBJECT_WORLD:
                    row = build_finding_row(
                        run_id=run_id, label=label, draw=str(draw), index=index,
                        subject=SUBJECT_WORLD, finding=finding, alert_rule_key=alert_rule_key,
                        judge_outcome=verdict_word, provenance="model")
                    _add_row(row, validator=_validate_world_row, sink=world_rows_out,
                             unqueueable=unqueueable, episode_dir=episode_dir)
                    continue
                if label in withheld_labels:
                    # O4 (F7): this world's difference was never measured — the finding is
                    # recorded WHOLE on `withheld_findings`, with the row's own reason, rather
                    # than dropped in silence the way `defender_blocked` (O7, below) is. O7's
                    # own artifact is the family record itself (the whole episode's outcome),
                    # so a `discard`/`corpus-contradiction` episode's findings stay unrecorded
                    # here exactly as `unqueueable` already leaves them — two different reasons
                    # a finding never reaches the queue, kept apart rather than merged into one
                    # drop.
                    withheld_findings.append(
                        {"finding": finding, "world": label, "reason": withheld_reasons[label]})
                    continue
                if defender_blocked:
                    # O7 (discard/corpus-contradiction): never a defender row, and never
                    # counted as unqueueable OR withheld — it was never eligible in the first
                    # place, and the family record's own outcome is the artifact for it.
                    continue
                row = build_finding_row(
                    run_id=run_id, label=label, draw=str(draw), index=index,
                    subject=SUBJECT_DEFENDER, finding=finding, alert_rule_key=alert_rule_key,
                    judge_outcome=verdict_word)
                _add_row(row, validator=_validate_row, sink=defender_rows,
                         unqueueable=unqueueable, episode_dir=episode_dir)

    # M3's mechanical world finding(s) — a FIXED synthetic (draw, index) coordinate per world,
    # so a re-grade is absorbed by the questioner channel's own idempotency
    # (`test_a_re_grade_appends_no_second_mechanical_world_finding`).
    for row_dict in world_rows:
        label = row_dict.get("world")
        for mech_index, finding in enumerate(row_dict.get("mechanical_world_findings") or []):
            wrow = build_finding_row(
                run_id=run_id, label=label, draw="mechanical", index=mech_index,
                subject=SUBJECT_WORLD, finding=finding, alert_rule_key=alert_rule_key,
                judge_outcome=verdict_word, provenance=finding.get("provenance", "mechanical"))
            _add_row(wrow, validator=_validate_world_row, sink=world_rows_out,
                     unqueueable=unqueueable, episode_dir=episode_dir)

    if defender_blocked:
        defender_appended, defender_malformed = 0, 0
    else:
        defender_appended, defender_malformed = append_rows_report(
            episode_dir, defender_rows, queue_dir=queue_dir)
    world_appended, world_malformed = append_world_rows_report(
        episode_dir, world_rows_out, queue_dir=queue_dir)
    reported_world_rows = [{**row, "judge_outcome": None} for row in world_rows_out]
    return EnqueueReport(
        appended=defender_appended, unqueueable=unqueueable,
        queue_malformed_rows=defender_malformed, world_appended=world_appended,
        world_queue_malformed_rows=world_malformed, world_rows=reported_world_rows,
        withheld_findings=withheld_findings)


__all__ = [
    "EnqueueReport", "append_rows", "append_rows_report", "append_world_rows",
    "append_world_rows_report", "build_finding_row", "enqueue", "enqueue_report",
]
