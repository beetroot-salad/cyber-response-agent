from __future__ import annotations

import contextlib
import json
import re
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

# Aliased to `_lockfile` so this module can keep `_flock` as its own name for `queue_lock`.
from defender import _flock as _lockfile
from defender._clock import now_iso
from defender._text import is_content_less
from defender._io import append_jsonl, read_jsonl_rows, write_atomic
from defender._run_paths import artifact_file
from defender.learning.core.config import (
    ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES,
    BENIGN_AUDIT_ONLY_FINDING_TYPES,
    DEFAULT_PATHS,
    RunUnprocessable,
    LoopPaths,
    QueueChannel,
    RunPaths,
    make_logger,
)
from defender.learning.core.validate import _benign_outcome_keyword, _outcome_keyword
# The reducer lane's routing key, at its owner (#870). Imported for the VALUE, the same way
# `lead_extraction` and `pitfalls_curator` take it: the three seams that ask "is this the
# reducer's row" have to compare the same literal, and a second spelling of it here is exactly
# the drift `is_reducer_row` was introduced to end.
from defender.scripts.gather_tools.record_query import BASH_SHIM_QUERY_ID




@contextlib.contextmanager
def queue_lock(lock_path: Path, *, timeout_seconds: int | None = None):
    """Exclusive hold of a queue's append-role lock.

    APPENDERS pass no deadline and wait forever: an append that gave up would lose the row
    it is carrying, and it waits on nothing but other appenders and the short rewrite window.

    THE DRAIN must pass one. It reaches this holding the repo lock, which serialises all four
    corpus channels — so a wedged appender on one channel would otherwise stall every sibling
    channel's tick unboundedly. Expiry raises `TimeoutError`, deliberately NOT in the drain's
    retire set: the batch is recorded stuck, never bumped, since a busy lock is not its fault.
    """
    fh = _lockfile.open_lock(lock_path)
    try:
        taken = _lockfile.take(fh, timeout_seconds=timeout_seconds)
    except BaseException:
        fh.close()
        raise
    if not taken:
        fh.close()
        raise TimeoutError(
            f"queue lock {lock_path} held by an appender for >{timeout_seconds}s"
        )
    try:
        yield
    finally:
        _lockfile.release(fh)


#: In-module callers and the lock suites reach for this spelling.
_flock = queue_lock


def _load_jsonl_ids(path: Path, key: str) -> set[str]:
    ids: set[str] = set()
    for obj in read_jsonl_rows(path):
        v = obj.get(key)
        if isinstance(v, str):
            ids.add(v)
    return ids


def _rewrite_queue(
    pending_file: Path,
    consumed_file: Path,
    id_key: str,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
) -> None:
    # ALWAYS merges: a non-merging rewrite would drop any row appended between the batch's
    # read and its rewrite. `.get`, not `[...]`: a row carrying no value under `id_key`
    # cannot be matched, and the drain routes such rows here deliberately so they leave.
    processed = {e.get(id_key) for e in held} | {e.get(id_key) for e in consumed}
    current = read_jsonl_rows(pending_file)
    survivors = list(held) + [r for r in current if r.get(id_key) not in processed]
    write_atomic(pending_file, "".join(json.dumps(entry) + "\n" for entry in survivors))
    if consumed:
        now = now_iso()
        rows = []
        for entry in consumed:
            rec = dict(entry)
            rec.setdefault("consumed_at", now)
            if rec.get("consumed_category") == "consumed_committed" and commit_sha:
                rec["consumed_commit"] = commit_sha
            rows.append(rec)
        append_jsonl(consumed_file, rows)


def rotate_queue_locked(
    *,
    pending_file: Path,
    consumed_file: Path,
    lock_file: Path,
    id_key: str,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
    timeout_seconds: int | None = None,
) -> None:
    pending_file.parent.mkdir(parents=True, exist_ok=True)
    with queue_lock(lock_file, timeout_seconds=timeout_seconds):
        _rewrite_queue(pending_file, consumed_file, id_key, held, consumed, commit_sha)


def _slugify(s: str) -> str:
    out = []
    prev_dash = False
    for ch in str(s).lower():
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    return "".join(out).strip("-") or "unkeyed"


def derive_alert_rule_key(alert: dict) -> str:
    rule = alert.get("rule")
    if isinstance(rule, dict) and rule.get("id") not in (None, ""):
        return f"rule-{rule['id']}"
    sig = alert.get("signature")
    if isinstance(sig, str) and sig.strip():
        return _slugify(sig)
    top_id = alert.get("id")
    if isinstance(top_id, (str, int)) and str(top_id).strip():
        return _slugify(str(top_id))
    return "unkeyed"


def _source_run_dir(learning_run_dir: Path, repo_root: Path) -> str:
    try:
        return str(learning_run_dir.relative_to(repo_root)) + "/"
    except ValueError:
        return str(learning_run_dir) + "/"




_SHARED_COPY_ARTIFACTS = ("alert", "report", "investigation")

_SHARED_INPUTS_LOCK = threading.Lock()

_persist_log = make_logger("persist")


def _refused(run_dir: Path, entries: list[Path]) -> None:
    """A staging refusal is loud: it is evidence about the run, not a copy detail, and silence
    here would read downstream as a case that simply gathered nothing."""
    for entry in entries:
        _persist_log(
            f"REFUSED to stage {entry} from {run_dir}: not a regular file or a real directory "
            "(a run writes neither links nor special files; #648)"
        )


def _copy_shared_inputs(run_dir: Path, learning_run_dir: Path) -> None:
    learning_run_dir.mkdir(parents=True, exist_ok=True)
    src_paths, dst_paths = RunPaths(run_dir), RunPaths(learning_run_dir)
    with _SHARED_INPUTS_LOCK:
        for name in _SHARED_COPY_ARTIFACTS:
            src = getattr(src_paths, name)
            if not artifact_file(src):
                # `is_file()` would answer about a link's TARGET and copy those bytes in under
                # the artifact's name — these three are what the actor and judge read as the
                # case itself, so a link at one is fatal, not skippable.
                raise RunUnprocessable(
                    f"source artifact for persist is missing or is not a regular file: {src}")
            dst = getattr(dst_paths, name)
            if name == "investigation":
                # No grandfather clause, on purpose: the disposition SELECTS the direction the
                # loop spends actor + oracle + judge calls on, so a headline outside the known
                # keywords has no direction and grandfathering would mean guessing one and
                # authoring lessons off the guess. Refusing costs a queued run a human can
                # hand-edit and re-drive out of `queue/failed/`.
                from defender.skills.invlang.validate import validate_companion

                # THE DOCUMENT IS ITS OWN BASELINE. This is a finished run, not a write: the
                # bytes are already committed and no repair can reach them. The surface rule
                # (#932) refuses only the unfenced block headers a WRITE introduces, so a
                # `None` baseline would read every one in the file as newly written and send
                # a whole run to `queue/failed/` for prose that has been there since the
                # append that wrote it. Passing the text as both halves makes the introduced
                # set empty; the append-only comparison against itself is likewise a no-op,
                # which is what `None` already meant here.
                committed = src.read_text(encoding="utf-8")
                errors = validate_companion(committed, committed)
                if errors:
                    raise RunUnprocessable(
                        f"investigation.md failed invlang validation on the copy path "
                        f"({src}): {errors}"
                    )
            # `src` is judged by `artifact_file` at the top of this loop, and a link there
            # raises rather than reaching the copy.
            shutil.copy2(src, dst)  # lint-tree-read-follows-link: ok — screened above
        loaded = run_dir / "lessons_loaded.jsonl"
        if artifact_file(loaded):
            # Guarded by the `artifact_file` above; the `elif` below is what a link here gets.
            shutil.copy2(  # lint-tree-read-follows-link: ok — screened on the line above
                loaded, learning_run_dir / "lessons_loaded.jsonl")
        elif loaded.exists() or loaded.is_symlink():
            _refused(run_dir, [loaded])
        from defender.learning import lead_repository

        _refused(run_dir, lead_repository.stage_tables(run_dir, learning_run_dir))


def _write_source_refs(
    run_dir: Path, learning_run_dir: Path, disposition: str, alert_rule_key: str
) -> None:
    rp = RunPaths(run_dir)
    source_refs = {
        "paths": {
            "source_run_dir": str(run_dir),
            "alert": str(rp.alert),
            "report": str(rp.report),
            "investigation": str(rp.investigation),
            "executed_queries": str(rp.executed_queries),
            "gather_raw": str(rp.gather_raw),
        },
        "normalized_disposition": disposition,
        "alert_rule_key": alert_rule_key,
    }
    with _SHARED_INPUTS_LOCK:
        # lint-artifact-gate: ok — the artifacts are NAMED here, not written: this is a
        # manifest of where the source run's files live, and the only file it writes is
        # `source_refs.yaml`. The gate keys on a write and an artifact name appearing in one
        # frame, which cannot tell "writes X while naming Y" from "writes Y" — the cost of
        # asking the question by co-occurrence rather than by dataflow, paid here.
        (learning_run_dir / "source_refs.yaml").write_text(yaml.safe_dump(source_refs), encoding="utf-8")


@dataclass(frozen=True)
class DirectionArtifacts:

    actor_story: str
    story_name: str
    judge_yaml: str | None
    judge_name: str


def persist_run(
    run_dir: Path,
    learning_run_dir: Path,
    *,
    artifacts: DirectionArtifacts,
    disposition: str,
    alert_rule_key: str,
) -> None:
    actor_story, story_name = artifacts.actor_story, artifacts.story_name
    judge_yaml, judge_name = artifacts.judge_yaml, artifacts.judge_name
    _copy_shared_inputs(run_dir, learning_run_dir)
    (learning_run_dir / story_name).write_text(actor_story, encoding="utf-8")
    if judge_yaml is not None:
        (learning_run_dir / judge_name).write_text(judge_yaml, encoding="utf-8")
    _write_source_refs(run_dir, learning_run_dir, disposition, alert_rule_key)




def append_findings(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    direction: str = "adversarial",
    paths: LoopPaths = DEFAULT_PATHS,
) -> int:
    if direction == "benign":
        outcome = _benign_outcome_keyword(judge_doc["outcome"])
        audit_only_types, namespace = BENIGN_AUDIT_ONLY_FINDING_TYPES, "benign/"
    else:
        outcome = _outcome_keyword(judge_doc["outcome"])
        audit_only_types, namespace = ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES, ""
    src = _source_run_dir(learning_run_dir, paths.repo_root)
    paths.pending_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "schema_version": 1,
            "finding_id": f"{run_id}/{namespace}{n}",
            "run_id": run_id,
            "alert_rule_key": alert_rule_key,
            "direction": direction,
            "type": f["type"],
            "subject_anchor": f["subject_anchor"],
            "subject_topic": f["subject_topic"],
            "finding": f["finding"],
            "judge_outcome": outcome,
            "citations": f["citations"],
            "source_run_dir": src,
        }
        for n, f in enumerate(judge_doc["defender_findings"])
        if f["type"] not in audit_only_types
    ]
    with queue_lock(paths.findings_lock_file):
        return append_jsonl(paths.pending_file, rows)




#: The envelope `record_query.payload_digest` wraps EVERY failing call in (`exit={code}; `).
#: It is shared by every failure of a system, so it is not itself a diagnosis.
_EXIT_ENVELOPE = re.compile(r"^\s*exit=-?\d+\s*;\s*")


def _digest_diagnosis(digest: str) -> str:
    return _EXIT_ENVELOPE.sub("", digest, count=1)


def is_reducer_row(row: dict) -> bool:
    """Is this queued row the REDUCER's mistake rather than a system's?

    THE ONE SPELLING, and it lives here because three seams ask it and they were three
    different questions until #870's review: `pitfalls_curator._is_reducer_row` asked the
    sentinel, `pitfalls_lane_is_open` asked `system == ""`, and `pitfall_key` did not ask at
    all. The three disagreed on exactly one population — a row queued BEFORE M5′ deployed,
    which carries the system its payload was attributed to AND the sentinel id — so the same
    row was routed to the reducer surface by one reader, refused the lane by another, and
    split into a record per attributed system by the third.

    EQUALITY with the reserved sentinel (U3). It is the `query_id` half of the predicate
    `lead_extraction.collect_general_failures` routes on; the `is_sentinel` half is the
    projection's verdict on a QUERIES-TABLE row and is not a field the queue carries, so this
    is the strongest form a queue reader can ask. Unconditional in the row's `system`, because
    a `defender-sql` mistake belongs to `defender-sql` however the reduce happened to be
    attributed (F1) — which is the whole content of the disagreement above.
    """
    return str(row.get("query_id") or "") == BASH_SHIM_QUERY_ID


def pitfall_key(row: dict) -> tuple[str, str]:
    """The identity of a MISTAKE, which is not the identity of a failing row.

    `(owner, stderr_digest)`, where the OWNER is the surface the lesson would be taught on:
    the reducer sentinel for a reducer row, the stripped system name otherwise. Keying on
    `system` alone splits and merges the wrong rows in both directions once the reducer
    surface is a second target — two reducer rows spelling their attributed system
    differently become two records of ONE `defender-sql` mistake, and a system row sharing a
    digest with a reducer row becomes one record whose fate falls to whichever the merge kept
    as exemplar. The sentinel is collision-free as an owner name because `is_system_name`
    admits no `∅`.

    The digest is the adapter's own diagnosis and is what `lead_pitfalls.md` step 2 reads to
    name the mistake and its fix, so two rows carrying the same one under the same owner are
    one lesson however differently the query was phrased. `query_id` is deliberately out of
    the key as an IDENTITY: two coined queries earning the identical rejection teach one
    bullet. It is read only to answer WHICH SURFACE owns the lesson — the question
    `is_reducer_row` exists for.

    The system name is STRIPPED to match `_build_pitfalls_handoffs`' grouping; a coarser key
    would hand the curator two entries it reads as two bullets. The reducer half needs no
    such agreement — the builder collects every reducer record into ONE entry.

    A row whose digest carries NO diagnosis — absent, blank, or nothing but the adapter's
    `exit=N;` envelope — keys to ITSELF. Merging on the absence of a verdict would fold
    unrelated mistakes behind one exemplar, hand the curator only that exemplar's query, and
    rotate the rest into `consumed` as though curated. `is_content_less`, not `.strip()`, so
    a digest of zero-width filler cannot read as a diagnosis either.
    """
    owner = (
        BASH_SHIM_QUERY_ID if is_reducer_row(row)
        else str(row.get("system") or "").strip()
    )
    digest = str(row.get("stderr_digest") or "")
    if is_content_less(_digest_diagnosis(digest)):
        return (owner, "\x00" + str(row.get("pitfall_id") or ""))
    return (owner, digest)


def _occurrences(row: dict) -> int:
    # A queue row IS one occurrence and carries no count of its own; a record already
    # merged carries the count it was merged from, so re-merging a merged set is a no-op.
    n = row.get("occurrences")
    return n if isinstance(n, int) and not isinstance(n, bool) and n > 0 else 1


def merge_pitfalls(rows: list[dict]) -> list[dict]:
    """Collapse repeats of one mistake into one record carrying `occurrences: N`.

    The count survives the collapse: it tells the curator which bullet is worth the context
    tax. The FIRST row of a key is the exemplar and keeps every other field (`pitfall_id`,
    `source_run`, any queue bookkeeping the drain stamped on it); later rows contribute their
    count and nothing else. Order is first-seen, and the result re-merges to itself, so either
    consuming seam can merge without caring whether the other already did.
    """
    out: list[dict] = []
    by_key: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = pitfall_key(row)
        if (exemplar := by_key.get(key)) is not None:
            exemplar["occurrences"] += _occurrences(row)
            continue
        rec = dict(row)
        rec["occurrences"] = _occurrences(row)
        by_key[key] = rec
        out.append(rec)
    return out


def pitfalls_lane_is_open(records: list[dict], threshold: int) -> bool:
    """ONE arrival condition, at both readers (#870 FK-3) — `pitfalls_curator.run_pitfalls`'
    tick gate and `drains._has_lead_author_work`' wake gate.

    The DISTINCT COUNT of merged records reaching the threshold, every record included and
    systemless ones with them, EXACTLY AS BEFORE — **or** some REDUCER record carrying
    `occurrences >= threshold` on its own.

    "Reducer record" is `is_reducer_row`, the lane's one spelling, and FK-3's own `system == ""`
    is what that replaces. The two agree on every row `collect_general_failures` has minted
    since M5′, which normalizes `system` to `""`; they disagree on the population `run_pitfalls`
    names in its own comment — rows queued BEFORE M5′ deployed, which still carry the system
    their payload was attributed to. Under the narrower spelling such a row was routed to the
    reducer surface by every other seam and yet could never open the lane on its own
    occurrences, so the round's own motivating incident (one unchanging `Binder Error` under
    eight varied attempts against one attributed envelope) sat in the queue untaught — the exact
    unreachability FK-3 was added to close. Asking the routing predicate is what makes the gate
    and the routing one decision.

    The disjunct is ADDED; nothing is removed. It exists because the count alone was
    anti-correlated with evidence quality on the reducer lane: the round's motivating incident
    is ONE merged record (one unchanging `Binder Error` under eight varied attempts), which
    could never clear a threshold of 3 alone, while N silent failures carrying no diagnosis
    ARE N records and did. And the narrower encoding — a systemless record leaving the count
    entirely — was rejected: it would silently raise the SYSTEM lane's own bar, which this is
    not the decision to make. A content-less digest keys to `(system, "\\x00" + pitfall_id)`,
    unique per row, so no number of silent failures ever satisfies the new disjunct.
    """
    if len(records) >= threshold:
        return True
    return any(is_reducer_row(r) and _occurrences(r) >= threshold for r in records)


def append_pitfalls(rows: list[dict], *, paths: LoopPaths = DEFAULT_PATHS) -> int:
    """Append the failing rows verbatim. The COLLAPSE happens on the way out.

    Deliberately not deduplicating here: exactly one function in `learning/` rewrites a queue
    file wholesale — the merging rotation — so an appender that bumped a count on a row
    already on disk would be the second, racing the drain's read-modify-write window for no
    gain. The queue stays the evidence, one line per failure.

    `merge_pitfalls` collapses it at both consuming seams — the curation threshold
    (`pitfalls_curator.run_pitfalls`, `drains._has_lead_author_work`) and the curator's
    handoff. A reader that counts these rows is counting failures, never lessons.
    """
    if not rows:
        return 0
    with queue_lock(paths.pitfalls.append_lock):
        return append_jsonl(paths.pitfalls.file, rows)


def read_pitfalls(paths: LoopPaths = DEFAULT_PATHS) -> list[dict]:
    return read_jsonl_rows(paths.pitfalls.file)


def rotate_pitfalls(
    batch_ids: list[str], commit_sha: str | None, *, paths: LoopPaths = DEFAULT_PATHS,
    category: str = "consumed_committed",
) -> None:
    ids = set(batch_ids)
    consumed = [
        {**r, "consumed_category": category}
        for r in read_jsonl_rows(paths.pitfalls.file)
        if r.get("pitfall_id") in ids
    ]
    rotate_queue_locked(
        pending_file=paths.pitfalls.file,
        consumed_file=paths.pitfalls.consumed,
        lock_file=paths.pitfalls.append_lock,
        id_key=paths.pitfalls.id_key,
        held=[],
        consumed=consumed,
        commit_sha=commit_sha,
    )




def _append_observations(
    queue_file: Path,
    consumed_file: Path,
    lock_file: Path,
    run_id: str,
    observations: list[dict],
    build_row: Callable[[int, dict, str], dict],
    *,
    id_prefix: str = "",
) -> int:
    with queue_lock(lock_file):
        existing = _load_jsonl_ids(queue_file, "observation_id") | _load_jsonl_ids(
            consumed_file, "observation_id"
        )
        rows: list[dict] = []
        for i, obs in enumerate(observations):
            obs_id = f"{run_id}/{id_prefix}{i}"
            if obs_id in existing:
                continue
            rows.append(build_row(i, obs, obs_id))
        return append_jsonl(queue_file, rows)


def append_actor_observations(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    paths: LoopPaths = DEFAULT_PATHS,
) -> int:
    outcome = _outcome_keyword(judge_doc["outcome"])
    if outcome == "skip-passthrough":
        return 0
    observations = judge_doc.get("actor_observations") or []
    if not observations:
        return 0
    src = _source_run_dir(learning_run_dir, paths.repo_root)

    def build_row(i: int, obs: dict, obs_id: str) -> dict:
        return {
            "observation_id": obs_id,
            "run_id": run_id,
            "observation_index": i,
            "alert_rule_key": alert_rule_key,
            "type": obs["type"],
            "subject_anchor": obs["subject_anchor"],
            "subject_topic": obs["subject_topic"],
            "observation": obs["observation"],
            "judge_outcome": outcome,
            "source_run_dir": src,
        }

    ch = paths.actor_observations
    return _append_observations(
        ch.file, ch.consumed, ch.append_lock,
        run_id, observations, build_row,
    )


def _anchor_with_case_key(judge_rule_ids: Any, alert_rule_key: str) -> list[str]:
    ids = judge_rule_ids if isinstance(judge_rule_ids, list) else [judge_rule_ids]
    # is_content_less, not `.strip()`: an id that renders as nothing must not survive
    # into the stored anchor, and `.strip()` cannot see the zero-width ones.
    ids = [str(r) for r in ids if not is_content_less(str(r))]
    if alert_rule_key and alert_rule_key not in ids:
        ids = [alert_rule_key, *ids]
    return ids


@dataclass(frozen=True)
class _EnvFactStream:

    outcome_keyword: Callable[[Any], str]
    channel: QueueChannel
    id_prefix: str
    provenance: str


def _append_env_fact_observations(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    paths: LoopPaths,
    stream: _EnvFactStream,
) -> int:
    outcome_keyword = stream.outcome_keyword
    ch, id_prefix, provenance = stream.channel, stream.id_prefix, stream.provenance
    outcome = outcome_keyword(judge_doc["outcome"])
    if outcome == "skip-passthrough":
        return 0
    observations = judge_doc.get("environment_observations") or []
    if not observations:
        return 0
    src = _source_run_dir(learning_run_dir, paths.repo_root)

    def build_row(i: int, obs: dict, obs_id: str) -> dict:
        row = {
            "observation_id": obs_id,
            "run_id": run_id,
            "observation_index": i,
            "alert_rule_key": alert_rule_key,
        }
        subject = obs.get("subject")
        if subject:
            row["subject"] = subject
        row.update({
            "alert_rule_ids": _anchor_with_case_key(obs["alert_rule_ids"], alert_rule_key),
            "entities": obs.get("entities") or [],
            "relevance_criteria": obs["relevance_criteria"],
            "fact": obs["fact"],
            "citations": obs.get("citations") or [],
            "judge_outcome": outcome,
            "source_run_dir": src,
            "provenance": provenance,
        })
        return row

    return _append_observations(
        ch.file, ch.consumed, ch.append_lock,
        run_id, observations, build_row,
        id_prefix=id_prefix,
    )


def append_environment_observations(
    judge_benign_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    paths: LoopPaths = DEFAULT_PATHS,
) -> int:
    return _append_env_fact_observations(
        judge_benign_doc, run_id, alert_rule_key, learning_run_dir,
        paths=paths,
        stream=_EnvFactStream(
            outcome_keyword=_benign_outcome_keyword,
            channel=paths.environment_observations,
            id_prefix="",
            provenance="benign",
        ),
    )


def append_actor_environment_observations(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    paths: LoopPaths = DEFAULT_PATHS,
) -> int:
    return _append_env_fact_observations(
        judge_doc, run_id, alert_rule_key, learning_run_dir,
        paths=paths,
        stream=_EnvFactStream(
            outcome_keyword=_outcome_keyword,
            channel=paths.actor_environment_observations,
            id_prefix="adv-env/",
            provenance="adversarial",
        ),
    )
