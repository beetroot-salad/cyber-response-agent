"""Per-run artifact persistence and `_pending/` queue appends.

All filesystem locations come from an injected `LoopPaths` (default `DEFAULT_PATHS`),
so tests pass `paths=LoopPaths(repo_root=tmp_path)` instead of monkeypatching globals.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import fcntl
import json
import os
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

from defender.learning import lead_repository
from defender.learning.core.config import (
    ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES,
    BENIGN_AUDIT_ONLY_FINDING_TYPES,
    DEFAULT_PATHS,
    LoopError,
    LoopPaths,
    RunDirs,
)
from defender.learning.core.validate import _benign_outcome_keyword, _outcome_keyword


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _flock(lock_path: Path):
    """Exclusive flock over ``lock_path`` for the duration of the block."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def _load_jsonl_ids(path: Path, key: str) -> set[str]:
    """Set of ``entry[key]`` strings in a JSONL file; missing file → empty set.

    Malformed lines are skipped, matching ``author.read_batch``'s tolerance.
    """
    if not path.is_file():
        return set()
    ids: set[str] = set()
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        v = obj.get(key)
        if isinstance(v, str):
            ids.add(v)
    return ids


def _append_jsonl(path: Path, rows: list[dict]) -> int:
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return len(rows)


def _read_jsonl_rows(path: Path) -> list[dict]:
    """All rows in a JSONL file (tolerant of blank/malformed lines)."""
    if not path.is_file():
        return []
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            rows.append(json.loads(s))
        except json.JSONDecodeError:
            continue
    return rows


def _rewrite_queue(
    pending_file: Path,
    consumed_file: Path,
    id_key: str,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
    *,
    merge: bool,
) -> None:
    """Atomically rewrite ``pending_file`` to the survivors and append consumed.

    ``merge=True`` re-reads the current file and keeps any row the author never
    processed (mutated ``held`` rows + untouched new arrivals); ``merge=False``
    writes ``held`` verbatim. The caller owns whatever lock the producer uses.
    """
    if merge:
        processed = {e[id_key] for e in held} | {e[id_key] for e in consumed}
        current = _read_jsonl_rows(pending_file)
        survivors = list(held) + [r for r in current if r.get(id_key) not in processed]
    else:
        survivors = list(held)
    tmp = pending_file.with_suffix(pending_file.suffix + ".tmp")
    with tmp.open("w") as fh:
        for entry in survivors:
            fh.write(json.dumps(entry) + "\n")
    os.replace(tmp, pending_file)
    if consumed:
        now = _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")
        with consumed_file.open("a") as fh:
            for entry in consumed:
                rec = dict(entry)
                rec.setdefault("consumed_at", now)
                if rec.get("consumed_category") == "consumed_committed" and commit_sha:
                    rec["consumed_commit"] = commit_sha
                fh.write(json.dumps(rec) + "\n")


def rotate_queue_locked(
    *,
    pending_file: Path,
    consumed_file: Path,
    lock_file: Path,
    id_key: str,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
    merge_concurrent: bool = True,
) -> None:
    """Drain a JSONL queue: rewrite survivors atomically + append consumed rows.

    ``merge_concurrent`` selects how the caller relates to the producer's
    ``lock_file``:

    * ``True`` (the findings path) — the caller held the queue lock only
      *briefly* to read its batch, so a producer may have appended new rows in
      the minutes since. Take ``lock_file`` here, re-read, and preserve any row
      whose ``id_key`` the author never processed.
    * ``False`` (the observation paths) — the caller already holds ``lock_file``
      across the whole read→rotate batch, so no row can arrive mid-batch and a
      held-only rewrite cannot lose data. Re-taking ``lock_file`` here would
      self-deadlock (flock denies a second fd held by the same process), so we
      must not — the caller's lock already serializes the rewrite.

    Consumed rows append to ``consumed_file`` with ``consumed_at`` /
    ``consumed_commit``.
    """
    pending_file.parent.mkdir(parents=True, exist_ok=True)
    if merge_concurrent:
        with _flock(lock_file):
            _rewrite_queue(
                pending_file, consumed_file, id_key, held, consumed, commit_sha, merge=True
            )
    else:
        _rewrite_queue(
            pending_file, consumed_file, id_key, held, consumed, commit_sha, merge=False
        )


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
    """POC-grade vendor-neutral key derivation per task §findings.jsonl."""
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
    """Path to the run bundle, as consumers resolve it (``repo_root / src``).

    Repo-relative when the run lives in-repo (the default); absolute when it
    lives out-of-repo under ``DEFENDER_LEARNING_STATE_DIR`` (no repo-relative
    form exists). Both resolve correctly via ``repo_root / src`` — pathlib lets
    an absolute right-hand side win — so the consumers (the authors' held-out
    double-check, the forward-checkers) need no special-casing. Trailing slash
    preserved for the existing string contract.
    """
    try:
        return str(learning_run_dir.relative_to(repo_root)) + "/"
    except ValueError:
        return str(learning_run_dir) + "/"


# ---------------------------------------------------------------------------
# Persist per-run artifacts
# ---------------------------------------------------------------------------


# Hard-required flat inputs. The two lead/query tables
# (executed_queries.jsonl + the gather_raw/ directory) are copied separately
# and are best-effort — a query-less run has neither, which is a monitor case,
# not a persist failure.
PERSIST_COPY_FILES = ("alert.json", "report.md", "investigation.md")

# Both directions write the same disposition-level shared artifacts (copied inputs
# + source_refs.yaml). When the legs run concurrently these truncating writes target
# identical paths, so serialize them — identical content doesn't make a non-atomic
# write safe.
_SHARED_INPUTS_LOCK = threading.Lock()


def _copy_shared_inputs(run_dir: Path, learning_run_dir: Path) -> None:
    learning_run_dir.mkdir(parents=True, exist_ok=True)
    with _SHARED_INPUTS_LOCK:
        for name in PERSIST_COPY_FILES:
            src = run_dir / name
            if not src.is_file():
                raise LoopError(f"missing source artifact for persist: {src}")
            shutil.copy2(src, learning_run_dir / name)
        # Best-effort: the lesson-load trace (record_lesson_load hook). Optional —
        # a run that loaded no lesson has none — so it is NOT in PERSIST_COPY_FILES;
        # copy it when present so trace_lesson survives the ephemeral run dir being
        # swept (it scans this durable dir, which also carries report.md above).
        loaded = run_dir / "lessons_loaded.jsonl"
        if loaded.is_file():
            shutil.copy2(loaded, learning_run_dir / "lessons_loaded.jsonl")
        # The two live tables (queries JSONL + the gather_raw/ tree). Staged
        # via the single lead_repository helper so this and the secondary-eval
        # staging step share one definition of the on-disk table set.
        lead_repository.stage_tables(run_dir, learning_run_dir)


def _write_source_refs(
    run_dir: Path, learning_run_dir: Path, disposition: str, alert_rule_key: str
) -> None:
    source_refs = {
        "paths": {
            "source_run_dir": str(run_dir),
            "alert": str(run_dir / "alert.json"),
            "report": str(run_dir / "report.md"),
            "investigation": str(run_dir / "investigation.md"),
            "executed_queries": str(run_dir / "executed_queries.jsonl"),
            "gather_raw": str(run_dir / "gather_raw"),
        },
        "normalized_disposition": disposition,
        "alert_rule_key": alert_rule_key,
    }
    with _SHARED_INPUTS_LOCK:
        (learning_run_dir / "source_refs.yaml").write_text(yaml.safe_dump(source_refs))


@dataclass(frozen=True)
class DirectionArtifacts:
    """The three per-direction artifacts ``persist_run`` writes, each a
    (content, on-disk name) pair. ``judge_yaml`` / ``telemetry_yaml`` are None on
    the actor-SKIP short-circuit (only the story is written)."""

    actor_story: str
    story_name: str
    judge_yaml: str | None
    judge_name: str
    telemetry_yaml: str | None
    telemetry_name: str


def persist_run(
    dirs: RunDirs,
    *,
    artifacts: DirectionArtifacts,
    disposition: str,
    alert_rule_key: str,
) -> None:
    """Persist one direction's per-run artifacts under direction-suffixed names.

    The four input copies + source_refs are shared across directions (an
    ``inconclusive`` run that runs both writes them once each; the copies are
    idempotent). ``judge_yaml`` / ``telemetry_yaml`` are the fence-stripped, validated
    YAML — caller-side raw text (if any) belongs in a ``*.raw.txt`` companion.
    """
    run_dir, learning_run_dir = dirs.run_dir, dirs.learning_run_dir
    actor_story, story_name = artifacts.actor_story, artifacts.story_name
    judge_yaml, judge_name = artifacts.judge_yaml, artifacts.judge_name
    telemetry_yaml, telemetry_name = artifacts.telemetry_yaml, artifacts.telemetry_name
    _copy_shared_inputs(run_dir, learning_run_dir)
    (learning_run_dir / story_name).write_text(actor_story)
    if telemetry_yaml is not None:
        (learning_run_dir / telemetry_name).write_text(telemetry_yaml)
    if judge_yaml is not None:
        (learning_run_dir / judge_name).write_text(judge_yaml)
    _write_source_refs(run_dir, learning_run_dir, disposition, alert_rule_key)


# ---------------------------------------------------------------------------
# Queue: defender findings (shared corpus, direction-tagged)
# ---------------------------------------------------------------------------


def append_findings(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    direction: str = "adversarial",
    paths: LoopPaths = DEFAULT_PATHS,
) -> int:
    """Append queueable defender findings to the shared pending queue.

    Both directions feed ``_pending/findings.jsonl`` → ``defender/lessons/``. The
    audit-only finding types are filtered out (``detection-confirmed``
    adversarially, ``disposition-confirmed`` benignly). Each
    row is tagged with ``direction`` so the shared curator applies the right
    ground-truth gate; benign ids live in a ``benign/`` namespace so the two
    directions never collide on a ``run_id``.
    """
    if direction == "benign":
        outcome = _benign_outcome_keyword(judge_doc["outcome"])
        audit_only_types, namespace = BENIGN_AUDIT_ONLY_FINDING_TYPES, "benign/"
    else:
        outcome = _outcome_keyword(judge_doc["outcome"])
        audit_only_types, namespace = ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES, ""
    src = _source_run_dir(learning_run_dir, paths.repo_root)
    appended = 0
    paths.pending_dir.mkdir(parents=True, exist_ok=True)
    with _flock(paths.findings_lock_file), paths.pending_file.open("a") as fh:
        for n, f in enumerate(judge_doc["defender_findings"]):
            if f["type"] in audit_only_types:
                continue
            entry = {
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
            fh.write(json.dumps(entry) + "\n")
            appended += 1
    return appended


# ---------------------------------------------------------------------------
# Queue: general-failure pitfalls (cross-run; feeds execution.md curation)
# ---------------------------------------------------------------------------


def append_pitfalls(rows: list[dict], *, paths: LoopPaths = DEFAULT_PATHS) -> int:
    """Append general-failure pitfall rows to the cross-run pending queue.

    Rows are pre-built by ``lead_author.collect_general_failures`` (one per
    agent-fixable execution failure that resolved to no template and is not a
    draft candidate). Each carries a deterministic ``pitfall_id`` so a
    re-collected duplicate (the failure-retry path) dedups by id at rotate time
    rather than double-counting. The lead-author curation mode (``run_pitfalls``)
    drains it into each system's ``execution.md`` ``## Common pitfalls`` section.
    Returns the number appended.
    """
    if not rows:
        return 0
    with _flock(paths.pitfalls_lock_file):
        return _append_jsonl(paths.pitfalls_pending_file, rows)


def read_pitfalls(paths: LoopPaths = DEFAULT_PATHS) -> list[dict]:
    """All queued pitfall rows (tolerant of blank/malformed lines)."""
    return _read_jsonl_rows(paths.pitfalls_pending_file)


def rotate_pitfalls(
    batch_ids: list[str], commit_sha: str | None, *, paths: LoopPaths = DEFAULT_PATHS
) -> None:
    """Drain the curated batch out of the pending queue after a successful commit.

    The fold is prose into ``execution.md`` with no per-id filter once merged, so
    — unlike the findings queue's ``hold_committed`` — consumed rows are rotated
    out *immediately* rather than held: a rejected PR loses them, recovered by
    re-collection when the same failure recurs. ``merge_concurrent=True`` re-reads
    under the lock so any row a concurrent collection tick appended while the
    curator agent ran is preserved (dedup is by ``pitfall_id``).
    """
    ids = set(batch_ids)
    consumed = [
        {**r, "consumed_category": "consumed_committed"}
        for r in _read_jsonl_rows(paths.pitfalls_pending_file)
        if r.get("pitfall_id") in ids
    ]
    rotate_queue_locked(
        pending_file=paths.pitfalls_pending_file,
        consumed_file=paths.pitfalls_consumed_file,
        lock_file=paths.pitfalls_lock_file,
        id_key="pitfall_id",
        held=[],
        consumed=consumed,
        commit_sha=commit_sha,
        merge_concurrent=True,
    )


# ---------------------------------------------------------------------------
# Queue: per-direction observation streams
# ---------------------------------------------------------------------------


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
    """Dedup ``observations`` on ``observation_id`` against active + consumed, then
    append the rows ``build_row`` produces. Shared by all observation streams.

    ``id_prefix`` namespaces the minted ``observation_id`` (``{run_id}/{prefix}{i}``).
    Streams that share one downstream corpus — and thus one corpus-wide idempotency
    set — must use distinct prefixes so a single ``run_id`` cannot collide across
    them (the adversarial + benign env streams both feed lessons-environment/; an
    ``inconclusive`` case runs both). Mirrors the ``benign/`` namespace in
    ``append_findings``."""
    with _flock(lock_file):
        existing = _load_jsonl_ids(queue_file, "observation_id") | _load_jsonl_ids(
            consumed_file, "observation_id"
        )
        rows: list[dict] = []
        for i, obs in enumerate(observations):
            obs_id = f"{run_id}/{id_prefix}{i}"
            if obs_id in existing:
                continue
            rows.append(build_row(i, obs, obs_id))
        return _append_jsonl(queue_file, rows)


def append_actor_observations(
    judge_doc: dict,
    run_id: str,
    alert_rule_key: str,
    learning_run_dir: Path,
    *,
    paths: LoopPaths = DEFAULT_PATHS,
) -> int:
    """Append judge ``actor_observations`` to the actor pending queue.

    The producer's only outcome filter is ``skip-passthrough`` (defensive — the judge
    emits none on SKIP); the author owns the caught/incoherent/survived policy.
    """
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

    return _append_observations(
        paths.actor_observations_file,
        paths.actor_observations_consumed_file,
        paths.actor_observations_lock_file,
        run_id, observations, build_row,
    )


def _anchor_with_case_key(judge_rule_ids: Any, alert_rule_key: str) -> list[str]:
    """Guarantee the case's deterministic rule key leads the stored anchor.

    The judge free-reads ``alert_rule_ids``; the benign actor + forward-check query
    with ``derive_alert_rule_key``. Unioning the canonical key in (leading) keeps the
    lesson retrievable for its own source case regardless of how the judge phrased the
    rule id, while preserving the judge's cross-rule generalizations.
    """
    ids = judge_rule_ids if isinstance(judge_rule_ids, list) else [judge_rule_ids]
    ids = [str(r) for r in ids if str(r).strip()]
    if alert_rule_key and alert_rule_key not in ids:
        ids = [alert_rule_key, *ids]
    return ids


@dataclass(frozen=True)
class _EnvFactStream:
    """One environment-observation queue + its id/provenance namespace. The benign
    and adversarial env streams differ only in these fields; the row shape is defined
    once in ``_append_env_fact_observations`` so the shared corpus can't drift."""

    outcome_keyword: Callable[[Any], str]
    queue_file: Path
    consumed_file: Path
    lock_file: Path
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
    """Append judge ``environment_observations`` to one env queue feeding the SHARED
    lessons-environment/ corpus (issue #298). The two sources differ only in their
    outcome-keyword enum, queue paths, id namespace, and ``provenance`` tag — the env
    row shape (the retrieval keys the curator and ``verify_forward_env.py`` read) is
    one definition here so the streams can't drift apart in the shared corpus."""
    outcome_keyword = stream.outcome_keyword
    queue_file, consumed_file = stream.queue_file, stream.consumed_file
    lock_file, id_prefix, provenance = stream.lock_file, stream.id_prefix, stream.provenance
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
        # The judge omits `subject` for observations not about one named referent;
        # carry it only when supplied so the curator never writes `subject: null`.
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
        queue_file, consumed_file, lock_file,
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
    """Append benign-judge ``environment_observations`` to the env queue (FP mirror of
    ``append_actor_observations``). Rows carry the retrieval keys the curator and
    ``verify_forward_env.py`` read directly, tagged ``provenance: benign``."""
    return _append_env_fact_observations(
        judge_benign_doc, run_id, alert_rule_key, learning_run_dir,
        paths=paths,
        stream=_EnvFactStream(
            outcome_keyword=_benign_outcome_keyword,
            queue_file=paths.environment_observations_file,
            consumed_file=paths.environment_observations_consumed_file,
            lock_file=paths.environment_observations_lock_file,
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
    """Append the adversarial judge's ``environment_observations`` to the SHARED
    lessons-environment/ corpus, via a dedicated adversarial env queue (issue #298).

    The adversarial direction's finding-bearing outcomes are ``caught``/``incoherent``
    (a grounded misprediction whose refutation cites real telemetry); the env author's
    adversarial config owns that outcome policy. Ids are namespaced ``adv-env/`` so they
    cannot collide with benign env ids from the same ``run_id`` in the shared corpus's
    idempotency set; rows are tagged ``provenance: adversarial``."""
    return _append_env_fact_observations(
        judge_doc, run_id, alert_rule_key, learning_run_dir,
        paths=paths,
        stream=_EnvFactStream(
            outcome_keyword=_outcome_keyword,
            queue_file=paths.actor_environment_observations_file,
            consumed_file=paths.actor_environment_observations_consumed_file,
            lock_file=paths.actor_environment_observations_lock_file,
            id_prefix="adv-env/",
            provenance="adversarial",
        ),
    )
