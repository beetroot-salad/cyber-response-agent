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
from pathlib import Path
from typing import Any, Callable

import yaml

import lead_repository
from _loop_config import DEFAULT_PATHS, LoopError, LoopPaths
from _loop_validate import _benign_outcome_keyword, _outcome_keyword


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


def persist_run(
    run_dir: Path,
    learning_run_dir: Path,
    *,
    actor_story: str,
    story_name: str,
    judge_yaml: str | None,
    judge_name: str,
    telemetry_yaml: str | None,
    telemetry_name: str,
    disposition: str,
    alert_rule_key: str,
) -> None:
    """Persist one direction's per-run artifacts under direction-suffixed names.

    The four input copies + source_refs are shared across directions (an
    ``inconclusive`` run that runs both writes them once each; the copies are
    idempotent). ``judge_yaml`` / ``telemetry_yaml`` are the fence-stripped, validated
    YAML — caller-side raw text (if any) belongs in a ``*.raw.txt`` companion.
    """
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
    audit-only finding type is filtered (``detection-confirmed`` adversarially,
    ``disposition-confirmed`` benignly). Each row is tagged with ``direction`` so the
    shared curator applies the right ground-truth gate; benign ids live in a
    ``benign/`` namespace so the two directions never collide on a ``run_id``.
    """
    if direction == "benign":
        outcome = _benign_outcome_keyword(judge_doc["outcome"])
        audit_only_type, namespace = "disposition-confirmed", "benign/"
    else:
        outcome = _outcome_keyword(judge_doc["outcome"])
        audit_only_type, namespace = "detection-confirmed", ""
    src = _source_run_dir(learning_run_dir, paths.repo_root)
    appended = 0
    paths.pending_dir.mkdir(parents=True, exist_ok=True)
    with _flock(paths.findings_lock_file):
        with paths.pending_file.open("a") as fh:
            for n, f in enumerate(judge_doc["defender_findings"]):
                if f["type"] == audit_only_type:
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
    ``verify_forward_env.py`` read directly."""
    outcome = _benign_outcome_keyword(judge_benign_doc["outcome"])
    if outcome == "skip-passthrough":
        return 0
    observations = judge_benign_doc.get("environment_observations") or []
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
        })
        return row

    return _append_observations(
        paths.environment_observations_file,
        paths.environment_observations_consumed_file,
        paths.environment_observations_lock_file,
        run_id, observations, build_row,
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
    adversarial config owns that outcome policy. Rows carry the same retrieval keys the
    benign env producer emits — ``alert_rule_key`` + ``source_run_dir`` are what
    ``verify_forward_env.py`` reads, and ``alert_rule_ids``/``entities`` drive
    retrieval. Ids are namespaced ``adv-env/`` so they cannot collide with benign env
    ids from the same ``run_id`` in the shared corpus's idempotency set."""
    outcome = _outcome_keyword(judge_doc["outcome"])
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
            "provenance": "adversarial",
        })
        return row

    return _append_observations(
        paths.actor_environment_observations_file,
        paths.actor_environment_observations_consumed_file,
        paths.actor_environment_observations_lock_file,
        run_id, observations, build_row,
        id_prefix="adv-env/",
    )
