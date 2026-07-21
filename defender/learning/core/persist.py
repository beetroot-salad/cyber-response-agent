from __future__ import annotations

import contextlib
import fcntl
import json
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

from defender._clock import now_iso
from defender._io import append_jsonl, read_jsonl_rows, write_atomic
from defender.learning.core.config import (
    ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES,
    BENIGN_AUDIT_ONLY_FINDING_TYPES,
    DEFAULT_PATHS,
    RunUnprocessable,
    LoopPaths,
    QueueChannel,
    RunPaths,
)
from defender.learning.core.validate import _benign_outcome_keyword, _outcome_keyword




@contextlib.contextmanager
def _flock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


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
    *,
    merge: bool,
) -> None:
    if merge:
        processed = {e[id_key] for e in held} | {e[id_key] for e in consumed}
        current = read_jsonl_rows(pending_file)
        survivors = list(held) + [r for r in current if r.get(id_key) not in processed]
    else:
        survivors = list(held)
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
    merge_concurrent: bool = True,
) -> None:
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


def _copy_shared_inputs(run_dir: Path, learning_run_dir: Path) -> None:
    learning_run_dir.mkdir(parents=True, exist_ok=True)
    src_paths, dst_paths = RunPaths(run_dir), RunPaths(learning_run_dir)
    with _SHARED_INPUTS_LOCK:
        for name in _SHARED_COPY_ARTIFACTS:
            src = getattr(src_paths, name)
            if not src.is_file():
                raise RunUnprocessable(f"missing source artifact for persist: {src}")
            dst = getattr(dst_paths, name)
            if name == "investigation":
                from defender.skills.invlang.validate import validate_companion

                errors = validate_companion(src.read_text(encoding="utf-8"), None)
                if errors:
                    raise RunUnprocessable(
                        f"investigation.md failed invlang validation on the copy path "
                        f"({src}): {errors}"
                    )
            shutil.copy2(src, dst)
        loaded = run_dir / "lessons_loaded.jsonl"
        if loaded.is_file():
            shutil.copy2(loaded, learning_run_dir / "lessons_loaded.jsonl")
        from defender.learning import lead_repository

        lead_repository.stage_tables(run_dir, learning_run_dir)


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
        (learning_run_dir / "source_refs.yaml").write_text(yaml.safe_dump(source_refs), encoding="utf-8")


@dataclass(frozen=True)
class DirectionArtifacts:

    actor_story: str
    story_name: str
    judge_yaml: str | None
    judge_name: str
    telemetry_yaml: str | None
    telemetry_name: str


def persist_run(
    dirs: RunPaths,
    *,
    artifacts: DirectionArtifacts,
    disposition: str,
    alert_rule_key: str,
) -> None:
    run_dir, learning_run_dir = dirs.run_dir, dirs.learning_run_dir
    assert learning_run_dir is not None, "persist_run requires a learning leg dir"
    actor_story, story_name = artifacts.actor_story, artifacts.story_name
    judge_yaml, judge_name = artifacts.judge_yaml, artifacts.judge_name
    telemetry_yaml, telemetry_name = artifacts.telemetry_yaml, artifacts.telemetry_name
    _copy_shared_inputs(run_dir, learning_run_dir)
    (learning_run_dir / story_name).write_text(actor_story, encoding="utf-8")
    if telemetry_yaml is not None:
        (learning_run_dir / telemetry_name).write_text(telemetry_yaml, encoding="utf-8")
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
    with _flock(paths.findings_lock_file):
        return append_jsonl(paths.pending_file, rows)




def append_pitfalls(rows: list[dict], *, paths: LoopPaths = DEFAULT_PATHS) -> int:
    if not rows:
        return 0
    with _flock(paths.pitfalls.lock):
        return append_jsonl(paths.pitfalls.file, rows)


def read_pitfalls(paths: LoopPaths = DEFAULT_PATHS) -> list[dict]:
    return read_jsonl_rows(paths.pitfalls.file)


def rotate_pitfalls(
    batch_ids: list[str], commit_sha: str | None, *, paths: LoopPaths = DEFAULT_PATHS
) -> None:
    ids = set(batch_ids)
    consumed = [
        {**r, "consumed_category": "consumed_committed"}
        for r in read_jsonl_rows(paths.pitfalls.file)
        if r.get("pitfall_id") in ids
    ]
    rotate_queue_locked(
        pending_file=paths.pitfalls.file,
        consumed_file=paths.pitfalls.consumed,
        lock_file=paths.pitfalls.lock,
        id_key="pitfall_id",
        held=[],
        consumed=consumed,
        commit_sha=commit_sha,
        merge_concurrent=True,
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
        ch.file, ch.consumed, ch.lock,
        run_id, observations, build_row,
    )


def _anchor_with_case_key(judge_rule_ids: Any, alert_rule_key: str) -> list[str]:
    ids = judge_rule_ids if isinstance(judge_rule_ids, list) else [judge_rule_ids]
    ids = [str(r) for r in ids if str(r).strip()]
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
        ch.file, ch.consumed, ch.lock,
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
