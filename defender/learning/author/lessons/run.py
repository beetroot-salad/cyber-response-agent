#!/usr/bin/env python3
from __future__ import annotations

import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import curator as _curator
from defender.learning.author import shared as _shared
from defender._yaml import safe_load
from defender._corpus import iter_lessons
from defender._io import read_jsonl_rows
from defender.learning.core.config import (
    AUTHOR_EFFORT,
    AUTHOR_MODEL,
    AUTHOR_REQUEST_LIMIT,
    AUTHOR_TIMEOUT,
    DEFAULT_PATHS,
    LoopPaths,
    make_logger,
    now_iso,
)
from defender.learning.core.persist import (
    _flock,
    rotate_queue_locked,
)




AuthorError = _shared.AuthorError


@dataclass(frozen=True)
class AuthorConfig:
    repo_root: Path
    lessons_dir: Path
    lessons_dir_rel: str
    runs_dir: Path
    pending_dir: Path
    pending_file: Path
    consumed_file: Path
    lock_file: Path
    findings_lock_file: Path
    repo_lock_file: Path
    repo_lock_wait_seconds: int
    held_report: Path
    author_run_log: Path
    author_prompt: Path
    invoke_agent: Callable[[list[dict], str, AuthorConfig], dict]
    author_model: str = AUTHOR_MODEL
    author_timeout: int = AUTHOR_TIMEOUT
    author_effort: str | None = AUTHOR_EFFORT
    manifest_seed: str | None = None


def build_author_config(
    paths: LoopPaths = DEFAULT_PATHS, *, manifest_seed: str | None = None
) -> AuthorConfig:
    return AuthorConfig(
        repo_root=paths.repo_root,
        lessons_dir=paths.lessons_dir,
        lessons_dir_rel=paths.lessons_dir_rel,
        runs_dir=paths.runs_dir,
        pending_dir=paths.pending_dir,
        pending_file=paths.pending_file,
        consumed_file=paths.pending_dir / "consumed.jsonl",
        lock_file=paths.pending_dir / ".lock",
        findings_lock_file=paths.findings_lock_file,
        repo_lock_file=paths.author_lock_file,
        repo_lock_wait_seconds=_shared.REPO_LOCK_WAIT_SECONDS,
        held_report=paths.pending_dir / "held_report.log",
        author_run_log=paths.pending_dir / "author_run.jsonl",
        author_prompt=paths.learning_dir / "author" / "lessons" / "prompt.md",
        invoke_agent=invoke_agent,
        manifest_seed=manifest_seed,
    )




def read_batch(cfg: AuthorConfig) -> list[dict]:
    if not cfg.pending_file.is_file():
        return []
    with _flock(cfg.findings_lock_file):
        return read_jsonl_rows(cfg.pending_file)


def disposition_for(cfg: AuthorConfig, run_id: str) -> str | None:
    refs = cfg.runs_dir / run_id / "source_refs.yaml"
    if not refs.is_file():
        return None
    try:
        doc = safe_load(refs.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    val = doc.get("normalized_disposition")
    return val if isinstance(val, str) else None


def existing_finding_ids(cfg: AuthorConfig) -> set[str]:
    ids: set[str] = set()
    for lesson in iter_lessons(
        cfg.lessons_dir, warn_label=lambda p: f"finding-id pre-flight: {p.name}"
    ):
        sids = lesson.fm.get("source_finding_ids") or []
        if isinstance(sids, list):
            ids.update(sid for sid in sids if isinstance(sid, str))
    return ids




def build_user_prompt(
    findings: list[dict], batch_id: str, cfg: AuthorConfig, *, salt: str | None = None
) -> str:
    return _shared.build_curator_user_prompt(
        findings, batch_id, corpus_dir=cfg.lessons_dir,
        corpus_dir_rel=cfg.lessons_dir_rel, label="findings",
        manifest_seed=cfg.manifest_seed,
        salt=salt,
    )


def invoke_agent(findings: list[dict], batch_id: str, cfg: AuthorConfig) -> dict:
    from defender.learning.author import curator_engine
    from defender.learning.author.verify_forward.checks import FINDINGS_CHECK

    cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    stage_salt = uuid.uuid4().hex
    return curator_engine.run_curator_stage(
        system_prompt_file=cfg.author_prompt,
        batch_id=batch_id,
        user_prompt=build_user_prompt(findings, batch_id, cfg, salt=stage_salt),
        corpus_dir=cfg.lessons_dir,
        check=FINDINGS_CHECK,
        runs_dir=cfg.runs_dir,
        pending=cfg.pending_file,
        queued_ids=frozenset(str(f["run_id"]) for f in findings if f.get("run_id")),
        repo_root=cfg.repo_root,
        learning_run_dir=cfg.pending_dir,
        log=_log,
        model=cfg.author_model,
        effort=cfg.author_effort,
        request_limit=AUTHOR_REQUEST_LIMIT,
        timeout=cfg.author_timeout,
        salt=stage_salt,
    )



def git_head_sha(repo_root: Path) -> str:
    return _shared.git_head_sha(repo_root)


def changes_outside_lessons(cfg: AuthorConfig) -> list[str]:
    return _shared.changes_outside(cfg.repo_root, cfg.lessons_dir_rel)


def commit_lessons(cfg: AuthorConfig, message: str) -> str | None:
    return _shared.commit_corpus(cfg.repo_root, cfg.lessons_dir, message)


def lessons_dir_clean(cfg: AuthorConfig) -> bool:
    return _shared.corpus_dir_clean(cfg.repo_root, cfg.lessons_dir)


def _result_list(result: dict, key: str) -> list[Any]:
    return _shared._result_list(result, key)


def _commit_message(result: dict) -> str:
    return _shared._commit_message(result, "findings")


def rotate_queue(
    cfg: AuthorConfig,
    *,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
) -> None:
    rotate_queue_locked(
        pending_file=cfg.pending_file,
        consumed_file=cfg.consumed_file,
        lock_file=cfg.findings_lock_file,
        id_key="finding_id",
        held=held,
        consumed=consumed,
        commit_sha=commit_sha,
    )


def write_held_report(
    cfg: AuthorConfig, *, batch_id: str, held_forward_bad: list[dict], skipped: list[dict]
) -> None:
    if not held_forward_bad and not skipped:
        return
    cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    line = (
        f"{now_iso()} batch={batch_id} "
        f"forward_bad={len(held_forward_bad)} "
        f"skipped={len(skipped)} "
        f"forward_bad_ids={[h.get('finding_id') for h in held_forward_bad]} "
        f"skipped_ids={[s.get('finding_id') for s in skipped]}\n"
    )
    with cfg.held_report.open("a", encoding="utf-8") as fh:
        fh.write(line)




_log = make_logger("author")


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths = DEFAULT_PATHS,
    cfg: AuthorConfig | None = None,
) -> int:
    if cfg is None:
        cfg = build_author_config(paths)
    return _shared.run_batch_envelope(
        queue_lock_file=cfg.lock_file,
        repo_lock_file=cfg.repo_lock_file,
        repo_lock_wait_seconds=cfg.repo_lock_wait_seconds,
        repo_root=cfg.repo_root,
        corpus_dir=cfg.lessons_dir,
        corpus_dir_rel=cfg.lessons_dir_rel,
        log=_log,
        inner=lambda: _run_batch_inner(cfg, hold_committed=hold_committed),
    )


def _run_batch_inner(cfg: AuthorConfig, *, hold_committed: bool = False) -> int:
    batch = read_batch(cfg)
    if not batch:
        _log("queue empty — nothing to author")
        return 0
    all_findings = _shared.by_id(batch, "finding_id")
    held, consumed_idempotent = _partition_pre_author(cfg, batch)
    gated_ids = {h["finding_id"] for h in held} | {
        c["finding_id"] for c in consumed_idempotent
    }
    to_author = [f for f in batch if f["finding_id"] not in gated_ids]

    batch_id = uuid.uuid4().hex[:12]
    _log(
        f"batch={batch_id} total={len(batch)} "
        f"to_author={len(to_author)} held={len(held)} "
        f"idempotent={len(consumed_idempotent)}"
    )

    commit_sha: str | None = None
    committed: list[dict] = []
    held_forward_bad: list[dict] = []
    consumed_skip: list[dict] = []
    if to_author:
        rc, commit_sha, committed, held_forward_bad, consumed_skip = (
            _author_to_author(cfg, to_author, all_findings, batch_id)
        )
        if rc != 0:
            return rc

    held_committed, rotated_committed = _shared.partition_committed(
        committed, hold_committed=hold_committed
    )
    try:
        rotate_queue(
            cfg,
            held=held + held_forward_bad + held_committed,
            consumed=consumed_idempotent + rotated_committed + consumed_skip,
            commit_sha=commit_sha,
        )
    except AuthorError as e:
        _log(f"FATAL during rotate: {e}")
        return 2
    if commit_sha is None:
        write_held_report(
            cfg,
            batch_id=batch_id,
            held_forward_bad=held_forward_bad,
            skipped=consumed_skip,
        )
    _log(
        f"done batch={batch_id} committed={len(committed)} "
        f"held_forward_bad={len(held_forward_bad)} "
        f"consumed_skip={len(consumed_skip)} "
        f"idempotent={len(consumed_idempotent)} "
        f"held_no_ground_truth={len(held)} "
        f"commit_sha={commit_sha}"
    )
    return 0


def _has_confident_ground_truth(direction: str, disposition: str | None) -> bool:
    if direction == "benign":
        return disposition == "malicious"
    return disposition == "benign"


def _partition_pre_author(cfg: AuthorConfig, batch: list[dict]) -> tuple[list[dict], list[dict]]:
    existing_ids = existing_finding_ids(cfg)
    held: list[dict] = []
    consumed_idempotent: list[dict] = []
    for entry in batch:
        fid = entry["finding_id"]
        if fid in existing_ids:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_idempotent"
            consumed_idempotent.append(rec)
            continue
        disp = disposition_for(cfg, entry["run_id"])
        direction = entry["direction"]
        if not _has_confident_ground_truth(direction, disp):
            rec = dict(entry)
            rec["held_reason"] = (
                f"no_ground_truth(direction={direction!r}, disposition={disp!r})"
            )
            held.append(rec)
    return held, consumed_idempotent


def _author_to_author(
    cfg: AuthorConfig, to_author: list[dict], all_findings: dict[str, dict], batch_id: str,
) -> tuple[int, str | None, list[dict], list[dict], list[dict]]:
    baseline_stray = changes_outside_lessons(cfg)
    try:
        result = cfg.invoke_agent(to_author, batch_id, cfg)
    except AuthorError as e:
        _log(f"FATAL: {e}")
        _curator._dead_letter_or_bump(
            to_author, queue_file=cfg.pending_file, pending_dir=cfg.pending_dir,
            id_key="finding_id", reason=str(e),
        )
        return 2, None, [], [], []
    try:
        _shared.verify_agent_state(
            cfg.repo_root, result, cfg.lessons_dir, cfg.lessons_dir_rel,
            "findings", baseline_stray,
        )
        _shared.validate_agent_result_partition(
            result, to_author, id_key="finding_id",
            buckets=("committed", "held_forward_bad", "consumed_skip"),
            noun="findings",
        )
        commit_sha: str | None = None
        if _result_list(result, "committed"):
            commit_sha = commit_lessons(cfg, _commit_message(result))
    except AuthorError as e:
        _log(f"FATAL: {e}")
        return 2, None, [], [], []
    committed: list[dict] = []
    held_forward_bad: list[dict] = []
    consumed_skip: list[dict] = []
    for fid in _result_list(result, "committed"):
        src = all_findings.get(fid)
        if src is None:
            raise AuthorError(f"author committed unknown finding_id={fid!r}")
        rec = dict(src)
        rec["consumed_category"] = "consumed_committed"
        committed.append(rec)
    for entry in _result_list(result, "held_forward_bad"):
        fid = entry.get("finding_id")
        src = all_findings.get(fid)
        if src is None:
            raise AuthorError(f"author held unknown finding_id={fid!r}")
        rec = dict(src)
        rec["held_reason"] = f"forward_bad: {entry.get('reason', '')}"
        held_forward_bad.append(rec)
    for entry in _result_list(result, "consumed_skip"):
        fid = entry.get("finding_id")
        src = all_findings.get(fid)
        if src is None:
            raise AuthorError(f"author skipped unknown finding_id={fid!r}")
        rec = dict(src)
        rec["consumed_category"] = "consumed_skip"
        rec["skip_reason"] = entry.get("reason", "")
        consumed_skip.append(rec)
    return 0, commit_sha, committed, held_forward_bad, consumed_skip


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
