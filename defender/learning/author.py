#!/usr/bin/env python3
"""Defender learning-loop V0.1 author.

Replaces the V0 stub at ``loop.py:invoke_stub_author``. The shape is
**deterministic Python pre-flight + LLM agent + deterministic Python
post-flight**:

  Pre-flight (Python):
    1. fcntl lock on _pending/.lock — concurrent ticks refuse cleanly.
    2. Clean-scope check: defender/lessons/ must be git-clean. Atomicity
       assumes a clean baseline so we can roll back on failure.
    3. Read the batch from _pending/findings.jsonl.
    4. Ground-truth gate: skip findings whose source case is
       inconclusive (no ground truth → forward check inapplicable).
    5. Idempotency: skip findings whose finding_id is already cited in
       any existing lesson's source_finding_ids.

  Agent invocation (Claude Code, file-edit + Bash tools):
    Hand the remaining findings to the curator agent
    (``author.md``). It enumerates existing lessons, decides
    new/fold/skip per finding, runs ``verify_forward.py`` on each
    edit, commits, and emits a final ``AUTHOR_RESULT: {...}`` line.

  Post-flight (Python):
    6. Parse AUTHOR_RESULT. Cross-check against git: if commit_sha is
       claimed, HEAD must match and only touch defender/lessons/. If
       no commit, defender/lessons/ must be clean.
    7. Rotate the queue atomically (tmp file + os.replace). Held
       findings stay in findings.jsonl; consumed findings append to
       consumed.jsonl with category + consumed_at + commit_sha.
    8. If no commit but there are held forward-BAD entries, write a
       one-line summary to _pending/held_report.log so the held-back
       surface isn't silent on no-commit runs.

The agent itself owns lesson dedup/fold judgment and the per-edit
forward gate; this module just enforces the transaction envelope.
"""
from __future__ import annotations

import datetime as _dt
import fcntl
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
LESSONS_DIR = REPO_ROOT / "defender" / "lessons"
RUNS_DIR = LEARNING_DIR / "runs"
PENDING_DIR = LEARNING_DIR / "_pending"
PENDING_FILE = PENDING_DIR / "findings.jsonl"
CONSUMED_FILE = PENDING_DIR / "consumed.jsonl"
LOCK_FILE = PENDING_DIR / ".lock"
HELD_REPORT = PENDING_DIR / "held_report.log"

AUTHOR_PROMPT = LEARNING_DIR / "author.md"
VERIFY_SCRIPT = LEARNING_DIR / "verify_forward.py"

AUTHOR_MODEL = os.environ.get("LEARNING_AUTHOR_MODEL", "claude-sonnet-4-6")
AUTHOR_TIMEOUT = int(os.environ.get("LEARNING_AUTHOR_TIMEOUT_SECONDS", "1800"))


class AuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort, queue stays intact."""


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def acquire_lock() -> Any:
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    fh = LOCK_FILE.open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        return None
    return fh


def release_lock(fh: Any) -> None:
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def assert_clean_lessons_dir() -> None:
    LESSONS_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(LESSONS_DIR)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    if proc.stdout.strip():
        raise AuthorError(
            "defender/lessons/ has uncommitted changes — refusing to author. "
            f"Output:\n{proc.stdout}"
        )


def read_batch() -> list[dict]:
    if not PENDING_FILE.is_file():
        return []
    out = []
    for line in PENDING_FILE.read_text().splitlines():
        s = line.strip()
        if not s:
            continue
        out.append(json.loads(s))
    return out


def disposition_for(run_id: str) -> str | None:
    """Return normalized_disposition from runs/<run_id>/source_refs.yaml.

    Returns None if the file or field is missing — caller routes that as
    "no ground truth" (held).
    """
    refs = RUNS_DIR / run_id / "source_refs.yaml"
    if not refs.is_file():
        return None
    try:
        doc = yaml.safe_load(refs.read_text())
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    val = doc.get("normalized_disposition")
    return val if isinstance(val, str) else None


_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---", re.DOTALL)


def existing_finding_ids() -> set[str]:
    """Union of source_finding_ids across all lesson frontmatter."""
    ids: set[str] = set()
    if not LESSONS_DIR.is_dir():
        return ids
    for path in sorted(LESSONS_DIR.glob("*.md")):
        text = path.read_text()
        m = _FRONTMATTER_RE.match(text)
        if not m:
            continue
        try:
            doc = yaml.safe_load(m.group(1))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        sids = doc.get("source_finding_ids") or []
        if isinstance(sids, list):
            for sid in sids:
                if isinstance(sid, str):
                    ids.add(sid)
    return ids


# ---------------------------------------------------------------------------
# Agent invocation
# ---------------------------------------------------------------------------


_RESULT_RE = re.compile(r"^AUTHOR_RESULT:\s*(\{.*\})\s*$", re.MULTILINE)


def invoke_agent(findings: list[dict], batch_id: str) -> dict:
    """Spawn the curator agent. Returns parsed AUTHOR_RESULT dict."""
    user_prompt = (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: defender/lessons/\n"
        f"findings ({len(findings)}):\n"
        f"{json.dumps(findings, indent=2)}\n"
    )
    cmd = [
        "claude",
        "--print",
        "--model",
        AUTHOR_MODEL,
        "--system-prompt-file",
        str(AUTHOR_PROMPT),
        "--permission-mode",
        "acceptEdits",
    ]
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        input=user_prompt,
        capture_output=True,
        text=True,
        timeout=AUTHOR_TIMEOUT,
    )
    if proc.returncode != 0:
        raise AuthorError(
            f"author agent failed (rc={proc.returncode}):\n"
            f"stderr: {proc.stderr[-2000:]}"
        )
    matches = _RESULT_RE.findall(proc.stdout)
    if not matches:
        raise AuthorError(
            "author agent did not emit AUTHOR_RESULT line:\n"
            + proc.stdout[-2000:]
        )
    try:
        return json.loads(matches[-1])
    except json.JSONDecodeError as e:
        raise AuthorError(f"AUTHOR_RESULT JSON invalid: {e}\n{matches[-1]}") from e


# ---------------------------------------------------------------------------
# Post-flight
# ---------------------------------------------------------------------------


def git_head_sha() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def head_changed_only_lessons() -> bool:
    proc = subprocess.run(
        ["git", "show", "--name-only", "--pretty=format:", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    files = [f for f in proc.stdout.splitlines() if f.strip()]
    if not files:
        return False
    return all(f.startswith("defender/lessons/") for f in files)


def lessons_dir_clean() -> bool:
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(LESSONS_DIR)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return not proc.stdout.strip()


def _result_list(result: dict, key: str) -> list[Any]:
    value = result.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise AuthorError(f"AUTHOR_RESULT field {key!r} must be a list")
    return value


def verify_agent_state(result: dict) -> None:
    commit_sha = result.get("commit_sha")
    committed = _result_list(result, "committed")
    if committed and not commit_sha:
        raise AuthorError(
            "author reported committed findings without a commit_sha; refusing to rotate queue"
        )
    if commit_sha:
        head = git_head_sha()
        if commit_sha != head:
            raise AuthorError(
                f"author claimed commit_sha={commit_sha} but HEAD={head}"
            )
        if not head_changed_only_lessons():
            raise AuthorError(
                "HEAD commit touches files outside defender/lessons/; refusing to rotate queue"
            )
        if not lessons_dir_clean():
            raise AuthorError(
                "author committed but defender/lessons/ still has uncommitted edits"
            )
    else:
        if not lessons_dir_clean():
            raise AuthorError(
                "author skipped commit but defender/lessons/ has uncommitted edits"
            )


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def rotate_queue(
    *,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
) -> None:
    """Atomic rewrite of findings.jsonl + append to consumed.jsonl."""
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    tmp = PENDING_FILE.with_suffix(".jsonl.tmp")
    with tmp.open("w") as fh:
        for entry in held:
            fh.write(json.dumps(entry) + "\n")
    os.replace(tmp, PENDING_FILE)
    if consumed:
        now = _now_iso()
        with CONSUMED_FILE.open("a") as fh:
            for entry in consumed:
                rec = dict(entry)
                rec.setdefault("consumed_at", now)
                if rec.get("consumed_category") == "consumed_committed" and commit_sha:
                    rec["consumed_commit"] = commit_sha
                fh.write(json.dumps(rec) + "\n")


def write_held_report(
    *, batch_id: str, held_forward_bad: list[dict], skipped: list[dict]
) -> None:
    """Single-line summary for no-commit runs.

    The agent surfaces held lessons in the commit message normally; if
    nothing committed, we still want a human-grep-able trace that BAD
    lessons existed.
    """
    if not held_forward_bad and not skipped:
        return
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    line = (
        f"{_now_iso()} batch={batch_id} "
        f"forward_bad={len(held_forward_bad)} "
        f"skipped={len(skipped)} "
        f"forward_bad_ids={[h.get('finding_id') for h in held_forward_bad]} "
        f"skipped_ids={[s.get('finding_id') for s in skipped]}\n"
    )
    with HELD_REPORT.open("a") as fh:
        fh.write(line)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _log(msg: str) -> None:
    print(f"[author] {msg}", file=sys.stderr)


def _by_id(findings: list[dict]) -> dict[str, dict]:
    return {f["finding_id"]: f for f in findings}


def _result_finding_id(bucket: str, entry: Any) -> str:
    if bucket == "committed":
        if not isinstance(entry, str) or not entry:
            raise AuthorError(
                "AUTHOR_RESULT committed entries must be non-empty finding_id strings"
            )
        return entry

    if not isinstance(entry, dict):
        raise AuthorError(f"AUTHOR_RESULT {bucket} entries must be objects")
    fid = entry.get("finding_id")
    if not isinstance(fid, str) or not fid:
        raise AuthorError(
            f"AUTHOR_RESULT {bucket} entries must include a non-empty finding_id"
        )
    return fid


def validate_agent_result_partition(result: dict, to_author: list[dict]) -> None:
    """Require each authored finding to appear in exactly one result bucket."""
    expected = {f["finding_id"] for f in to_author}
    occurrences: dict[str, list[str]] = {}

    for entry in _result_list(result, "committed"):
        fid = _result_finding_id("committed", entry)
        occurrences.setdefault(fid, []).append("committed")
    for bucket in ("held_forward_bad", "consumed_skip"):
        for entry in _result_list(result, bucket):
            fid = _result_finding_id(bucket, entry)
            occurrences.setdefault(fid, []).append(bucket)

    unknown = sorted(fid for fid in occurrences if fid not in expected)
    if unknown:
        raise AuthorError(f"author result contains unknown findings: {unknown}")

    repeated = {
        fid: buckets
        for fid, buckets in sorted(occurrences.items())
        if len(buckets) != 1
    }
    if repeated:
        raise AuthorError(
            "author result classified findings more than once: "
            + json.dumps(repeated, sort_keys=True)
        )

    unseen = sorted(expected - occurrences.keys())
    if unseen:
        raise AuthorError(f"author result missing findings: {unseen}")


def run_batch() -> int:
    lock_fh = acquire_lock()
    if lock_fh is None:
        _log("lock held by another process — skipping this tick")
        return 0
    try:
        try:
            assert_clean_lessons_dir()
        except AuthorError as e:
            _log(f"FATAL: {e}")
            return 2

        batch = read_batch()
        if not batch:
            _log("queue empty — nothing to author")
            return 0

        all_findings = _by_id(batch)
        existing_ids = existing_finding_ids()

        held: list[dict] = []  # stay in findings.jsonl
        consumed_idempotent: list[dict] = []
        for entry in batch:
            fid = entry["finding_id"]
            if fid in existing_ids:
                rec = dict(entry)
                rec["consumed_category"] = "consumed_idempotent"
                consumed_idempotent.append(rec)
                continue
            disp = disposition_for(entry["run_id"])
            if disp != "benign":
                # No confident ground truth (inconclusive / unknown). Hold,
                # don't consume — a future fixture/policy may re-enable.
                rec = dict(entry)
                rec["held_reason"] = (
                    f"no_ground_truth(disposition={disp!r})"
                )
                held.append(rec)
                continue

        # Findings that pass both gates go to the agent.
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
            try:
                result = invoke_agent(to_author, batch_id)
            except AuthorError as e:
                _log(f"FATAL: {e}")
                return 2
            try:
                verify_agent_state(result)
                validate_agent_result_partition(result, to_author)
            except AuthorError as e:
                _log(f"FATAL: {e}")
                return 2
            commit_sha = result.get("commit_sha")
            for fid in _result_list(result, "committed"):
                src = all_findings.get(fid)
                if src is None:
                    raise AuthorError(
                        f"author committed unknown finding_id={fid!r}"
                    )
                rec = dict(src)
                rec["consumed_category"] = "consumed_committed"
                committed.append(rec)
            for entry in _result_list(result, "held_forward_bad"):
                fid = entry.get("finding_id")
                src = all_findings.get(fid)
                if src is None:
                    raise AuthorError(
                        f"author held unknown finding_id={fid!r}"
                    )
                rec = dict(src)
                rec["held_reason"] = (
                    f"forward_bad: {entry.get('reason', '')}"
                )
                held_forward_bad.append(rec)
            for entry in _result_list(result, "consumed_skip"):
                fid = entry.get("finding_id")
                src = all_findings.get(fid)
                if src is None:
                    raise AuthorError(
                        f"author skipped unknown finding_id={fid!r}"
                    )
                rec = dict(src)
                rec["consumed_category"] = "consumed_skip"
                rec["skip_reason"] = entry.get("reason", "")
                consumed_skip.append(rec)

        try:
            rotate_queue(
                held=held + held_forward_bad,
                consumed=consumed_idempotent + committed + consumed_skip,
                commit_sha=commit_sha,
            )
        except AuthorError as e:
            _log(f"FATAL during rotate: {e}")
            return 2

        if commit_sha is None:
            write_held_report(
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
    finally:
        release_lock(lock_fh)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
