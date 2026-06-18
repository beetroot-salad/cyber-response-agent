#!/usr/bin/env python3
"""Defender learning-loop V0.1 author.

Replaces the V0 stub at ``loop.py:invoke_stub_author``. The shape is
**deterministic Python pre-flight + LLM agent + deterministic Python
post-flight**:

  Pre-flight (Python):
    1. fcntl lock on _pending/.lock — concurrent ticks refuse cleanly.
       Then acquire the shared repo lock (defender/learning/_author.lock)
       so the actor author can't interleave its fold-and-commit with
       ours. Queue lock first, repo lock second; release in reverse.
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

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

# Subprocess driver + repo-lock helpers shared with author_actor.py.
from defender.learning import _author_runner as _runner
from defender.learning import _author_shared as _shared
from defender.learning._loop_config import DEFAULT_PATHS
from defender.learning._loop_persist import (
    _flock,
    _read_jsonl_rows,
    rotate_queue_locked,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
LESSONS_DIR = REPO_ROOT / "defender" / "lessons"
# Mutable learning state resolves from DEFAULT_PATHS so it honors
# DEFENDER_LEARNING_STATE_DIR — the same single location the producer
# (_loop_persist.append_findings) writes to. Prompts/corpus stay repo-relative.
RUNS_DIR = DEFAULT_PATHS.runs_dir
PENDING_DIR = DEFAULT_PATHS.pending_dir
PENDING_FILE = DEFAULT_PATHS.pending_file
FINDINGS_LOCK_FILE = DEFAULT_PATHS.findings_lock_file
CONSUMED_FILE = PENDING_DIR / "consumed.jsonl"
LOCK_FILE = PENDING_DIR / ".lock"
HELD_REPORT = PENDING_DIR / "held_report.log"

AUTHOR_PROMPT = LEARNING_DIR / "author.md"
VERIFY_SCRIPT = LEARNING_DIR / "verify_forward.py"

AUTHOR_MODEL = os.environ.get("LEARNING_AUTHOR_MODEL", "claude-sonnet-4-6")
AUTHOR_TIMEOUT = int(os.environ.get("LEARNING_AUTHOR_TIMEOUT_SECONDS", "1800"))
AUTHOR_EFFORT = os.environ.get("LEARNING_AUTHOR_EFFORT")  # low|medium|high|xhigh|max


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
    """Snapshot the findings queue under the producer's lock.

    Unlike the observation authors, this author's instance lock (``.lock``) and
    the shared repo lock are NOT the lock ``append_findings`` writes under
    (``.findings.lock``), so a concurrent live run can be mid-append while we
    read. Take ``FINDINGS_LOCK_FILE`` briefly (released before the minutes-long
    agent call) so we never read a torn multi-line append, and parse tolerantly
    so a blank/torn line left by a crashed prior append is skipped, not raised
    (the row stays queued and is picked up next tick)."""
    if not PENDING_FILE.is_file():
        return []
    with _flock(FINDINGS_LOCK_FILE):
        return _read_jsonl_rows(PENDING_FILE)


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


AUTHOR_RUN_LOG = PENDING_DIR / "author_run.jsonl"


def invoke_agent(findings: list[dict], batch_id: str) -> dict:
    """Spawn the curator agent. Returns parsed AUTHOR_RESULT dict.

    Subprocess driver lives in ``_author_runner.invoke_claude_print`` —
    shared with ``author_actor.py``. This wrapper builds the
    defender-specific user prompt + allowed-tools spec and translates
    ``RunnerError`` into ``AuthorError`` so the caller's error path is
    unchanged.
    """
    verifier_py = _runner.resolve_verifier_python(REPO_ROOT)
    user_prompt = (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: defender/lessons/\n"
        f"--direction <direction> <lesson_path> <run_id>\n"
        f"verify_batch_command: {verifier_py} defender/learning/verify_batch.py "
        f"defender/learning/verify_forward.py "
        f"<lesson_path>=<run_id>=<direction> [<lesson_path>=<run_id>=<direction> ...]\n"
        f"findings ({len(findings)}):\n"
        f"{json.dumps(findings, indent=2)}\n"
    )
    allowed_tools = (
        "Read,Glob,Grep,"
        "Edit(defender/lessons/**),Write(defender/lessons/**),"
        "Bash(git add:*),Bash(git commit:*),Bash(git checkout:*),"
        "Bash(git rev-parse:*),Bash(git status:*),Bash(git diff:*),"
        f"Bash({verifier_py} defender/learning/verify_batch.py:*),"
        f"Bash({verifier_py} defender/learning/verify_forward.py:*),"
        "Bash(rm defender/lessons/*.md),"
        f"Bash(rm {LESSONS_DIR}/*.md)"
    )
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    options = _runner.RunnerOptions(
        system_prompt_file=AUTHOR_PROMPT,
        allowed_tools=allowed_tools,
        model=AUTHOR_MODEL,
        effort=AUTHOR_EFFORT,
        timeout_seconds=AUTHOR_TIMEOUT,
        cwd=REPO_ROOT,
        log_path=AUTHOR_RUN_LOG,
        result_marker="AUTHOR_RESULT:",
        batch_id=batch_id,
    )
    try:
        return _runner.invoke_claude_print(options, user_prompt, _log)
    except _runner.RunnerError as e:
        raise AuthorError(str(e)) from e


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
    for f in files:
        if not f.startswith("defender/lessons/"):
            return False
        # Lesson files only — agent improvisations like .py shims would
        # land in scope but aren't lessons.
        if not f.endswith(".md"):
            return False
    return True


def _canonical_sha(sha: str) -> str:
    """Resolve a (possibly abbreviated) sha to the full commit hash."""
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", sha],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise AuthorError(
            f"author claimed commit_sha={sha!r} but git rev-parse rejects it: "
            f"{proc.stderr.strip()}"
        )
    return proc.stdout.strip()


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
        # Agents routinely emit short SHAs ("97f8711"); compare against
        # canonical form rather than failing on length mismatch.
        canonical = _canonical_sha(commit_sha)
        if canonical != head:
            raise AuthorError(
                f"author claimed commit_sha={commit_sha} ({canonical}) but HEAD={head}"
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
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def rotate_queue(
    *,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
) -> None:
    """Drain findings.jsonl under the findings flock, preserving concurrent appends."""
    rotate_queue_locked(
        pending_file=PENDING_FILE,
        consumed_file=CONSUMED_FILE,
        lock_file=FINDINGS_LOCK_FILE,
        id_key="finding_id",
        held=held,
        consumed=consumed,
        commit_sha=commit_sha,
    )


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


def run_batch(*, hold_committed: bool = False) -> int:
    """Drain a findings batch into the lessons corpus.

    ``hold_committed`` (set by the serial author drain, which commits onto an
    unmerged PR branch) keeps the just-committed findings in the queue instead of
    rotating them to ``consumed.jsonl``, so a rejected/edited PR can't strand
    them: they re-author next batch unless the PR merged — in which case
    ``existing_finding_ids()`` (reading the post-fetch ``origin/main`` corpus)
    filters them to ``consumed_idempotent`` and they rotate out cleanly. Standalone
    callers leave it False (today's commit-and-rotate behavior)."""
    lock_fh = acquire_lock()
    if lock_fh is None:
        _log("lock held by another process — skipping this tick")
        return 0
    repo_lock = None
    try:
        try:
            repo_lock = _shared.acquire_repo_lock()
        except TimeoutError as e:
            _log(f"repo lock unavailable: {e}; queue intact")
            return 0
        try:
            assert_clean_lessons_dir()
        except AuthorError as e:
            _log(f"FATAL: {e}")
            return 2
        return _run_batch_inner(hold_committed=hold_committed)
    finally:
        if repo_lock is not None:
            _shared.release_repo_lock(repo_lock)
        release_lock(lock_fh)


def _run_batch_inner(*, hold_committed: bool = False) -> int:
    batch = read_batch()
    if not batch:
        _log("queue empty — nothing to author")
        return 0
    all_findings = _by_id(batch)
    held, consumed_idempotent = _partition_pre_author(batch)
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
            _author_to_author(to_author, all_findings, batch_id)
        )
        if rc != 0:
            return rc

    # Under the drain (hold_committed) the commit lands on an unmerged PR branch,
    # so keep `committed` in the queue (stripped of the consumed stamp) rather than
    # rotating it to consumed.jsonl. `consumed_idempotent` (already in origin/main)
    # and `consumed_skip` (no lesson anchor → would re-author forever if held) ALWAYS
    # rotate out. See author_branch.py / platform-design §4.4.
    held_committed, rotated_committed = _shared.partition_committed(
        committed, hold_committed=hold_committed
    )
    try:
        rotate_queue(
            held=held + held_forward_bad + held_committed,
            consumed=consumed_idempotent + rotated_committed + consumed_skip,
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


def _has_confident_ground_truth(direction: str, disposition: str | None) -> bool:
    """Whether a finding's disposition confidently confirms its direction.

    The two learning directions confirm on opposite dispositions: an
    adversarial finding (missed attack) is a confident false-negative only when
    the defender's disposition was ``benign``; a benign finding (over-escalation)
    is a confident false-positive only when the disposition was ``malicious``.
    ``inconclusive`` and unknown dispositions confirm neither and are held.
    """
    if direction == "benign":
        return disposition == "malicious"
    return disposition == "benign"


def _partition_pre_author(batch: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split the queue into (held, consumed_idempotent) before the agent runs.

    held → no confident ground truth for the finding's direction; stays in
    findings.jsonl. consumed_idempotent → already-committed findings the agent
    shouldn't see again.
    """
    existing_ids = existing_finding_ids()
    held: list[dict] = []
    consumed_idempotent: list[dict] = []
    for entry in batch:
        fid = entry["finding_id"]
        if fid in existing_ids:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_idempotent"
            consumed_idempotent.append(rec)
            continue
        disp = disposition_for(entry["run_id"])
        direction = entry["direction"]
        if not _has_confident_ground_truth(direction, disp):
            rec = dict(entry)
            rec["held_reason"] = (
                f"no_ground_truth(direction={direction!r}, disposition={disp!r})"
            )
            held.append(rec)
    return held, consumed_idempotent


def _author_to_author(
    to_author: list[dict], all_findings: dict[str, dict], batch_id: str,
) -> tuple[int, str | None, list[dict], list[dict], list[dict]]:
    """Run the agent on `to_author` and partition its result.

    Returns (rc, commit_sha, committed, held_forward_bad, consumed_skip).
    rc != 0 means a FATAL happened and the caller should bail with that
    code; the queue stays intact via the outer lock/rotate flow.
    """
    try:
        result = invoke_agent(to_author, batch_id)
    except AuthorError as e:
        _log(f"FATAL: {e}")
        return 2, None, [], [], []
    try:
        verify_agent_state(result)
        validate_agent_result_partition(result, to_author)
    except AuthorError as e:
        _log(f"FATAL: {e}")
        return 2, None, [], [], []
    commit_sha = result.get("commit_sha")
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
