#!/usr/bin/env python3
"""Environment lessons curator — consumer half of the env-observation queue.

The false-positive-direction analog of ``defender/learning/author_actor.py``.
It drains ``_pending/environment_observations.jsonl`` (produced by the benign
judge via ``loop.append_environment_observations``) into the checked-in
environment corpus at ``defender/lessons-environment/``, the corpus the benign
(ops-teamer) actor retrieves by classification before constructing a routine
story.

  Pre-flight (Python):
    1. fcntl lock on _pending/.environment.lock — concurrent ticks refuse cleanly.
    2. Acquire the shared repo lock (_author.lock) after the queue lock; hold
       through child-agent + post-flight + rotate. Release in reverse.
    3. Clean-scope check: defender/lessons-environment/ must be git-clean.
    4. Read the batch from _pending/environment_observations.jsonl.
    5. Outcome-policy filter: keep only ``survived`` (the confirmed-FP outcome
       whose grounded story yields reliable standing facts); drop the rest to
       consumed_skip with reason ``outcome_policy:{outcome}``.
    6. Held-out double-check: if ``{source_run_dir}/ground_truth.yaml`` declares
       ``held_out: true``, route to held with reason ``held_out_double_check``.
    7. Idempotency: any observation_id already cited in a lesson's
       source_observation_ids → consumed_idempotent.

  Agent invocation (Claude Code, file-edit + Bash tools):
    Hand the remaining observations + generation + benign_actor_model to the
    curator agent (``author_actor_benign.md``). It places the judge's retrieval
    keys, decides fold/supersede/new/skip per ``subject``, runs the
    deterministic forward-check (``verify_forward_env.py``), commits with the
    required Generation/Benign-Actor-Model trailers, and emits a final
    ``AUTHOR_RESULT: {...}`` line.

  Post-flight (Python):
    8. Parse AUTHOR_RESULT. Cross-check against git: if a commit is claimed,
       HEAD must match, touch only defender/lessons-environment/*.md, and carry
       both ``Generation: N`` and ``Benign-Actor-Model: M`` trailers matching
       the handed-in values. If no commit, HEAD must be unchanged and the
       corpus clean.
    9. Rotate the queue atomically. Held rows stay with a held_reason; consumed
       rows append to environment_observations.consumed.jsonl.

The agent owns fold/supersede/new judgment and the forward-check flow; this
module enforces the transaction envelope.
"""
from __future__ import annotations

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

# Sibling modules — imported by path (no package __init__ chain).
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import _author_runner as _runner  # type: ignore[import-not-found]
    import _author_shared as _shared  # type: ignore[import-not-found]
    from _loop_config import DEFAULT_PATHS  # type: ignore[import-not-found]
    from _loop_persist import rotate_queue_locked  # type: ignore[import-not-found]
finally:
    sys.path.pop(0)


REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
LESSONS_ENV_DIR = REPO_ROOT / "defender" / "lessons-environment"
LESSONS_ENV_DIR_REL = "defender/lessons-environment/"
# Mutable state resolves from DEFAULT_PATHS (honors DEFENDER_LEARNING_STATE_DIR);
# corpus/prompts stay repo-relative. LOCK_FILE is the queue lock shared with the
# producer (_loop_persist.append_environment_observations).
PENDING_DIR = DEFAULT_PATHS.pending_dir
PENDING_FILE = DEFAULT_PATHS.environment_observations_file
CONSUMED_FILE = DEFAULT_PATHS.environment_observations_consumed_file
LOCK_FILE = DEFAULT_PATHS.environment_observations_lock_file

AUTHOR_PROMPT = LEARNING_DIR / "author_actor_benign.md"
AUTHOR_RUN_LOG = PENDING_DIR / "author_actor_benign_run.jsonl"
VERIFY_SCRIPT_REL = "defender/learning/verify_forward_env.py"
PENDING_FILE_REL = "defender/learning/_pending/environment_observations.jsonl"

BENIGN_ACTOR_MODEL = os.environ.get("BENIGN_ACTOR_MODEL", "claude-sonnet-4-6")
AUTHOR_ENV_MODEL = os.environ.get(
    "LEARNING_AUTHOR_ENV_MODEL", "claude-sonnet-4-6"
)
AUTHOR_ENV_TIMEOUT = int(
    os.environ.get("LEARNING_AUTHOR_ENV_TIMEOUT_SECONDS", "1800")
)
AUTHOR_ENV_EFFORT = os.environ.get("LEARNING_AUTHOR_ENV_EFFORT", "low")

GROUND_TRUTH_FILE = "ground_truth.yaml"

# Outcome policy — see judge_benign.md. ``survived`` is the confirmed-FP outcome
# whose routine story held against the evidence, so the standing facts it
# grounds are reliable. Other outcomes yield no trustworthy env fact.
OUTCOME_AUTHOR = {"survived"}
OUTCOME_SKIP_BY_POLICY = {"refuted", "undecidable", "incoherent"}


class AuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort, queue stays intact."""


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def acquire_queue_lock() -> Any:
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    fh = LOCK_FILE.open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        return None
    return fh


def release_queue_lock(fh: Any) -> None:
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def assert_clean_lessons_env_dir() -> None:
    LESSONS_ENV_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(LESSONS_ENV_DIR)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    if proc.stdout.strip():
        raise AuthorError(
            "defender/lessons-environment/ has uncommitted changes — refusing "
            f"to author. Output:\n{proc.stdout}"
        )


def read_batch() -> list[dict]:
    if not PENDING_FILE.is_file():
        return []
    out: list[dict] = []
    for line in PENDING_FILE.read_text().splitlines():
        s = line.strip()
        if not s:
            continue
        out.append(json.loads(s))
    return out


_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---", re.DOTALL)


def existing_observation_ids() -> set[str]:
    """Union of source_observation_ids across all environment lessons."""
    ids: set[str] = set()
    if not LESSONS_ENV_DIR.is_dir():
        return ids
    for path in sorted(LESSONS_ENV_DIR.glob("*.md")):
        if path.name.startswith("_"):
            continue
        m = _FRONTMATTER_RE.match(path.read_text())
        if not m:
            continue
        try:
            doc = yaml.safe_load(m.group(1))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        sids = doc.get("source_observation_ids") or []
        if isinstance(sids, list):
            for sid in sids:
                if isinstance(sid, str):
                    ids.add(sid)
    return ids


def is_held_out_source(source_run_dir: str) -> bool:
    """True if ``{source_run_dir}/ground_truth.yaml`` declares held-out.

    ``source_run_dir`` is repo-relative in-repo, absolute out-of-repo (under
    DEFENDER_LEARNING_STATE_DIR); ``REPO_ROOT / src`` resolves both (pathlib lets
    an absolute right-hand side win)."""
    if not source_run_dir:
        return False
    path = REPO_ROOT / source_run_dir.rstrip("/") / GROUND_TRUTH_FILE
    if not path.is_file():
        return False
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError:
        return False
    return isinstance(doc, dict) and doc.get("held_out") is True


# ---------------------------------------------------------------------------
# Agent invocation
# ---------------------------------------------------------------------------


def invoke_agent(
    observations: list[dict],
    batch_id: str,
    generation: int,
    benign_actor_model: str,
) -> dict:
    """Spawn the curator agent. Returns parsed AUTHOR_RESULT dict."""
    verifier_py = _runner.resolve_verifier_python(REPO_ROOT)
    forward_check_command = (
        f"{verifier_py} {VERIFY_SCRIPT_REL} "
        f"--corpus {LESSONS_ENV_DIR_REL} --pending {PENDING_FILE_REL}"
    )
    user_prompt = (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: {LESSONS_ENV_DIR_REL}\n"
        f"generation: {generation}\n"
        f"benign_actor_model: {benign_actor_model}\n"
        f"forward_check_command: {forward_check_command}\n"
        f"observations ({len(observations)}):\n"
        f"{json.dumps(observations, indent=2)}\n"
    )
    allowed_tools = (
        "Read,Glob,Grep,"
        f"Edit({LESSONS_ENV_DIR_REL}**),Write({LESSONS_ENV_DIR_REL}**),"
        "Bash(git add:*),Bash(git commit:*),Bash(git checkout:*),"
        "Bash(git rev-parse:*),Bash(git status:*),Bash(git diff:*),"
        "Bash(git log:*),"
        f"Bash({verifier_py} {VERIFY_SCRIPT_REL}:*),"
        f"Bash(rm {LESSONS_ENV_DIR_REL}*.md),"
        f"Bash(rm {LESSONS_ENV_DIR}/*.md)"
    )
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    options = _runner.RunnerOptions(
        system_prompt_file=AUTHOR_PROMPT,
        allowed_tools=allowed_tools,
        model=AUTHOR_ENV_MODEL,
        effort=AUTHOR_ENV_EFFORT,
        timeout_seconds=AUTHOR_ENV_TIMEOUT,
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
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def head_changed_only_lessons_env() -> bool:
    proc = subprocess.run(
        ["git", "show", "--name-only", "--pretty=format:", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    files = [f for f in proc.stdout.splitlines() if f.strip()]
    if not files:
        return False
    for f in files:
        if not f.startswith(LESSONS_ENV_DIR_REL):
            return False
        if not f.endswith(".md"):
            return False
    return True


def head_commit_message() -> str:
    proc = subprocess.run(
        ["git", "log", "-1", "--pretty=%B", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return proc.stdout


_TRAILER_GEN = re.compile(r"^Generation:\s*(\d+)\s*$", re.MULTILINE)
_TRAILER_MODEL = re.compile(r"^Benign-Actor-Model:\s*(\S.*?)\s*$", re.MULTILINE)


def assert_head_trailers(expected_generation: int, expected_model: str) -> None:
    msg = head_commit_message()
    m_gen = _TRAILER_GEN.search(msg)
    if m_gen is None or int(m_gen.group(1)) != expected_generation:
        raise AuthorError(
            f"HEAD commit missing or wrong Generation: trailer "
            f"(expected {expected_generation}); message was:\n{msg}"
        )
    m_model = _TRAILER_MODEL.search(msg)
    if m_model is None or m_model.group(1).strip() != expected_model:
        raise AuthorError(
            f"HEAD commit missing or wrong Benign-Actor-Model: trailer "
            f"(expected {expected_model}); message was:\n{msg}"
        )


def _canonical_sha(sha: str) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", sha],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise AuthorError(
            f"author claimed commit_sha={sha!r} but git rev-parse rejects it: "
            f"{proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def lessons_env_dir_clean() -> bool:
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(LESSONS_ENV_DIR)],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return not proc.stdout.strip()


def _result_list(result: dict, key: str) -> list[Any]:
    value = result.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise AuthorError(f"AUTHOR_RESULT field {key!r} must be a list")
    return value


def _result_observation_id(bucket: str, entry: Any) -> str:
    if bucket == "committed":
        if not isinstance(entry, str) or not entry:
            raise AuthorError(
                "AUTHOR_RESULT committed entries must be non-empty observation_id strings"
            )
        return entry
    if not isinstance(entry, dict):
        raise AuthorError(f"AUTHOR_RESULT {bucket} entries must be objects")
    oid = entry.get("observation_id")
    if not isinstance(oid, str) or not oid:
        raise AuthorError(
            f"AUTHOR_RESULT {bucket} entries must include a non-empty observation_id"
        )
    return oid


def validate_agent_result_partition(result: dict, to_author: list[dict]) -> None:
    expected = {o["observation_id"] for o in to_author}
    occurrences: dict[str, list[str]] = {}
    for entry in _result_list(result, "committed"):
        oid = _result_observation_id("committed", entry)
        occurrences.setdefault(oid, []).append("committed")
    for entry in _result_list(result, "consumed_skip"):
        oid = _result_observation_id("consumed_skip", entry)
        occurrences.setdefault(oid, []).append("consumed_skip")

    unknown = sorted(oid for oid in occurrences if oid not in expected)
    if unknown:
        raise AuthorError(f"author result contains unknown observations: {unknown}")
    repeated = {
        oid: buckets for oid, buckets in sorted(occurrences.items())
        if len(buckets) != 1
    }
    if repeated:
        raise AuthorError(
            "author result classified observations more than once: "
            + json.dumps(repeated, sort_keys=True)
        )
    unseen = sorted(expected - occurrences.keys())
    if unseen:
        raise AuthorError(f"author result missing observations: {unseen}")


def verify_agent_state(
    result: dict,
    expected_generation: int,
    expected_model: str,
    pre_agent_head: str,
) -> None:
    commit_sha = result.get("commit_sha")
    committed = _result_list(result, "committed")
    if committed and not commit_sha:
        raise AuthorError(
            "author reported committed observations without a commit_sha; "
            "refusing to rotate queue"
        )
    if commit_sha:
        head = git_head_sha()
        canonical = _canonical_sha(commit_sha)
        if canonical != head:
            raise AuthorError(
                f"author claimed commit_sha={commit_sha} ({canonical}) but HEAD={head}"
            )
        if not head_changed_only_lessons_env():
            raise AuthorError(
                "HEAD commit touches files outside "
                "defender/lessons-environment/*.md; refusing to rotate queue"
            )
        if not lessons_env_dir_clean():
            raise AuthorError(
                "author committed but defender/lessons-environment/ still has "
                "uncommitted edits"
            )
        assert_head_trailers(expected_generation, expected_model)
    else:
        head = git_head_sha()
        if head != pre_agent_head:
            raise AuthorError(
                "author skipped commit but HEAD changed "
                f"from {pre_agent_head} to {head}; refusing to rotate queue"
            )
        if not lessons_env_dir_clean():
            raise AuthorError(
                "author skipped commit but defender/lessons-environment/ has "
                "uncommitted edits"
            )


# ---------------------------------------------------------------------------
# Queue rotation
# ---------------------------------------------------------------------------


def rotate_queue(
    *,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
) -> None:
    """Held-only rewrite of the queue + append to consumed (the shared
    ``rotate_queue_locked`` with ``merge_concurrent=False``).

    No re-read-merge (unlike ``author.rotate_queue``): ``run_batch`` holds the
    queue lock (``acquire_queue_lock`` on ``LOCK_FILE``) across read→rotate, and
    the producer's append blocks on that same lock, so no observation can arrive
    mid-batch — a held-only rewrite cannot lose data, and re-taking ``LOCK_FILE``
    here would self-deadlock (hence ``merge_concurrent=False``)."""
    rotate_queue_locked(
        pending_file=PENDING_FILE,
        consumed_file=CONSUMED_FILE,
        lock_file=LOCK_FILE,
        id_key="observation_id",
        held=held,
        consumed=consumed,
        commit_sha=commit_sha,
        merge_concurrent=False,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _log(msg: str) -> None:
    print(f"[author_actor_benign] {msg}", file=sys.stderr)


def _by_id(rows: list[dict]) -> dict[str, dict]:
    return {r["observation_id"]: r for r in rows}


def run_batch(*, hold_committed: bool = False) -> int:
    """Drain an environment-observation batch into the environment-lessons corpus.

    ``hold_committed`` (set by the serial author drain) keeps just-committed
    observations in the queue instead of rotating them out — see
    ``author.run_batch`` for the rationale."""
    queue_lock = acquire_queue_lock()
    if queue_lock is None:
        _log("queue lock held by another process — skipping this tick")
        return 0
    repo_lock = None
    try:
        try:
            repo_lock = _shared.acquire_repo_lock()
        except TimeoutError as e:
            _log(f"repo lock unavailable: {e}; queue intact")
            return 0
        try:
            assert_clean_lessons_env_dir()
        except AuthorError as e:
            _log(f"FATAL: {e}")
            return 2
        return _run_batch_inner(hold_committed=hold_committed)
    finally:
        if repo_lock is not None:
            _shared.release_repo_lock(repo_lock)
        release_queue_lock(queue_lock)


def _run_batch_inner(*, hold_committed: bool = False) -> int:
    batch = read_batch()
    if not batch:
        _log("queue empty — nothing to author")
        return 0
    all_obs = _by_id(batch)
    held, consumed_pre, to_author = _partition_pre_author(batch)

    batch_id = uuid.uuid4().hex[:12]
    generation = _shared.benign_generation_count()
    _log(
        f"batch={batch_id} generation={generation} "
        f"benign_actor_model={BENIGN_ACTOR_MODEL} total={len(batch)} "
        f"to_author={len(to_author)} held={len(held)} pre_consumed={len(consumed_pre)}"
    )

    commit_sha: str | None = None
    committed: list[dict] = []
    consumed_skip: list[dict] = []
    if to_author:
        rc, commit_sha, committed, consumed_skip = _author_to_author(
            to_author, all_obs, batch_id, generation,
        )
        if rc != 0:
            return rc

    # hold_committed: keep `committed` in the queue (stripped of the consumed
    # stamp) instead of rotating it out, since the commit is on an unmerged PR
    # branch. consumed_pre + consumed_skip always rotate out. See author.py.
    held_committed, rotated_committed = _shared.partition_committed(
        committed, hold_committed=hold_committed
    )
    try:
        rotate_queue(
            held=held + held_committed,
            consumed=consumed_pre + rotated_committed + consumed_skip,
            commit_sha=commit_sha,
        )
    except AuthorError as e:
        _log(f"FATAL during rotate: {e}")
        return 2
    _log(
        f"done batch={batch_id} committed={len(committed)} "
        f"consumed_skip={len(consumed_skip)} pre_consumed={len(consumed_pre)} "
        f"held={len(held)} commit_sha={commit_sha}"
    )
    return 0


def _partition_pre_author(
    batch: list[dict],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Split into (held, consumed_pre, to_author) before the agent runs."""
    existing = existing_observation_ids()
    held: list[dict] = []
    consumed_pre: list[dict] = []
    to_author: list[dict] = []
    for entry in batch:
        oid = entry["observation_id"]
        if oid in existing:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_idempotent"
            consumed_pre.append(rec)
            continue
        outcome = entry.get("judge_outcome")
        if outcome in OUTCOME_SKIP_BY_POLICY:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_skip"
            rec["skip_reason"] = f"outcome_policy:{outcome}"
            consumed_pre.append(rec)
            continue
        if is_held_out_source(entry.get("source_run_dir", "")):
            rec = dict(entry)
            rec["held_reason"] = "held_out_double_check"
            held.append(rec)
            continue
        if outcome not in OUTCOME_AUTHOR:
            rec = dict(entry)
            rec["held_reason"] = f"unexpected_outcome:{outcome}"
            held.append(rec)
            continue
        to_author.append(entry)
    return held, consumed_pre, to_author


def _author_to_author(
    to_author: list[dict], all_obs: dict[str, dict],
    batch_id: str, generation: int,
) -> tuple[int, str | None, list[dict], list[dict]]:
    """Run the agent on `to_author` and partition its result."""
    pre_agent_head = git_head_sha()
    try:
        result = invoke_agent(to_author, batch_id, generation, BENIGN_ACTOR_MODEL)
    except AuthorError as e:
        _log(f"FATAL: {e}")
        return 2, None, [], []
    try:
        verify_agent_state(result, generation, BENIGN_ACTOR_MODEL, pre_agent_head)
        validate_agent_result_partition(result, to_author)
    except AuthorError as e:
        _log(f"FATAL: {e}")
        return 2, None, [], []
    commit_sha = result.get("commit_sha")
    committed: list[dict] = []
    consumed_skip: list[dict] = []
    for oid in _result_list(result, "committed"):
        src = all_obs.get(oid)
        if src is None:
            raise AuthorError(f"author committed unknown observation_id={oid!r}")
        rec = dict(src)
        rec["consumed_category"] = "consumed_committed"
        committed.append(rec)
    for entry in _result_list(result, "consumed_skip"):
        oid = entry.get("observation_id")
        src = all_obs.get(oid)
        if src is None:
            raise AuthorError(f"author skipped unknown observation_id={oid!r}")
        rec = dict(src)
        rec["consumed_category"] = "consumed_skip"
        rec["skip_reason"] = entry.get("reason", "")
        consumed_skip.append(rec)
    return 0, commit_sha, committed, consumed_skip


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_benign.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
