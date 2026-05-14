#!/usr/bin/env python3
"""Actor lessons curator — consumer half of the actor learning queue.

Mirrors ``defender/learning/author.py`` but works on the actor side:

  Pre-flight (Python):
    1. fcntl lock on _pending/.actor.lock — concurrent ticks refuse cleanly.
    2. Acquire the shared repo lock (_author.lock) after the queue lock;
       hold through child-agent + post-flight + rotate. Release in
       reverse. Concurrency contract per §learning-loop-actor-learning.
    3. Clean-scope check: defender/lessons-actor/ must be git-clean.
    4. Read the batch from _pending/actor_observations.jsonl.
    5. Outcome-policy filter: drop survived/undecidable to consumed_skip
       with reason ``outcome_policy:{outcome}``. (Producer queues
       broadly; author owns the policy.)
    6. Held-out double-check: if ``{source_run_dir}/ground_truth.yaml``
       declares ``held_out: true``, route to held with reason
       ``held_out_double_check`` (producer should have dropped it; this
       is defense in depth).
    7. Idempotency: any observation_id already cited in any lesson's
       source_observation_ids → consumed_idempotent.

  Agent invocation (Claude Code, file-edit + Bash tools):
    Hand the remaining observations + generation + actor_model to the
    curator agent (``author_actor.md``). It enumerates existing
    lessons, decides new/fold/skip per observation, runs the channel
    test, performs contradiction-with-replacement on env, commits with
    the required Generation/Actor-Model trailers, and emits a final
    ``AUTHOR_RESULT: {...}`` line.

  Post-flight (Python):
    8. Parse AUTHOR_RESULT. Cross-check against git: if commit_sha is
       claimed, HEAD must match, touch only defender/lessons-actor/
       *.md files, and carry both ``Generation: N`` and
       ``Actor-Model: M`` trailers matching the values handed to the
       agent. If no commit, defender/lessons-actor/ must be clean.
    9. Rotate the queue atomically (tmp file + os.replace). Held rows
       stay in actor_observations.jsonl with a held_reason annotation;
       consumed rows append to actor_observations.consumed.jsonl with
       category + consumed_at + commit_sha.

The agent owns the channel-test, fold/new judgment, and the env
invalidation flow; this module enforces the transaction envelope.
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

# Sibling modules — author_actor is invoked as a script, so we import
# by path (no package __init__ chain).
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import _author_runner as _runner  # type: ignore[import-not-found]
    import _author_shared as _shared  # type: ignore[import-not-found]
finally:
    sys.path.pop(0)


REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
LESSONS_ACTOR_DIR = REPO_ROOT / "defender" / "lessons-actor"
PENDING_DIR = LEARNING_DIR / "_pending"
PENDING_FILE = PENDING_DIR / "actor_observations.jsonl"
CONSUMED_FILE = PENDING_DIR / "actor_observations.consumed.jsonl"
LOCK_FILE = PENDING_DIR / ".actor.lock"

AUTHOR_PROMPT = LEARNING_DIR / "author_actor.md"
AUTHOR_RUN_LOG = PENDING_DIR / "author_actor_run.jsonl"

ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")
AUTHOR_ACTOR_MODEL = os.environ.get(
    "LEARNING_AUTHOR_ACTOR_MODEL", "claude-sonnet-4-6"
)
AUTHOR_ACTOR_TIMEOUT = int(
    os.environ.get("LEARNING_AUTHOR_ACTOR_TIMEOUT_SECONDS", "1800")
)
AUTHOR_ACTOR_EFFORT = os.environ.get("LEARNING_AUTHOR_ACTOR_EFFORT")

GROUND_TRUTH_FILE = "ground_truth.yaml"

# Outcome policy — see judge.md outcome enum.
OUTCOME_AUTHOR = {"caught", "incoherent"}
OUTCOME_SKIP_BY_POLICY = {"survived", "undecidable"}


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


def assert_clean_lessons_actor_dir() -> None:
    LESSONS_ACTOR_DIR.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(LESSONS_ACTOR_DIR)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    if proc.stdout.strip():
        raise AuthorError(
            "defender/lessons-actor/ has uncommitted changes — refusing to author. "
            f"Output:\n{proc.stdout}"
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
    """Union of source_observation_ids across all actor lessons.

    Walks both ``tradecraft/`` and ``environment/`` directories. Lessons
    missing the field or with a non-list value are skipped silently.
    """
    ids: set[str] = set()
    if not LESSONS_ACTOR_DIR.is_dir():
        return ids
    for channel in ("tradecraft", "environment"):
        chan_dir = LESSONS_ACTOR_DIR / channel
        if not chan_dir.is_dir():
            continue
        for path in sorted(chan_dir.glob("*.md")):
            if path.name.startswith("_"):
                continue
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
            sids = doc.get("source_observation_ids") or []
            if isinstance(sids, list):
                for sid in sids:
                    if isinstance(sid, str):
                        ids.add(sid)
    return ids


def is_held_out_source(source_run_dir: str) -> bool:
    """Return True if ``{source_run_dir}/ground_truth.yaml`` declares held-out.

    ``source_run_dir`` is repo-relative with a trailing slash, matching
    the producer's convention in ``loop.py:_source_run_dir``. Missing
    file or malformed YAML → False (defense in depth, not enforcement).
    """
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
    actor_model: str,
) -> dict:
    """Spawn the curator agent. Returns parsed AUTHOR_RESULT dict.

    Hands the agent the observation JSON, the generation integer, and
    the actor model id. Stream-json driver lives in
    ``_author_runner.invoke_claude_print``.
    """
    user_prompt = (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: defender/lessons-actor/\n"
        f"generation: {generation}\n"
        f"actor_model: {actor_model}\n"
        f"observations ({len(observations)}):\n"
        f"{json.dumps(observations, indent=2)}\n"
    )
    allowed_tools = (
        "Read,Glob,Grep,"
        "Edit(defender/lessons-actor/**),Write(defender/lessons-actor/**),"
        "Bash(git add:*),Bash(git commit:*),Bash(git checkout:*),"
        "Bash(git rev-parse:*),Bash(git status:*),Bash(git diff:*),"
        "Bash(git log:*),"
        "Bash(rm defender/lessons-actor/tradecraft/*.md),"
        "Bash(rm defender/lessons-actor/environment/*.md),"
        f"Bash(rm {LESSONS_ACTOR_DIR}/tradecraft/*.md),"
        f"Bash(rm {LESSONS_ACTOR_DIR}/environment/*.md)"
    )
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    try:
        return _runner.invoke_claude_print(
            system_prompt_file=AUTHOR_PROMPT,
            user_prompt=user_prompt,
            allowed_tools=allowed_tools,
            model=AUTHOR_ACTOR_MODEL,
            effort=AUTHOR_ACTOR_EFFORT,
            timeout_seconds=AUTHOR_ACTOR_TIMEOUT,
            cwd=REPO_ROOT,
            log_path=AUTHOR_RUN_LOG,
            result_marker="AUTHOR_RESULT:",
            log_fn=_log,
            batch_id=batch_id,
        )
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


def head_changed_only_lessons_actor() -> bool:
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
        if not f.startswith("defender/lessons-actor/"):
            return False
        if not f.endswith(".md"):
            return False
    return True


def head_commit_message() -> str:
    proc = subprocess.run(
        ["git", "log", "-1", "--pretty=%B", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


_TRAILER_GEN = re.compile(r"^Generation:\s*(\d+)\s*$", re.MULTILINE)
_TRAILER_MODEL = re.compile(r"^Actor-Model:\s*(\S.*?)\s*$", re.MULTILINE)


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
            f"HEAD commit missing or wrong Actor-Model: trailer "
            f"(expected {expected_model}); message was:\n{msg}"
        )


def _canonical_sha(sha: str) -> str:
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


def lessons_actor_dir_clean() -> bool:
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(LESSONS_ACTOR_DIR)],
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
        oid: buckets
        for oid, buckets in sorted(occurrences.items())
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
    result: dict, expected_generation: int, expected_model: str
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
        if not head_changed_only_lessons_actor():
            raise AuthorError(
                "HEAD commit touches files outside defender/lessons-actor/*.md; "
                "refusing to rotate queue"
            )
        if not lessons_actor_dir_clean():
            raise AuthorError(
                "author committed but defender/lessons-actor/ still has uncommitted edits"
            )
        assert_head_trailers(expected_generation, expected_model)
    else:
        if not lessons_actor_dir_clean():
            raise AuthorError(
                "author skipped commit but defender/lessons-actor/ has uncommitted edits"
            )


# ---------------------------------------------------------------------------
# Queue rotation
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def rotate_queue(
    *,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
) -> None:
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


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _log(msg: str) -> None:
    print(f"[author_actor] {msg}", file=sys.stderr)


def _by_id(rows: list[dict]) -> dict[str, dict]:
    return {r["observation_id"]: r for r in rows}


def run_batch() -> int:
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
            assert_clean_lessons_actor_dir()
        except AuthorError as e:
            _log(f"FATAL: {e}")
            return 2

        batch = read_batch()
        if not batch:
            _log("queue empty — nothing to author")
            return 0

        all_obs = _by_id(batch)
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
                # Producer should have dropped held-out runs; defense-in-depth
                # hold so a held-out observation can never seed a lesson.
                rec = dict(entry)
                rec["held_reason"] = "held_out_double_check"
                held.append(rec)
                continue

            if outcome not in OUTCOME_AUTHOR:
                # Unknown / unexpected outcome — hold for human review.
                rec = dict(entry)
                rec["held_reason"] = f"unexpected_outcome:{outcome}"
                held.append(rec)
                continue

            to_author.append(entry)

        batch_id = uuid.uuid4().hex[:12]
        generation = _shared.actor_generation_count()
        _log(
            f"batch={batch_id} generation={generation} actor_model={ACTOR_MODEL} "
            f"total={len(batch)} to_author={len(to_author)} "
            f"held={len(held)} pre_consumed={len(consumed_pre)}"
        )

        commit_sha: str | None = None
        committed: list[dict] = []
        consumed_skip: list[dict] = []

        if to_author:
            try:
                result = invoke_agent(to_author, batch_id, generation, ACTOR_MODEL)
            except AuthorError as e:
                _log(f"FATAL: {e}")
                return 2
            try:
                verify_agent_state(result, generation, ACTOR_MODEL)
                validate_agent_result_partition(result, to_author)
            except AuthorError as e:
                _log(f"FATAL: {e}")
                return 2

            commit_sha = result.get("commit_sha")
            for oid in _result_list(result, "committed"):
                src = all_obs.get(oid)
                if src is None:
                    raise AuthorError(
                        f"author committed unknown observation_id={oid!r}"
                    )
                rec = dict(src)
                rec["consumed_category"] = "consumed_committed"
                committed.append(rec)
            for entry in _result_list(result, "consumed_skip"):
                oid = entry.get("observation_id")
                src = all_obs.get(oid)
                if src is None:
                    raise AuthorError(
                        f"author skipped unknown observation_id={oid!r}"
                    )
                rec = dict(src)
                rec["consumed_category"] = "consumed_skip"
                rec["skip_reason"] = entry.get("reason", "")
                consumed_skip.append(rec)

        try:
            rotate_queue(
                held=held,
                consumed=consumed_pre + committed + consumed_skip,
                commit_sha=commit_sha,
            )
        except AuthorError as e:
            _log(f"FATAL during rotate: {e}")
            return 2

        _log(
            f"done batch={batch_id} committed={len(committed)} "
            f"consumed_skip={len(consumed_skip)} "
            f"pre_consumed={len(consumed_pre)} held={len(held)} "
            f"commit_sha={commit_sha}"
        )
        return 0
    finally:
        if repo_lock is not None:
            _shared.release_repo_lock(repo_lock)
        release_queue_lock(queue_lock)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
