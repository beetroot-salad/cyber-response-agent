#!/usr/bin/env python3
"""Shared transaction engine for the actor / environment lessons curators.

``author_actor.py`` (actor tradecraft) and ``author_actor_benign.py`` (the two
environment-lessons directions) are the same curator: lock the queue, lock the
repo, clean-scope check, partition the batch, hand the survivors to a ``claude -p``
curator agent, cross-check what it committed against git, then rotate the queue.
Only the corpus directory, queue paths, outcome policy, commit trailer, generation
counter, curator-agent prompt/model, and forward-check invocation differ — captured
in a ``CuratorConfig``. This module owns the envelope; the direction modules own the
config + the one genuinely-divergent piece (``invoke_agent``).

The agent owns fold/supersede/new judgment and the forward-check flow; this module
enforces the transaction envelope (mirrors the prose in ``author.py`` /
``author_actor_benign.py``).
"""
from __future__ import annotations

import fcntl
import json
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from re import Pattern
from collections.abc import Callable

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
_PENDING_DIR = DEFAULT_PATHS.pending_dir

GROUND_TRUTH_FILE = "ground_truth.yaml"


class AuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort, queue stays intact."""


# ---------------------------------------------------------------------------
# Direction config — everything that differs between the curators.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CuratorConfig:
    # Corpus the agent edits (absolute) + its repo-relative form (trailing slash).
    corpus_dir: Path
    corpus_dir_rel: str
    # Queue files (honor DEFENDER_LEARNING_STATE_DIR via DEFAULT_PATHS).
    pending_file: Path
    consumed_file: Path
    lock_file: Path
    # Outcome policy — which judge_outcomes author vs skip-by-policy.
    outcome_author: frozenset[str]
    outcome_skip: frozenset[str]
    # Commit-message trailer key (no colon) + its generation counter.
    trailer_label: str
    generation_fn: Callable[[], int]
    actor_model: str
    log_prefix: str
    # Curator agent (claude -p) wiring.
    author_prompt: Path
    author_model: str
    author_timeout: int
    author_effort: str
    # The one genuinely-divergent step: build the AUTHOR_RESULT dict from the
    # batch. Signature: (observations, batch_id, generation, cfg) -> dict.
    invoke_agent: Callable[[list[dict], str, int, CuratorConfig], dict]

    @property
    def pending_file_rel(self) -> str:
        """Repo-relative queue path for the forward-check ``--pending`` arg.

        Derived from ``pending_file`` so a relocated ``DEFENDER_LEARNING_STATE_DIR``
        queue and the forward-check stay in sync — an out-of-repo queue falls back
        to its absolute path (which the verifier resolves directly)."""
        try:
            return str(self.pending_file.relative_to(REPO_ROOT))
        except ValueError:
            return str(self.pending_file)

    @property
    def run_log(self) -> Path:
        return _PENDING_DIR / f"{self.log_prefix}_run.jsonl"

    @property
    def trailer_re(self) -> Pattern[str]:
        """Matcher for the commit's model trailer, derived from ``trailer_label`` so
        the label and the pattern cannot drift. Tolerates a zero-space trailer to
        match what the generation counter (``_generation_count``) counts."""
        return re.compile(
            rf"^{re.escape(self.trailer_label)}:\s*(\S.*?)\s*$", re.MULTILINE
        )


def _logger(cfg: CuratorConfig) -> Callable[[str], None]:
    def _log(msg: str) -> None:
        print(f"[{cfg.log_prefix}] {msg}", file=sys.stderr)
    return _log


def _by_id(rows: list[dict]) -> dict[str, dict]:
    return {r["observation_id"]: r for r in rows}


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def acquire_queue_lock(cfg: CuratorConfig) -> Any:
    cfg.lock_file.parent.mkdir(parents=True, exist_ok=True)
    fh = cfg.lock_file.open("a+")
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


def assert_clean_corpus_dir(cfg: CuratorConfig) -> None:
    cfg.corpus_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(cfg.corpus_dir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    if proc.stdout.strip():
        raise AuthorError(
            f"{cfg.corpus_dir_rel} has uncommitted changes — refusing to author. "
            f"Output:\n{proc.stdout}"
        )


def read_batch(cfg: CuratorConfig) -> list[dict]:
    if not cfg.pending_file.is_file():
        return []
    out: list[dict] = []
    for line in cfg.pending_file.read_text().splitlines():
        s = line.strip()
        if not s:
            continue
        out.append(json.loads(s))
    return out


_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---", re.DOTALL)

# Cache of the corpus-wide id set, keyed on a (name, mtime_ns) signature of the
# corpus files. The repo lock means the corpus only changes when a commit lands,
# which bumps the signature and invalidates the cache — so two drains on an
# unchanged corpus (e.g. benign + adversarial in one serial tick) reuse the parse
# instead of re-globbing + re-parsing YAML. Keyed by corpus dir so curators over
# distinct corpora don't collide.
_EXISTING_IDS_CACHE: dict[tuple[str, tuple[tuple[str, int], ...]], set[str]] = {}


def existing_observation_ids(corpus_dir: Path) -> set[str]:
    """Union of source_observation_ids across all lessons in ``corpus_dir``.

    Corpus-wide, so an id already authored into this corpus (by any direction that
    shares it) is treated as consumed. Lessons missing the field or with a non-list
    value are skipped silently."""
    if not corpus_dir.is_dir():
        return set()
    paths = [
        p for p in sorted(corpus_dir.glob("*.md")) if not p.name.startswith("_")
    ]
    sig = (str(corpus_dir), tuple((p.name, p.stat().st_mtime_ns) for p in paths))
    cached = _EXISTING_IDS_CACHE.get(sig)
    if cached is not None:
        return set(cached)
    ids: set[str] = set()
    for path in paths:
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
    _EXISTING_IDS_CACHE.clear()  # keep only the latest signature
    _EXISTING_IDS_CACHE[sig] = set(ids)
    return ids


def is_held_out_source(source_run_dir: str) -> bool:
    """True if ``{source_run_dir}/ground_truth.yaml`` declares held-out.

    ``source_run_dir`` follows ``_loop_persist._source_run_dir``: repo-relative
    in-repo, absolute when the run lives out-of-repo under
    DEFENDER_LEARNING_STATE_DIR. ``REPO_ROOT / src`` resolves both (pathlib lets an
    absolute right-hand side win). Missing file or malformed YAML → False (defense
    in depth, not enforcement)."""
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
# Agent invocation — shared scaffolding; directions supply the forward-check
# prompt lines + allowed-tools entries (the one place the contract differs).
# ---------------------------------------------------------------------------


def invoke_curator_agent(
    cfg: CuratorConfig,
    observations: list[dict],
    batch_id: str,
    generation: int,
    *,
    extra_prompt: str,
    extra_tools: str,
) -> dict:
    """Spawn the curator agent and return its parsed AUTHOR_RESULT dict.

    ``extra_prompt`` carries the direction's forward-check command line(s); it is
    spliced between the standard header and the observations. ``extra_tools`` carries
    the direction's verifier ``Bash(...)`` allowances, spliced into the corpus-scoped
    git + edit allowlist."""
    user_prompt = (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: {cfg.corpus_dir_rel}\n"
        f"generation: {generation}\n"
        f"actor_model: {cfg.actor_model}\n"
        f"{extra_prompt}"
        f"observations ({len(observations)}):\n"
        f"{json.dumps(observations, indent=2)}\n"
    )
    allowed_tools = (
        "Read,Glob,Grep,"
        f"Edit({cfg.corpus_dir_rel}**),Write({cfg.corpus_dir_rel}**),"
        "Bash(git add:*),Bash(git commit:*),Bash(git checkout:*),"
        "Bash(git rev-parse:*),Bash(git status:*),Bash(git diff:*),"
        "Bash(git log:*),"
        f"{extra_tools}"
        f"Bash(rm {cfg.corpus_dir_rel}*.md),"
        f"Bash(rm {cfg.corpus_dir}/*.md)"
    )
    _PENDING_DIR.mkdir(parents=True, exist_ok=True)
    options = _runner.RunnerOptions(
        system_prompt_file=cfg.author_prompt,
        allowed_tools=allowed_tools,
        model=cfg.author_model,
        effort=cfg.author_effort,
        timeout_seconds=cfg.author_timeout,
        cwd=REPO_ROOT,
        log_path=cfg.run_log,
        result_marker="AUTHOR_RESULT:",
        batch_id=batch_id,
    )
    try:
        return _runner.invoke_claude_print(options, user_prompt, _logger(cfg))
    except _runner.RunnerError as e:
        raise AuthorError(str(e)) from e


# ---------------------------------------------------------------------------
# Post-flight — git cross-check
# ---------------------------------------------------------------------------


def git_head_sha() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def head_changed_only(corpus_dir_rel: str) -> bool:
    proc = subprocess.run(
        ["git", "show", "--name-only", "--pretty=format:", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    files = [f for f in proc.stdout.splitlines() if f.strip()]
    if not files:
        return False
    for f in files:
        if not f.startswith(corpus_dir_rel):
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


def assert_head_trailers(
    expected_generation: int, expected_model: str, cfg: CuratorConfig
) -> None:
    msg = head_commit_message()
    m_gen = _TRAILER_GEN.search(msg)
    if m_gen is None or int(m_gen.group(1)) != expected_generation:
        raise AuthorError(
            f"HEAD commit missing or wrong Generation: trailer "
            f"(expected {expected_generation}); message was:\n{msg}"
        )
    m_model = cfg.trailer_re.search(msg)
    if m_model is None or m_model.group(1).strip() != expected_model:
        raise AuthorError(
            f"HEAD commit missing or wrong {cfg.trailer_label}: trailer "
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


def corpus_dir_clean(corpus_dir: Path) -> bool:
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(corpus_dir)],
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
    cfg: CuratorConfig,
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
        if not head_changed_only(cfg.corpus_dir_rel):
            raise AuthorError(
                f"HEAD commit touches files outside {cfg.corpus_dir_rel}*.md; "
                "refusing to rotate queue"
            )
        if not corpus_dir_clean(cfg.corpus_dir):
            raise AuthorError(
                f"author committed but {cfg.corpus_dir_rel} still has uncommitted edits"
            )
        assert_head_trailers(expected_generation, expected_model, cfg)
    else:
        head = git_head_sha()
        if head != pre_agent_head:
            raise AuthorError(
                "author skipped commit but HEAD changed "
                f"from {pre_agent_head} to {head}; refusing to rotate queue"
            )
        if not corpus_dir_clean(cfg.corpus_dir):
            raise AuthorError(
                f"author skipped commit but {cfg.corpus_dir_rel} has uncommitted edits"
            )


# ---------------------------------------------------------------------------
# Queue rotation
# ---------------------------------------------------------------------------


def rotate_queue(
    *,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
    cfg: CuratorConfig,
) -> None:
    """Held-only rewrite of the queue + append to consumed (the shared
    ``rotate_queue_locked`` with ``merge_concurrent=False``).

    No re-read-merge (unlike ``author.rotate_queue``): ``run_batch`` holds the queue
    lock across read→rotate, and the producer's append blocks on that same lock, so
    no observation can arrive mid-batch — a held-only rewrite cannot lose data, and
    re-taking the lock here would self-deadlock (hence ``merge_concurrent=False``)."""
    rotate_queue_locked(
        pending_file=cfg.pending_file,
        consumed_file=cfg.consumed_file,
        lock_file=cfg.lock_file,
        id_key="observation_id",
        held=held,
        consumed=consumed,
        commit_sha=commit_sha,
        merge_concurrent=False,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_batch(*, hold_committed: bool, cfg: CuratorConfig) -> int:
    """Drain one observation batch into ``cfg``'s corpus.

    ``hold_committed`` (set by the serial author drain) keeps just-committed
    observations in the queue instead of rotating them out, since the commit is on an
    unmerged PR branch — see ``author.run_batch`` for the rationale (a rejected PR
    must not strand them; a merged one filters them via ``existing_observation_ids``
    next batch)."""
    log = _logger(cfg)
    queue_lock = acquire_queue_lock(cfg)
    if queue_lock is None:
        log("queue lock held by another process — skipping this tick")
        return 0
    repo_lock = None
    try:
        try:
            repo_lock = _shared.acquire_repo_lock()
        except TimeoutError as e:
            log(f"repo lock unavailable: {e}; queue intact")
            return 0
        try:
            assert_clean_corpus_dir(cfg)
        except AuthorError as e:
            log(f"FATAL: {e}")
            return 2
        return _run_batch_inner(hold_committed=hold_committed, cfg=cfg)
    finally:
        if repo_lock is not None:
            _shared.release_repo_lock(repo_lock)
        release_queue_lock(queue_lock)


def _run_batch_inner(*, hold_committed: bool, cfg: CuratorConfig) -> int:
    log = _logger(cfg)
    batch = read_batch(cfg)
    if not batch:
        log("queue empty — nothing to author")
        return 0
    all_obs = _by_id(batch)
    held, consumed_pre, to_author = _partition_pre_author(batch, cfg)

    batch_id = uuid.uuid4().hex[:12]
    generation = cfg.generation_fn()
    log(
        f"batch={batch_id} generation={generation} actor_model={cfg.actor_model} "
        f"total={len(batch)} to_author={len(to_author)} "
        f"held={len(held)} pre_consumed={len(consumed_pre)}"
    )

    commit_sha: str | None = None
    committed: list[dict] = []
    consumed_skip: list[dict] = []
    if to_author:
        rc, commit_sha, committed, consumed_skip = _author_to_author(
            to_author, all_obs, batch_id, generation, cfg,
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
            cfg=cfg,
        )
    except AuthorError as e:
        log(f"FATAL during rotate: {e}")
        return 2
    log(
        f"done batch={batch_id} committed={len(committed)} "
        f"consumed_skip={len(consumed_skip)} pre_consumed={len(consumed_pre)} "
        f"held={len(held)} commit_sha={commit_sha}"
    )
    return 0


def _partition_pre_author(
    batch: list[dict], cfg: CuratorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Split the queue into (held, consumed_pre, to_author) before the agent runs.

    consumed_pre bundles already-authored (idempotent) observations and
    skip-by-policy outcomes. held covers held-out double-checks and unexpected
    outcomes (kept for human review)."""
    existing = existing_observation_ids(cfg.corpus_dir)
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
        if outcome in cfg.outcome_skip:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_skip"
            rec["skip_reason"] = f"outcome_policy:{outcome}"
            consumed_pre.append(rec)
            continue
        if is_held_out_source(entry.get("source_run_dir", "")):
            # Producer should have dropped held-out runs; defense-in-depth hold
            # so a held-out observation can never seed a lesson.
            rec = dict(entry)
            rec["held_reason"] = "held_out_double_check"
            held.append(rec)
            continue
        if outcome not in cfg.outcome_author:
            rec = dict(entry)
            rec["held_reason"] = f"unexpected_outcome:{outcome}"
            held.append(rec)
            continue
        to_author.append(entry)
    return held, consumed_pre, to_author


def _author_to_author(
    to_author: list[dict], all_obs: dict[str, dict],
    batch_id: str, generation: int, cfg: CuratorConfig,
) -> tuple[int, str | None, list[dict], list[dict]]:
    """Run the agent on `to_author` and partition its result.

    Returns (rc, commit_sha, committed, consumed_skip). rc != 0 means a FATAL
    happened and the caller should bail with that code."""
    log = _logger(cfg)
    pre_agent_head = git_head_sha()
    try:
        result = cfg.invoke_agent(to_author, batch_id, generation, cfg)
    except AuthorError as e:
        log(f"FATAL: {e}")
        return 2, None, [], []
    try:
        verify_agent_state(result, generation, cfg.actor_model, pre_agent_head, cfg)
        validate_agent_result_partition(result, to_author)
    except AuthorError as e:
        log(f"FATAL: {e}")
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
