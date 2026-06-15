#!/usr/bin/env python3
"""Environment lessons curator — consumer half of the env-observation queues.

Drains an env-observation queue into the checked-in, **shared** environment
corpus at ``defender/lessons-environment/`` — the corpus both actors retrieve by
classification before constructing a story.

Two sources feed that one corpus, each via its own queue + ``EnvAuthorConfig``
(issue #298), so each drains as a single-direction batch with clean per-commit
trailers and its own outcome policy:

  - **benign (FP) direction** — ``BENIGN_CONFIG``. The false-positive analog of
    ``author_actor.py``. Drains ``_pending/environment_observations.jsonl``
    (produced by the benign judge via ``loop.append_environment_observations``).
    Finding-bearing outcome: ``survived`` (the confirmed-FP story whose grounded
    routine explanation yields reliable standing facts). Commit trailer
    ``Benign-Actor-Model:``.
  - **adversarial direction** — ``ADVERSARIAL_CONFIG``. Drains
    ``_pending/actor_environment_observations.jsonl`` (the adversarial judge's
    positive-polarity env facts, extracted from grounded mispredictions whose
    refutation cited real telemetry). Finding-bearing outcomes:
    ``caught``/``incoherent``. Commit trailer ``Actor-Env-Model:``. Exposed via
    the thin ``author_actor_env.py`` entry point.

Both configs share the corpus, the clean-scope check, the corpus-wide
idempotency set, the repo lock (which serializes commits on the corpus), and the
``verify_forward_env.py`` gate — only the queue paths, outcome policy, commit
trailer + generation counter, and the actor model differ.

  Pre-flight (Python):
    1. fcntl lock on the config's queue lock — concurrent ticks refuse cleanly.
    2. Acquire the shared repo lock (_author.lock) after the queue lock; hold
       through child-agent + post-flight + rotate. Release in reverse.
    3. Clean-scope check: defender/lessons-environment/ must be git-clean.
    4. Read the batch from the config's pending queue.
    5. Outcome-policy filter (per config): keep the finding-bearing outcomes;
       drop the rest to consumed_skip with reason ``outcome_policy:{outcome}``.
    6. Held-out double-check: if ``{source_run_dir}/ground_truth.yaml`` declares
       ``held_out: true``, route to held with reason ``held_out_double_check``.
    7. Idempotency: any observation_id already cited in a lesson's
       source_observation_ids → consumed_idempotent.

  Agent invocation (Claude Code, file-edit + Bash tools):
    Hand the remaining observations + generation + actor model to the curator
    agent (``author_actor_benign.md``). It places the judge's retrieval keys,
    decides fold/supersede/new/skip per ``subject``, runs the deterministic
    forward-check (``verify_forward_env.py`` against the config's queue), commits
    with the required Generation/<trailer> trailers, and emits a final
    ``AUTHOR_RESULT: {...}`` line.

  Post-flight (Python):
    8. Parse AUTHOR_RESULT. Cross-check against git: if a commit is claimed,
       HEAD must match, touch only defender/lessons-environment/*.md, and carry
       both ``Generation: N`` and the config's model trailer matching the
       handed-in values. If no commit, HEAD must be unchanged and the corpus
       clean.
    9. Rotate the queue atomically. Held rows stay with a held_reason; consumed
       rows append to the config's consumed file.

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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Pattern

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

AUTHOR_PROMPT = LEARNING_DIR / "author_actor_benign.md"
VERIFY_SCRIPT_REL = "defender/learning/verify_forward_env.py"

# The curator *agent* model/effort/timeout are shared across directions — only the
# *actor* model (recorded in the commit trailer + handed to the curator as context)
# differs per source.
AUTHOR_ENV_MODEL = os.environ.get("LEARNING_AUTHOR_ENV_MODEL", "claude-sonnet-4-6")
AUTHOR_ENV_TIMEOUT = int(os.environ.get("LEARNING_AUTHOR_ENV_TIMEOUT_SECONDS", "1800"))
AUTHOR_ENV_EFFORT = os.environ.get("LEARNING_AUTHOR_ENV_EFFORT", "low")

BENIGN_ACTOR_MODEL = os.environ.get("BENIGN_ACTOR_MODEL", "claude-sonnet-4-6")
ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")

GROUND_TRUTH_FILE = "ground_truth.yaml"


class AuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort, queue stays intact."""


# ---------------------------------------------------------------------------
# Direction config — the only things that differ between the two sources that
# feed the shared lessons-environment/ corpus.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvAuthorConfig:
    pending_file: Path
    consumed_file: Path
    lock_file: Path
    outcome_author: frozenset[str]
    outcome_skip: frozenset[str]
    trailer_label: str             # commit-message trailer key (no colon)
    generation_fn: Callable[[], int]
    actor_model: str
    log_prefix: str

    @property
    def pending_file_rel(self) -> str:
        """Repo-relative queue path passed to ``verify_forward_env.py --pending``.

        Derived from ``pending_file`` (not a fixed string) so a relocated
        ``DEFENDER_LEARNING_STATE_DIR`` queue and the forward-check stay in sync —
        an out-of-repo queue falls back to its absolute path, which the verifier
        resolves directly, instead of a stale ``defender/learning/_pending/...``
        string the agent's cwd-relative read would miss."""
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


_PENDING_DIR = DEFAULT_PATHS.pending_dir

# Benign (FP) direction — see judge_benign.md. ``survived`` is the confirmed-FP
# outcome whose routine story held against the evidence, so the standing facts it
# grounds are reliable. Other outcomes yield no trustworthy env fact.
BENIGN_CONFIG = EnvAuthorConfig(
    pending_file=DEFAULT_PATHS.environment_observations_file,
    consumed_file=DEFAULT_PATHS.environment_observations_consumed_file,
    lock_file=DEFAULT_PATHS.environment_observations_lock_file,
    outcome_author=frozenset({"survived"}),
    outcome_skip=frozenset({"refuted", "undecidable", "incoherent"}),
    trailer_label="Benign-Actor-Model",
    generation_fn=_shared.benign_generation_count,
    actor_model=BENIGN_ACTOR_MODEL,
    log_prefix="author_actor_benign",
)

# Adversarial direction (issue #298) — the env facts the adversarial judge
# extracts from grounded mispredictions. Finding-bearing outcomes mirror
# author_actor.py: ``caught``/``incoherent`` (the refutation cited real
# telemetry); ``survived``/``undecidable`` carry no reliable env fact.
ADVERSARIAL_CONFIG = EnvAuthorConfig(
    pending_file=DEFAULT_PATHS.actor_environment_observations_file,
    consumed_file=DEFAULT_PATHS.actor_environment_observations_consumed_file,
    lock_file=DEFAULT_PATHS.actor_environment_observations_lock_file,
    outcome_author=frozenset({"caught", "incoherent"}),
    outcome_skip=frozenset({"survived", "undecidable"}),
    trailer_label="Actor-Env-Model",
    generation_fn=_shared.actor_env_generation_count,
    actor_model=ACTOR_MODEL,
    log_prefix="author_actor_env",
)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def acquire_queue_lock(cfg: EnvAuthorConfig) -> Any:
    _PENDING_DIR.mkdir(parents=True, exist_ok=True)
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


def read_batch(cfg: EnvAuthorConfig) -> list[dict]:
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
# corpus files. Both env curators (benign + adversarial) drain in one serial tick
# and each calls this; the repo lock means the corpus only changes when a commit
# lands, which bumps the signature and invalidates the cache. So a second drain on
# an unchanged corpus reuses the parse instead of re-globbing + re-parsing YAML.
_EXISTING_IDS_CACHE: dict[tuple[tuple[str, int], ...], set[str]] = {}


def existing_observation_ids() -> set[str]:
    """Union of source_observation_ids across all environment lessons.

    Corpus-wide (both sources share the corpus), so an id already authored by
    either direction is treated as consumed."""
    if not LESSONS_ENV_DIR.is_dir():
        return set()
    paths = [
        p for p in sorted(LESSONS_ENV_DIR.glob("*.md")) if not p.name.startswith("_")
    ]
    sig = tuple((p.name, p.stat().st_mtime_ns) for p in paths)
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
    cfg: EnvAuthorConfig,
) -> dict:
    """Spawn the curator agent. Returns parsed AUTHOR_RESULT dict."""
    verifier_py = _runner.resolve_verifier_python(REPO_ROOT)
    forward_check_command = (
        f"{verifier_py} {VERIFY_SCRIPT_REL} "
        f"--corpus {LESSONS_ENV_DIR_REL} --pending {cfg.pending_file_rel}"
    )
    user_prompt = (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: {LESSONS_ENV_DIR_REL}\n"
        f"generation: {generation}\n"
        f"actor_model: {cfg.actor_model}\n"
        f"trailer_label: {cfg.trailer_label}\n"
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
    _PENDING_DIR.mkdir(parents=True, exist_ok=True)
    options = _runner.RunnerOptions(
        system_prompt_file=AUTHOR_PROMPT,
        allowed_tools=allowed_tools,
        model=AUTHOR_ENV_MODEL,
        effort=AUTHOR_ENV_EFFORT,
        timeout_seconds=AUTHOR_ENV_TIMEOUT,
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


def assert_head_trailers(
    expected_generation: int, expected_model: str, cfg: EnvAuthorConfig
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
    cfg: EnvAuthorConfig,
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
        assert_head_trailers(expected_generation, expected_model, cfg)
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
    cfg: EnvAuthorConfig,
) -> None:
    """Held-only rewrite of the queue + append to consumed (the shared
    ``rotate_queue_locked`` with ``merge_concurrent=False``).

    No re-read-merge (unlike ``author.rotate_queue``): ``run_batch`` holds the
    queue lock across read→rotate, and the producer's append blocks on that same
    lock, so no observation can arrive mid-batch — a held-only rewrite cannot lose
    data, and re-taking the lock here would self-deadlock (hence
    ``merge_concurrent=False``)."""
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


def _logger(cfg: EnvAuthorConfig) -> Callable[[str], None]:
    def _log(msg: str) -> None:
        print(f"[{cfg.log_prefix}] {msg}", file=sys.stderr)
    return _log


def _by_id(rows: list[dict]) -> dict[str, dict]:
    return {r["observation_id"]: r for r in rows}


def run_batch(*, hold_committed: bool = False, cfg: EnvAuthorConfig = BENIGN_CONFIG) -> int:
    """Drain an env-observation batch into the shared environment-lessons corpus.

    ``hold_committed`` (set by the serial author drain) keeps just-committed
    observations in the queue instead of rotating them out — see
    ``author.run_batch`` for the rationale."""
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
            assert_clean_lessons_env_dir()
        except AuthorError as e:
            log(f"FATAL: {e}")
            return 2
        return _run_batch_inner(hold_committed=hold_committed, cfg=cfg)
    finally:
        if repo_lock is not None:
            _shared.release_repo_lock(repo_lock)
        release_queue_lock(queue_lock)


def _run_batch_inner(*, hold_committed: bool, cfg: EnvAuthorConfig) -> int:
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
        f"batch={batch_id} generation={generation} "
        f"actor_model={cfg.actor_model} total={len(batch)} "
        f"to_author={len(to_author)} held={len(held)} pre_consumed={len(consumed_pre)}"
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
    batch: list[dict], cfg: EnvAuthorConfig,
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
        if outcome in cfg.outcome_skip:
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
        if outcome not in cfg.outcome_author:
            rec = dict(entry)
            rec["held_reason"] = f"unexpected_outcome:{outcome}"
            held.append(rec)
            continue
        to_author.append(entry)
    return held, consumed_pre, to_author


def _author_to_author(
    to_author: list[dict], all_obs: dict[str, dict],
    batch_id: str, generation: int, cfg: EnvAuthorConfig,
) -> tuple[int, str | None, list[dict], list[dict]]:
    """Run the agent on `to_author` and partition its result."""
    log = _logger(cfg)
    pre_agent_head = git_head_sha()
    try:
        result = invoke_agent(to_author, batch_id, generation, cfg)
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


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_benign.py", file=sys.stderr)
        return 64
    return run_batch(cfg=BENIGN_CONFIG)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
