#!/usr/bin/env python3
"""Shared transaction engine for the actor / environment lessons curators.

``author_actor.py`` (actor tradecraft) and ``author_actor_benign.py`` (the two
environment-lessons directions) are the same curator: lock the queue, lock the
repo, clean-scope check, partition the batch, hand the survivors to an in-process (PydanticAI)
curator agent, cross-check the working tree it left against git, commit that corpus
with the provenance trailers, then rotate the queue. Only the corpus directory, queue
paths, outcome policy, commit trailer, generation counter, curator-agent prompt/model,
and forward-check invocation differ — captured in a ``CuratorConfig``. This module owns
the envelope; the direction modules own the config + the one genuinely-divergent piece
(``invoke_agent``).

The agent runs **no git**: it authors lesson content + a commit message (returned as
data) and the loop is the sole committer (``commit_corpus``). The loop owns the
``Generation:`` / ``{trailer_label}:`` provenance trailers — it already computes both
values, so the recorded provenance can't drift off a hand-typed literal, and there is no
commit→stamp split that could leave an un-stamped lesson commit behind (issue #321).
Confining the agent to no-git is also what lets prod fence its writable set to the corpus
at the OS layer (``docs/platform-design.md`` §4.7).

The agent owns fold/supersede/new judgment and the forward-check flow; this module
enforces the transaction envelope. The deterministic git plumbing (stray scope-gate,
corpus-clean predicate, the loop-owned pathspec-scoped committer, HEAD-sha reader, and
the working-tree cross-check) is shared with ``author.py`` via ``_author_shared``,
parameterized by the corpus dir + the ``Generation:``/``{trailer_label}:`` provenance
trailers; the ``commit_corpus`` / ``changes_outside_corpus`` / ``corpus_dir_clean`` /
``verify_agent_state`` here are thin ``CuratorConfig``-threading adapters over it
(issue #330).
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

from defender.learning.author import shared as _shared
from defender.learning.author.verify_forward.checks import ForwardCheck
from defender._io import append_jsonl, read_jsonl_rows, write_atomic
from defender._run_paths import resolve_run_bundle
from defender.learning.core import config
from defender.learning.core.config import QueueChannel, make_logger
from defender.learning.core.persist import rotate_queue_locked


GROUND_TRUTH_FILE = "ground_truth.yaml"


# Unified with author.py via the shared module — all three raise the same class,
# so the shared git layer (`_author_shared`) can raise it too (issue #330).
AuthorError = _shared.AuthorError


# ---------------------------------------------------------------------------
# Direction config — everything that differs between the curators.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CuratorConfig:
    # Repo root (git cwd + relative-path anchor) and the _pending state dir,
    # resolved from the injected ``LoopPaths`` by the per-direction factory so the
    # engine reads no import-time module globals.
    repo_root: Path
    pending_dir: Path
    # Run-bundle dir for the held-out double-check. Resolved from the injected
    # ``LoopPaths.runs_dir``, which ``with_repo_root`` keeps pinned to the shared state
    # root — so it stays correct even though ``repo_root`` moves to a batch worktree
    # (#425). Do NOT resolve the bundle off ``repo_root``.
    runs_dir: Path
    # Shared mutable-state root (``LoopPaths.state_root``) — the value pinned as
    # DEFENDER_LEARNING_STATE_DIR for the curator agent's forward-check subprocesses
    # (#425). A first-class field, not ``runs_dir.parent``: see ``LoopPaths.state_root``.
    state_root: Path
    # Corpus the agent edits (absolute) + its repo-relative form (trailing slash).
    corpus_dir: Path
    corpus_dir_rel: str
    # The forward-check verifier scripts dir (absolute, under repo_root) — resolved from the
    # injected LoopPaths so it follows the batch worktree, not hand-built off repo_root.
    verifier_dir: Path
    # Queue channel — file/consumed/lock for the stream this curator drains
    # (honors DEFENDER_LEARNING_STATE_DIR via DEFAULT_PATHS).
    channel: QueueChannel
    # Shared repo lock every curator serializes on + its wait ceiling, threaded
    # from the LoopPaths so tests inject a tmp lock instead of patching
    # _author_shared module globals (issue #389).
    repo_lock_file: Path
    repo_lock_wait_seconds: int
    # Outcome policy — which judge_outcomes author vs skip-by-policy.
    outcome_author: frozenset[str]
    outcome_skip: frozenset[str]
    # Commit-message trailer key (no colon) + its generation counter.
    trailer_label: str
    generation_fn: Callable[[], int]
    # Actor model stamped into the {trailer_label}: provenance trailer — commit
    # metadata, NOT authoring input (the curator agent never sees it). Sourced from
    # core.config's ACTOR_MODEL/BENIGN_ACTOR_MODEL, the same constants the real actor
    # invocation reads, so the recorded model matches the model the actor ran at (#449).
    actor_model: str
    log_prefix: str
    # Curator agent (in-process PydanticAI) wiring.
    author_prompt: Path
    author_model: str
    author_timeout: int
    author_effort: str
    # The one genuinely-divergent step: build the AUTHOR_RESULT dict from the
    # batch. Signature: (observations, batch_id, cfg) -> dict.
    invoke_agent: Callable[[list[dict], str, CuratorConfig], dict]

    @property
    def pending_file_rel(self) -> str:
        """Repo-relative queue path for the forward-check ``--pending`` arg.

        Derived from ``channel.file`` so a relocated ``DEFENDER_LEARNING_STATE_DIR``
        queue and the forward-check stay in sync — an out-of-repo queue falls back
        to its absolute path (which the verifier resolves directly)."""
        try:
            return str(self.channel.file.relative_to(self.repo_root))
        except ValueError:
            return str(self.channel.file)

    @property
    def run_log(self) -> Path:
        return self.pending_dir / f"{self.log_prefix}_run.jsonl"


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def read_batch(cfg: CuratorConfig) -> list[dict]:
    # Tolerant read: a torn last line from an interrupted append is skipped, not
    # raised — a JSONDecodeError here would escape every drain guard and crash
    # the author_drain every tick until the queue was hand-fixed (#446).
    return read_jsonl_rows(cfg.channel.file)


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


def is_held_out_source(runs_dir: Path, source_run_dir: str) -> bool:
    """True if the source run's ``ground_truth.yaml`` declares held-out.

    Resolve the bundle via ``resolve_run_bundle`` off ``runs_dir`` — which must be the
    shared-state ``LoopPaths.runs_dir`` (worktree-immune), NOT ``repo_root /
    source_run_dir``: under a batch author worktree the latter resolves into the
    worktree's empty ``runs/`` and the held-out net silently lets a held-out case leak
    into the corpus (#425). A *present* bundle with a missing/malformed ``ground_truth.yaml``
    → False: that's a genuinely not-held-out run. The anomalous case — a non-empty
    ``source_run_dir`` whose bundle dir is *absent* — is caught loudly upstream in
    ``_partition_pre_author`` (held as ``source_bundle_missing``), so a resolution
    regression can't reach here and silently read a missing file as not-held-out."""
    if not source_run_dir:
        return False
    path = resolve_run_bundle(runs_dir, source_run_dir) / GROUND_TRUTH_FILE
    if not path.is_file():
        return False
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError:
        return False
    return isinstance(doc, dict) and doc.get("held_out") is True


# ---------------------------------------------------------------------------
# Agent invocation — shared scaffolding; directions supply the forward-check
# prompt lines (the one place the contract differs).
# ---------------------------------------------------------------------------


def invoke_curator_agent(
    cfg: CuratorConfig,
    observations: list[dict],
    batch_id: str,
    *,
    check: ForwardCheck,
    request_limit: int,
) -> dict:
    """Spawn the in-process curator on GLM and return its parsed AUTHOR_RESULT dict.

    ``check`` is the direction's forward-check, bound onto the curator's deps at spawn — which is
    what leaves the ``forward_check`` tool with no script operand to gate. ``request_limit`` is the
    direction's per-curator cap. The agent
    runs **no git**: it authors lesson content (+ a commit message it returns as data) and the loop
    is the sole committer (``commit_corpus``) — so the agent is handed neither the generation nor the
    model, and there is no intermediate un-stamped commit it could leave behind (issue #321). Routed
    through ``curator_engine.run_curator_stage`` (imported lazily — it pulls the pydantic-ai graph),
    which sources the metered key, drives the in-process spawn under ``require_output=True``, and
    parses the ``AUTHOR_RESULT`` marker from the returned text (via ``curator_engine.extract_marked_result``). The
    RequestLogger trace lands in the persistent shared ``pending_dir`` (not the throwaway worktree),
    keyed ``{batch_id}.{pid}`` so two curators in one drain tick never truncate each other's trace.
    The nested checks read the real source bundle straight off ``cfg.runs_dir`` (the shared state
    root), so no ``DEFENDER_LEARNING_STATE_DIR`` needs pinning into any subprocess env (#425, #558)."""
    from defender.learning.author import curator_engine

    cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    return curator_engine.run_curator_stage(
        system_prompt_file=cfg.author_prompt,
        batch_id=batch_id,
        user_prompt=_shared.build_curator_user_prompt(
            observations, batch_id, corpus_dir_rel=cfg.corpus_dir_rel, label="observations",
        ),
        corpus_dir=cfg.corpus_dir,
        check=check,
        runs_dir=cfg.runs_dir,
        pending=cfg.channel.file,
        queued_ids=frozenset(
            str(o["observation_id"]) for o in observations if o.get("observation_id")
        ),
        repo_root=cfg.repo_root,
        learning_run_dir=cfg.pending_dir,
        log=make_logger(cfg.log_prefix),
        model=cfg.author_model,
        effort=cfg.author_effort,
        request_limit=request_limit,
        timeout=cfg.author_timeout,
    )


# ---------------------------------------------------------------------------
# Post-flight — working-tree cross-check + loop-owned commit
# ---------------------------------------------------------------------------


def git_head_sha(repo_root: Path) -> str:
    return _shared.git_head_sha(repo_root)


def changes_outside_corpus(repo_root: Path, corpus_dir_rel: str) -> list[str]:
    """Curator adapter over ``_shared.changes_outside`` — scope gate for the cfg corpus."""
    return _shared.changes_outside(repo_root, corpus_dir_rel)


def commit_corpus(
    generation: int, model: str, message: str, cfg: CuratorConfig,
) -> str | None:
    """Curator adapter over ``_shared.commit_corpus`` — pins the cfg corpus and stamps the
    loop-owned ``Generation:`` / ``{trailer_label}:`` provenance trailers."""
    return _shared.commit_corpus(
        cfg.repo_root,
        cfg.corpus_dir,
        message,
        trailers=[("Generation", str(generation)), (cfg.trailer_label, model)],
    )


def corpus_dir_clean(repo_root: Path, corpus_dir: Path) -> bool:
    return _shared.corpus_dir_clean(repo_root, corpus_dir)


def _result_list(result: dict, key: str) -> list[Any]:
    return _shared._result_list(result, key)


def _commit_message(result: dict) -> str:
    """Curator adapter over ``_shared._commit_message`` (noun: ``observations``)."""
    return _shared._commit_message(result, "observations")


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
        pending_file=cfg.channel.file,
        consumed_file=cfg.channel.consumed,
        lock_file=cfg.channel.lock,
        id_key="observation_id",
        held=held,
        consumed=consumed,
        commit_sha=commit_sha,
        merge_concurrent=False,
    )


# ---------------------------------------------------------------------------
# Dead-letter queue — batch-granular quarantine of a poison batch
# ---------------------------------------------------------------------------


def _deadletter_file(queue_file: Path) -> Path:
    """The per-queue dead-letter sidecar under ``_pending`` — ``<queue>.deadletter.jsonl``,
    beside the active queue so a discovered sidecar is unambiguously this stream's."""
    return queue_file.with_suffix(".deadletter.jsonl")


def _dead_letter_or_bump(
    batch: list[dict], *, queue_file: Path, pending_dir: Path, id_key: str, reason: str,
) -> None:
    """On a per-run authoring fault (``invoke_agent`` raised ``AuthorError`` — a ``RunUnprocessable``
    or an unparseable AUTHOR_RESULT, both relocated into that raise by ``run_curator_stage``), bump an
    ``attempts`` counter on the batch's active queue rows so a poison batch quarantines after
    ``LEARNING_AUTHOR_MAX_ATTEMPTS`` instead of retrying every tick forever.

    Config-agnostic on purpose: keyed by ``id_key`` (``observation_id`` for the actor/env curators,
    ``finding_id`` for the findings curator) over the explicit ``queue_file`` + ``pending_dir``, so
    BOTH the observation curators (``curator.py``) and the findings curator (``lessons/run.py``) share
    the ONE dead-letter mechanism the spec binds every curator to — not just the three that route
    through this module's envelope.

    Runs under the queue lock the envelope already holds (``run_batch_envelope`` acquires the queue
    lock), so it re-reads/rewrites the active queue WITHOUT re-locking — no self-deadlock, and since
    this rc-2 fault path returns before ``rotate_queue``, this rewrite is the queue's final state this
    tick. Batch-granular: rc 2 originates before any per-row attribution, so ALL ``batch`` rows share
    the fault. A row reaching the attempt budget moves — carrying its reason + attempt count — to the
    ``deadletter.jsonl`` sidecar and out of the active queue (the move-aside shape of the lead author's
    ``_quarantine_marker`` at the row level); the rest are rewritten with the incremented counter.
    Held / pre-consumed rows (not in ``batch``) are preserved verbatim for the next tick's
    re-partition. The sidecar append lands BEFORE the active-queue rewrite so a crash between the two
    writes duplicates a quarantined row (at-least-once) rather than losing the poison batch entirely.

    Only THIS per-run authoring fault bumps: systemic faults (``FatalConfigError`` / ``StageAbort``)
    escape uncaught and never reach here, and the dirty-corpus pre-flight (rc 2, environment) / lock
    contention (rc 0, never ran) return from the envelope before ``_author_to_author`` runs."""
    batch_ids = {o[id_key] for o in batch}
    max_attempts = config.LEARNING_AUTHOR_MAX_ATTEMPTS
    survivors: list[dict] = []
    quarantined: list[dict] = []
    for row in read_jsonl_rows(queue_file):
        if row.get(id_key) not in batch_ids:
            survivors.append(row)
            continue
        rec = dict(row)
        rec["attempts"] = int(row.get("attempts") or 0) + 1
        if rec["attempts"] >= max_attempts:
            rec["deadletter_reason"] = reason
            quarantined.append(rec)
        else:
            survivors.append(rec)
    if quarantined:
        pending_dir.mkdir(parents=True, exist_ok=True)
        append_jsonl(_deadletter_file(queue_file), quarantined)
    write_atomic(queue_file, "".join(json.dumps(r) + "\n" for r in survivors))


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
    return _shared.run_batch_envelope(
        queue_lock_file=cfg.channel.lock,
        repo_lock_file=cfg.repo_lock_file,
        repo_lock_wait_seconds=cfg.repo_lock_wait_seconds,
        repo_root=cfg.repo_root,
        corpus_dir=cfg.corpus_dir,
        corpus_dir_rel=cfg.corpus_dir_rel,
        log=make_logger(cfg.log_prefix),
        inner=lambda: _run_batch_inner(hold_committed=hold_committed, cfg=cfg),
    )


def _run_batch_inner(*, hold_committed: bool, cfg: CuratorConfig) -> int:
    log = make_logger(cfg.log_prefix)
    batch = read_batch(cfg)
    if not batch:
        log("queue empty — nothing to author")
        return 0
    all_obs = _shared.by_id(batch, "observation_id")
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
    skip-by-policy outcomes. held covers held-out double-checks, a missing source
    bundle, and unexpected outcomes (kept for human review)."""
    existing = existing_observation_ids(cfg.corpus_dir)
    log = make_logger(cfg.log_prefix)
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
        src = entry.get("source_run_dir", "")
        if src and not resolve_run_bundle(cfg.runs_dir, src).is_dir():
            # The durable learning-leg bundle is copied under runs_dir at LEARN time
            # precisely so it outlives the ephemeral run dir, so for a queued observation
            # it should always exist. A missing bundle dir is therefore an anomaly — a
            # #425-class resolution regression or a deleted bundle — NOT a normal
            # not-held-out run. Fail SAFE + LOUD: hold it (an unverifiable case must never
            # seed a lesson) and surface it, rather than letting is_held_out_source read a
            # missing ground_truth.yaml and silently return False — the exact silent mode
            # #425 exploited.
            log(f"source bundle missing for observation {oid} "
                f"(source_run_dir={src!r} → {resolve_run_bundle(cfg.runs_dir, src)}) — holding")
            rec = dict(entry)
            rec["held_reason"] = "source_bundle_missing"
            held.append(rec)
            continue
        if is_held_out_source(cfg.runs_dir, src):
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
    log = make_logger(cfg.log_prefix)
    baseline_stray = changes_outside_corpus(cfg.repo_root, cfg.corpus_dir_rel)
    try:
        result = cfg.invoke_agent(to_author, batch_id, cfg)
    except AuthorError as e:
        # A per-run authoring fault (the in-process spawn's RunUnprocessable / an unparseable
        # AUTHOR_RESULT, both surfaced as AuthorError). Bump the batch's attempt counter (and
        # quarantine at the budget) BEFORE returning rc 2, so a poison batch stops blocking the queue.
        log(f"FATAL: {e}")
        _dead_letter_or_bump(
            to_author, queue_file=cfg.channel.file, pending_dir=cfg.pending_dir,
            id_key="observation_id", reason=str(e),
        )
        return 2, None, [], []
    try:
        _shared.verify_agent_state(
            cfg.repo_root, result, cfg.corpus_dir, cfg.corpus_dir_rel,
            "observations", baseline_stray,
        )
        _shared.validate_agent_result_partition(
            result, to_author, id_key="observation_id",
            buckets=("committed", "consumed_skip"), noun="observations",
        )
        commit_sha: str | None = None
        if _result_list(result, "committed"):
            # The agent runs no git; the loop is the sole committer. Commit the
            # corpus the agent left in the working tree, stamping Generation:/<model>
            # at creation time (atomic — no un-stamped intermediate, issue #321).
            commit_sha = commit_corpus(
                generation, cfg.actor_model, _commit_message(result), cfg,
            )
    except AuthorError as e:
        log(f"FATAL: {e}")
        return 2, None, [], []
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
