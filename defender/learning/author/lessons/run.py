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

  Agent invocation (Claude Code, file-edit tools — no git):
    Hand the remaining findings to the curator agent
    (``author.md``). It enumerates existing lessons, decides
    new/fold/skip per finding, runs ``verify_forward.py`` on each
    edit, leaves ``defender/lessons/`` in its final state, and emits a
    final ``AUTHOR_RESULT: {...}`` line (with the commit message as data).

  Post-flight (Python):
    6. Parse AUTHOR_RESULT. Cross-check the working tree: nothing
       changed outside defender/lessons/*.md, and the corpus is dirty
       iff the agent committed anything. Then the loop — the sole
       committer — commits the corpus (``commit_lessons``).
    7. Rotate the queue atomically (tmp file + os.replace). Held
       findings stay in findings.jsonl; consumed findings append to
       consumed.jsonl with category + consumed_at + commit_sha.
    8. If no commit but there are held forward-BAD entries, write a
       one-line summary to _pending/held_report.log so the held-back
       surface isn't silent on no-commit runs.

The agent itself owns lesson dedup/fold judgment and the per-edit
forward gate; this module just enforces the transaction envelope. The
deterministic git plumbing (stray scope-gate, corpus-clean predicate, the
loop-owned pathspec-scoped committer, HEAD-sha reader, working-tree
cross-check) lives once in ``_author_shared``; this module's
``commit_lessons`` / ``changes_outside_lessons`` / ``lessons_dir_clean`` /
``verify_agent_state`` are thin adapters that pin the ``defender/lessons/``
corpus and pass no provenance trailers (issue #330).
"""
from __future__ import annotations

import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

# Subprocess driver + repo-lock helpers shared with author_actor.py.
from defender.learning.author import curator as _curator
from defender.learning.author import shared as _shared
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




# Unified with _author_curator via the shared module — all three raise the same
# class, so the shared git layer (`_author_shared`) can raise it too (issue #330).
AuthorError = _shared.AuthorError


@dataclass(frozen=True)
class AuthorConfig:
    """Injected filesystem layout + curator-agent wiring for the findings author.

    Built once per ``run_batch`` from a ``LoopPaths`` so every helper reads ``cfg.x``
    instead of an import-time module global — the findings-corpus analog of
    ``_author_curator.CuratorConfig``. Mutable learning state (runs/_pending) honors
    DEFENDER_LEARNING_STATE_DIR via the paths; prompts/corpus stay repo-relative."""
    repo_root: Path
    lessons_dir: Path
    lessons_dir_rel: str
    runs_dir: Path
    pending_dir: Path
    pending_file: Path
    consumed_file: Path
    lock_file: Path
    findings_lock_file: Path
    # The shared repo lock every curator serializes on + its wait ceiling, threaded
    # from the config so tests inject a tmp lock instead of patching _author_shared
    # module globals (issue #389).
    repo_lock_file: Path
    repo_lock_wait_seconds: int
    held_report: Path
    author_run_log: Path
    author_prompt: Path
    # The curator spawn — a field (defaulted to the module ``invoke_agent``) so tests
    # inject a fake via ``dataclasses.replace(cfg, invoke_agent=fake)``.
    invoke_agent: Callable[[list[dict], str, AuthorConfig], dict]
    author_model: str = AUTHOR_MODEL
    author_timeout: int = AUTHOR_TIMEOUT
    author_effort: str | None = AUTHOR_EFFORT
    # Pins the corpus manifest's shuffle seed. Production leaves it None and the manifest is
    # seeded from the batch_id; only the author eval sets it, because batch_id is a fresh uuid4
    # per drain and an eval that redraws the curator's menu order every run cannot measure the
    # position bias the shuffle exists to remove.
    manifest_seed: str | None = None


def build_author_config(
    paths: LoopPaths = DEFAULT_PATHS, *, manifest_seed: str | None = None
) -> AuthorConfig:
    """Resolve the findings author's paths + agent wiring from an injected ``LoopPaths``.

    Constructed at call time (not import) so a test rooted at a tmp tree threads one
    ``LoopPaths(repo_root=tmp)`` instead of monkeypatching module path globals."""
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


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def read_batch(cfg: AuthorConfig) -> list[dict]:
    """Snapshot the findings queue under the producer's lock.

    Unlike the observation authors, this author's instance lock (``.lock``) and
    the shared repo lock are NOT the lock ``append_findings`` writes under
    (``.findings.lock``), so a concurrent live run can be mid-append while we
    read. Take ``FINDINGS_LOCK_FILE`` briefly (released before the minutes-long
    agent call) so we never read a torn multi-line append, and parse tolerantly
    so a blank/torn line left by a crashed prior append is skipped, not raised
    (the row stays queued and is picked up next tick)."""
    if not cfg.pending_file.is_file():
        return []
    with _flock(cfg.findings_lock_file):
        return read_jsonl_rows(cfg.pending_file)


def disposition_for(cfg: AuthorConfig, run_id: str) -> str | None:
    """Return normalized_disposition from runs/<run_id>/source_refs.yaml.

    Returns None if the file or field is missing — caller routes that as
    "no ground truth" (held).
    """
    refs = cfg.runs_dir / run_id / "source_refs.yaml"
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


def existing_finding_ids(cfg: AuthorConfig) -> set[str]:
    """Union of source_finding_ids across all lesson frontmatter.

    Walks the corpus through the shared ``iter_lessons``, like the manifest this pre-flight runs
    beside, so the two cannot disagree about what a lesson *is*. The hand-rolled walk this replaces
    disagreed on two counts, each a live bug: it read the file OUTSIDE any guard, so one
    undecodable byte raised ``UnicodeDecodeError`` (a ``ValueError``, not an ``OSError``) and took
    the whole author drain down instead of skipping one lesson; and it did not skip ``_``-prefixed
    files, the one corpus convention every other reader honours.

    NOT a third count, though an earlier draft of this docstring claimed one: its ``\\A---\\n``
    regex did *not* miss a CRLF lesson. ``Path.read_text()`` opens with ``newline=None``, so
    universal-newline translation has already turned ``\\r\\n`` into ``\\n`` before any pattern
    runs. Left recorded because the false version is the sort of claim that gets cited while
    triaging a real encoding bug."""
    ids: set[str] = set()
    for lesson in iter_lessons(
        cfg.lessons_dir, warn_label=lambda p: f"finding-id pre-flight: {p.name}"
    ):
        sids = lesson.fm.get("source_finding_ids") or []
        if isinstance(sids, list):
            ids.update(sid for sid in sids if isinstance(sid, str))
    return ids


# ---------------------------------------------------------------------------
# Agent invocation
# ---------------------------------------------------------------------------


def build_user_prompt(findings: list[dict], batch_id: str, cfg: AuthorConfig) -> str:
    """The findings curator's user payload — the shared curator builder, with this curator's
    corpus and row label."""
    return _shared.build_curator_user_prompt(
        findings, batch_id, corpus_dir=cfg.lessons_dir,
        corpus_dir_rel=cfg.lessons_dir_rel, label="findings",
        manifest_seed=cfg.manifest_seed,
    )


def invoke_agent(findings: list[dict], batch_id: str, cfg: AuthorConfig) -> dict:
    """Spawn the in-process findings curator on GLM. Returns the parsed AUTHOR_RESULT dict.

    Routed through ``curator_engine.run_curator_stage`` (imported lazily — it pulls the pydantic-ai
    graph), shared with the actor/env curators: it sources the metered key, drives the in-process
    spawn under ``require_output=True``, and relocates the ``AUTHOR_RESULT`` marker parse out of the
    retired ``claude -p`` transport (a per-run fault / unparseable marker → ``AuthorError``, the
    caller's rc-2 lane, unchanged). This wrapper builds the findings-specific user prompt and binds
    the findings forward-check onto the deps; the curator's per-spawn ``AgentPolicy`` (built in
    ``CuratorDeps.for_run``) confines writes to ``defender/lessons/**.md`` and the bash lane to a
    scoped ``rm`` + the corpus viewers. The agent runs no git: it authors lesson content (+ a commit
    message it returns as data) and the loop is the sole committer (``commit_lessons``).

    ``queued_ids`` are the batch's own source ``run_id``s — the forward-check tool confines the
    model-supplied id to them, so a curator cannot check a lesson against an unrelated case's
    transcript."""
    from defender.learning.author import curator_engine
    from defender.learning.author.verify_forward.checks import FINDINGS_CHECK

    cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    return curator_engine.run_curator_stage(
        system_prompt_file=cfg.author_prompt,
        batch_id=batch_id,
        user_prompt=build_user_prompt(findings, batch_id, cfg),
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
    )

# ---------------------------------------------------------------------------
# Post-flight
# ---------------------------------------------------------------------------


def git_head_sha(repo_root: Path) -> str:
    return _shared.git_head_sha(repo_root)


def changes_outside_lessons(cfg: AuthorConfig) -> list[str]:
    """Author adapter over ``_shared.changes_outside`` — scope gate for ``defender/lessons/``."""
    return _shared.changes_outside(cfg.repo_root, cfg.lessons_dir_rel)


def commit_lessons(cfg: AuthorConfig, message: str) -> str | None:
    """Author adapter over ``_shared.commit_corpus`` — pins ``defender/lessons/`` and passes
    no provenance trailers (unlike the actor/env curators, the findings corpus carries none)."""
    return _shared.commit_corpus(cfg.repo_root, cfg.lessons_dir, message)


def lessons_dir_clean(cfg: AuthorConfig) -> bool:
    return _shared.corpus_dir_clean(cfg.repo_root, cfg.lessons_dir)


def _result_list(result: dict, key: str) -> list[Any]:
    return _shared._result_list(result, key)


def _commit_message(result: dict) -> str:
    """Author adapter over ``_shared._commit_message`` (noun: ``findings``)."""
    return _shared._commit_message(result, "findings")


def rotate_queue(
    cfg: AuthorConfig,
    *,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
) -> None:
    """Drain findings.jsonl under the findings flock, preserving concurrent appends."""
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
    """Single-line summary for no-commit runs.

    The agent surfaces held lessons in the commit message normally; if
    nothing committed, we still want a human-grep-able trace that BAD
    lessons existed.
    """
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
    with cfg.held_report.open("a") as fh:
        fh.write(line)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


_log = make_logger("author")


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths = DEFAULT_PATHS,
    cfg: AuthorConfig | None = None,
) -> int:
    """Drain a findings batch into the lessons corpus.

    ``hold_committed`` (set by the serial author drain, which commits onto an
    unmerged PR branch) keeps the just-committed findings in the queue instead of
    rotating them to ``consumed.jsonl``, so a rejected/edited PR can't strand
    them: they re-author next batch unless the PR merged — in which case
    ``existing_finding_ids()`` (reading the post-fetch ``origin/main`` corpus)
    filters them to ``consumed_idempotent`` and they rotate out cleanly. Standalone
    callers leave it False (today's commit-and-rotate behavior).

    ``cfg`` defaults to one built from ``paths``; tests pass a cfg with a fake
    ``invoke_agent`` (``dataclasses.replace``) to avoid spawning ``claude``."""
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


def _partition_pre_author(cfg: AuthorConfig, batch: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split the queue into (held, consumed_idempotent) before the agent runs.

    held → no confident ground truth for the finding's direction; stays in
    findings.jsonl. consumed_idempotent → already-committed findings the agent
    shouldn't see again.
    """
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
    """Run the agent on `to_author` and partition its result.

    Returns (rc, commit_sha, committed, held_forward_bad, consumed_skip).
    rc != 0 means a FATAL happened and the caller should bail with that
    code; the queue stays intact via the outer lock/rotate flow.
    """
    baseline_stray = changes_outside_lessons(cfg)
    try:
        result = cfg.invoke_agent(to_author, batch_id, cfg)
    except AuthorError as e:
        # A per-run authoring fault (the in-process spawn's RunUnprocessable / an unparseable
        # AUTHOR_RESULT). Bump the batch's attempt counter (and quarantine at the budget) BEFORE
        # returning rc 2, so a poison findings batch stops blocking the queue — the same
        # batch-granular dead-letter the observation curators get (findings rows key on finding_id).
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
            # The agent runs no git; the loop is the sole committer. Commit the
            # lessons the agent left in the working tree (no provenance trailers).
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
