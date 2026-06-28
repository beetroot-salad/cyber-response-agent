#!/usr/bin/env python3
"""Minimal lead-author driver: fold lessons from one defender run into
the executed-side query template catalog at
``defender/skills/gather/queries/`` plus the per-system ``SKILL.md`` surface.

Per ``defender/CLAUDE.md``, defender is an experimental PoC; this
driver carries the minimum discipline needed for safe interleaving
with the gap-side authors and nothing more.

**The agent runs no git; the loop is the sole committer** (mirrors the lessons
author). The agent edits ``defender/skills/`` and ``rm``s discarded/promoted
drafts; the loop verifies the working-tree edits and commits them, pathspec-scoped,
via ``_author_shared.commit_corpus``. The lead-author **drain** runs this in its own
``lead-author/<id>`` git worktree (``core.orchestrate.lead_author_drain``), so two
authors never share a HEAD — ``run`` here just edits + commits at ``deps.paths.repo_root``
(the worktree in prod; a tmp tree under test) and is agnostic to which it is.

Lifecycle, per tick (one queued run dir):

  1. Acquire the per-author queue lock
     (``_pending_leads/.lock``). Non-blocking; another in-flight tick ⇒ return 0.
     (No shared repo lock — worktree isolation + the drain lock replace it.)
  2. Preflight brake: ``<run_dir>/lead_author/done`` ⇒ already processed.
  3. Extract ``ExecutedLead`` records by joining the leads + queries tables;
     synthesize ``_draft/`` skeletons for executed-but-uncatalogued verbs.
  4. Capture the pre-agent stray baseline (paths outside ``defender/skills/``*.md).
  5. Build per-lead handoff blocks + pending system-skill drafts.
  6. Spawn ``claude -p`` with a no-git allowlist (Edit/Write ``defender/skills/`` +
     ``rm`` drafts). Non-zero exit ⇒ return rc=2; the drain quarantines the marker.
  7. Loop-side scope gate (``_verify_skills_state``) over one ``git status`` read:
     no strays outside scope, no protected-surface mutation, no established/SKILL.md
     deletion. A violation raises ``LeadAuthorError`` (the drain quarantines the marker).
  8. Loop commits the corpus pathspec-scoped (``commit_corpus``) with a deterministic
     loop-authored message, then writes the ``done`` sentinel.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning import lead_repository
from defender.learning.author import runner as _author_runner
from defender.learning.author import shared as _author_shared
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
from defender.learning.leads import lead_classifier
from defender.learning.leads import lead_neighbors
from defender.learning.leads import lead_render

# Three cohesive leaf modules carry the draft-synthesis, lead-extraction, and
# scope-gate-path-classifier groups; this driver re-exports the symbols they own so
# orchestrate.py + the tests reach them on ``lead_author`` unchanged. The path
# constants live in ``path_validation`` (the lowest leaf) and are imported back here,
# so a leaf never imports them *from* this module (which would cycle).
from defender.learning.leads.path_validation import (  # noqa: F401  (re-exported)
    CATALOG_DIR,
    CATALOG_REL,
    LEARNING_DIR,
    REPO_ROOT,
    SKILLS_DIR,
    SKILLS_REL,
    _draft_twin,
    _is_catalog_path,
    _is_draft_readme,
    _is_in_scope,
    _is_schema_md,
    _is_system_execution_md,
    _is_system_file,
    _is_system_skill_draft,
    _is_system_skill_md,
    _porcelain_records,
    _under_draft,
)
from defender.learning.leads.draft_synthesis import (  # noqa: F401  (re-exported)
    _ESQL_SYSTEMS,
    _NON_CANDIDATE_VERBS,
    _SAFE_ID_SEGMENT,
    _draft_candidate_segments,
    _draft_skeleton,
    _executed_query,
    _is_esql,
    synthesize_drafts,
)
from defender.learning.leads.lead_extraction import (  # noqa: F401  (re-exported)
    _VALID_PAYLOAD_STATUSES,
    ExecutedLead,
    LeadAuthorError,
    collect_general_failures,
    extract,
    extract_from_joined,
)


# Mutable lead-author queue state resolves from DEFAULT_PATHS so it honors
# DEFENDER_LEARNING_STATE_DIR (out-of-repo under concurrent runs).
PENDING_DIR = _loop_config.DEFAULT_PATHS.lead_pending_dir
QUEUE_LOCK_FILE = PENDING_DIR / ".lock"
RUN_LOG_FILE = PENDING_DIR / "lead_author_run.log"
LEAD_AUTHOR_PROMPT = LEARNING_DIR / "leads" / "lead_author.md"
LEAD_PITFALLS_PROMPT = LEARNING_DIR / "leads" / "lead_pitfalls.md"

LEAD_AUTHOR_MODEL = os.environ.get("LEAD_AUTHOR_MODEL", "claude-sonnet-4-6")
LEAD_AUTHOR_TIMEOUT = int(os.environ.get("LEAD_AUTHOR_TIMEOUT_SECONDS", "1800"))


def _lift_threshold() -> int:
    """Min count of pending system-skill drafts before the lift activates.

    Mirrors ``LEARNING_AUTHOR_THRESHOLD`` from ``loop.py``: drain the
    queue only once enough have accumulated to make the spawn worthwhile.
    Read at call time so tests can monkeypatch via ``monkeypatch.setenv``.
    """
    return _loop_config.env_int("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", 5)


# The pitfalls-curation threshold is read from ``core.config.pitfalls_threshold`` — the
# shared reader the lead-author drain's wake gate uses too, so the gate and this curator
# can't disagree about whether the queue is at threshold (see that function's docstring).


# ---------------------------------------------------------------------------
# Driver primitives
# ---------------------------------------------------------------------------


_log = _loop_config.make_logger("lead-author", flush=True)


def acquire_queue_lock() -> Any:
    """Non-blocking acquire of the per-author queue lock.

    Returns the open file handle on success, ``None`` if another tick
    holds it.
    """
    _log(f"acquire queue-lock={QUEUE_LOCK_FILE}")
    fh = _author_shared.acquire_flock(QUEUE_LOCK_FILE)
    if fh is None:
        _log("queue-lock held by another tick — skipping")
        return None
    _log("queue-lock acquired")
    return fh


def release_queue_lock(fh: Any) -> None:
    if fh is None:
        return
    _author_shared.release_flock(fh)
    _log("release queue-lock")


# ---------------------------------------------------------------------------
# Handoff construction
# ---------------------------------------------------------------------------


def build_handoff(
    run_dir: Path, executed: list[ExecutedLead], joined_leads: list | None = None,
    *, repo_root: Path | None = None, catalog_dir: Path | None = None,
    catalog: list | None = None,
) -> list[dict]:
    """Build per-*template* handoff blocks for the agent prompt.

    One handoff per ``executed_template_path``, even when the same
    template was touched multiple times in this run — the invocations
    list collapses what would otherwise be three sequential edit
    cycles on the same file into one decision.

    Leads whose ``query_id`` doesn't resolve in the catalog are dropped
    with a corpus-health warning. Per ``defender/CLAUDE.md`` every id
    is supposed to resolve at lead-author time; a miss is a runtime
    contract violation worth surfacing in the log but not worth taking
    the catalog out for.
    """
    # None ⇒ resolve the module global at call time (the production default); the
    # deps factory binds the injected paths so tests drive a tmp tree via LoopPaths.
    repo_root = repo_root if repo_root is not None else REPO_ROOT
    # Reuse the tick's once-loaded catalog when threaded; else load. The caller
    # threads it only when synthesis minted no drafts this tick — when drafts were
    # minted, `catalog` is None here and we re-glob so a freshly-minted `_draft/`
    # resolves into a handoff (the WARN-and-draft path) instead of WARN-and-drop.
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    by_id = {t.id: t for t in catalog}
    idf = lead_neighbors.build_idf(lead_neighbors._all_query_variants(catalog))
    # Reconstruct dict-shaped entries from the join surface for the
    # (dict-based) composite classifier — one entry per joined lead, in the
    # same order as the entry_index ExecutedLead carries. Reuse the caller's
    # already-joined list when given, rather than re-reading both tables.
    if joined_leads is None:
        joined_leads = lead_repository.joined(run_dir)
    entries = [
        {"queries": [{"id": q.query_id, "params": dict(q.params)} for q in jl.queries]}
        for jl in joined_leads
    ]
    template_path_by_id = {
        tid: str(tpl.path.relative_to(repo_root))
        for tid, tpl in by_id.items()
    }

    # Group invocations by the executed template path. Preserve
    # first-seen order so the handoff stream is deterministic.
    grouped: dict[Path, list[ExecutedLead]] = {}
    seen_order: list[Path] = []
    for lead in executed:
        tpl = by_id.get(lead.query_id)
        if tpl is None:
            _log(
                f"WARN unresolved query_id={lead.query_id!r} at lead "
                f"{lead.lead_id} (runtime contract violation; dropping invocation)"
            )
            continue
        if tpl.path not in grouped:
            grouped[tpl.path] = []
            seen_order.append(tpl.path)
        grouped[tpl.path].append(lead)

    handoffs: list[dict] = []
    for tpl_path in seen_order:
        invocations_raw = grouped[tpl_path]
        tpl = by_id[invocations_raw[0].query_id]
        neighbors = lead_neighbors.top_k_neighbors(
            tpl.id, catalog, idf=idf, k=3,
        )
        invocations: list[dict] = []
        for lead in invocations_raw:
            entry = entries[lead.entry_index] if lead.entry_index < len(entries) else {}
            query = (entry.get("queries") or [])[lead.query_index] \
                if isinstance(entry.get("queries"), list) else {}
            composite_kind = lead_classifier.infer_composite_kind(
                entry, query, entries,
            )
            co_dispatched = lead_classifier.co_dispatched_template_paths(
                entry, lead.query_index, template_path_by_id,
            )
            try:
                rendered_query = lead_render.render_query(tpl.path, lead.params)
            except OSError as e:
                _log(f"WARN render_query failed for {tpl.path}: {e}")
                rendered_query = ""
            invocations.append(
                {
                    "lead_id": lead.lead_id,
                    "query_index": lead.query_index,
                    "goal_text": lead.goal_text,
                    "what_to_summarize": list(lead.what_to_summarize),
                    "params": dict(lead.params),
                    "executed_query": _executed_query(lead),
                    "rendered_query": rendered_query,
                    "payload_status": lead.payload_status,
                    "payload_digest": lead.payload_digest,
                    "result_refs": (
                        [str(lead.raw_ref.relative_to(run_dir))] if lead.raw_ref else []
                    ),
                    "composite_kind": composite_kind,
                    "co_dispatched_with": co_dispatched,
                }
            )
        handoffs.append(
            {
                "executed_template_path": str(tpl.path.relative_to(repo_root)),
                "query_id": tpl.id,
                "status": tpl.status,
                "neighbors": [
                    {
                        "template_path": str(n.template_path.relative_to(repo_root)),
                        "score": n.score,
                    }
                    for n in neighbors
                ],
                "invocations": invocations,
            }
        )
    return handoffs


# ---------------------------------------------------------------------------
# System-skill draft discovery (lift queue)
# ---------------------------------------------------------------------------


_DRAFT_README_NAMES = frozenset({"README.md", "_TEMPLATE.md"})


def discover_system_drafts(*, skills_dir: Path | None = None) -> list[Path]:
    """Pending drafts under ``defender/skills/{system}/_draft/`` (one level).

    Excludes the surface-declaration README and any template skeletons.
    The single-level glob naturally excludes catalog drafts at
    ``defender/skills/gather/queries/{system}/_draft/`` — those are
    handled by the executed-template handoff stream.
    """
    skills_dir = skills_dir if skills_dir is not None else SKILLS_DIR
    out: list[Path] = []
    if not skills_dir.is_dir():
        return out
    for system_dir in sorted(skills_dir.iterdir()):
        if not system_dir.is_dir():
            continue
        draft_dir = system_dir / "_draft"
        if not draft_dir.is_dir():
            continue
        for draft in sorted(draft_dir.iterdir()):
            if not draft.is_file():
                continue
            if draft.suffix != ".md":
                continue
            if draft.name in _DRAFT_README_NAMES:
                continue
            out.append(draft)
    return out


def build_system_draft_handoffs(
    drafts: list[Path], *, repo_root: Path | None = None,
) -> list[dict]:
    """One handoff per pending draft. ``{draft_path, system, skill_path}`` (repo-relative)."""
    repo_root = repo_root if repo_root is not None else REPO_ROOT
    out: list[dict] = []
    for draft in drafts:
        rel = draft.relative_to(repo_root)
        # Parent is .../skills/{system}/_draft → grandparent is the system dir.
        system_dir = draft.parent.parent
        system = system_dir.name
        skill_md = system_dir / "SKILL.md"
        out.append(
            {
                "draft_path": str(rel),
                "system": system,
                "skill_path": str(skill_md.relative_to(repo_root)),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Agent invocation
# ---------------------------------------------------------------------------


# The agent runs NO git — the loop is the sole committer. Edit/Write are scoped to the
# skills tree; promote = Write the established template + ``rm`` the draft, discard = ``rm``
# the draft, fold/split/lift = Edit/Write. The loop's ``_verify_skills_state`` enforces the
# fine scope (in-scope, no protected-surface mutation, draft-only deletion), so the
# allowlist itself can be the coarse ``defender/skills/`` tree.
#
# Two matcher grammars, deliberately: ``**`` is the documented recursive glob for the
# *file-path* tools (Edit/Write/Read), so it matches a nested draft path there. Claude
# Code's *Bash* matcher is a different grammar — a single ``*`` over the raw command
# string, which already crosses ``/`` — and ``**`` is undefined for it, so the ``rm`` grant
# uses the documented ``:*`` prefix form (``Bash(rm defender/skills/:*)``) rather than an
# undocumented ``**`` that only matches nested drafts by accident. The drain hands the agent
# repo-relative paths and runs it with cwd at the worktree, so one repo-relative matcher
# covers every removal — no worktree-absolute twin needed.
_ALLOWLIST = (
    "Read,Glob,Grep,"
    f"Edit({SKILLS_REL}**),"
    f"Write({SKILLS_REL}**),"
    f"Bash(rm {SKILLS_REL}:*)"
)


def invoke_agent(
    run_dir: Path,
    handoffs: list[dict],
    pending_drafts: list[dict] | None = None,
    *,
    repo_root: Path = REPO_ROOT,
) -> int:
    """Spawn ``claude -p`` via the shared runner with the lead-author prompt. Returns rc.

    Routed through ``_author_runner.invoke_claude_print_raw`` (issue #373) so the lead
    author shares the one spawn path — select-loop deadline, stderr drain, non-blocking
    stdin, event teeing to the run log — instead of its own ``subprocess.run``. The agent
    runs no git and writes no result marker; its edits + ``rm``s sit in the working tree
    (the source of truth), so it uses the raw variant (no ``AUTHOR_RESULT:`` marker) and
    maps the runner's timeout to rc 124 so ``_run_locked`` returns rc=2 and the drain
    quarantines the marker. ``repo_root`` is the batch worktree (the drain
    passes ``deps.paths.repo_root``) and becomes the agent's cwd, so its repo-relative
    ``rm`` paths resolve under it — no worktree-absolute matcher is needed."""
    pending_drafts = pending_drafts or []
    user_prompt = (
        f"run_dir: {run_dir}\n"
        f"catalog_dir: {CATALOG_REL}\n"
        f"skills_dir: {SKILLS_REL}\n"
        f"executed_template_handoffs ({len(handoffs)}):\n"
        f"{json.dumps(handoffs, indent=2)}\n"
        f"pending_system_drafts ({len(pending_drafts)}):\n"
        f"{json.dumps(pending_drafts, indent=2)}\n"
    )
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    _log(f"spawn claude (model={LEAD_AUTHOR_MODEL}, timeout={LEAD_AUTHOR_TIMEOUT}s)")
    options = _author_runner.RunnerOptions(
        system_prompt_file=LEAD_AUTHOR_PROMPT,
        allowed_tools=_ALLOWLIST,
        model=LEAD_AUTHOR_MODEL,
        effort=None,
        timeout_seconds=LEAD_AUTHOR_TIMEOUT,
        cwd=repo_root,
        log_path=RUN_LOG_FILE,
        result_marker=None,
        batch_id=run_dir.name,
    )
    try:
        rc, _text = _author_runner.invoke_claude_print_raw(options, user_prompt, _log)
    except _author_runner.RunnerError as e:
        _log(f"claude failed: {e}")
        return 124
    _log(f"claude exited rc={rc}")
    return rc


# ---------------------------------------------------------------------------
# Scope gate — the loop verifies the agent's working-tree edits before committing
# ---------------------------------------------------------------------------


def _verify_skills_state(repo_root: Path, baseline_stray: list[str]) -> list[str]:
    """Verify the agent's uncommitted edits before the loop commits + writes ``done``.

    The agent runs no git, so its edits sit in the working tree. One ``git status`` read
    (``_porcelain_records``) drives every check; returns the in-scope changed paths (for
    the commit message). Raises ``LeadAuthorError`` — the drain quarantines the marker — on:
      * a NEW change outside ``defender/skills/``*.md (stray ``Write`` / improvised shim),
        diffed against ``baseline_stray`` captured before the agent ran so pre-existing
        leftovers aren't blamed on it;
      * an in-skills change outside lead_author's scope (not catalog / system ``SKILL.md`` /
        ``_draft/``), or a ``_draft/README.md`` / catalog ``SCHEMA.md`` mutation;
      * a deletion of a non-draft established template or ``SKILL.md`` — delete-prohibition,
        which also covers a demotion (rm-established + write-draft shows the ``D`` here);
      * a half-promote — an established catalog template written while its ``_draft/`` twin
        still exists on disk (the promote's ``rm`` never happened). This one is invisible to
        the records-only checks above: the surviving draft is *unchanged*, so it isn't in
        ``git status`` at all — only a filesystem probe of the twin sees it.
    """
    records = _porcelain_records(repo_root)

    def _in_corpus(p: str) -> bool:
        return p.startswith(SKILLS_REL) and p.endswith(".md")

    strays = sorted({p for _, p in records if not _in_corpus(p)})
    new_stray = sorted(set(strays) - set(baseline_stray))
    if new_stray:
        raise LeadAuthorError(
            f"agent changed files outside {SKILLS_REL}*.md: {new_stray}; refusing to commit"
        )

    changed: list[str] = []
    for xy, path in records:
        if not _in_corpus(path):
            continue  # non-corpus strays already rejected above
        if not _is_in_scope(path):
            raise LeadAuthorError(
                f"agent edited an out-of-scope skills path ({path}); refusing to commit"
            )
        if _is_draft_readme(path) or _is_schema_md(path):
            raise LeadAuthorError(
                f"agent mutated a protected surface file ({path}); refusing to commit"
            )
        if "D" in xy and not (_under_draft(path) or _is_system_skill_draft(path)):
            raise LeadAuthorError(
                f"agent deleted an established template / SKILL.md ({path}); refusing to "
                "commit (delete-prohibition; a demotion is rejected the same way)"
            )
        # Half-promote: an established catalog template was written (promote target, or an
        # in-place fold of an existing template) but its ``_draft/`` twin still exists, so
        # the promote's ``rm`` didn't happen and we'd commit both. (A delete already raised
        # above, so this path is a non-delete write; a plain fold has no twin on disk, so it
        # never trips.) The surviving draft is unchanged ⇒ not in ``records`` ⇒ the only
        # signal is the filesystem.
        if _is_catalog_path(path) and not _under_draft(path) and not _is_schema_md(path):
            twin = _draft_twin(path)
            if (repo_root / twin).exists():
                raise LeadAuthorError(
                    f"half-promote: established template {path} was written but its draft "
                    f"twin {twin} still exists; refusing to commit (the promote's `rm` "
                    "didn't happen — established + draft would both land)"
                )
        changed.append(path)
    return sorted(changed)


def _loop_commit_message(run_dir: Path, changed: list[str]) -> str:
    """Deterministic loop-authored commit message — the agent runs no git and authors no
    message. Title names the scope touched + the source run; body lists the changed paths.

    (Distinct from ``_author_shared._commit_message``, which *extracts* the agent-authored
    message for the lessons curators — opposite direction; named apart to avoid confusion.)"""
    has_catalog = any(_is_catalog_path(p) for p in changed)
    has_skill = any(_is_system_skill_md(p) or _is_system_skill_draft(p) for p in changed)
    if has_catalog and has_skill:
        scope = "gather catalog + system skills"
    elif has_skill:
        scope = "system skills"
    else:
        scope = "gather catalog"
    body_paths = "\n".join(f"- {p}" for p in changed)
    return (
        f"learning(lead-author): {scope} for {run_dir.name}\n\n"
        "Curated by the lead author; loop-committed (the agent runs no git).\n\n"
        f"Paths:\n{body_paths}\n\n"
        f"source-run: {run_dir.name}\n"
    )


# ---------------------------------------------------------------------------
# Pitfalls curation mode (Stage 2) — fold general failures into execution.md
# ---------------------------------------------------------------------------
#
# A second, cross-run, threshold-gated spawn that rides the SAME lead-author drain
# (worktree / committer / PR). It drains the central pitfalls queue that the per-run
# tick fills (`collect_general_failures`) into each system's `execution.md`
# `## Common pitfalls` — the file gather reads at dispatch, so the mistake is
# PREVENTED next time, not merely catalogued. Its edit scope is disjoint from the
# per-run agent's (execution.md only), enforced by `_verify_pitfalls_state`.


def _build_pitfalls_handoffs(rows: list[dict]) -> list[dict]:
    """Group queued pitfalls by system → one handoff per system.

    Carries the repo-relative ``execution.md`` path the curator edits plus the
    failures to fold (query_id / goal / executed_query / stderr_digest). The
    curator Reads the execution.md itself — the handoff is records + path only,
    mirroring the system-draft handoff. Rows with no ``system`` are dropped.
    """
    by_system: dict[str, list[dict]] = {}
    for r in rows:
        system = str(r.get("system") or "").strip()
        if system:
            by_system.setdefault(system, []).append(r)
    out: list[dict] = []
    for system in sorted(by_system):
        out.append(
            {
                "system": system,
                "execution_md_path": f"{SKILLS_REL}{system}/execution.md",
                "failures": [
                    {
                        "query_id": f.get("query_id", ""),
                        "goal": f.get("goal", ""),
                        "executed_query": f.get("executed_query", ""),
                        "stderr_digest": f.get("stderr_digest", ""),
                    }
                    for f in by_system[system]
                ],
            }
        )
    return out


def _invoke_pitfalls_agent(handoffs: list[dict], *, repo_root: Path) -> int:
    """Spawn the pitfalls curator via the shared runner. Mirrors ``invoke_agent``:
    raw variant (no result marker), timeout → rc 124, cwd at the batch worktree.
    The coarse ``_ALLOWLIST`` (Edit/Write ``defender/skills/**``) already covers
    execution.md; the ``rm`` grant goes unused (the curator only edits)."""
    user_prompt = (
        f"skills_dir: {SKILLS_REL}\n"
        f"pitfalls_handoffs ({len(handoffs)}):\n"
        f"{json.dumps(handoffs, indent=2)}\n"
    )
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    _log(f"spawn pitfalls curator (model={LEAD_AUTHOR_MODEL}, timeout={LEAD_AUTHOR_TIMEOUT}s)")
    options = _author_runner.RunnerOptions(
        system_prompt_file=LEAD_PITFALLS_PROMPT,
        allowed_tools=_ALLOWLIST,
        model=LEAD_AUTHOR_MODEL,
        effort=None,
        timeout_seconds=LEAD_AUTHOR_TIMEOUT,
        cwd=repo_root,
        log_path=RUN_LOG_FILE,
        result_marker=None,
        batch_id="pitfalls",
    )
    try:
        rc, _text = _author_runner.invoke_claude_print_raw(options, user_prompt, _log)
    except _author_runner.RunnerError as e:
        _log(f"pitfalls curator failed: {e}")
        return 124
    _log(f"pitfalls curator exited rc={rc}")
    return rc


def _verify_pitfalls_state(repo_root: Path, baseline_stray: list[str]) -> list[str]:
    """Verify the curator's working-tree edits before the loop commits. Narrower
    than ``_verify_skills_state``: the ONLY in-corpus change permitted is an edit
    to a system ``execution.md``. Returns the changed paths; raises
    ``LeadAuthorError`` (the drain quarantines) on a stray outside
    ``defender/skills/``*.md, any other skills path, or a deletion (execution.md
    is pruned in place, never removed)."""
    records = _porcelain_records(repo_root)

    def _in_corpus(p: str) -> bool:
        return p.startswith(SKILLS_REL) and p.endswith(".md")

    new_stray = sorted({p for _, p in records if not _in_corpus(p)} - set(baseline_stray))
    if new_stray:
        raise LeadAuthorError(
            f"pitfalls curator changed files outside {SKILLS_REL}*.md: {new_stray}; "
            "refusing to commit"
        )
    changed: list[str] = []
    for xy, path in records:
        if not _in_corpus(path):
            continue
        if not _is_system_execution_md(path):
            raise LeadAuthorError(
                f"pitfalls curator edited a non-execution.md skills path ({path}); "
                "refusing to commit (its scope is execution.md only)"
            )
        if "D" in xy:
            raise LeadAuthorError(
                f"pitfalls curator deleted {path}; refusing to commit "
                "(execution.md is pruned in place, never removed)"
            )
        changed.append(path)
    return sorted(changed)


def _pitfalls_commit_message(changed: list[str]) -> str:
    """Deterministic loop-authored message for the execution.md fold."""
    body_paths = "\n".join(f"- {p}" for p in changed)
    return (
        "learning(lead-author): execution.md pitfalls\n\n"
        "Folded agent-fixable general failures into per-system execution.md "
        "## Common pitfalls; loop-committed (the agent runs no git).\n\n"
        f"Paths:\n{body_paths}\n"
    )


def run_pitfalls(
    *,
    paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS,
    invoke: Callable[..., int] | None = None,
) -> int:
    """Curation mode: fold queued general failures into per-system ``execution.md``.

    Cross-run + threshold-gated (unlike the per-run tick). Below threshold it is a
    no-op with the queue intact. Otherwise: build per-system handoffs, spawn the
    curator (edits execution.md, runs no git), verify the working tree, commit
    pathspec-scoped, and rotate the processed batch out of the central queue. Runs
    inside the lead-author drain's worktree (``paths.repo_root``); the queue
    resolves to the shared state root.

    The batch rotates out once the curator has *processed* it (returned rc=0),
    whether or not it produced a commit — a no-edit tick is a valid outcome (the
    prompt blesses making no edits when every failure is already documented or too
    thin to name a fix), and an all-system-less batch can't be folded at all.
    Leaving such a batch queued would keep it at/above threshold and re-spawn the
    curator on the same un-foldable rows every drain tick. Rotation is immediate by
    design (no ``hold_committed``); a failure that recurs is re-collected.

    ``invoke`` is injectable for tests. Returns 0 on success / no-op / no-edit, 2
    on a curator spawn failure (queue left intact for retry). A scope violation
    raises ``LeadAuthorError``, which the drain (``_drain_pitfalls``) logs and
    swallows — discarding the worktree edits and leaving the queue intact; there is
    no marker to quarantine on this cross-run path.
    """
    rows = _loop_persist.read_pitfalls(paths)
    threshold = _loop_config.pitfalls_threshold()
    if len(rows) < threshold:
        if rows:
            _log(
                f"pitfalls queue below threshold (n={len(rows)}, "
                f"threshold={threshold}) — skipping curation"
            )
        return 0
    batch_ids = [str(r["pitfall_id"]) for r in rows if r.get("pitfall_id")]
    handoffs = _build_pitfalls_handoffs(rows)
    if not handoffs:
        # No row carried a system, so none maps to a defender/skills/{system}/
        # execution.md to fold into. Drop the batch rather than leave it stuck at
        # threshold re-waking the drain forever; an unfoldable row is dead weight.
        _log(f"{len(rows)} queued pitfall(s) but none carried a system — dropping")
        _loop_persist.rotate_pitfalls(batch_ids, None, paths=paths)
        return 0
    repo_root = paths.repo_root
    baseline_stray = _author_shared.changes_outside(repo_root, SKILLS_REL)
    _log(f"pitfalls curation: {len(rows)} failure(s) across {len(handoffs)} system(s)")

    rc = (invoke or _invoke_pitfalls_agent)(handoffs, repo_root=repo_root)
    if rc != 0:
        _log(f"FATAL: pitfalls curator exited rc={rc}; leaving queue intact")
        return 2

    changed = _verify_pitfalls_state(repo_root, baseline_stray)
    sha = None
    if changed:
        sha = _author_shared.commit_corpus(
            repo_root, repo_root / "defender" / "skills", SKILLS_REL,
            _pitfalls_commit_message(changed),
        )
    else:
        _log("pitfalls curator made no execution.md edits (valid no-edit tick)")
    # Rotate whether or not a commit was made: the curator processed the batch, so
    # leaving it queued would only re-spawn the curator on the same rows next tick.
    _loop_persist.rotate_pitfalls(batch_ids, sha, paths=paths)
    _log(
        f"pitfalls curation done; commit={(sha or 'none')[:12]}, edits={len(changed)}, "
        f"rotated {len(batch_ids)} row(s) out of the queue"
    )
    return 0


# ---------------------------------------------------------------------------
# Run dir state
# ---------------------------------------------------------------------------


def _state_dir(run_dir: Path) -> Path:
    return run_dir / "lead_author"


def _done_sentinel(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "done"


def _write_state(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LeadAuthorDeps:
    """Injected collaborators for ``run`` — the spawn, the leaf I/O helpers, and the
    queue-lock pair — plus the filesystem ``paths``. Defaults to production via
    ``build_lead_author_deps``; tests pass fakes (``dataclasses.replace``) instead of
    monkeypatching lead_author's own functions (the SUT-patching #374 removes)."""
    paths: _loop_config.LoopPaths
    invoke_agent: Callable[..., int]
    extract: Callable[[Path], tuple[list, list[ExecutedLead]]]
    synthesize: Callable[..., list[Path]]
    build_handoff: Callable[..., list[dict]]
    discover_system_drafts: Callable[[], list[Path]]
    acquire_queue_lock: Callable[[], Any]
    release_queue_lock: Callable[[Any], None]


def build_lead_author_deps(
    paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS,
) -> LeadAuthorDeps:
    """Bind the production collaborators, threading ``paths`` into the leaf helpers that
    resolve repo-relative paths (``build_handoff`` / ``discover_system_drafts``) so a test
    rooted at a tmp tree drives them with one ``LoopPaths(repo_root=tmp)``."""
    return LeadAuthorDeps(
        paths=paths,
        # The agent edits + the loop commits at paths.repo_root (the batch worktree),
        # so the spawn's cwd + rm matcher resolve there, not at the module REPO_ROOT.
        invoke_agent=functools.partial(invoke_agent, repo_root=paths.repo_root),
        extract=extract,
        synthesize=synthesize_drafts,
        build_handoff=functools.partial(
            build_handoff, repo_root=paths.repo_root, catalog_dir=paths.catalog_dir
        ),
        discover_system_drafts=functools.partial(
            discover_system_drafts, skills_dir=paths.skills_dir
        ),
        acquire_queue_lock=acquire_queue_lock,
        release_queue_lock=release_queue_lock,
    )


def run(
    run_dir: Path,
    *,
    paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS,
    deps: LeadAuthorDeps | None = None,
) -> int:
    if not run_dir.is_dir():
        _log(f"FATAL: run_dir not found: {run_dir}")
        return 2

    if deps is None:
        deps = build_lead_author_deps(paths)
    # No shared repo lock: each lead-author tick runs in its own git worktree (the
    # drain's ``lead-author/<id>`` checkout), so it can't collide with the lessons
    # author or another tick on a shared HEAD. The non-blocking queue lock still
    # makes a stray second tick a no-op.
    queue_lock = deps.acquire_queue_lock()
    if queue_lock is None:
        return 0
    try:
        return _run_locked(run_dir, deps)
    finally:
        deps.release_queue_lock(queue_lock)


def _run_locked(run_dir: Path, deps: LeadAuthorDeps) -> int:
    # Preflight brake: skip a run already processed in a prior tick. A *failed* run
    # is surfaced by the drain (it quarantines the marker on the rc=2 / raised gate),
    # so there is no per-run failure brake here to re-check.
    if _done_sentinel(run_dir).is_file():
        _log("already processed (done sentinel exists) — nothing to do")
        return 0

    # Join the two tables ONCE for this tick and reuse it everywhere (draft
    # synthesis, handoff extraction, the composite classifier's entry view) —
    # the run dir is immutable by now, so re-joining would be pure repeated I/O.
    try:
        joined_leads, executed = deps.extract(run_dir)
    except (FileNotFoundError, ValueError) as e:
        _log(f"FATAL: cannot extract leads: {e}")
        return 2

    # Likewise load the query catalog ONCE and thread it into the consumers below.
    # `load_catalog` globs every `{system}/*.md` + read/parses each, so re-loading
    # per consumer is real catalog-size-scaling I/O. Draft synthesis and
    # general-failure collection both reuse this pre-synthesis snapshot (synthesis
    # *writes* new `_draft/*.md` but reads the pre-synthesis set; collection wants the
    # pre-synthesis set too — see its docstring). `build_handoff` needs the
    # post-synthesis set, so the snapshot is refreshed below when drafts were minted.
    catalog = lead_neighbors.load_catalog(deps.paths.catalog_dir)

    # Mint drafts for executed-but-uncatalogued verbs. They land under
    # {system}/_draft/ in the worktree corpus; the agent curates each (promote/
    # discard), and whatever survives is committed by the loop with the rest.
    synth = deps.synthesize(
        executed, catalog_dir=deps.paths.catalog_dir, catalog=catalog
    )
    if synth:
        _log(
            f"synthesized {len(synth)} draft(s) for uncatalogued verbs: "
            + ", ".join(p.name for p in synth)
        )

    # Collect agent-fixable general failures into the cross-run pitfalls queue.
    # MUST run here — before `_prepare_handoffs`, which writes the `done` sentinel
    # and early-returns precisely in the "all extracted leads had unresolved
    # query_ids" case (the very case that produces general failures). A dedicated
    # `pitfalls_collected` sentinel makes it idempotent: a later rc=2 quarantines
    # the marker without writing `done`, so a manual re-queue would re-enter here
    # and the deterministic `pitfall_id` would otherwise re-append the same rows.
    # `deps.paths` resolves the SHARED state root even from inside the drain
    # worktree, so the append lands in the central queue, not the throwaway checkout.
    collected_marker = _state_dir(run_dir) / "pitfalls_collected"
    if not collected_marker.is_file():
        failures = collect_general_failures(
            executed, run_dir, catalog_dir=deps.paths.catalog_dir, catalog=catalog
        )
        if failures:
            _loop_persist.append_pitfalls(failures, paths=deps.paths)
            _log(f"collected {len(failures)} general-failure pitfall(s) into the queue")
        _write_state(collected_marker, _loop_config.now_iso() + "\n")

    # The agent edits + the loop commits at the injected repo root (the batch
    # worktree in prod; a tmp tree under test). The agent runs no git, so capture the
    # pre-agent stray baseline (paths outside defender/skills/*.md) to diff against —
    # a fresh worktree is clean, but the synthesized drafts above are in-scope *.md and
    # so are never counted as strays.
    repo_root = deps.paths.repo_root
    baseline_stray = _author_shared.changes_outside(repo_root, SKILLS_REL)

    # build_handoff needs the catalog INCLUDING any freshly-minted drafts. When
    # synthesis minted nothing (the steady-state common case) the once-loaded snapshot
    # is still current; when it minted drafts, refresh it so a just-minted `_draft/`
    # resolves into a handoff (the WARN-and-draft path) instead of WARN-and-drop. After
    # this point `catalog` is authoritative for any consumer of the post-synthesis set.
    if synth:
        catalog = lead_neighbors.load_catalog(deps.paths.catalog_dir)
    handoffs, pending_drafts, rc = _prepare_handoffs(
        run_dir, deps, executed, joined_leads, catalog=catalog
    )
    if rc is not None:
        return rc
    _log(
        f"built {len(handoffs)} executed-template handoff(s) and "
        f"{len(pending_drafts)} pending system-skill draft(s)"
    )

    rc = deps.invoke_agent(run_dir, handoffs, pending_drafts)
    if rc != 0:
        # The agent crashed / timed out (the worktree is a throwaway the drain discards).
        # Return rc=2 — the drain quarantines the marker to failed/ for a human; the run
        # log under _pending_leads/ is the diagnostic.
        _log(f"FATAL: claude exited rc={rc}; see {RUN_LOG_FILE} (drain will quarantine)")
        return 2

    # Scope gate over the working tree, then the loop commits pathspec-scoped. A gate
    # or commit failure raises (LeadAuthorError / AuthorError), which the drain catches
    # and quarantines the marker for a human — no auto-reset.
    changed = _verify_skills_state(repo_root, baseline_stray)
    sha = _author_shared.commit_corpus(
        repo_root, repo_root / "defender" / "skills", SKILLS_REL,
        _loop_commit_message(run_dir, changed),
    )
    _write_state(
        _done_sentinel(run_dir),
        f"commit: {sha or 'none'}\nat: {_loop_config.now_iso()}\ncommit_made: {sha is not None}\n",
    )
    _log(f"done; commit_made={sha is not None} commit={(sha or 'none')[:12]}")
    return 0


def _prepare_handoffs(
    run_dir: Path, deps: LeadAuthorDeps,
    executed: list | None = None, joined_leads: list | None = None,
    *, catalog: list | None = None,
) -> tuple[list, list, int | None]:
    """Extract leads + build executed-template + system-draft handoffs.

    Returns ``(handoffs, pending_drafts, early-rc)``. ``early-rc`` is
    ``None`` when work remains; an ``int`` rc when the caller should
    return immediately. Both lists may be empty independently:

    - Executed handoffs come from the two tables (``executed_queries.jsonl``
      + ``gather_raw/``) joined via ``lead_repository``.
    - Pending drafts come from ``discover_system_drafts()`` and are gated
      on ``_lift_threshold()`` — below threshold, the list is forced
      empty so the lift portion is silently skipped this tick.

    Early exit-zero fires only when **both** lists are empty after the
    threshold gate. Failures extracting executed leads return rc=2.
    """
    pending_drafts_raw = deps.discover_system_drafts()
    threshold = _lift_threshold()
    if len(pending_drafts_raw) < threshold:
        if pending_drafts_raw:
            _log(
                f"lift queue below threshold "
                f"(n={len(pending_drafts_raw)}, threshold={threshold}) — "
                "skipping lift"
            )
        pending_drafts: list[dict] = []
    else:
        pending_drafts = build_system_draft_handoffs(
            pending_drafts_raw, repo_root=deps.paths.repo_root
        )

    if executed is None:
        try:
            joined_leads, executed = deps.extract(run_dir)
        except (FileNotFoundError, ValueError) as e:
            _log(f"FATAL: cannot extract leads: {e}")
            return [], [], 2

    if not executed:
        if not pending_drafts:
            _log("no executed leads and no pending drafts — nothing to do")
            return [], [], 0
        _log(
            "no executed leads with on-disk payloads — proceeding with "
            f"{len(pending_drafts)} pending system-skill draft(s) only"
        )
        return [], pending_drafts, None

    try:
        handoffs = deps.build_handoff(run_dir, executed, joined_leads, catalog=catalog)
    except LeadAuthorError as e:
        _log(f"FATAL: cannot build handoffs: {e}")
        return [], [], 2

    if not handoffs and not pending_drafts:
        _log(
            f"all {len(executed)} extracted lead(s) had unresolved "
            "query_ids and no pending drafts — nothing to do"
        )
        _write_state(
            _done_sentinel(run_dir),
            f"commit: none\nat: {_loop_config.now_iso()}\ncommit_made: False\n",
        )
        return [], [], 0

    return handoffs, pending_drafts, None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_HELP_EPILOG = """\
The agent runs no git; the loop commits. Invoked directly this commits onto the
current branch/worktree's HEAD — in production the lead-author drain
(``loop.py --lead-author-drain``) runs it inside a fresh ``lead-author/<id>``
worktree and opens the PR.

Preconditions
  * No other lead-author tick may be running (per-author queue lock at
    defender/learning/_pending_leads/.lock).
  * ``<run_dir>/executed_queries.jsonl`` and ``<run_dir>/gather_raw/``
    (the two tables) must exist — written live during the run by
    record_query.py + record_lead.py.

State files written under ``<run_dir>/lead_author/``
  done           sentinel on successful completion; makes the run a no-op.

On a non-zero ``claude`` exit this returns rc=2 and the lead-author drain quarantines
the run's marker to the author-queue's ``failed/`` dir (surfaced for a human, not
dropped); the run log under ``_pending_leads/`` is the diagnostic.

Environment
  LEAD_AUTHOR_MODEL                          claude model id (default claude-sonnet-4-6)
  LEAD_AUTHOR_TIMEOUT_SECONDS                spawn timeout (default 1800)
  LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD        min pending-draft count to fire the
                                             system-skill lift queue (default 5)
  LEARNING_PITFALLS_THRESHOLD                min queued general-failure count to
                                             fire the execution.md curation mode
                                             (default 5)
"""


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="lead_author",
        description="Fold lessons from one defender run into the executed-side "
                    "query template catalog.",
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("run_dir", type=Path,
                   help="defender run dir containing executed_queries.jsonl + gather_raw/")
    args = p.parse_args(argv)
    return run(args.run_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
