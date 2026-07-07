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
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import runner as _author_runner  # noqa: F401  (re-exported: the per-run invoke_agent tests patch this runner seam; the spawn lives in _lead_spine)
from defender.learning.author import shared as _author_shared
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
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
    _is_system_file,
    _is_system_skill_draft,
    _is_system_skill_md,
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
from defender.learning.leads._lead_spine import (
    PENDING_DIR,
    _log,
    _loop_commit_body,
    _spawn_author_agent,
    _verify_corpus_scope,
)


# The per-run queue lock + prompt. The shared spawn/verify/commit spine and its constants
# (PENDING_DIR / the ``lead-author`` logger) live in ``_lead_spine``, which routes the spawn
# to the in-process PydanticAI engine (GLM); the cross-run pitfalls curation mode now lives
# in ``pitfalls_curator`` (#455 Part 2 / #513).
QUEUE_LOCK_FILE = PENDING_DIR / ".lock"
LEAD_AUTHOR_PROMPT = LEARNING_DIR / "leads" / "lead_author.md"


def _lift_threshold() -> int:
    """Min count of pending system-skill drafts before the lift activates.

    Mirrors ``LEARNING_AUTHOR_THRESHOLD`` from ``loop.py``: drain the
    queue only once enough have accumulated to make the spawn worthwhile.
    Read at call time so tests can monkeypatch via ``monkeypatch.setenv``.
    """
    return _loop_config.env_int("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", 5)


# ---------------------------------------------------------------------------
# Driver primitives
# ---------------------------------------------------------------------------


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
    *, repo_root: Path = REPO_ROOT, catalog_dir: Path | None = None,
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
    # Reuse the tick's once-loaded catalog when threaded; else load. The caller
    # threads it only when synthesis minted no drafts this tick — when drafts were
    # minted, `catalog` is None here and we re-glob so a freshly-minted `_draft/`
    # resolves into a handoff (the WARN-and-draft path) instead of WARN-and-drop.
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    by_id = {t.id: t for t in catalog}
    idf = lead_neighbors.build_idf(lead_neighbors._all_query_variants(catalog))

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


def discover_system_drafts(*, skills_dir: Path = SKILLS_DIR) -> list[Path]:
    """Pending drafts under ``defender/skills/{system}/_draft/`` (one level).

    Excludes the surface-declaration README and any template skeletons.
    The single-level glob naturally excludes catalog drafts at
    ``defender/skills/gather/queries/{system}/_draft/`` — those are
    handled by the executed-template handoff stream.
    """
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
    drafts: list[Path], *, repo_root: Path = REPO_ROOT,
) -> list[dict]:
    """One handoff per pending draft. ``{draft_path, system, skill_path}`` (repo-relative)."""
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


def invoke_agent(
    run_dir: Path,
    handoffs: list[dict],
    pending_drafts: list[dict] | None = None,
    *,
    repo_root: Path = REPO_ROOT,
) -> int:
    """Run the lead-author spawn via ``_spawn_author_agent`` (the in-process PydanticAI GLM engine)
    with the lead-author prompt. Returns rc (124 on a per-run fault; a systemic config fault
    propagates). ``repo_root`` is the batch worktree — where the agent's file writers land; the
    case ``run_dir`` is the observability trace anchor."""
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
    return _spawn_author_agent(
        system_prompt_file=LEAD_AUTHOR_PROMPT,
        batch_id=run_dir.name,
        user_prompt=user_prompt,
        repo_root=repo_root,
        learning_run_dir=run_dir,
        log_label="claude",
    )


# ---------------------------------------------------------------------------
# Scope gate — the loop verifies the agent's working-tree edits before committing
# ---------------------------------------------------------------------------


def _skills_path_rule(repo_root: Path, xy: str, path: str) -> None:
    """Per-path scope rule for the per-run lead author. Raises ``LeadAuthorError`` on: an
    out-of-scope skills path or a ``_draft/README.md`` / catalog ``SCHEMA.md`` mutation; a
    deletion of a non-draft established template or ``SKILL.md`` (delete-prohibition, which
    also covers a demotion); or a half-promote — an established catalog template written while
    its ``_draft/`` twin still exists on disk (the promote's ``rm`` didn't happen, so both
    would land). The half-promote is invisible to the ``git status`` records — the surviving
    draft is unchanged — so only a filesystem probe of the twin catches it."""
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
    if _is_catalog_path(path) and not _under_draft(path) and not _is_schema_md(path):
        twin = _draft_twin(path)
        if (repo_root / twin).exists():
            raise LeadAuthorError(
                f"half-promote: established template {path} was written but its draft "
                f"twin {twin} still exists; refusing to commit (the promote's `rm` "
                "didn't happen — established + draft would both land)"
            )


def _verify_skills_state(repo_root: Path, baseline_stray: list[str]) -> list[str]:
    """Verify the per-run agent's uncommitted edits before the loop commits. Routes the shared
    preamble through ``_verify_corpus_scope`` and the per-path contract through
    ``_skills_path_rule``; returns the in-scope changed paths."""
    return _verify_corpus_scope(
        repo_root, baseline_stray, actor="agent",
        rule=functools.partial(_skills_path_rule, repo_root),
    )


def _loop_commit_message(run_dir: Path, changed: list[str]) -> str:
    """Deterministic loop-authored commit message for the per-run catalog/skill fold. Title
    names the scope touched (a 3-way branch: gather catalog / system skills / both) + the
    source run; body lists the changed paths; a ``source-run:`` trailer closes it."""
    has_catalog = any(_is_catalog_path(p) for p in changed)
    has_skill = any(_is_system_skill_md(p) or _is_system_skill_draft(p) for p in changed)
    if has_catalog and has_skill:
        scope = "gather catalog + system skills"
    elif has_skill:
        scope = "system skills"
    else:
        scope = "gather catalog"
    return _loop_commit_body(
        f"learning(lead-author): {scope} for {run_dir.name}",
        "Curated by the lead author; loop-committed (the agent runs no git).",
        changed,
        trailer=f"\nsource-run: {run_dir.name}\n",
    )


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
    ``build_lead_author_deps``; tests pass fakes (``dataclasses.replace``) rather than
    monkeypatching lead_author's own functions."""
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
        # A per-run fault — the agent timed out / errored (the worktree is a throwaway the drain
        # discards). Return rc=2 — the drain quarantines the marker to failed/ for a human; the
        # per-spawn RequestLogger trace under the run dir is the diagnostic. (A systemic config
        # fault does not reach here — it propagates from the engine as exit 2.)
        _log(f"FATAL: lead-author spawn exited rc={rc}; see the trace under {run_dir} (drain will quarantine)")
        return 2

    # Scope gate over the working tree, then the loop commits pathspec-scoped. A scope-gate
    # violation raises LeadAuthorError, which the drain catches and quarantines the marker
    # for a human; a git commit failure raises GitError — a systemic fault the drain maps to
    # exit 2 (a broken tree, not a poison marker) — no auto-reset.
    changed = _verify_skills_state(repo_root, baseline_stray)
    sha = _author_shared.commit_corpus(
        repo_root, repo_root / "defender" / "skills",
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

On a per-run fault this returns rc=2 and the lead-author drain quarantines the run's
marker to the author-queue's ``failed/`` dir (surfaced for a human, not dropped); the
per-spawn RequestLogger trace under the run dir is the diagnostic. (A systemic config
fault — no key / unroutable model / bad effort — propagates from the in-process engine
as exit 2 instead, halting the drain rather than quarantining every marker.)

Environment
  LEAD_AUTHOR_MODEL                          in-process model id (default glm-5.2; any
                                             provider providers.provider_for routes)
  LEAD_AUTHOR_EFFORT                          reasoning effort (default low)
  LEAD_AUTHOR_TIMEOUT_SECONDS                per-spawn wall-clock ceiling (default 1800)
  LEAD_AUTHOR_REQUEST_LIMIT                   tool-loop request cap (default 250)
  LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD        min pending-draft count to fire the
                                             system-skill lift queue (default 5)
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
