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
import re
import subprocess
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
from defender.learning.leads import lead_classifier
from defender.learning.leads import lead_neighbors
from defender.learning.leads import lead_render


REPO_ROOT = Path(__file__).resolve().parents[3]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
CATALOG_DIR = REPO_ROOT / "defender" / "skills" / "gather" / "queries"
CATALOG_REL = "defender/skills/gather/queries/"
SKILLS_DIR = REPO_ROOT / "defender" / "skills"
SKILLS_REL = "defender/skills/"
# Mutable lead-author queue state resolves from DEFAULT_PATHS so it honors
# DEFENDER_LEARNING_STATE_DIR (out-of-repo under concurrent runs).
PENDING_DIR = _loop_config.DEFAULT_PATHS.lead_pending_dir
QUEUE_LOCK_FILE = PENDING_DIR / ".lock"
RUN_LOG_FILE = PENDING_DIR / "lead_author_run.log"
LEAD_AUTHOR_PROMPT = LEARNING_DIR / "leads" / "lead_author.md"

LEAD_AUTHOR_MODEL = os.environ.get("LEAD_AUTHOR_MODEL", "claude-sonnet-4-6")
LEAD_AUTHOR_TIMEOUT = int(os.environ.get("LEAD_AUTHOR_TIMEOUT_SECONDS", "1800"))


def _lift_threshold() -> int:
    """Min count of pending system-skill drafts before the lift activates.

    Mirrors ``LEARNING_AUTHOR_THRESHOLD`` from ``loop.py``: drain the
    queue only once enough have accumulated to make the spawn worthwhile.
    Read at call time so tests can monkeypatch via ``monkeypatch.setenv``.
    """
    return int(os.environ.get("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5"))


# Ids gather coins for one-off, no-template probes — never catalog candidates.
# An *untagged* adapter call (no ``--query-id``) collapses to ``{system}.{verb}``
# where ``{verb}`` is the adapter subcommand (e.g. an adapter exposing ``esql`` / ``query``)
# or ``ad-hoc`` for a flags-only call; drafting any of those would mint a junk
# catch-all template, so they are filtered alongside prefix-less ids.
_NON_CANDIDATE_VERBS = frozenset({"esql", "query", "ad-hoc"})

# A `query_id` segment (`{system}` / `{verb}`) becomes a path component in the
# `{system}/_draft/{verb}.md` draft path below. The id is model-coined (the
# gather subagent passes it as `--query-id`), so an untrusted segment containing
# `/`, `\`, or a leading `.` (e.g. `..`) would escape the catalog dir and write
# an arbitrary `.md` file. Require each segment to be a single safe path
# component: starts alphanumeric, then `[a-z0-9._-]` — which the real kebab ids
# (`sshd-auth-baseline-7d`, `change-mgmt`) all satisfy while `..`, `a/b`, and
# `/abs` are rejected. A containment clamp on the resolved path backs this up.
_SAFE_ID_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


# Systems whose query body is a server-side ES|QL pipe — the whole query is one
# positional (``params["arg0"]``) with the bindings inlined, not flag/positional
# scalars. The one place the "this system speaks ES|QL" policy lives, so engine
# shape (which field is the canonical query, draft frontmatter/fence) is decided
# from the recorded ``system`` rather than re-split out of ``query_id`` or a
# system literal scattered across call sites.
_ESQL_SYSTEMS = frozenset({"elastic"})  # lint-shippable: ok — ES|QL system id matched against the queries-table system value (real config, not illustrative)


def _is_esql(system: str) -> bool:
    return system in _ESQL_SYSTEMS


def _draft_skeleton(query_id: str, system: str, goal: str, query_body: str) -> str:
    """Render a draft skeleton in the lean/ES|QL shape.

    Built by concatenation rather than ``str.format`` because ``query_body``
    is the literal executed query and may itself contain ``{`` / ``}`` (ES|QL
    ``GROK`` patterns use ``%{WORD:field}``), which a format call would choke on.

    Shape mirrors the migrated catalog (``## Goal`` / ``## Query`` / ``## Pitfalls``
    + narrowing note) — no ``## What to summarize`` / ``## Baseline`` / KQL
    placeholder. The ``## Query`` body is the *exact* query that ran (from the
    queries table), so a promotion is one keyword-recall pass away, not a
    "fill in the invocation" stub.
    """
    is_esql = _is_esql(system)
    engine_fm = "\nengine: esql" if is_esql else ""
    fence_lang = "esql" if is_esql else ""
    goal_line = (goal or "").replace("\n", " ").strip() or "(no lead goal recorded)"
    return (
        f"---\nid: {query_id}\nstatus: draft{engine_fm}\n---\n\n"
        "## Goal\n\n"
        f"`{query_id}` — auto-drafted from a coined gather query with no matching\n"
        f'catalog template. The defender\'s lead goal was: "{goal_line}".\n\n'
        "**Before promoting**, check the handoff `neighbors`: if this is a "
        "*narrowing*\nof an existing wide template (same measurement, fewer "
        "filter/`BY` axes), discard\nthis draft and widen that template's `## Goal` "
        "for keyword recall instead of\nminting a sibling. Promote only when this "
        "names a genuinely new measurement.\n\n"
        "## Query\n\n"
        "The exact query that ran (narrow/widen on promote):\n\n"
        f"```{fence_lang}\n{query_body}\n```\n\n"
        "## Pitfalls\n\n"
        "- (fill in any data-source quirk this query exposed — null-heavy field,\n"
        "  renamed column, case-sensitive match — grounded in the executed payload)\n"
    )


def synthesize_drafts(
    executed: list[ExecutedLead], *, catalog_dir: Path | None = None,
) -> list[Path]:
    """Mint a ``{system}/_draft/{verb}.md`` skeleton for each executed
    query_id that resolves to no catalog template.

    This replaces the lead-author's WARN-and-drop on an unresolved verb
    (`build_handoff`) with WARN-and-draft: the gather subagent ran a query
    under a ``{system}.{verb}`` id that no template covers, so we
    deterministically draft it and let the lead-author's existing
    promote/discard/skip machinery curate it. ``query_id`` comes from the
    dispatch contract via the wrapper (``--query-id``); ad-hoc leads
    (``query_id`` with no ``{system}.`` prefix) and bare untagged verbs
    (``{system}.esql`` / ``{system}.ad-hoc`` — what a call with no ``--query-id``
    collapses to) are skipped: they are not catalog candidates. Idempotent —
    skips drafts that already exist on disk or were minted earlier in this call.

    The drafted ``## Query`` is the literal query that ran: under ES|QL the
    bindings live inside the pipe (``params`` is just ``{"arg0": "<the pipe>"}``),
    so the captured command — not a ``${param}`` re-render — is the canonical
    record (see ``_executed_query``).
    """
    catalog_dir = catalog_dir if catalog_dir is not None else CATALOG_DIR
    by_id = {t.id for t in lead_neighbors.load_catalog(catalog_dir)}
    created: list[Path] = []
    for lead in executed:
        qid = lead.query_id
        if not qid or "." not in qid or qid in by_id:
            continue
        system, verb = qid.split(".", 1)
        # A malformed id with an empty system (``.verb``) or empty verb
        # (``system.``) would write off the documented ``{system}/_draft/{kebab}``
        # surface — ``.verb`` lands a draft at the catalog root ``_draft/`` (which
        # then trips the dirty-protected preflight and bricks the tick), ``system.``
        # mints a hidden ``_draft/.md`` dotfile. Drop both alongside reserved verbs.
        if not system or not verb or verb in _NON_CANDIDATE_VERBS:
            continue
        # `system`/`verb` become path components — a `/`, `\`, or `..` segment
        # from a model-coined id would escape the catalog (arbitrary `.md` write).
        # Reject any non-single-component segment, then clamp the resolved draft
        # under the system's `_draft/` dir as belt-and-suspenders.
        if not _SAFE_ID_SEGMENT.match(system) or not _SAFE_ID_SEGMENT.match(verb):
            continue
        draft = catalog_dir / system / "_draft" / f"{verb}.md"
        draft_root = (catalog_dir / system / "_draft").resolve()
        if not draft.resolve().is_relative_to(draft_root):
            continue
        if draft.exists() or draft in created:
            continue
        query_body = _executed_query(lead) or "# (no command captured for this query)"
        try:
            draft.parent.mkdir(parents=True, exist_ok=True)
            draft.write_text(
                _draft_skeleton(qid, system, lead.goal_text, query_body)
            )
            created.append(draft)
            by_id.add(qid)
        except OSError:
            continue
    return created


# ---------------------------------------------------------------------------
# Lead extraction (inlined from PR-209's lead_extract.py)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutedLead:
    lead_id: str                  # the :L row id (FK), e.g. "l-001"
    query_index: int              # positional index within this lead's queries
    is_multi_query: bool          # parent lead had >1 query
    entry_index: int              # index into the joined-leads list
    query_id: str
    system: str                   # adapter system (siem/cmdb/...), from the queries table
    params: dict[str, Any]
    raw_command: str              # verbatim executed command (the literal query)
    goal_text: str
    what_to_summarize: tuple[str, ...]
    raw_ref: Path | None          # this query's payload, by-ref
    payload_status: str           # from the queries table (record_query)
    payload_digest: str


_VALID_PAYLOAD_STATUSES = frozenset(
    {"ok", "empty", "suspect_empty", "error", "partial"}
)


def _executed_query(lead: ExecutedLead) -> str:
    """The literal query that ran, as the canonical record.

    Under ES|QL the whole pipe is a single positional captured as
    ``params["arg0"]`` — the named bindings (`user`, `src`, window) live
    *inside* the string, not as separate params — so the ``arg0`` body, not
    a ``${param}`` re-render, is the canonical query. For other systems
    ``arg0`` is just a bare positional *value* (an IP for ``cmdb.hostname-by-ip``
    ``${ip}``, a CR id for ``change-mgmt.get-change`` ``${cr_id}``), not the
    query — so the full ``raw_command`` is the faithful record there. Pick by
    the recorded ``system`` (``_is_esql``), falling back to the other form when
    the preferred one is absent.
    """
    arg0 = (lead.params or {}).get("arg0")
    arg0 = arg0 if isinstance(arg0, str) and arg0.strip() else ""
    raw = lead.raw_command or ""
    return (arg0 or raw) if _is_esql(lead.system) else (raw or arg0)


def extract(run_dir: Path) -> tuple[list, list[ExecutedLead]]:
    """Join the two tables via ``lead_repository`` and emit one ExecutedLead
    per executed query. Returns ``(joined_leads, executed)`` so a caller that
    needs the raw join surface too (for handoff building) reuses this single
    read instead of re-joining.

    Queries whose payload file is missing are dropped silently (the dispatch
    never landed). The payload status comes from the queries-table row
    (``record_query`` writes it deterministically); an out-of-vocabulary
    status is a loud failure — the loop refuses to author against it.
    """
    joined = lead_repository.joined(run_dir)
    return joined, extract_from_joined(joined)


def extract_from_joined(joined_leads: list) -> list[ExecutedLead]:
    """``extract`` over an already-joined leads list (no disk I/O).

    Lets a caller that already holds ``lead_repository.joined(run_dir)`` reuse
    it instead of re-reading both tables. ``joined_leads`` is a list of
    ``lead_repository.JoinedLead``.
    """
    out: list[ExecutedLead] = []
    for entry_idx, jl in enumerate(joined_leads):
        goal = jl.goal or ""
        wtc = tuple(str(x) for x in jl.what_to_summarize if isinstance(x, (str, int)))
        is_multi = len(jl.queries) > 1
        for q_idx, q in enumerate(jl.queries):
            if q.raw_ref is None or not q.raw_ref.is_file():
                continue
            if q.payload_status not in _VALID_PAYLOAD_STATUSES:
                raise LeadAuthorError(
                    f"{jl.lead_id} seq {q.seq}: payload_status must be one of "
                    f"{sorted(_VALID_PAYLOAD_STATUSES)}, got {q.payload_status!r}"
                )
            out.append(
                ExecutedLead(
                    lead_id=jl.lead_id,
                    query_index=q_idx,
                    is_multi_query=is_multi,
                    entry_index=entry_idx,
                    query_id=q.query_id,
                    system=q.system,
                    params=dict(q.params),
                    raw_command=q.raw_command,
                    goal_text=goal,
                    what_to_summarize=wtc,
                    raw_ref=q.raw_ref,
                    payload_status=q.payload_status,
                    payload_digest=str(q.payload_digest)[:200],
                )
            )
    return out


# ---------------------------------------------------------------------------
# Driver primitives
# ---------------------------------------------------------------------------


class LeadAuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort."""


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
# Path classifiers — lead_author's edit scope (domain logic, not git lifecycle)
# ---------------------------------------------------------------------------


def _under_draft(path: str) -> bool:
    """True if ``path`` lies under any catalog ``{system}/_draft/`` subdirectory."""
    if not path.startswith(CATALOG_REL):
        return False
    rest = path[len(CATALOG_REL):]
    parts = rest.split("/")
    return len(parts) >= 3 and parts[1] == "_draft"


def _is_catalog_path(path: str) -> bool:
    return path.startswith(CATALOG_REL)


def _is_system_skill_md(path: str) -> bool:
    """True if ``path`` is exactly ``defender/skills/{system}/SKILL.md``.

    Excludes ``gather/queries/SCHEMA.md`` and nested files like
    ``skills/{system}/queries/foo.md`` — only the top-level system SKILL
    is in lift scope.
    """
    if not path.startswith(SKILLS_REL):
        return False
    rest = path[len(SKILLS_REL):]
    parts = rest.split("/")
    return len(parts) == 2 and parts[1] == "SKILL.md"


def _is_system_skill_draft(path: str) -> bool:
    """True if ``path`` is under a system-skill ``_draft/`` (one segment deep).

    Catalog drafts at ``skills/gather/queries/{system}/_draft/`` are NOT
    system-skill drafts — they're handled by the catalog-side draft flow.
    """
    if not path.startswith(SKILLS_REL):
        return False
    rest = path[len(SKILLS_REL):]
    parts = rest.split("/")
    return len(parts) >= 3 and parts[1] == "_draft"


def _is_draft_readme(path: str) -> bool:
    """True if ``path`` is a ``_draft/README.md`` surface-declaration file."""
    if not _is_system_skill_draft(path) and not _under_draft(path):
        return False
    return Path(path).name == "README.md"


def _is_schema_md(path: str) -> bool:
    """True if ``path`` is a catalog ``SCHEMA.md`` (the template-schema doc, not a
    template). Loop-protected: the lead author curates templates, never the schema."""
    return _is_catalog_path(path) and Path(path).name == "SCHEMA.md"


def _is_in_scope(path: str) -> bool:
    """True if ``path`` is within lead_author's edit scope.

    Two scopes: the gather query catalog and the system-skill surface
    (``SKILL.md`` + sibling ``_draft/``).
    """
    return (
        _is_catalog_path(path)
        or _is_system_skill_md(path)
        or _is_system_skill_draft(path)
    )


def _porcelain_records(repo_root: Path) -> list[tuple[str, str]]:
    """``[(XY, path)]`` from ``git status --porcelain --untracked-files=all -z`` at
    ``repo_root`` (a batch worktree). The agent runs no git, so its edits sit uncommitted
    in the working tree (``M`` / ``D`` / ``??``) — this is the single read the scope gate
    verifies. The agent stages nothing, so no rename/copy (``R`` / ``C``) records arise (a
    "move" shows as a delete + an untracked add): each ``-z`` field is therefore one
    ``XY␣path`` record. A stray staged rename, were one ever to appear, fails safe — its
    second (source) field reads as an out-of-corpus path and the gate quarantines rather
    than mis-committing.
    """
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "-z"],
        cwd=repo_root, capture_output=True, text=True, check=True,
    )
    out: list[tuple[str, str]] = []
    for rec in proc.stdout.split("\0"):
        if not rec or len(rec) < 3:
            continue
        out.append((rec[:2], rec[3:] if rec[2] == " " else rec[2:]))
    return out


# ---------------------------------------------------------------------------
# Handoff construction
# ---------------------------------------------------------------------------


def build_handoff(
    run_dir: Path, executed: list[ExecutedLead], joined_leads: list | None = None,
    *, repo_root: Path | None = None, catalog_dir: Path | None = None,
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
_ALLOWLIST = (
    "Read,Glob,Grep,"
    f"Edit({SKILLS_REL}**),"
    f"Write({SKILLS_REL}**),"
    f"Bash(rm {SKILLS_REL}**)"
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
    quarantines the marker. ``repo_root`` is the batch worktree (the drain passes
    ``deps.paths.repo_root``); the agent's cwd + ``rm`` matcher resolve under it."""
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
    # Also permit the worktree-absolute form of the rm matcher, since the agent may pass
    # an absolute path; the relative form covers cwd-relative `rm`.
    allowed_tools = _ALLOWLIST + f",Bash(rm {repo_root / 'defender' / 'skills'}/**)"
    options = _author_runner.RunnerOptions(
        system_prompt_file=LEAD_AUTHOR_PROMPT,
        allowed_tools=allowed_tools,
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
        which also covers a demotion (rm-established + write-draft shows the ``D`` here).
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

    # Mint drafts for executed-but-uncatalogued verbs. They land under
    # {system}/_draft/ in the worktree corpus; the agent curates each (promote/
    # discard), and whatever survives is committed by the loop with the rest.
    synth = deps.synthesize(executed, catalog_dir=deps.paths.catalog_dir)
    if synth:
        _log(
            f"synthesized {len(synth)} draft(s) for uncatalogued verbs: "
            + ", ".join(p.name for p in synth)
        )

    # The agent edits + the loop commits at the injected repo root (the batch
    # worktree in prod; a tmp tree under test). The agent runs no git, so capture the
    # pre-agent stray baseline (paths outside defender/skills/*.md) to diff against —
    # a fresh worktree is clean, but the synthesized drafts above are in-scope *.md and
    # so are never counted as strays.
    repo_root = deps.paths.repo_root
    baseline_stray = _author_shared.changes_outside(repo_root, SKILLS_REL)

    handoffs, pending_drafts, rc = _prepare_handoffs(
        run_dir, deps, executed, joined_leads
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
        handoffs = deps.build_handoff(run_dir, executed, joined_leads)
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
