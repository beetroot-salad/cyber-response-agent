#!/usr/bin/env python3
"""Minimal lead-author driver: fold lessons from one defender run into
the executed-side query template catalog at
``defender/skills/gather/queries/``.

Per ``defender/CLAUDE.md``, defender is an experimental PoC; this
driver carries the minimum discipline needed for safe interleaving
with the gap-side authors (`author.py`, `author_actor.py`) and nothing
more. No Tier-1 gate, no streaming JSON parse, no result marker — git
is the source of truth.

Lifecycle, per tick:

  1. Acquire the per-author queue lock
     (``defender/learning/_pending_leads/.lock``). Non-blocking; another
     in-flight tick ⇒ return 0 silently.
  2. Acquire the shared repo lock
     (``defender/learning/_author.lock``) via ``_author_shared``.
     Blocking with timeout — same discipline as ``author.py``.
  3. Preflight brakes (in order):
       a. ``<run_dir>/lead_author/failure.txt`` ⇒ a prior tick aborted
          mid-stream; refuse to retry until a human clears it.
       b. ``<run_dir>/lead_author/done`` ⇒ already processed.
  4. Capture ``base_sha`` + ``baseline_status``. Refuse to author if the
     catalog itself is already dirty (uncommitted file under
     ``defender/skills/gather/queries/``).
  5. Extract ``ExecutedLead`` records by joining the leads + queries
     tables via ``lead_repository.joined(<run_dir>)``.
  6. Build per-lead handoff blocks (top-k neighbors via
     ``lead_neighbors.top_k_neighbors``).
  7. Spawn ``claude -p`` with a narrow allowlist. Stdout/stderr → log.
     Non-zero exit ⇒ write ``failure.txt`` and return rc=2, even if a
     valid catalog commit was made; the next tick refuses to retry
     until a human clears ``failure.txt``.
  8. Post-flight scope check: at most one commit; that commit's paths
     all under the catalog; no newly-dirty paths outside the catalog;
     no-commit runs must end clean. Violations ⇒ write ``violation.txt``,
     return rc=2. **No auto-reset** — destructive.
  9. Optional push (``LEAD_AUTHOR_PUSH=1``). Refuses ``origin/main`` /
     ``origin/master`` under any circumstance. Push failure ⇒ logged,
     manual retry required.
 10. Write ``<run_dir>/lead_author/done`` sentinel.
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
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning import (
    _author_runner,
    _author_shared,
    _loop_config,
    lead_classifier,
    lead_neighbors,
    lead_render,
    lead_repository,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
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
LEAD_AUTHOR_PROMPT = LEARNING_DIR / "lead_author.md"

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
    by_id = {t.id for t in lead_neighbors.load_catalog()}
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


def extract(run_dir: Path) -> list[ExecutedLead]:
    """Join the two tables via ``lead_repository`` and emit one ExecutedLead
    per executed query.

    Queries whose payload file is missing are dropped silently (the dispatch
    never landed). The payload status comes from the queries-table row
    (``record_query`` writes it deterministically); an out-of-vocabulary
    status is a loud failure — the loop refuses to author against it.
    """
    return extract_from_joined(lead_repository.joined(run_dir))


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
# Git helpers — porcelain v1 -z parsing
# ---------------------------------------------------------------------------


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=check,
    )


def _parse_status_z(blob: str) -> set[tuple[str, str]]:
    """Parse ``git status --porcelain=v1 -z`` into ``{(XY, path)}``.

    Porcelain v1 record format: ``XY <space> path`` where ``XY`` is
    exactly two characters (one for staged status, one for working-tree
    status — either can be space). With ``-z``, records are separated
    by NUL bytes. Rename/copy entries use TWO NUL-terminated records:
    the destination path first, then the source path. We key on the
    destination (the post-rename name) because that's the one a
    baseline-vs-post diff cares about.
    """
    out: set[tuple[str, str]] = set()
    parts = blob.split("\0")
    i = 0
    while i < len(parts):
        rec = parts[i]
        if not rec or len(rec) < 3:
            i += 1
            continue
        xy = rec[:2]
        path = rec[3:] if rec[2] == " " else rec[2:]
        if xy[0] in ("R", "C"):
            i += 2  # consume source record
        else:
            i += 1
        out.add((xy, path))
    return out


def _diff_name_only_z(base_sha: str, head_sha: str) -> list[str]:
    proc = _git("diff", "--name-only", "-z", f"{base_sha}..{head_sha}")
    return [p for p in proc.stdout.split("\0") if p]


def _diff_name_status_z(base_sha: str, head_sha: str) -> list[tuple[str, list[str]]]:
    """Parse ``git diff --name-status -z`` into ``[(code, [paths])]``.

    Status codes: ``M``/``A``/``D``/``T`` carry one path each; ``R<score>``
    and ``C<score>`` carry two (source then destination). With ``-z``
    each field is NUL-separated.
    """
    proc = _git("diff", "--name-status", "-z", f"{base_sha}..{head_sha}")
    parts = [p for p in proc.stdout.split("\0") if p]
    out: list[tuple[str, list[str]]] = []
    i = 0
    while i < len(parts):
        code = parts[i]
        i += 1
        if code[:1] in ("R", "C"):
            if i + 1 >= len(parts):
                break
            out.append((code, [parts[i], parts[i + 1]]))
            i += 2
        else:
            if i >= len(parts):
                break
            out.append((code, [parts[i]]))
            i += 1
    return out


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


def _git_head() -> str:
    return _git("rev-parse", "HEAD").stdout.strip()


def _git_rev_list_count(base_sha: str) -> int:
    return int(_git("rev-list", "--count", f"{base_sha}..HEAD").stdout.strip())


def _git_status_records() -> set[tuple[str, str]]:
    proc = _git("status", "--porcelain=v1", "-z", "--untracked-files=all")
    return _parse_status_z(proc.stdout)


def _stage_pending_drafts() -> list[str]:
    """Stage untracked ``_draft/`` deposits so the curator's ``git mv``
    (promote/lift) and ``git rm -f`` (discard) operate on index-tracked
    files — git refuses both on an untracked source.

    Covers both catalog drafts (gather-authored mid-run or auto-synthesized
    by ``synthesize_drafts``) and any pending system-skill drafts under
    ``_draft/``. Called *before* the baseline snapshot so the staged drafts
    are recorded as expected queue content, not flagged as post-flight dirt.
    """
    proc = _git("ls-files", "--others", "--exclude-standard", "-z")
    untracked = [p for p in proc.stdout.split("\0") if p]
    drafts = [
        p for p in untracked
        if (_under_draft(p) or _is_system_skill_draft(p)) and not _is_draft_readme(p)
    ]
    if drafts:
        _git("add", "--", *drafts)
    return drafts


# ---------------------------------------------------------------------------
# Handoff construction
# ---------------------------------------------------------------------------


def build_handoff(
    run_dir: Path, executed: list[ExecutedLead], joined_leads: list | None = None,
    *, repo_root: Path | None = None,
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
    # None ⇒ resolve the module global at call time (back-compat: a test that
    # setattrs REPO_ROOT still takes); the deps factory binds the injected paths.
    repo_root = repo_root if repo_root is not None else REPO_ROOT
    catalog = lead_neighbors.load_catalog()
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


_ALLOWLIST = (
    "Read,Glob,Grep,"
    f"Edit({CATALOG_REL}**),"
    f"Write({CATALOG_REL}**),"
    f"Edit({SKILLS_REL}*/SKILL.md),"
    f"Write({SKILLS_REL}*/SKILL.md),"
    f"Bash(git add {SKILLS_REL}:*),"
    "Bash(git mv:*),"
    "Bash(git rm:*),"
    "Bash(git commit:*),"
    "Bash(git status:*),"
    "Bash(git diff:*)"
)


def invoke_agent(
    run_dir: Path,
    handoffs: list[dict],
    pending_drafts: list[dict] | None = None,
) -> int:
    """Spawn ``claude -p`` via the shared runner with the lead-author prompt. Returns rc.

    Routed through ``_author_runner.invoke_claude_print_raw`` (issue #373) so the lead
    author shares the one spawn path — select-loop deadline, stderr drain, non-blocking
    stdin, event teeing to the run log — instead of its own ``subprocess.run``. It reads
    its result from the working tree (git is the source of truth), so it uses the raw
    variant (no ``AUTHOR_RESULT:`` marker) and maps the runner's timeout to rc 124 so the
    ``_run_locked`` caller writes ``failure.txt`` and refuses retry until a human clears it."""
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
        cwd=REPO_ROOT,
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
# Post-flight
# ---------------------------------------------------------------------------


def _dirty_protected_paths(baseline: set[tuple[str, str]]) -> list[str]:
    """Established paths in ``baseline`` that lead_author must not stomp.

    Covers:
      * catalog paths outside ``{system}/_draft/`` (established templates),
      * system-skill ``SKILL.md`` files (lift targets).

    Untracked deposits under any ``_draft/`` are expected queue content
    and intentionally not flagged.
    """
    out: list[str] = []
    for _, p in baseline:
        if _is_catalog_path(p) and not _under_draft(p) or _is_system_skill_md(p):
            out.append(p)
    return out


def verify_postflight(
    base_sha: str, baseline: set[tuple[str, str]]
) -> tuple[bool, str, dict]:
    """Check post-flight git state. Returns (ok, reason, details)."""
    head_sha = _git_head()
    fail = _check_base_sha_ancestor(base_sha, head_sha)
    if fail:
        return fail
    count = _git_rev_list_count(base_sha)
    if count > 1:
        return False, "more than one commit since base", {
            "rev_list_count": count, "head": head_sha,
        }
    diff_paths: list[str] = []
    if count == 1:
        diff_paths = _diff_name_only_z(base_sha, head_sha)
        fail = _check_commit_contents(base_sha, head_sha, count, diff_paths)
        if fail:
            return fail
    new_paths, fail = _check_post_status(baseline, count)
    if fail:
        return fail
    return True, "ok", {
        "rev_list_count": count,
        "head": head_sha,
        "diff_paths": diff_paths,
        "new_paths": new_paths,
    }


def _check_base_sha_ancestor(
    base_sha: str, head_sha: str,
) -> tuple[bool, str, dict] | None:
    # If base_sha isn't an ancestor of HEAD, the agent rewrote history
    # (`git commit --amend`, `git rebase`, `git reset`), a hard-rule
    # violation that would make rev-list / diff comparisons against
    # base_sha lie. `merge-base --is-ancestor` exits 0 when ancestor,
    # 1 when not, ≥2 on error.
    anc = _git("merge-base", "--is-ancestor", base_sha, head_sha, check=False)
    if anc.returncode == 1:
        return False, "base_sha is not an ancestor of HEAD (history rewritten)", {
            "base": base_sha, "head": head_sha,
        }
    if anc.returncode != 0:
        return False, "merge-base --is-ancestor failed", {
            "base": base_sha, "head": head_sha,
            "stderr": anc.stderr.strip(),
        }
    return None


def _check_commit_contents(
    base_sha: str, head_sha: str, count: int, diff_paths: list[str],
) -> tuple[bool, str, dict] | None:
    for path in diff_paths:
        if not _is_in_scope(path):
            return False, "commit touches paths outside lead_author scope", {
                "rev_list_count": count, "head": head_sha,
                "diff_paths": diff_paths,
            }
        if _is_draft_readme(path):
            return False, "commit touches a _draft/README.md (surface declaration)", {
                "rev_list_count": count, "head": head_sha,
                "diff_paths": diff_paths,
                "touched_readme": path,
            }
    # Deletions are only allowed for drafts (catalog drafts or system-skill
    # drafts). SKILL.md and established templates are delete-prohibited.
    # Renames may move a draft into the system root (catalog promotion) but
    # not the reverse.
    for code, paths in _diff_name_status_z(base_sha, head_sha):
        if code == "D":
            src = paths[0]
            if not (_under_draft(src) or _is_system_skill_draft(src)):
                return False, "commit deletes an established file", {
                    "rev_list_count": count, "head": head_sha,
                    "diff_paths": diff_paths,
                    "deleted_path": src,
                }
        if code.startswith(("R", "C")):
            src, dst = paths[0], paths[1]
            # Catalog: established → _draft demotion.
            if _under_draft(dst) and not _under_draft(src):
                return False, "commit demotes an established template to _draft", {
                    "rev_list_count": count, "head": head_sha,
                    "rename_src": src,
                    "rename_dst": dst,
                }
            # System-skill: SKILL.md → _draft demotion.
            if _is_system_skill_draft(dst) and not _is_system_skill_draft(src):
                return False, "commit demotes a system-skill file into _draft", {
                    "rev_list_count": count, "head": head_sha,
                    "rename_src": src,
                    "rename_dst": dst,
                }
    return None


def _check_post_status(
    baseline: set[tuple[str, str]], count: int,
) -> tuple[list[str], tuple[bool, str, dict] | None]:
    post = _git_status_records()
    new_records = post - baseline
    new_paths = sorted({p for _, p in new_records})
    if count == 0:
        if new_records:
            return new_paths, (False, "no commit but new dirty/untracked records exist", {
                "new_paths": new_paths,
            })
        return new_paths, None
    for _, path in new_records:
        if _is_in_scope(path):
            return new_paths, (False, "uncommitted in-scope dirt alongside commit", {
                "new_paths": new_paths,
            })
        if path.startswith("defender/"):
            return new_paths, (False, "new dirt under defender/ outside lead_author scope", {
                "new_paths": new_paths,
            })
    return new_paths, None


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------


_FORBIDDEN_UPSTREAMS = {"origin/main", "origin/master"}


def maybe_push(commit_made: bool) -> None:
    """Push to upstream if ``LEAD_AUTHOR_PUSH=1`` and the upstream is allowed."""
    if not commit_made:
        return
    if os.environ.get("LEAD_AUTHOR_PUSH") != "1":
        _log("push skipped (LEAD_AUTHOR_PUSH not set)")
        return
    try:
        proc = _git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}",
                    check=False)
    except subprocess.CalledProcessError:
        proc = subprocess.CompletedProcess([], 1, "", "")
    if proc.returncode != 0 or not proc.stdout.strip():
        _log("push skipped — no upstream configured")
        return
    upstream = proc.stdout.strip()
    if upstream in _FORBIDDEN_UPSTREAMS:
        _log(f"push REFUSED — upstream={upstream} (origin/main and origin/master are forbidden)")
        return
    _log(f"push upstream={upstream}")
    push = _git("push", check=False)
    if push.returncode != 0:
        _log(f"push FAILED rc={push.returncode}: {push.stderr.strip()} "
             "(manual retry required — done sentinel will block driver retries)")
    else:
        _log("push ok")


# ---------------------------------------------------------------------------
# Run dir state
# ---------------------------------------------------------------------------


def _state_dir(run_dir: Path) -> Path:
    return run_dir / "lead_author"


def _done_sentinel(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "done"


def _failure_marker(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "failure.txt"


def _violation_marker(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "violation.txt"


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
    extract: Callable[[Path], list[ExecutedLead]]
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
        invoke_agent=invoke_agent,
        extract=extract,
        build_handoff=functools.partial(build_handoff, repo_root=paths.repo_root),
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
    queue_lock = deps.acquire_queue_lock()
    if queue_lock is None:
        return 0
    repo_lock = None
    try:
        _log(f"acquire repo-lock={_author_shared.REPO_LOCK_FILE}")
        try:
            repo_lock = _author_shared.acquire_repo_lock()
        except TimeoutError as e:
            _log(f"repo-lock unavailable: {e}; releasing queue-lock")
            return 0
        _log("repo-lock acquired")
        return _run_locked(run_dir, deps)
    finally:
        _author_shared.release_repo_lock(repo_lock)
        _log("release repo-lock")
        deps.release_queue_lock(queue_lock)


def _run_locked(run_dir: Path, deps: LeadAuthorDeps) -> int:
    # Preflight brakes — failure first, then done sentinel.
    if _failure_marker(run_dir).is_file():
        _log(f"FATAL preflight: {_failure_marker(run_dir)} present — human cleanup required")
        return 2
    if _done_sentinel(run_dir).is_file():
        _log("already processed (done sentinel exists) — nothing to do")
        return 0

    # Join the two tables ONCE for this tick and reuse it everywhere (draft
    # synthesis, handoff extraction, the composite classifier's entry view) —
    # the run dir is immutable by now, so re-joining would be pure repeated I/O.
    try:
        joined_leads = lead_repository.joined(run_dir)
        executed = extract_from_joined(joined_leads)
    except (FileNotFoundError, ValueError) as e:
        _log(f"FATAL: cannot extract leads: {e}")
        return 2

    # Mint drafts for executed-but-uncatalogued verbs BEFORE capturing the
    # git baseline, so the new {system}/_draft/ files are expected queue
    # content (the dirty-protected preflight ignores _draft/) and the
    # post-flight verifies against a baseline that already includes them.
    synth = synthesize_drafts(executed, catalog_dir=deps.paths.catalog_dir)
    if synth:
        _log(
            f"synthesized {len(synth)} draft(s) for uncatalogued verbs: "
            + ", ".join(p.name for p in synth)
        )

    # Stage all pending drafts (synthesized + gather-authored + system-skill
    # deposits) so the curator can `git mv` (promote/lift) and `git rm -f`
    # (discard) them — git refuses both on an untracked source. Stage before
    # the baseline so they read as expected queue content, not post-flight dirt.
    staged = _stage_pending_drafts()
    if staged:
        _log(f"staged {len(staged)} pending draft(s) for curation")

    base_sha = _git_head()
    baseline = _git_status_records()
    # Refuse if the established catalog is already dirty. Untracked drafts
    # under {system}/_draft/ are the expected gather output that this
    # author is being run to process — they belong in the baseline.
    dirty_protected = _dirty_protected_paths(baseline)
    if dirty_protected:
        _log(f"FATAL preflight: protected paths dirty before authoring: {dirty_protected}")
        return 2

    handoffs, pending_drafts, rc = _prepare_handoffs(
        run_dir, base_sha, deps, executed, joined_leads
    )
    if rc is not None:
        return rc
    _log(
        f"built {len(handoffs)} executed-template handoff(s) and "
        f"{len(pending_drafts)} pending system-skill draft(s); "
        f"base_sha={base_sha[:12]}"
    )

    rc = deps.invoke_agent(run_dir, handoffs, pending_drafts)
    if rc != 0:
        _write_state(
            _failure_marker(run_dir),
            f"claude exited rc={rc} at {_loop_config.now_iso()}\n"
            f"see {RUN_LOG_FILE} for stdout/stderr\n"
            "Human action required: review the catalog state, either drop\n"
            "any questionable commit from HEAD or remove this failure.txt\n"
            "to opt in to a retry on the next tick.\n",
        )
        _log(f"FATAL: claude exited non-zero; wrote {_failure_marker(run_dir)}")
        return 2

    ok, reason, detail = verify_postflight(base_sha, baseline)
    if not ok:
        _write_state(
            _violation_marker(run_dir),
            f"reason: {reason}\nat: {_loop_config.now_iso()}\ndetail: {json.dumps(detail, indent=2)}\n",
        )
        _log(f"FATAL post-flight: {reason}; wrote {_violation_marker(run_dir)}")
        return 2

    commit_made = detail["rev_list_count"] == 1
    maybe_push(commit_made)
    _write_state(
        _done_sentinel(run_dir),
        f"head_sha: {detail['head']}\nat: {_loop_config.now_iso()}\ncommit_made: {commit_made}\n",
    )
    _log(f"done; commit_made={commit_made} head={detail['head'][:12]}")
    return 0


def _prepare_handoffs(
    run_dir: Path, base_sha: str, deps: LeadAuthorDeps,
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
            executed = deps.extract(run_dir)
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
            f"head_sha: {base_sha}\nat: {_loop_config.now_iso()}\ncommit_made: False\n",
        )
        return [], [], 0

    return handoffs, pending_drafts, None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_HELP_EPILOG = """\
Preconditions
  * ``defender/skills/gather/queries/`` and each ``defender/skills/{system}/SKILL.md``
    must be git-clean (untracked deposits under ``_draft/`` are expected).
  * No other lead-author tick may be running (per-author queue lock at
    defender/learning/_pending_leads/.lock).
  * No defender-side author tick may be running (shared repo lock at
    defender/learning/_author.lock).
  * ``<run_dir>/executed_queries.jsonl`` and ``<run_dir>/gather_raw/``
    (the two tables) must exist — written live during the run by
    record_query.py + record_lead.py.

State files written under ``<run_dir>/lead_author/``
  done           sentinel on successful completion; makes the run a no-op.
  failure.txt    written when ``claude`` exits non-zero; preflight refuses
                 to retry until a human removes it.
  violation.txt  written when post-flight scope check fails.

Environment
  LEAD_AUTHOR_MODEL                          claude model id (default claude-sonnet-4-6)
  LEAD_AUTHOR_TIMEOUT_SECONDS                spawn timeout (default 1800)
  LEAD_AUTHOR_PUSH=1                         attempt to push the commit upstream
                                             (refuses origin/main / origin/master)
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
