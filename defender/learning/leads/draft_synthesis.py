#!/usr/bin/env python3
"""Draft-skeleton synthesis: mint ``{system}/_draft/{verb}.md`` skeletons for the
executed-but-uncatalogued gather verbs the lead author then curates.

The WARN-and-draft path. ``_draft_candidate_segments`` is the shared candidacy
predicate (``synthesize_drafts`` mints the draft, ``lead_extraction.collect_general_failures``
captures the residue that is *not* drafted) — it lives here, the lower leaf, so the
extraction module imports it rather than the reverse. ``_executed_query`` (the canonical
recorded-query picker) likewise lives here so both leaves share one engine-shape policy
without a cycle.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

# Put the workspace root on sys.path so the `defender.*` namespace imports below
# resolve whether this file is imported directly or via lead_author.
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.leads import lead_neighbors
from defender.learning.leads.path_validation import CATALOG_DIR

if TYPE_CHECKING:
    from defender.learning.leads.lead_extraction import ExecutedLead


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


def _draft_candidate_segments(query_id: str, by_id: set[str]) -> tuple[str, str] | None:
    """``(system, verb)`` if ``query_id`` is a mintable draft candidate, else None.

    The single home for the candidacy rule the WARN-and-draft path applies, so
    ``synthesize_drafts`` (which mints the draft) and ``collect_general_failures``
    (which captures the residue that is *not* drafted) agree by construction — a
    query_id is drafted XOR a general-failure candidate, never both, never neither
    by accident. Returns None when:

    - the id resolves to an existing catalog template (``by_id``) — not a draft;
    - it carries no ``{system}.`` prefix (an ``ad-hoc`` probe);
    - the verb is reserved (``esql`` / ``query`` / ``ad-hoc`` — an untagged call) —
      drafting it would mint a junk catch-all;
    - either segment is empty or not a single safe path component.

    Path-containment (the ``_draft/`` clamp) stays at the write site in
    ``synthesize_drafts``; this predicate decides candidacy only.
    """
    if not query_id or "." not in query_id or query_id in by_id:
        return None
    system, verb = query_id.split(".", 1)
    if not system or not verb or verb in _NON_CANDIDATE_VERBS:
        return None
    if not _SAFE_ID_SEGMENT.match(system) or not _SAFE_ID_SEGMENT.match(verb):
        return None
    return system, verb


def synthesize_drafts(
    executed: list[ExecutedLead], *, catalog_dir: Path = CATALOG_DIR,
    catalog: list | None = None,
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
    # Reuse the tick's once-loaded catalog when threaded; else load (the direct
    # `catalog_dir`-only call path). This is the FIRST consumer, so the
    # pre-synthesis catalog is exactly what a fresh load would return.
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    by_id = {t.id for t in catalog}
    created: list[Path] = []
    for lead in executed:
        qid = lead.query_id
        # Candidacy (resolves to no template, real {system}.{verb}, safe segments)
        # is the shared predicate; the non-candidate cases it rejects — empty
        # segments, reserved verbs, unsafe path components — are exactly the ones
        # that would mint junk or escape the catalog dir.
        segs = _draft_candidate_segments(qid, by_id)
        if segs is None:
            continue
        system, verb = segs
        # `system`/`verb` become path components — clamp the resolved draft under
        # the system's `_draft/` dir as belt-and-suspenders over the segment check.
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
                _draft_skeleton(qid, system, lead.goal_text, query_body), encoding="utf-8"
            )
            created.append(draft)
            by_id.add(qid)
        except OSError:
            continue
    return created
