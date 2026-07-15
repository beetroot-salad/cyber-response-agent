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

import yaml

# Put the workspace root on sys.path so the `defender.*` namespace imports below
# resolve whether this file is imported directly or via lead_author.
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.leads import lead_neighbors
from defender.learning.leads.path_validation import CATALOG_DIR
from defender.runtime.verbs import body_param_for, engine_for

if TYPE_CHECKING:
    from defender.learning.leads.lead_extraction import ExecutedLead


# A `query_id` segment (`{system}` / `{verb}`) becomes a path component in the
# `{system}/_draft/{verb}.md` draft path below. The id is model-coined (the
# gather subagent passes it to the `query` tool as `query_id`), so an untrusted segment containing
# `/`, `\`, or a leading `.` (e.g. `..`) would escape the catalog dir and write
# an arbitrary `.md` file. Require each segment to be a single safe path
# component: starts alphanumeric, then `[a-z0-9._-]` — which the real kebab ids
# (`sshd-auth-baseline-7d`, `change-mgmt`) all satisfy while `..`, `a/b`, and
# `/abs` are rejected. A containment clamp on the resolved path backs this up.
_SAFE_ID_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# A fence-opening line, matched AFTER lstrip — the same thing `_corpus.section_bodies` toggles
# on. Any line that starts (post-lstrip) with ``` or ~~~ closes a Markdown code fence there.
_FENCE_LINE = re.compile(r"^(?:```|~~~)")


def _structured_call(verb_name: str, params: dict) -> str:
    """The canonical record for a PARAM-ONLY verb: a structured ``{verb, params}`` rendering,
    re-runnable and derivable from the frozen row alone (never ``raw_command``, never a bare
    ``${param}`` skeleton). YAML — a REAL serializer, not an f-string — so an adversarial param
    value (a fence, a colon, a newline, a quote) is quoted/escaped rather than able to inject a
    sibling key or close the draft's ``## Query`` fence."""
    doc = {"verb": verb_name, "params": dict(params or {})}
    return yaml.safe_dump(
        doc, sort_keys=False, allow_unicode=True, default_flow_style=False
    ).strip()


def _executed_query(lead: ExecutedLead) -> str:
    """The literal query that ran, as the canonical record — resolved PER VERB, offline.

    For an engine verb (the SIEM's esql/query/alerts) the whole query is a native-language body in
    ONE declared param (``query`` for esql, ``native_query`` for lucene) — so the VERBATIM value
    of that body param is the record. For a param-only verb the record is the structured
    ``{verb, params}`` call (:func:`_structured_call`). Never ``raw_command`` (the ``shlex``
    audit string its own docstring forbids fencing) and never the dead ``params['arg0']`` the
    query tool stopped writing at #617.
    """
    engine = engine_for(lead.system, lead.verb)
    if engine != "none":
        body_param = body_param_for(lead.system, lead.verb)
        body = (lead.params or {}).get(body_param) if body_param else None
        if isinstance(body, str) and body.strip():
            return body
        # An engine verb whose body param is absent/blank on this row: fall through to the
        # structured render rather than leaking raw_command.
    return _structured_call(lead.verb, lead.params or {})


def _fence_safe(text: str) -> bool:
    """True when ``text`` can sit inside a ``` fence without escaping it: no line opens/closes a
    fence (``_corpus.section_bodies`` toggles ``fenced`` on any ```/~~~ line, lstripped) and no
    line starts a ``## `` heading at column 0. A body that trips either could close the draft's
    ``## Query`` fence and forge a sibling ``## `` section in a file the lead-author LLM reads."""
    for line in text.splitlines():
        if _FENCE_LINE.match(line.lstrip()) or line.startswith("## "):
            return False
    return True


def _render_query_body(record: str, fence_lang: str) -> str:
    """Render the canonical ``record`` as the draft's ``## Query`` content, injection-safe.

    The safe case is one intact ```<lang> fence. Removing ``raw_command`` removed ``shlex``'s
    quoting, so an adversarial body carrying a fence-closing ``` or a ``## `` heading must not be
    able to break out: when ``record`` is unsafe, indent EVERY line so none sits at column 0 — a
    ``## `` line can no longer be a heading and nothing escapes the ``## Query`` section (the
    fence-toggle may swallow the fixed skeleton's later ``## Pitfalls`` into the display, but it
    can never forge a NEW sibling section, which is the property that matters)."""
    if _fence_safe(record):
        return f"```{fence_lang}\n{record}\n```"
    indented = "\n".join("    " + ln for ln in record.splitlines())
    return (
        "The executed query body contained a code fence and is shown as an indented literal "
        "(neutralized — not runnable as-is):\n\n" + indented
    )


def _draft_skeleton(query_id: str, goal: str, record: str, engine: str) -> str:
    """Render a draft skeleton whose ``## Query`` carries the verb's CANONICAL ``record``.

    The fence language + ``engine:`` frontmatter follow the VERB's declared ``engine`` (``esql`` /
    ``lucene`` for an engine verb, a structured ```` ```query ```` call for a param-only verb) —
    resolved offline from ``(system, verb)`` by the caller, never re-guessed from the system.
    Built by concatenation, not ``str.format`` (an ES|QL ``GROK`` body carries literal ``{`` /
    ``}``), and the body goes through :func:`_render_query_body` so an attacker-influenced value
    cannot forge a section. Shape mirrors the migrated catalog (``## Goal`` / ``## Query`` /
    ``## Pitfalls``).
    """
    if engine != "none":
        engine_fm = f"\nengine: {engine}"
        query_block = _render_query_body(record, engine)
    else:
        engine_fm = ""
        query_block = _render_query_body(record, "query")
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
        f"{query_block}\n\n"
        "## Pitfalls\n\n"
        "- (fill in any data-source quirk this query exposed — null-heavy field,\n"
        "  renamed column, case-sensitive match — grounded in the executed payload)\n"
    )


def _draft_candidate_segments(
    query_id: str, verb_name: str, by_id: set[str],
) -> tuple[str, str] | None:
    """``(system, id-suffix)`` if ``query_id`` is a mintable draft candidate, else None.

    The single home for the candidacy rule the WARN-and-draft path applies, so
    ``synthesize_drafts`` (which mints the draft) and ``collect_general_failures``
    (which captures the residue that is *not* drafted) agree by construction — a
    query_id is drafted XOR a general-failure candidate, never both, never neither
    by accident. Returns None when:

    - the id resolves to an existing catalog template (``by_id``) — not a draft;
    - it carries no ``{system}.`` prefix (an ``ad-hoc`` probe);
    - the id SUFFIX equals the row's RECORDED VERB — an untagged call (no ``query_id``)
      collapses to ``{system}.{verb}``, so a suffix that IS the declared verb is not a coined
      id and drafting it would mint a junk catch-all. Keying on the row's own recorded verb
      (not a roster re-imported at read time) keeps a persisted artifact's candidacy stable
      across the tree that resolves it (``frozen_actor_replay`` re-execs in a pinned worktree);
    - either segment is empty or not a single safe path component.

    Path-containment (the ``_draft/`` clamp) stays at the write site in
    ``synthesize_drafts``; this predicate decides candidacy only.
    """
    if not query_id or "." not in query_id or query_id in by_id:
        return None
    system, suffix = query_id.split(".", 1)
    if not system or not suffix or suffix == verb_name:
        return None
    if not _SAFE_ID_SEGMENT.match(system) or not _SAFE_ID_SEGMENT.match(suffix):
        return None
    return system, suffix


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
    promote/discard/skip machinery curate it. ``query_id`` is the id the gather
    subagent passes to the ``query`` tool; an untagged call (no ``query_id``)
    collapses to ``{system}.{verb}`` — whose suffix IS the recorded verb — and is
    skipped along with ad-hoc leads (``query_id`` with no ``{system}.`` prefix):
    neither is a catalog candidate. Idempotent — skips drafts that already exist
    on disk or were minted earlier in this call.

    The drafted ``## Query`` is the canonical record of what ran — an engine
    verb's native-language body verbatim, or a param-only verb's structured
    ``{verb, params}`` call — never ``raw_command`` and never a ``${param}``
    re-render (see ``_executed_query``).
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
        # Candidacy (resolves to no template, coined {system}.{suffix} whose suffix is not the
        # row's own recorded verb, safe segments) is the shared predicate; the non-candidate
        # cases it rejects — empty segments, an untagged {system}.{verb} id, unsafe path
        # components — are exactly the ones that would mint junk or escape the catalog dir.
        segs = _draft_candidate_segments(qid, lead.verb, by_id)
        if segs is None:
            continue
        system, suffix = segs
        # `system`/`suffix` become path components — clamp the resolved draft under
        # the system's `_draft/` dir as belt-and-suspenders over the segment check.
        draft = catalog_dir / system / "_draft" / f"{suffix}.md"
        draft_root = (catalog_dir / system / "_draft").resolve()
        if not draft.resolve().is_relative_to(draft_root):
            continue
        if draft.exists() or draft in created:
            continue
        record = _executed_query(lead) or "# (no command captured for this query)"
        engine = engine_for(lead.system, lead.verb)
        try:
            draft.parent.mkdir(parents=True, exist_ok=True)
            draft.write_text(
                _draft_skeleton(qid, lead.goal_text, record, engine), encoding="utf-8"
            )
            created.append(draft)
            by_id.add(qid)
        except OSError:
            continue
    return created
