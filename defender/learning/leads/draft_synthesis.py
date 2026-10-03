#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import logging
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _yaml
from defender._io import ENTRY_DIR, ENTRY_FILE, Held
from defender._tree_listing import entry_kind
from defender.learning.leads import lead_neighbors
from defender.learning.leads.path_validation import CATALOG_FOLDER
from defender.runtime.verbs import body_param_for, engine_for

if TYPE_CHECKING:
    from defender.learning.leads.lead_extraction import ExecutedLead

_logger = logging.getLogger(__name__)


#: Guard on a model-coined `query_id` segment. `\A`/`\Z` rather than `^`/`$`, since `$` also
#: matches before a trailing newline, which would mint a catalog path holding a control
#: character and a draft whose frontmatter never parses.
_SAFE_ID_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")

_FENCE_LINE = re.compile(r"^(?:```|~~~)")

#: Hex characters of `sha256(query_id)` that become a draft's basename and id suffix.
#:
#: Derived rather than model-supplied: the coined `query_id` describes one query, which
#: `SCHEMA.md` says a template must not be named for — naming is the author's job at promote.
#: A digest also can't be `SCHEMA`/`README`/`execution`, carry a control character, or
#: traverse. The coined name is kept in `covers:`. 48 bits is ample for one system's catalog.
_DIGEST_LEN = 12


def _structured_call(verb_name: str, params: dict) -> str:
    doc = {"verb": verb_name, "params": dict(params or {})}
    return _yaml.safe_dump(
        doc, sort_keys=False, allow_unicode=True, default_flow_style=False
    ).strip()


def _executed_query(lead: ExecutedLead) -> str:
    engine = engine_for(lead.system, lead.verb)
    if engine != "none":
        body_param = body_param_for(lead.system, lead.verb)
        body = (lead.params or {}).get(body_param) if body_param else None
        if isinstance(body, str) and body.strip():
            return body
    return _structured_call(lead.verb, lead.params or {})


def _fence_safe(text: str) -> bool:
    for line in text.splitlines():
        if _FENCE_LINE.match(line.lstrip()) or line.startswith("## "):
            return False
    return True


def _render_query_body(record: str, fence_lang: str) -> str:
    if _fence_safe(record):
        return f"```{fence_lang}\n{record}\n```"
    indented = "\n".join("    " + ln for ln in record.splitlines())
    return (
        "The executed query body contained a code fence and is shown as an indented literal "
        "(neutralized — not runnable as-is):\n\n" + indented
    )


def _draft_params(lead: ExecutedLead) -> list[str]:
    """The param names this run bound, as the `params:` frontmatter key SCHEMA.md defines.

    Read off the row, not an adapter: the call reached a system, so `validate_params` already
    accepted these names, and an adapter that won't import in the worktree shouldn't lose a
    draft. The engine body param is excluded, since its value became the `## Executed query`
    recording rather than a `${placeholder}`.
    """
    body_param = body_param_for(lead.system, lead.verb)
    return sorted(n for n in (lead.params or {}) if n != body_param)


def _draft_frontmatter(
    draft_id: str, verb_name: str, params: list[str], engine: str, covers: list[str],
) -> str:
    """Rendered through `yaml.safe_dump`, not an f-string: the values are model-coined, and
    `covers:` keeps the coined `query_id` verbatim, so quoting can't be left to upstream guards.

    No `body_substitutions:`: a draft has no `## Query`, only a recording, and declaring one
    would turn one execution's data into an interface claim.
    """
    doc: dict[str, object] = {"id": draft_id, "status": "draft", "verb": verb_name}
    if engine != "none":
        doc["engine"] = engine
    doc["params"] = params
    doc["covers"] = covers
    return _yaml.safe_dump(
        doc, sort_keys=False, allow_unicode=True, default_flow_style=None
    ).strip()


def _draft_skeleton(
    query_id: str, draft_id: str, verb_name: str, params: list[str], goal: str, record: str,
    engine: str,
) -> str:
    query_block = _render_query_body(record, engine if engine != "none" else "query")
    # `split()`, not `replace("\n", " ")`: `_corpus.section_bodies` uses `splitlines()`, which
    # also splits on `\r`, `\v`, `\f`, `\x1c`-`\x1e`, `\x85`, `\u2028`/`\u2029`. Any of them in
    # a model-authored goal could smuggle a `## ` heading or fence onto its own line; all are
    # `str.isspace()`, which a bare `split()` breaks on.
    goal_line = " ".join((goal or "").split()) or "(no lead goal recorded)"
    return (
        # `covers:` holds both identities: the coined `query_id` and the draft's own `id:`.
        # Gather may bind a draft's derived id as `query_id`, and on promote the `id:` is
        # replaced, so without this a row under it would mint a draft of the digest. Copying
        # `covers:` onto the promoted file transfers both.
        f"---\n{_draft_frontmatter(draft_id, verb_name, params, engine, [draft_id, query_id])}"
        "\n---\n\n"
        "## Goal\n\n"
        f"`{query_id}` — auto-drafted from a coined gather query with no matching\n"
        f'catalog template. The defender\'s lead goal was: "{goal_line}".\n\n'
        # Its own section: `## Goal` is what `template_search` matches and what carries onto
        # the promoted file, so promotion prose there would reach every gather dispatch prompt.
        "## Curation notes\n\n"
        "**This file is named by a digest, and naming it is your job.** The id above "
        "is\nderived from the coined `query_id` in `covers:`, which gather wrote "
        "mid-investigation\nfor one lead — a description of *this query*, not a name "
        "for a template. On promote,\nname the established file for **what it "
        "measures** (`SCHEMA.md`), and carry `covers:`\nthrough so this draft is not "
        "minted again.\n\n"
        "**Before promoting**, check the handoff `neighbors`: if this is a "
        "*narrowing*\nof an existing wide template (same measurement, fewer "
        "filter/`BY` axes), discard\nthis draft and widen that template's `## Goal` "
        "for keyword recall instead of\nminting a sibling — adding this draft's "
        "`covers:` entry to the template you widen.\nPromote only when this names a "
        "genuinely new measurement.\n\n"
        "What follows is **evidence, not a template query**: the literal values this "
        "one\nrun bound, so it holds no placeholders and declares no "
        "`body_substitutions:`.\nWhich axes are variable is a property of the "
        "measurement, not of this one\nexecution — on promote, write the "
        "wide/superset `## Query` yourself, carrying\nevery filter axis it could "
        "take.\n\n"
        # The recording and nothing else: consumers read this section to recover what ran,
        # and prose there would be indistinguishable from payload.
        "## Executed query\n\n"
        f"{query_block}\n\n"
        "## Pitfalls\n\n"
        "- (fill in any data-source quirk this query exposed — null-heavy field,\n"
        "  renamed column, case-sensitive match — grounded in the executed payload)\n"
    )


def _draft_basename(query_id: str) -> str:
    """The draft's basename and id suffix, derived from the coined `query_id`.

    Hashes the `query_id`, not the recorded query: runs asking the same question with
    different bound values land on one draft instead of a sibling per value set.
    Deterministic, so a re-run recognizes the draft it already wrote.
    """
    return hashlib.sha256(query_id.encode("utf-8")).hexdigest()[:_DIGEST_LEN]


def _mint_order(executed: list[ExecutedLead]) -> list[ExecutedLead]:
    """`executed`, with `ok`-payload rows first, order kept within each group.

    The mint takes the first candidate row per identity, so a successful execution should be
    the draft's evidence rather than one that errored, came back empty or was truncated.
    """
    ok = [lead for lead in executed if lead.payload_status == "ok"]
    rest = [lead for lead in executed if lead.payload_status != "ok"]
    return ok + rest


def answered_identities(catalog: list) -> set[str]:
    """Every identity the catalog already answers — ids plus `covers:` (a promote that renamed
    the file, or a widen that absorbed a draft).

    Shared by `synthesize_drafts` and `collect_general_failures` so they partition rows the
    same way. Returns a fresh `set`: `synthesize_drafts` adds to it as it mints.
    """
    return {t.id for t in catalog} | {c for t in catalog for c in t.covers}


def _draft_candidate_segments(
    query_id: str, verb_name: str, by_id: set[str], *, row_system: str,
) -> tuple[str, str] | None:
    if not query_id or "." not in query_id or query_id in by_id:
        return None
    system, suffix = query_id.split(".", 1)
    if not system or not suffix or suffix == verb_name:
        return None
    # The id's prefix must be the system the row reached; otherwise `ghost.something` run
    # against `cmdb` would mint a catalog directory for an undeclared system that the scaffold
    # sweep can't evaluate. `query_tool.resolve_query_id` enforces this for new rows, but old
    # rows in `executed_queries.jsonl` are re-read every tick, so the sink checks too. A
    # rejected row lands in the pitfalls residue (this predicate is shared with
    # `collect_general_failures`).
    if system != row_system:
        return None
    # The verb is declared in the draft's frontmatter, and an unresolvable one would fail the
    # corpus-wide check and so the lane's next commit.
    if not _SAFE_ID_SEGMENT.match(verb_name or ""):
        return None
    # `system` becomes a path component; `suffix` goes into `covers:`. An id that isn't a
    # well-formed `{system}.{segment}` came from an old or foreign writer and would record an
    # identity nothing else matches.
    if not _SAFE_ID_SEGMENT.match(system) or not _SAFE_ID_SEGMENT.match(suffix):
        return None
    # No reserved-name screen needed: the basename is a hex digest.
    return system, _draft_basename(query_id)


def synthesize_drafts(
    executed: list[ExecutedLead], *, skills: Held, where: Path,
    catalog: list | None = None, systems: frozenset[str],
) -> list[Path]:
    """Mint a catalog draft for each uncatalogued coined `query_id`; return the drafts written,
    each spelled `where / name`.

    `skills` is the lane's held `skills/` mount and `where` the Path it is spelled as (never
    opened). A draft is written at `gather/queries/<system>/_draft/<hex>.md` below the mount point,
    so a link planted anywhere below it (the catalog folder included) is refused, never followed
    (#1134 O3, O5.4). A refused draft — a link at its name or at a holding folder, or a holding
    folder that cannot be listed — is logged and skipped, and the claim goes on (O5.5)."""
    if catalog is None:
        catalog = lead_neighbors.load_lane_catalog(skills.view(), where=where)
    # Includes `covers:`, or every promoted or discarded draft is re-minted when a run next
    # coins its id.
    by_id = answered_identities(catalog)
    created: list[Path] = []
    for lead in _mint_order(executed):
        # Sentinel rows never reached a system. Checked explicitly rather than relying on `∅`
        # failing `_SAFE_ID_SEGMENT`.
        if lead.is_sentinel:
            continue
        qid = lead.query_id
        segs = _draft_candidate_segments(qid, lead.verb, by_id, row_system=lead.system)
        if segs is None:
            continue
        system, suffix = segs
        if system not in systems:
            # This host-side mkdir+write runs from a model-supplied query_id before any agent,
            # so an undeclared system is refused here, and reported.
            _logger.warning(
                f"synthesize_drafts: refused to mint a draft for {system!r} "
                f"(query_id={qid!r}); not a declared system"
            )
            continue
        # No containment check needed: `suffix` is a hex digest and `system` passed both
        # `_SAFE_ID_SEGMENT` and the declared set.
        name = f"{CATALOG_FOLDER}/{system}/_draft/{suffix}.md"
        draft = where / name
        if draft in created:
            continue
        record = _executed_query(lead) or "# (no command captured for this query)"
        engine = engine_for(lead.system, lead.verb)
        try:
            # A plain file or folder at the name is the draft already there. Anything else falls
            # through to the write, which refuses what is not plain: a link at the name, or a
            # holding folder whose listing was refused (linked, not a directory). The probe never
            # raises; a refused write is this draft's, never the claim's.
            if entry_kind(skills.view(), name).kind in (ENTRY_FILE, ENTRY_DIR):
                continue
            # Replace stages beside the name and renames onto it, so a crash can't leave a
            # truncated draft; the held mount makes each missing holding folder and follows no
            # link below the mount point.
            skills.write(
                name,
                _draft_skeleton(
                    qid, f"{system}.{suffix}", lead.verb, _draft_params(lead),
                    lead.goal_text, record, engine,
                ),
                mode="replace",
            )
            created.append(draft)
            by_id.add(qid)
        except OSError as e:
            # Reported: the `OSError` may be a refused planted link, which would otherwise look
            # like a tick with nothing to mint.
            _logger.error(f"synthesize_drafts: could not write {draft} (query_id={qid!r}): {e}")
            continue
    return created
