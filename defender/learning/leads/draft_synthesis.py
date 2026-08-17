#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._io import guarded_mkdir, write_atomic
from defender.learning.core import config as _loop_config
from defender.learning.leads import lead_neighbors
from defender.learning.leads.path_validation import CATALOG_DIR
from defender.runtime.verbs import body_param_for, engine_for

if TYPE_CHECKING:
    from defender.learning.leads.lead_extraction import ExecutedLead

_log = _loop_config.make_logger("lead-author", flush=True)


#: The sink-side hostile-id guard on a MODEL-COINED `query_id` segment, anchored with
#: `\A`/`\Z` rather than `^`/`$`: `$` also matches immediately before a trailing newline, so
#: a segment ending in one would pass and mint a catalog path holding a control character — a
#: draft whose own frontmatter never parses again. Both anchors are explicit so the pattern
#: keeps that property under `search`/`fullmatch`, not only under the `match` its call sites
#: use.
_SAFE_ID_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")

_FENCE_LINE = re.compile(r"^(?:```|~~~)")

#: Hex characters of `sha256(query_id)` that become a draft's basename and id suffix.
#:
#: The draft's name is DERIVED, not model-supplied. The coined `query_id` is the gather
#: subagent's description of one query written mid-investigation — exactly the two things
#: `SCHEMA.md` says a template must not be named for. Naming the measurement is the AUTHOR's
#: job at promote; until then the file needs an identifier, not a name.
#:
#: Deriving it also means no screen is needed for a model-chosen path component: a digest
#: cannot be `SCHEMA`, `README` or `execution`, cannot carry a control character, and cannot
#: traverse. The coined name is not discarded — it rides in `covers:`, where it feeds the
#: dedup, the commit gate's twin-matching, and the author's naming.
#:
#: 12 hex is 48 bits, over the coined ids of one system's catalog: far past collision risk,
#: short enough to read in a path and in `git log`.
_DIGEST_LEN = 12


def _structured_call(verb_name: str, params: dict) -> str:
    doc = {"verb": verb_name, "params": dict(params or {})}
    return yaml.safe_dump(
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

    Every name here is a declared param of the verb by construction — the call reached a system,
    so `validate_params` already accepted its param set — which is why this reads the ROW and
    imports no adapter: the minter runs against a worktree it does not otherwise import from,
    and an adapter that would not import is not a reason to lose a draft.

    The engine body param is excluded: its VALUE became the fenced `## Executed query`
    recording (`_executed_query`), so naming it as a param bound by a `${placeholder}` would
    describe a file that does not exist.
    """
    body_param = body_param_for(lead.system, lead.verb)
    return sorted(n for n in (lead.params or {}) if n != body_param)


def _draft_frontmatter(
    draft_id: str, verb_name: str, params: list[str], engine: str, covers: list[str],
) -> str:
    """Rendered through `yaml.safe_dump`, not an f-string: every value here comes off the queries
    table, and a frontmatter block a model-coined value can break is a draft that never parses
    again. The dump quotes what needs quoting instead of trusting the upstream guards to be the
    only line — `covers:` most of all, since it keeps the coined `query_id` VERBATIM.

    No `body_substitutions:`. That key declares which `${name}`s of a template's `## Query` are
    body text rather than params, and a draft has no `## Query` to declare anything about: it
    carries a recording under `## Executed query` instead. Emitting one would derive an
    INTERFACE claim from one execution's DATA — e.g. a bound `host: web-${env}-1` declared as
    a substitution the template does not have.
    """
    doc: dict[str, object] = {"id": draft_id, "status": "draft", "verb": verb_name}
    if engine != "none":
        doc["engine"] = engine
    doc["params"] = params
    doc["covers"] = covers
    return yaml.safe_dump(
        doc, sort_keys=False, allow_unicode=True, default_flow_style=None
    ).strip()


def _draft_skeleton(
    query_id: str, draft_id: str, verb_name: str, params: list[str], goal: str, record: str,
    engine: str,
) -> str:
    query_block = _render_query_body(record, engine if engine != "none" else "query")
    # `split()`, not `replace("\n", " ")`: the reader this line must survive is
    # `_corpus.section_bodies`, which walks `body.splitlines()` — and that splits on `\r`,
    # `\v`, `\f`, `\x1c`-`\x1e`, `\x85` and `\u2028`/`\u2029` as well as on `\n`. A
    # model-authored `goal_text` carrying any of them opens a new LINE in the draft, so a `## `
    # heading or a ``` fence smuggled into a goal re-partitions the template's sections and can
    # swallow the recording whole. Every one of those separators is `str.isspace()`, which is
    # exactly what a bare `split()` breaks on.
    goal_line = " ".join((goal or "").split()) or "(no lead goal recorded)"
    return (
        # `covers:` holds BOTH identities this file answers: the coined `query_id` the row
        # carried, and the draft's OWN `id:`. The second is not redundant — `template_search`
        # publishes `_draft/` hits and gather may bind a draft's derived id as `query_id`, so
        # rows really are recorded under it. On promote the `id:` is replaced by the author's
        # name, and an identity that only lived there would be orphaned: the next drain
        # reaching such a row mints a draft OF THE DIGEST. Carrying it here means the author's
        # one instruction — copy `covers:` onto the file you promote — transfers both.
        f"---\n{_draft_frontmatter(draft_id, verb_name, params, engine, [draft_id, query_id])}"
        "\n---\n\n"
        "## Goal\n\n"
        f"`{query_id}` — auto-drafted from a coined gather query with no matching\n"
        f'catalog template. The defender\'s lead goal was: "{goal_line}".\n\n'
        # The curation guidance gets its OWN section rather than sitting under `## Goal`:
        # `## Goal` is the template's index entry, the body `template_search` matches, and the
        # section the author carries onto the promoted file — so prose about promoting there
        # would end up in every gather dispatch prompt. Beside the recording rather than
        # inside it, for the reason the comment below `## Executed query` gives.
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
        # The section body is the RECORDING and nothing else: `section_bodies("Executed
        # query")` is what a consumer reads to recover what ran, and prose there is
        # indistinguishable from payload to every one of them.
        "## Executed query\n\n"
        f"{query_block}\n\n"
        "## Pitfalls\n\n"
        "- (fill in any data-source quirk this query exposed — null-heavy field,\n"
        "  renamed column, case-sensitive match — grounded in the executed payload)\n"
    )


def _draft_basename(query_id: str) -> str:
    """The draft's basename and id suffix, derived from the coined `query_id`.

    Over the WHOLE `query_id` rather than over the recorded query, because `query_id` is the
    identity a call asserts and the bound values are instances under it. Two runs asking the
    same question about `web-1` and `web-2` carry the same `query_id`, so they land on one
    draft and `draft.exists()` dedups the second; hashing the recording instead would mint a
    draft per distinct value set, which is exactly the sibling-per-axis underfold the whole
    lane is written to prevent.

    Deterministic, so the mapping is recomputable from a row without reading the file — which
    is what lets a re-run recognize the draft it already wrote.
    """
    return hashlib.sha256(query_id.encode("utf-8")).hexdigest()[:_DIGEST_LEN]


def _mint_order(executed: list[ExecutedLead]) -> list[ExecutedLead]:
    """`executed`, with the rows whose payload came back `ok` first and order kept within each
    group.

    The mint takes the FIRST candidate row for an identity and dedups the rest, so which row it
    sees first decides which execution becomes the draft's evidence. In plain document order a
    query that errored, came back empty or was truncated could become the exemplar while a
    later row under the same `query_id` that actually returned data was dropped — the wrong
    instance, since a failed call is evidence about the call, not the measurement. Document
    order is kept WITHIN each group, so the choice among successful rows is unchanged.
    """
    ok = [lead for lead in executed if lead.payload_status == "ok"]
    rest = [lead for lead in executed if lead.payload_status != "ok"]
    return ok + rest


def answered_identities(catalog: list) -> set[str]:
    """Every identity the catalog already answers — ids UNION `covers:`.

    THE reader of that rule, so the two collectors that partition a row on it give the same
    answer. An identity is answered either by a template that IS it (the `id:`) or by one that
    took it over (`covers:` — a promote that renamed the file, a widen that absorbed the draft).
    Both `synthesize_drafts` (decide whether to mint) and `collect_general_failures` (decide
    whether a failed row is a draft candidate or pitfalls residue) key on this set; a second
    copy in either is how one starts dropping a row the other still expects to handle.

    A fresh `set` each call: `synthesize_drafts` adds to it as it mints.
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
    # The id's routing prefix must BE the system the row reached. A call that ran against `cmdb`
    # under the coined id `ghost.something` would otherwise mint `queries/ghost/_draft/
    # something.md` — a catalog directory for a system no adapter declares, whose
    # `verb:`/`engine:` were resolved against `cmdb` and which the corpus-wide scaffold sweep
    # cannot even evaluate (it raises `ScaffoldRuleError` rather than reporting a finding).
    #
    # The LIVE writer already pins this (`query_tool.resolve_query_id` keeps a model-coined id
    # verbatim only when `prefix == system`), but rows appended to `executed_queries.jsonl`
    # before that rule keep their phantom prefix forever and are re-read on every later tick —
    # as would rows from any future second writer. The sink asserting the invariant its source
    # claims is the point; do not delete this on the strength of the source's clause.
    #
    # The row is not lost: this predicate is shared with `collect_general_failures`, so a
    # rejected row lands in the pitfalls residue instead.
    if system != row_system:
        return None
    # The VERB is held to the same alphabet as the id segments, because a draft DECLARES it
    # (`verb:` frontmatter) and a declaration nothing can resolve is worse than no draft: the
    # corpus-wide check refuses it, so a junk verb on one row fails the whole lane's next
    # commit. A rejected row lands in the pitfalls residue instead.
    if not _SAFE_ID_SEGMENT.match(verb_name or ""):
        return None
    # Both segments are screened, for DIFFERENT reasons. `system` is a path component —
    # `synthesize_drafts` composes it into a directory — so its screen is a path screen.
    # `suffix` reaches no path; its screen is about what goes into `covers:`, the dedup key and
    # the provenance the author reads. A coined id that is not a well-formed
    # `{system}.{segment}` is one `resolve_query_id` would never emit, so the row is old or
    # from a foreign writer, and a draft minted from it records an identity nothing else in
    # the corpus will ever match.
    if not _SAFE_ID_SEGMENT.match(system) or not _SAFE_ID_SEGMENT.match(suffix):
        return None
    # No `_is_schema_md` / `_is_draft_readme` / `execution.md` screen is needed on the
    # basename: `resolve_query_id`'s kebab segment admits `SCHEMA`, `README` and `execution`
    # like any other name, but the basename below is a hex digest, which is none of them.
    return system, _draft_basename(query_id)


def synthesize_drafts(
    executed: list[ExecutedLead], *, catalog_dir: Path = CATALOG_DIR,
    catalog: list | None = None, systems: frozenset[str],
) -> list[Path]:
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    # Ids UNION `covers:` — through the shared reader, because `collect_general_failures`
    # partitions the same rows on the same question. Without the `covers:` half, every promoted
    # or discarded draft is re-minted the next time a run coins its id, and the author spends a
    # tick discarding it again.
    by_id = answered_identities(catalog)
    created: list[Path] = []
    for lead in _mint_order(executed):
        # `is_sentinel` explicitly, not by the id alphabet. A `∅.`-prefixed row is a writer-only
        # record of something that never reached a system (a refused repeat, a failed shim). It
        # would also fall out of `_draft_candidate_segments` because `∅` fails the leading
        # `[A-Za-z0-9]`, but that is an accident of the guard's alphabet, not a decision about
        # sentinels — the mint asks the same question the projection was partitioned on.
        if lead.is_sentinel:
            continue
        qid = lead.query_id
        segs = _draft_candidate_segments(qid, lead.verb, by_id, row_system=lead.system)
        if segs is None:
            continue
        system, suffix = segs
        if system not in systems:
            # The host-side writer is reachable before the agent is ever spawned — a
            # mkdir+write from a model-supplied query_id — so an undeclared system is refused
            # here, and REPORTED rather than silently skipped.
            _log(
                f"synthesize_drafts: refused to mint a draft for {system!r} "
                f"(query_id={qid!r}); not a declared system"
            )
            continue
        # No containment check on the composed path: `suffix` is a hex digest and `system` has
        # cleared both `_SAFE_ID_SEGMENT` and the declared-systems set, so neither segment can
        # carry a separator or a `..` to escape with.
        draft = catalog_dir / system / "_draft" / f"{suffix}.md"
        if draft.exists() or draft in created:
            continue
        record = _executed_query(lead) or "# (no command captured for this query)"
        engine = engine_for(lead.system, lead.verb)
        try:
            # `guarded_mkdir` + `write_atomic`, not `mkdir` + `write_text`, for two properties:
            # the write is ATOMIC, so a crash or full disk cannot leave a truncated draft
            # (which reads to every consumer as "the minter wrote a bad file"); and both halves
            # refuse a planted symlink instead of following it — the seam every other host-side
            # writer into a shared tree uses. `write_atomic` also stages under an UNPREDICTABLE
            # name (`_io.stage_name`), which a hand-rolled `<name>.tmp` does not.
            guarded_mkdir(draft.parent, base=catalog_dir)
            write_atomic(
                draft,
                _draft_skeleton(
                    qid, f"{system}.{suffix}", lead.verb, _draft_params(lead),
                    lead.goal_text, record, engine,
                ),
            )
            created.append(draft)
            by_id.add(qid)
        except OSError as e:
            # REPORTED, not just skipped: an `OSError` here is not only "the disk is full" —
            # `guarded_mkdir` and `write_atomic` raise it to REFUSE a planted symlink or hard
            # link at the draft's name, and a refusal nothing prints reads from the outside
            # exactly like a tick that had no draft to mint.
            _log(f"synthesize_drafts: could not write {draft} (query_id={qid!r}): {e}")
            continue
    return created
