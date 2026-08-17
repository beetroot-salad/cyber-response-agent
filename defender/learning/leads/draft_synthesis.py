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


#: The sink-side hostile-id guard on a MODEL-COINED `query_id` segment, anchored at both
#: ends with `\A`/`\Z` rather than `^`/`$` (#852 F-21). `$` also matches immediately before a
#: trailing newline, so a segment ending in one passed this guard and minted a catalog path
#: holding a control character — a draft whose own frontmatter no longer parses, leaving that id
#: permanently uncataloguable and silently absent from the pitfalls queue. `\Z` matches at the
#: end of the string and nowhere else, which is the property the guard was written to have.
#: Both anchors are explicit so the pattern keeps that property under `search`/`fullmatch`
#: too, not only under the `match` its call sites happen to use.
_SAFE_ID_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")

_FENCE_LINE = re.compile(r"^(?:```|~~~)")

#: Hex characters of `sha256(query_id)` that become a draft's basename and id suffix.
#:
#: The draft's name is DERIVED, not model-supplied, and that is the whole of it. The coined
#: `query_id` is the gather subagent's description of one query, written mid-investigation
#: while it optimized for one lead — which is exactly the two things `SCHEMA.md` says a
#: template must not be named for ("the axis you happen to filter on", "why the defender asked
#: for it"). Naming the measurement is the AUTHOR's job, at promote, holding the recording and
#: the neighbor scores. Until then the file needs an identifier, not a name.
#:
#: Deriving it also retires the screens that existed only because a model chose a path
#: component: a digest cannot be `SCHEMA`, `README` or `execution`, cannot carry a control
#: character, and cannot traverse. The coined name is not discarded — it rides in `covers:`,
#: where it feeds the dedup, the commit gate's twin-matching, and the author's naming.
#:
#: 12 hex is 48 bits. The population is the coined ids of one system's catalog, so this is far
#: past where collision is a real risk; it is short enough to read in a path and in `git log`.
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
    imports no adapter. The minter runs in the loop process against a worktree it does not
    otherwise import from, and an adapter that would not import is not a reason to lose a draft.

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
    again (#852 F-21, the same failure the id guard exists for). The dump quotes what needs
    quoting instead of trusting the guards upstream to be the only line. `covers:` is the key
    that most needs it now — it is where the coined `query_id` is kept VERBATIM, so it is the
    one value here still shaped by a model.

    No `body_substitutions:`. That key declares which `${name}`s of a template's `## Query` are
    body text rather than params, and a draft has no `## Query` to declare anything about: it
    carries a recording under `## Executed query` instead. The minter emitting one meant
    deriving an INTERFACE claim from one execution's DATA — which is how a bound value like
    `host: web-${env}-1` came to be declared as a substitution the template does not have.
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
    # `split()`, not `replace("\n", " ")`: the reader this line has to survive is
    # `_corpus.section_bodies`, which walks `body.splitlines()` — and that splits on `\r`,
    # `\v`, `\f`, `\x1c`-`\x1e`, `\x85` and `\u2028`/`\u2029` as well as on `\n`. A
    # model-authored `goal_text` carrying any of them opened a new LINE in the draft, so a `## `
    # heading or a ``` fence smuggled into a goal re-partitioned the template's sections and
    # could swallow the recording whole. Every one of those separators is `str.isspace()`, which
    # is exactly what a bare `split()` breaks on, so one call neutralizes the set (#852 F-21's
    # argument about a control character in an id, applied to the other model-supplied string
    # this skeleton interpolates).
    goal_line = " ".join((goal or "").split()) or "(no lead goal recorded)"
    return (
        f"---\n{_draft_frontmatter(draft_id, verb_name, params, engine, [query_id])}\n---\n\n"
        "## Goal\n\n"
        f"`{query_id}` — auto-drafted from a coined gather query with no matching\n"
        f'catalog template. The defender\'s lead goal was: "{goal_line}".\n\n'
        # The curation guidance gets its OWN section, and does not sit under `## Goal`.
        # `## Goal` is the template's index entry on a dispatch to its own system and the body
        # `template_search` matches (`SCHEMA.md`), and it is the one section the author is told
        # to carry onto the promoted file for keyword recall — so prose about promoting is text
        # that ends up in every gather dispatch prompt, describing the curation loop rather
        # than the measurement. Beside the recording rather than inside it, for the reason the
        # comment below `## Executed query` gives.
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
        # The section body is the RECORDING and nothing else. The guidance above used to sit
        # under this heading, which put author-facing prose inside the one section every reader
        # treats as the executed call — `section_bodies("Executed query")` is what a consumer
        # reads to recover what ran, and prose there is indistinguishable from payload to all
        # of them (`test_canonical_record_param_only_is_structured_call` reads exactly this).
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
    sees first decides which execution becomes the draft's evidence. Untouched, that was
    document order: a query that errored, came back empty, or was truncated could be recorded
    as the exemplar for a measurement while a later row under the same `query_id` that actually
    returned data was dropped by the dedup. Under "the values are instances of the identity"
    that is simply the wrong instance — a failed call is evidence about the call, not about the
    measurement. Document order is kept WITHIN each group, so the choice among successful rows
    is unchanged — one `sorted(key=…)` on the same predicate would give that too (Python's sort
    is stable); the partition is spelled out because it names the two groups.
    """
    ok = [lead for lead in executed if lead.payload_status == "ok"]
    rest = [lead for lead in executed if lead.payload_status != "ok"]
    return ok + rest


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
    # something.md` — a catalog directory for a system no adapter declares (the phantom-system
    # class, #855 F-06), whose `verb:`/`engine:` were resolved against `cmdb` and which the
    # corpus-wide scaffold sweep cannot even evaluate (it raises `ScaffoldRuleError` rather than
    # reporting a finding).
    #
    # The LIVE writer already pins this: `query_tool.resolve_query_id`'s FK-7 clause returns a
    # model-coined id verbatim only when `prefix == system`, and falls back to `{system}.{verb}`
    # otherwise. What this screen covers is the rows that writer did not mint — every row
    # appended to `executed_queries.jsonl` BEFORE FK-7 landed keeps its phantom prefix forever
    # and is re-read on every later tick (`test_synthesize_drafts_screens_a_row_recorded_before_
    # the_writer_rule` seeds exactly one) — plus any future second writer of that table. The
    # sink asserting the invariant its source claims is the point; do not delete this on the
    # strength of the source's clause.
    #
    # The row is not lost: this predicate is shared with `collect_general_failures`, so a
    # rejected row lands in the pitfalls residue instead.
    if system != row_system:
        return None
    # The VERB is held to the same alphabet as the id segments, because a draft DECLARES it
    # (`verb:` frontmatter, #901) and a declaration nothing can resolve is worse than no draft:
    # the corpus-wide check refuses it, so a junk verb on one row would fail the whole lane's
    # next commit. A row this rejects is not lost — the predicate is shared with
    # `collect_general_failures`, so it lands in the pitfalls residue instead.
    if not _SAFE_ID_SEGMENT.match(verb_name or ""):
        return None
    # Both segments stay screened, for two DIFFERENT reasons now that the basename is derived.
    #
    # `system` is still a path component — `synthesize_drafts` composes it into a directory — so
    # its screen is the same path screen it always was.
    #
    # `suffix` no longer reaches any path, and its screen is no longer about one. It is about
    # what goes into `covers:`, which is the dedup key and the provenance the author reads: a
    # coined id that is not a well-formed `{system}.{segment}` is one `resolve_query_id`'s FK-7
    # clause would never have emitted, so the row is pre-FK-7 or from a foreign writer, and a
    # draft minted from it records an identity nothing else in the corpus will ever match. The
    # guard is kept and re-aimed rather than deleted with the basename it used to defend.
    if not _SAFE_ID_SEGMENT.match(system) or not _SAFE_ID_SEGMENT.match(suffix):
        return None
    # What IS gone is the `_is_schema_md` / `_is_draft_readme` / `execution.md` triad (#772's
    # host-side half). `resolve_query_id`'s kebab segment admits `SCHEMA`, `README` and
    # `execution` like any other name, so a coined `{system}.SCHEMA` used to mint
    # `queries/{system}/_draft/SCHEMA.md` — a protected surface — and cost the tick's whole
    # batch before the agent was even spawned. A hex digest is none of those names. The triad
    # was right about the danger; the model-chosen basename it was defending is what changed.
    return system, _draft_basename(query_id)


def synthesize_drafts(
    executed: list[ExecutedLead], *, catalog_dir: Path = CATALOG_DIR,
    catalog: list | None = None, systems: frozenset[str],
) -> list[Path]:
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    # Ids UNION `covers:`. An identity is answered either by a template that IS it (the id) or
    # by one that took it over (a promote that renamed the file, a widen that absorbed the
    # draft) — and once the author names the established file for what it measures, the id no
    # longer echoes the coined `query_id`, so `covers:` is the only thing left tying the two
    # together. Without this half, every promoted or discarded draft is re-minted the next time
    # a run coins its id, and the author spends a tick discarding it again.
    by_id = {t.id for t in catalog} | {c for t in catalog for c in t.covers}
    created: list[Path] = []
    for lead in _mint_order(executed):
        # `is_sentinel` explicitly, not by the id alphabet. A `∅.`-prefixed row is a writer-only
        # record of something that never reached a system (a refused repeat, a failed shim), and
        # it happens to fall out of `_draft_candidate_segments` because `∅` fails the leading
        # `[A-Za-z0-9]`. That is an accident of the guard's alphabet, not a decision about
        # sentinels; the projection already carries the predicate it was partitioned on (#841),
        # so the mint asks the same question the projection answered.
        if lead.is_sentinel:
            continue
        qid = lead.query_id
        segs = _draft_candidate_segments(qid, lead.verb, by_id, row_system=lead.system)
        if segs is None:
            continue
        system, suffix = segs
        if system not in systems:
            # M4/FK-3: site 3, the host-side writer, is reachable TODAY — a mkdir+write_text
            # from a model-supplied query_id, before the agent is ever spawned. Refused and
            # REPORTED (O3 mints this surface; there is none today).
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
            # `guarded_mkdir` + `write_atomic`, not `mkdir` + `write_text`. Two properties, and
            # the mint had neither: the write is now ATOMIC, so a crash or a full disk mid-write
            # cannot leave a truncated draft (which is a draft whose frontmatter no longer
            # parses — reported by every reader as "the minter wrote a bad file" rather than as
            # a partial write); and both halves refuse a planted symlink instead of following
            # it, which is the #771 M3 seam every other host-side writer into a shared tree
            # already routed through. `write_atomic` stages under an UNPREDICTABLE name
            # (`_io.stage_name`), which a hand-rolled `<name>.tmp` beside the target does not.
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
        except OSError:
            continue
    return created
