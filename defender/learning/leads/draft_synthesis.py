#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._scaffold_rules import placeholders
from defender.learning.core import config as _loop_config
from defender.learning.leads import lead_neighbors
from defender.learning.leads.path_validation import (
    CATALOG_DIR,
    CATALOG_REL,
    _is_draft_readme,
    _is_schema_md,
)
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

    The engine body param is excluded: its VALUE became the fenced `## Query` body
    (`_executed_query`), so naming it as a param bound by a `${placeholder}` would describe a
    file that does not exist.
    """
    body_param = body_param_for(lead.system, lead.verb)
    return sorted(n for n in (lead.params or {}) if n != body_param)


def _draft_frontmatter(
    query_id: str, verb_name: str, params: list[str], engine: str, body_subs: list[str],
) -> str:
    """Rendered through `yaml.safe_dump`, not an f-string: every value here comes off the queries
    table, and a frontmatter block a model-coined value can break is a draft that never parses
    again (#852 F-21, the same failure the id guard exists for). The dump quotes what needs
    quoting instead of trusting the guards upstream to be the only line."""
    doc: dict[str, object] = {"id": query_id, "status": "draft", "verb": verb_name}
    if engine != "none":
        doc["engine"] = engine
    doc["params"] = params
    if body_subs:
        doc["body_substitutions"] = body_subs
    return yaml.safe_dump(
        doc, sort_keys=False, allow_unicode=True, default_flow_style=None
    ).strip()


def _body_substitutions(query_block: str, params: list[str]) -> list[str]:
    """The `${name}`s the rendered `## Query` actually carries that are NOT declared params.

    A param-only verb's minted body holds literal VALUES, never `${placeholder}`s — so a
    `${…}` reaching here came out of a bound value (`host: web-${env}-1`) or out of an engine
    body's own query language. Either way it is body text, which is exactly what
    `body_substitutions:` means in `SCHEMA.md`, and declaring it is what keeps the mint
    conformant to the rule the corpus-wide sweep runs (#901). Left undeclared, one such value
    mints a draft the sweep refuses — and the lane's commit gate deliberately does not check
    `_draft/`, so the refusal lands in CI on everyone rather than on the batch that wrote it.

    Classified through `_scaffold_rules.placeholders`, the CHECKER's own reader, rather than
    against a second copy of its regex here: a writer that classifies by a near-miss of the
    grammar it is writing for is the drift this issue is about.
    """
    declared = set(params)
    return sorted(placeholders(query_block) - declared)


def _draft_skeleton(
    query_id: str, verb_name: str, params: list[str], goal: str, record: str, engine: str,
) -> str:
    query_block = _render_query_body(record, engine if engine != "none" else "query")
    # `split()`, not `replace("\n", " ")`: the reader this line has to survive is
    # `_corpus.section_bodies`, which walks `body.splitlines()` — and that splits on `\r`,
    # `\v`, `\f`, `\x1c`-`\x1e`, `\x85` and `\u2028`/`\u2029` as well as on `\n`. A
    # model-authored `goal_text` carrying any of them opened a new LINE in the draft, so a `## `
    # heading or a ``` fence smuggled into a goal re-partitioned the template's sections and
    # could swallow `## Query` whole. Every one of those separators is `str.isspace()`, which
    # is exactly what a bare `split()` breaks on, so one call neutralizes the set (#852 F-21's
    # argument about a control character in an id, applied to the other model-supplied string
    # this skeleton interpolates).
    goal_line = " ".join((goal or "").split()) or "(no lead goal recorded)"
    body_subs = _body_substitutions(query_block, params)
    return (
        f"---\n{_draft_frontmatter(query_id, verb_name, params, engine, body_subs)}\n---\n\n"
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
    query_id: str, verb_name: str, by_id: set[str], *, row_system: str,
) -> tuple[str, str] | None:
    if not query_id or "." not in query_id or query_id in by_id:
        return None
    system, suffix = query_id.split(".", 1)
    if not system or not suffix or suffix == verb_name:
        return None
    # The id's routing prefix must BE the system the row reached. `resolve_query_id` returns a
    # model-coined `query_id` verbatim once it clears the reserved/traversal screen, so nothing
    # upstream ties the prefix to `system`: a call that ran against `cmdb` under the coined id
    # `ghost.something` would otherwise mint `queries/ghost/_draft/something.md` — a catalog
    # directory for a system no adapter declares (the phantom-system class, #855 F-06), whose
    # `verb:`/`engine:` were resolved against `cmdb` and which the corpus-wide scaffold sweep
    # cannot even evaluate (it raises `ScaffoldRuleError` rather than reporting a finding).
    # The row is not lost: this predicate is shared with `collect_general_failures`, so a
    # rejected row lands in the pitfalls residue instead.
    if system != row_system:
        return None
    # The VERB is held to the same alphabet as the id segments, because a draft now DECLARES it
    # (`verb:` frontmatter, #901) and a declaration nothing can resolve is worse than no draft:
    # the corpus-wide check refuses it, so a junk verb on one row would fail the whole lane's
    # next commit. A row this rejects is not lost — the predicate is shared with
    # `collect_general_failures`, so it lands in the pitfalls residue instead.
    if not _SAFE_ID_SEGMENT.match(verb_name or ""):
        return None
    if not _SAFE_ID_SEGMENT.match(system) or not _SAFE_ID_SEGMENT.match(suffix):
        return None
    # …and the BASENAME the mint would take must not be one the commit gate refuses by
    # DISCARDING the batch. `resolve_query_id`'s kebab segment admits `SCHEMA`, `README` and
    # `execution` like any other name, so a coined `{system}.SCHEMA` mints
    # `queries/{system}/_draft/SCHEMA.md` — which `_is_schema_md` calls a protected surface at
    # ANY depth under the catalog — and `{system}.README` / `{system}.execution` land on
    # `_is_draft_readme` and `_skills_path_rule`'s basename rule the same way. Each costs the
    # whole tick's batch, from a model-coined id, before the agent is even spawned. #772 closed
    # exactly these three on the AGENT's write lane; this is the host-side minter, the other
    # writer of the same paths, held to the same set — through the gate's OWN predicates rather
    # than a second copy of the name list.
    minted = f"{CATALOG_REL}{system}/_draft/{suffix}.md"
    if _is_schema_md(minted) or _is_draft_readme(minted) or Path(minted).name == "execution.md":
        return None
    return system, suffix


def synthesize_drafts(
    executed: list[ExecutedLead], *, catalog_dir: Path = CATALOG_DIR,
    catalog: list | None = None, systems: frozenset[str],
) -> list[Path]:
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    by_id = {t.id for t in catalog}
    created: list[Path] = []
    for lead in executed:
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
                _draft_skeleton(
                    qid, lead.verb, _draft_params(lead), lead.goal_text, record, engine,
                ),
                encoding="utf-8",
            )
            created.append(draft)
            by_id.add(qid)
        except OSError:
            continue
    return created
