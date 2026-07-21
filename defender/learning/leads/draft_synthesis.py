#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.leads import lead_neighbors
from defender.learning.leads.path_validation import CATALOG_DIR
from defender.runtime.verbs import body_param_for, engine_for

if TYPE_CHECKING:
    from defender.learning.leads.lead_extraction import ExecutedLead


_SAFE_ID_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

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


def _draft_skeleton(query_id: str, goal: str, record: str, engine: str) -> str:
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
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    by_id = {t.id for t in catalog}
    created: list[Path] = []
    for lead in executed:
        qid = lead.query_id
        segs = _draft_candidate_segments(qid, lead.verb, by_id)
        if segs is None:
            continue
        system, suffix = segs
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
