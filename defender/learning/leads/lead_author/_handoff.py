"""The queue lock, what a handoff contains, and dispatching the agent that acts on it."""
#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import shared as _author_shared
from defender._frontmatter import parse_frontmatter_or_none
from defender._untrusted import wrap
from defender.learning.core import config as _loop_config
from defender.learning._prompt import stage_user_message, structured_json_body
from defender.learning.leads import lead_neighbors
from defender.learning.leads import lead_render
from defender.runtime.verbs import engine_for

from defender.learning.leads.path_validation import (  # noqa: F401  (re-exported)
    CATALOG_DIR,
    CATALOG_REL,
    LEARNING_DIR,
    REPO_ROOT,
    SKILLS_DIR,
    SKILLS_REL,
    _draft_twin,
    _is_catalog_path,
    _is_catalog_template,
    _is_draft_readme,
    _is_in_scope,
    _is_schema_md,
    _is_system_file,
    _is_system_skill_draft,
    _is_system_skill_md,
    _under_draft,
)
from defender.learning.leads.draft_synthesis import (  # noqa: F401  (re-exported)
    _SAFE_ID_SEGMENT,
    _draft_basename,
    _draft_candidate_segments,
    _draft_skeleton,
    _executed_query,
    answered_identities,
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
    _spawn_author_agent,
)

_logger = logging.getLogger(__name__)


#: The per-author queue lock under DEFAULT_PATHS — what the CLI locks. `queue_lock_file(paths)`
#: gives it for any `LoopPaths`, so the drain and a by-hand run contend on one file.
QUEUE_LOCK_FILE = PENDING_DIR / ".lock"

#: What `run` returns when it did not serve because another tick holds the queue lock. Not 0,
#: or the drain would delete the claimed request as served; not 2, since it isn't a fault and
#: the next tick serves it.
QUEUE_LOCK_SKIP_RC = 3
LEAD_AUTHOR_PROMPT = LEARNING_DIR / "leads" / "lead_author.md"  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir


def _lift_threshold() -> int:
    return _loop_config.env_int("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", 5)




def queue_lock_file(paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS) -> Path:
    return paths.lead_pending_dir / ".lock"


def acquire_queue_lock(paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS) -> Any:
    lock = queue_lock_file(paths)
    _logger.debug(f"acquire queue-lock={lock}")
    fh = _author_shared.acquire_flock(lock)
    if fh is None:
        _logger.info("queue-lock held by another tick — skipping")
        return None
    _logger.debug("queue-lock acquired")
    return fh


def release_queue_lock(fh: Any) -> None:
    if fh is None:
        return
    _author_shared.release_flock(fh)
    _logger.debug("release queue-lock")




def _templates_by_identity(catalog: list) -> dict:
    """`{identity -> template}` over both the ids templates have and the ids they cover.

    A queries-table row carries the coined `query_id`, which a just-minted draft records in
    `covers:` rather than `id:`; indexing on `id` alone would drop that row as unresolved.
    `setdefault`, so a real `id:` beats an alias and the first template wins a tie.
    """
    by_id = {t.id: t for t in catalog}
    for template in catalog:
        for covered in template.covers:
            by_id.setdefault(covered, template)
    return by_id


def build_handoff(
    run_dir: Path, executed: list[ExecutedLead], joined_leads: list | None = None,
    *, repo_root: Path = REPO_ROOT, catalog_dir: Path | None = None,
    catalog: list | None = None,
) -> list[dict]:
    if catalog is None:
        catalog = lead_neighbors.load_catalog(catalog_dir)
    by_id = _templates_by_identity(catalog)
    idf = lead_neighbors.build_idf(lead_neighbors._all_query_variants(catalog))

    grouped: dict[Path, list[ExecutedLead]] = {}
    seen_order: list[Path] = []
    for lead in executed:
        if lead.is_sentinel:
            # A sentinel records something the defender didn't run and belongs to the pitfalls
            # residue; skip it quietly rather than warn as catalog drift.
            continue
        tpl = by_id.get(lead.query_id)
        if tpl is None:
            _logger.warning(
                f"unresolved query_id={lead.query_id!r} at lead "
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
            if engine_for(lead.system, lead.verb) != "none":
                rendered_query = _executed_query(lead)
            else:
                try:
                    rendered_query = lead_render.render_query(tpl.path, lead.params)
                except OSError as e:
                    _logger.warning(f"render_query failed for {tpl.path}: {e}")
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




_DRAFT_README_NAMES = frozenset({"README.md", "_TEMPLATE.md"})


def _draft_contradicts_skill(draft: Path) -> bool:
    """True only when `draft`'s frontmatter declares `contradicts_skill: true` — it disagrees
    with a claim already in the system's SKILL.md rather than adding detail. Such a draft
    bypasses `_lift_threshold`, since a SKILL.md that is actively wrong shouldn't wait for
    unrelated drafts to accumulate.

    Opt-in only: missing or unparseable frontmatter, or no key, doesn't bypass.
    """
    try:
        text = draft.read_text(encoding="utf-8")
    except OSError:
        return False
    fm = parse_frontmatter_or_none(text)
    if not fm:
        return False
    return fm.get("contradicts_skill") is True


def discover_system_drafts(
    *, skills_dir: Path = SKILLS_DIR, systems: frozenset[str],
) -> list[Path]:
    """Every draft under a declared system's `_draft/` in `skills_dir`. Undeclared directories
    are skipped (the commit gate would refuse their edits) and each skip is logged."""
    out: list[Path] = []
    if not skills_dir.is_dir():
        return out
    for system_dir in sorted(skills_dir.iterdir()):
        if not system_dir.is_dir():
            continue
        if system_dir.name not in systems:
            _logger.warning(
                f"discover_system_drafts: skipped undeclared directory {system_dir.name!r}"
            )
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
    out: list[dict] = []
    for draft in drafts:
        rel = draft.relative_to(repo_root)
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




def invoke_agent(
    run_dir: Path,
    handoffs: list[dict],
    pending_drafts: list[dict] | None = None,
    *,
    repo_root: Path = REPO_ROOT,
    spawn: Callable[..., int] = _spawn_author_agent,
    salt: str | None = None,
    box: Any = None,
) -> int:
    pending_drafts = pending_drafts or []
    stage_salt = salt if salt is not None else uuid4().hex
    context = (
        f"run_dir: {run_dir}\n"
        f"catalog_dir: {CATALOG_REL}\n"
        f"skills_dir: {SKILLS_REL}"
    )
    user_prompt = stage_user_message(
        stage_salt,
        wrap(context, "lead_author_context", stage_salt),  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
        wrap(structured_json_body(handoffs), "handoffs", stage_salt),
        wrap(
            structured_json_body(pending_drafts),
            "pending_system_drafts",
            stage_salt,
        ),
    )
    return spawn(
        system_prompt_file=LEAD_AUTHOR_PROMPT,
        batch_id=run_dir.name,
        user_prompt=user_prompt,
        repo_root=repo_root,
        learning_run_dir=run_dir,
        log_label="lead author",
        salt=stage_salt, box=box,
    )
