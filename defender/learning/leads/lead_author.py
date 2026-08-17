#!/usr/bin/env python3
from __future__ import annotations

import argparse
import functools
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any
from uuid import uuid4

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import shared as _author_shared
from defender import _corpus
from defender import _git
from defender import _scaffold_rules
from defender._untrusted import wrap
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
from defender.learning.pipeline._prompt import stage_user_message, structured_json_body
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
    _log,
    _loop_commit_body,
    _spawn_author_agent,
    _verify_corpus_scope,
)


QUEUE_LOCK_FILE = PENDING_DIR / ".lock"

#: What `run` returns when it did NOT serve because another lead-author tick holds the queue
#: lock. Distinct from 0 because the drain's next move is to delete the request it just
#: served: a skip reported as a completed serve deleted every marker the pass had claimed —
#: the whole queued batch gone, no work done, no dead letter, no retry (#852 F-03). Distinct
#: from 2 because it is not a fault: the request is intact and the next tick serves it.
QUEUE_LOCK_SKIP_RC = 3
LEAD_AUTHOR_PROMPT = LEARNING_DIR / "leads" / "lead_author.md"


def _lift_threshold() -> int:
    return _loop_config.env_int("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", 5)




def acquire_queue_lock() -> Any:
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




def _templates_by_identity(catalog: list) -> dict:
    """`{identity -> template}` over both the ids templates HAVE and the ids they COVER.

    A queries-table row carries the coined `query_id` gather dispatched under, and that stopped
    being any template's `id:` when the mint began deriving a draft's name from it. Indexed on
    `id` alone, the draft this tick just minted does not resolve, `build_handoff` drops the row
    as an unresolved contract violation, and the author is handed nothing about the one file
    the tick was spawned to curate.

    `setdefault` so a real `id:` always beats an alias, and so the first template in catalog
    order wins if two ever claim the same identity.
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
            # Not a contract violation and not this collector's row: a `∅.`-prefixed sentinel
            # records something the defender did NOT run, and it is routed to the pitfalls
            # residue by construction (#823). Before #841 it fell to the WARN below, which
            # said "runtime contract violation" about the one row shape the runtime is
            # supposed to write — one line of noise per refusal, in the log an operator reads
            # to find real catalog drift.
            continue
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
            if engine_for(lead.system, lead.verb) != "none":
                rendered_query = _executed_query(lead)
            else:
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


def discover_system_drafts(
    *, skills_dir: Path = SKILLS_DIR, systems: frozenset[str],
) -> list[Path]:
    """FK-4's fourth composition site: walks every child of `skills_dir` and skips any
    directory `systems` (this lane's UNION, NF2) does not declare, so an undeclared `_draft/`
    never becomes work the agent is instructed to do and the commit gate then refuses.

    Every skip is reported (O3, phase F): a skipped directory reads from the outside exactly
    like a tree that had none, so a silent skip is a refusal with no trace."""
    out: list[Path] = []
    if not skills_dir.is_dir():
        return out
    for system_dir in sorted(skills_dir.iterdir()):
        if not system_dir.is_dir():
            continue
        if system_dir.name not in systems:
            _log(
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
        wrap(context, "lead_author_context", stage_salt),
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




def _membership_segment(path: str) -> str:
    """The segment the rule keys membership on (F2's two-key reading): catalog paths key on
    the segment after `queries/`, hopping over `_draft`; system-skill and system-draft paths
    key on the segment after `defender/skills/`."""
    rest = path[len(CATALOG_REL):] if _is_catalog_path(path) else path[len(SKILLS_REL):]
    return rest.split("/", 1)[0]


def _frontmatter_id(repo_root: Path, path: str) -> str | None:
    from defender._frontmatter import parse_frontmatter_or_none

    full = repo_root / path
    if not full.is_file():
        return None
    fm = parse_frontmatter_or_none(full.read_text(encoding="utf-8"))
    if not fm:
        return None
    value = fm.get("id")
    return value if isinstance(value, str) and value else None


def _refuse(path: str, findings: list[_scaffold_rules.Finding]) -> None:
    if not findings:
        return
    detail = "; ".join(f.message for f in findings)
    raise LeadAuthorError(
        f"agent wrote {path}, which is not well-formed ({detail}); refusing to commit"
    )


def _check_promoted_template(
    repo_root: Path, resolver: _scaffold_rules.VerbResolver, path: str,
) -> None:
    """The content half of the promotion gate (#901).

    `connect`'s invariants were enforced once, by a maintainer, at scaffold time — and
    `validate_scaffold` excluded `_draft/`, which is the only directory this lane mints into. So
    the lane that writes this tree continuously was the lane no content check reached, and a
    template whose `${placeholder}` is not a param its verb declares was refused by nothing.

    Fires at PROMOTION, the same seam the half-promote guard below sits at, and not at the
    lane's `_draft/` writes: a draft is auto-minted from a query that really ran, and refusing
    the batch over one would discard signal the loop wanted. What makes that split safe is that
    the minter now emits a conformant skeleton (`draft_synthesis._draft_frontmatter`), so a
    promotion starts from a file that already passes this.
    """
    template, reason = _corpus.read_query_template(repo_root / path)
    if template is None:
        raise LeadAuthorError(
            f"agent wrote {path}, which is not a readable query template ({reason}); "
            "refusing to commit"
        )
    try:
        verbs = resolver.verbs(template.system)
    except _scaffold_rules.ScaffoldRuleError as e:
        # NOT a skip. A template under a system with no importable adapter is the phantom-system
        # class (#855 F-06) wearing a catalog path, and "could not check" silently accepted is
        # the exact defect this gate closes.
        raise LeadAuthorError(
            f"agent wrote {path}, whose system could not be resolved ({e}); refusing to commit"
        ) from e
    _refuse(path, _scaffold_rules.check_template(template, verbs))


def _skills_content_rule(
    repo_root: Path, resolver: _scaffold_rules.VerbResolver, xy: str, path: str,
) -> None:
    """The content half of the gate, split out from the path half above it.

    Both halves grew independently (#869 gave the path half its membership and identity rules,
    #901 gave the gate a content half at all) and together they overran one function's budget.
    The seam is the honest one: everything above answers "may the agent touch this path", and
    everything here answers "is what it wrote well-formed" — which is why only this half needs
    the resolver, and why it runs last, on paths the path half has already admitted.
    """
    if _is_catalog_path(path) and not _under_draft(path) and not _is_schema_md(path):
        twin = _draft_twin(path)
        if (repo_root / twin).exists():
            raise LeadAuthorError(
                f"half-promote: established template {path} was written but its draft "
                f"twin {twin} still exists; refusing to commit (the promote's `rm` "
                "didn't happen — established + draft would both land)"
            )
        # After the pair check and only on a file that is still there: a delete has already been
        # refused by the path half, and a content rule cannot read a path git says is gone.
        #
        # `_is_catalog_template`, not `_is_catalog_path`: the content rule reads a file as a
        # TEMPLATE, and the catalog also holds files that are not one (a `{system}/README.md`,
        # a note at the catalog root). Judging those by the template rule refuses them for a
        # reason that is not their defect — "no `id:`", or a system named `queries`.
        if "D" not in xy and (repo_root / path).is_file() and _is_catalog_template(path):
            _check_promoted_template(repo_root, resolver, path)
    if _is_system_skill_md(path) and "D" not in xy and (repo_root / path).is_file():
        _refuse(
            path,
            _scaffold_rules.check_system_skill(repo_root / path, Path(path).parent.name),
        )


def _skills_path_rule(repo_root: Path, xy: str, path: str, *, systems: frozenset[str]) -> None:
    # `execution.md`, at ANY depth under `defender/skills`, is the one per-system file this
    # lane can never get committed (C32/F1) — under NF1 the marker's integrity IS the commit
    # gate, so this keys on the BASENAME rather than on which in-scope form owns the path.
    if Path(path).name == "execution.md":
        raise LeadAuthorError(
            f"agent wrote {path}; refusing to commit (execution.md is not "
            "agent-committable at any depth)"
        )
    if not _is_in_scope(path):
        raise LeadAuthorError(
            f"agent edited an out-of-scope skills path ({path}); refusing to commit"
        )
    if _is_draft_readme(path) or _is_schema_md(path):
        raise LeadAuthorError(
            f"agent mutated a protected surface file ({path}); refusing to commit"
        )
    # M5/RF2/FK-16: membership fires BEFORE the delete-prohibition, so a `D` record under an
    # undeclared directory is reported by NAME with the registry reason, never absorbed into
    # a deletion complaint about a directory that should never have been written to.
    system = _membership_segment(path)
    if system not in systems:
        raise LeadAuthorError(
            f"agent wrote {path} under an undeclared system ({system!r}); refusing to commit"
        )
    if "D" in xy and not (_under_draft(path) or _is_system_skill_draft(path)):
        raise LeadAuthorError(
            f"agent deleted an established template / SKILL.md ({path}); refusing to "
            "commit (delete-prohibition; a demotion is rejected the same way)"
        )
    # RF2: the frontmatter `id:` prefix must agree with the directory it sits in, closing the
    # CONTENT channel alongside the directory channel — an idless in-scope file (a system
    # `SKILL.md`, `SCHEMA.md`) is spared (NF3).
    ident = _frontmatter_id(repo_root, path)
    if ident is not None and ident.split(".", 1)[0] != system:
        raise LeadAuthorError(
            f"agent wrote {path} with id {ident!r} disagreeing with its directory "
            f"({system!r}); refusing to commit"
        )


def _skills_rule(
    repo_root: Path,
    resolver: _scaffold_rules.VerbResolver,
    xy: str,
    path: str,
    *,
    systems: frozenset[str],
) -> None:
    """The whole per-path gate: the path half, then the content half on what it admitted.

    Composed rather than folded into one function because the two halves ask different
    questions and arrived from different changes (#869, #901) — and because the content half
    must not read a path the path half has already refused.
    """
    _skills_path_rule(repo_root, xy, path, systems=systems)
    _skills_content_rule(repo_root, resolver, xy, path)


def _template_at_head(repo_root: Path, path: str) -> _corpus.QueryTemplate | None:
    """The template `path` was at HEAD, or `None` if HEAD did not carry it or it did not parse.

    A `None` for an unparseable pre-image is deliberate and it fails OPEN. Everything this
    answers is a question about what the agent's edit DID to a file, and a pre-image the corpus
    reader cannot parse is one no invariant was holding before this batch either — refusing the
    commit over it would punish the author for the state of the tree they were handed."""
    text = _git.git_show_head(repo_root, path)
    if text is None:
        return None
    template, _reason = _corpus.parse_query_template(text, repo_root / path)
    return template


#: The mint wrote nothing this tick — the default for every caller of the gate that is not
#: `_run_locked` (the tests that drive it directly, and any future one). A frozen mapping
#: rather than a `None` the body re-coalesces, and rather than a `{}` literal default.
_NO_MINTED: Mapping[Path, tuple[str, ...]] = MappingProxyType({})


def _minted_identities(created: list[Path]) -> Mapping[Path, tuple[str, ...]]:
    """`{draft path -> the identities it records}` for the drafts THIS tick's mint wrote.

    Read HERE, between the mint and the agent, because after the agent runs the answer may no
    longer be on disk — and for a freshly minted draft there is nowhere else to get it. A draft
    an EARLIER tick committed departs as a `D` porcelain record whose identities come out of
    `git show HEAD:…`; a draft this tick minted is untracked, so deleting it before the commit
    leaves git no record and no pre-image at all. That is not the corner case: `_run_locked`
    mints and then hands the same draft to the author in the same tick (the catalog is reloaded
    after the mint precisely so it resolves), so a bare discard of a just-minted draft is the
    common shape of the failure `_covers_rule`'s transfer half exists to refuse.
    """
    out: dict[Path, tuple[str, ...]] = {}
    for path in created:
        template = _corpus.read_query_template(path)[0]
        if template is not None and template.covers:
            out[path] = template.covers
    return out


def _covered_by_established(repo_root: Path) -> set[str]:
    """Every identity an ESTABLISHED template in the tree accounts for once this batch lands.

    Read off the working tree, so it already includes whatever the agent just wrote. The
    transfer rule below is about one question — "will this identity be re-minted next run?" —
    and `synthesize_drafts` answers it from the whole catalog, not from one batch's diff. Scored
    against the batch alone, a draft whose identity a template took over in an EARLIER tick is
    refused for a delete that costs nothing, and the refusal discards the tick's whole batch.
    """
    covered: set[str] = set()
    for path in sorted((repo_root / CATALOG_REL).glob("*/*.md")):
        template = _corpus.read_query_template(path)[0]
        if template is not None:
            covered.update(template.covers)
    return covered


def _refuse_half_promote(repo_root: Path, taken_over: set[str]) -> None:
    """The other side of transfer: an identity may not land on an established template while the
    draft that recorded it is still on disk.

    This is `_skills_content_rule`'s half-promote probe, re-aimed at `covers:` for the same
    reason the transfer rule exists at all. That probe derives the twin from the BASENAME
    (`_draft_twin`), and a promote stopped sharing one the moment the draft's name became a
    digest and the established file's name became the author's — so it can no longer see the
    failure it was written for: established + draft both landing because the promote's `rm`
    never happened. The surviving draft is unchanged, so no `git status` record carries it;
    only a filesystem probe can.
    """
    if not taken_over:
        return
    for path in sorted((repo_root / CATALOG_REL).glob("*/_draft/*.md")):
        template = _corpus.read_query_template(path)[0]
        if template is None:
            continue
        if stranded := sorted(set(template.covers) & taken_over):
            rel = path.relative_to(repo_root).as_posix()
            raise LeadAuthorError(
                f"half-promote: draft {rel} still exists, but the identities it records "
                f"({stranded}) were taken over by an established template in this batch; "
                "refusing to commit (the promote's / widen's `rm` didn't happen — established "
                "+ draft would both land, and the draft is handed back as work every tick "
                "until it is removed)"
            )


def _departed_drafts(
    repo_root: Path,
    minted: Mapping[Path, tuple[str, ...]],
    records: list[tuple[str, str]],
) -> list[tuple[str, tuple[str, ...]]]:
    """`(path, identities)` for every draft that is no longer in the tree — from the TWO places
    a departure can be read, because a draft has two provenances.

    A draft an earlier tick committed departs as a `D` porcelain record, and its identities come
    out of its HEAD pre-image. A draft this tick minted has neither: the mint writes it
    untracked, so removing it before the commit leaves `git status` nothing to report and `git
    show HEAD:` nothing to parse. Those identities are captured at mint time instead
    (`_minted_identities`) and carried in — without this half the transfer rule is inert for
    exactly the batch it was written for, since the tick that mints a draft is the tick that
    hands it to the author.
    """
    out: list[tuple[str, tuple[str, ...]]] = []
    for xy, path in records:
        # The draft half, spelled with `_under_draft` rather than `_is_catalog_template`:
        # that predicate EXCLUDES drafts, so the two together admit nothing. The catalog's own
        # non-template surfaces are still screened off — a `_draft/README.md` and a `SCHEMA.md`
        # are protected files the path rule has already refused, and neither carries `covers:`.
        if "D" not in xy or not _under_draft(path):
            continue
        if _is_draft_readme(path) or _is_schema_md(path):
            continue
        draft = _template_at_head(repo_root, path)
        if draft is not None and draft.covers:
            out.append((path, draft.covers))
    # A distinct name, not a rebinding of `path` above: that one is the repo-relative `str` git
    # reports, this one is the absolute `Path` the mint returned, and reusing the name made the
    # two look interchangeable when the whole point of the loop below is that they are not.
    for draft_path, identities in minted.items():
        if draft_path.exists():
            continue
        rel = (
            draft_path.relative_to(repo_root).as_posix()
            if draft_path.is_relative_to(repo_root) else str(draft_path)
        )
        out.append((rel, identities))
    return out


def _covers_rule(
    repo_root: Path,
    minted: Mapping[Path, tuple[str, ...]],
    records: list[tuple[str, str]],
) -> None:
    """The two whole-batch invariants on `covers:` — the identities a template accounts for.

    Both exist because the draft's basename stopped being derivable from its content. While a
    promote was `_draft/{id}.md` -> `{id}.md`, the shared basename WAS the link: `_draft_twin`
    derived one from the other, and `synthesize_drafts` suppressed a re-mint because the
    promoted template's `id` still echoed the coined `query_id`. Now the author names the
    established file for what it measures, so `covers:` is the only thing tying the two
    together, and it has to be carried rather than merely encouraged.

    **Transfer.** A draft that leaves the tree must have its identities land somewhere. Both
    dispositions `lead_author.md` gives satisfy this — a promote writes them onto the new file,
    a discard-into-widen adds them to the template it widened. What it refuses is the bare
    discard, and the refusal names the alternative: a draft you cannot attribute to any
    template is one to SKIP, not to delete. Unenforced, the omission is silent and self-
    repeating — the identity is re-minted the next time a run coins it, the author discards it
    again, and nothing in the loop ever reports that it is going in circles. Scored against the
    whole tree (`_covered_by_established`) rather than against this batch's edits, because the
    question is the one `synthesize_drafts` will ask next run and it reads the whole catalog.
    Both provenances of a departed draft are read — the committed one out of git, the one this
    tick minted out of `minted`, which git cannot see (`_departed_drafts`). Its mirror is
    `_refuse_half_promote`: an identity that lands on a template while its draft is still on
    disk is the takeover half-done.

    **Monotonicity.** An established template may gain identities and may never lose them, and
    its `id:` may not change under an edit. This is the collision detector: the write lane
    admits any `{system}/{name}.md`, and overwriting an established template is a legal FOLD, so
    an author who picks a name that already exists does not get an error today — it silently
    replaces a different measurement, taking that template's own `covers:` down with it. Losing
    provenance is the observable that separates a clobber from a widen, and it is the one the
    clobbered template's future re-mints depend on.
    """
    # `_is_catalog_template` is already draft-excluding (it is the predicate the content rule
    # uses to decide what may be READ as a template), so this is the established half by
    # construction — no second `_under_draft` test, which would read as though it were adding a
    # condition the predicate does not already carry.
    established = [p for xy, p in records if "D" not in xy and _is_catalog_template(p)]
    # The identities this batch moved ONTO an established template — `after` minus `before`, not
    # `after`, so the half-promote probe below fires on a takeover and never on a template that
    # already accounted for the identity before the agent was spawned.
    taken_over: set[str] = set()
    for path in established:
        after = _corpus.read_query_template(repo_root / path)[0]
        if after is None:
            # Its own refusal already, from `_check_promoted_template` on the per-path pass.
            continue
        before = _template_at_head(repo_root, path)
        _refuse_lost_provenance(path, before, after)
        taken_over.update(set(after.covers) - set(before.covers if before is not None else ()))

    # The tree walk is behind the `if`: `_covered_by_established` parses every established
    # template in the catalog, and the question it answers is only ever asked about a draft
    # that left. A batch that deleted none pays nothing.
    if departed := _departed_drafts(repo_root, minted, records):
        covered = _covered_by_established(repo_root)
        for path, identities in departed:
            if orphaned := sorted(set(identities) - covered):
                raise LeadAuthorError(
                    f"agent deleted draft {path} without attributing it: {orphaned} is covered "
                    "by no established template; refusing to commit (a promote carries "
                    "`covers:` onto the new file and a discard-into-widen adds it to the "
                    "template it widened — a draft that fits neither is one to leave alone and "
                    "SKIP, because deleting it here only means minting it again next run)"
                )

    _refuse_half_promote(repo_root, taken_over)


def _refuse_lost_provenance(
    path: str, before: _corpus.QueryTemplate | None, after: _corpus.QueryTemplate,
) -> None:
    """The monotonicity half of `_covers_rule`, on ONE established template.

    Split out for its own sake as much as for the complexity budget: this is the only part of
    the rule that compares a file against its own pre-image, and reading it beside the
    batch-wide accumulation above made two different questions look like one loop. The
    pre-image is passed IN rather than read here, because the caller needs it too — reading it
    twice is a second `git show` per changed template for an answer that cannot have moved.
    """
    if before is None:
        return
    if before.id != after.id:
        raise LeadAuthorError(
            f"agent rewrote the identity of an established template ({path}): it was "
            f"{before.id!r} at HEAD and is {after.id!r} now; refusing to commit (a promote "
            "writes a NEW file — an edit that replaces an existing template's `id:` is a "
            "name collision that has silently overwritten a different measurement)"
        )
    if lost := sorted(set(before.covers) - set(after.covers)):
        raise LeadAuthorError(
            f"agent dropped `covers:` entries from an established template ({path}): "
            f"{lost}; refusing to commit (a template may gain the identities it accounts "
            "for and may never lose them — every dropped entry is a query_id that will be "
            "re-drafted on the next run that coins it)"
        )


def _verify_skills_state(
    repo_root: Path, baseline_stray: list[str], *, systems: frozenset[str],
    minted: Mapping[Path, tuple[str, ...]] = _NO_MINTED,
) -> list[str]:
    # ONE resolver for the whole batch, built on the tree being committed rather than on the
    # process's own: the drain runs this from the main checkout against a `lead-author/<id>`
    # worktree, and `_load_adapter_module` keys its cache on the resolved absolute path, so this
    # is what makes the verdict a statement about the commit it is about to make.
    resolver = _scaffold_rules.VerbResolver(repo_root / "defender")
    return _verify_corpus_scope(
        repo_root, baseline_stray, actor="agent",
        rule=functools.partial(_skills_rule, repo_root, resolver, systems=systems),
        batch_rule=functools.partial(_covers_rule, repo_root, minted),
    )


def _loop_commit_message(run_dir: Path, changed: list[str]) -> str:
    has_catalog = any(_is_catalog_path(p) for p in changed)
    has_skill = any(_is_system_skill_md(p) or _is_system_skill_draft(p) for p in changed)
    if has_catalog and has_skill:
        scope = "gather catalog + system skills"
    elif has_skill:
        scope = "system skills"
    else:
        scope = "gather catalog"
    return _loop_commit_body(
        f"learning(lead-author): {scope} for {run_dir.name}",
        "Curated by the lead author; loop-committed (the agent runs no git).",
        changed,
        trailer=f"\nsource-run: {run_dir.name}\n",
    )




def _state_dir(run_dir: Path) -> Path:
    return run_dir / "lead_author"


def _done_sentinel(run_dir: Path) -> Path:
    return _state_dir(run_dir) / "done"


def _write_state(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")




@dataclass(frozen=True)
class LeadAuthorDeps:
    paths: _loop_config.LoopPaths
    #: The UNION (adapter glob ∪ committed marker, NF2) resolved ONCE at the boundary — before
    #: the agent is ever spawned — and threaded non-Optional into every path-composition
    #: consumer on this lane (M2). Never re-derived by any consumer (`consumers_do_not_
    #: rederive`).
    systems: frozenset[str]
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
    from defender.learning.leads.declared_systems import declared_systems

    systems = declared_systems(paths.repo_root)
    return LeadAuthorDeps(
        paths=paths,
        systems=systems,
        invoke_agent=functools.partial(invoke_agent, repo_root=paths.repo_root),
        extract=extract,
        synthesize=synthesize_drafts,
        build_handoff=functools.partial(
            build_handoff, repo_root=paths.repo_root, catalog_dir=paths.catalog_dir
        ),
        discover_system_drafts=functools.partial(
            discover_system_drafts, skills_dir=paths.skills_dir, systems=systems
        ),
        acquire_queue_lock=acquire_queue_lock,
        release_queue_lock=release_queue_lock,
    )


def run(
    run_dir: Path,
    *,
    paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS,
    deps: LeadAuthorDeps | None = None,
    box: Any = None,
) -> int:
    if not run_dir.is_dir():
        _log(f"FATAL: run_dir not found: {run_dir}")
        return 2

    # The lock is checked BEFORE `deps` is built when the caller supplied none: resolving
    # membership (#869) is real subprocess work, and a tick that is about to skip on a
    # contended lock should not pay for it, nor fail hard on a tree the resolver cannot yet
    # read (#852 F-03 — a skip must never present as anything but the skip rc).
    if deps is not None:
        queue_lock = deps.acquire_queue_lock()
        if queue_lock is None:
            return QUEUE_LOCK_SKIP_RC
        try:
            return _run_locked(run_dir, deps, box=box)
        finally:
            deps.release_queue_lock(queue_lock)

    queue_lock = acquire_queue_lock()
    if queue_lock is None:
        return QUEUE_LOCK_SKIP_RC
    try:
        deps = build_lead_author_deps(paths)
        return _run_locked(run_dir, deps, box=box)
    finally:
        release_queue_lock(queue_lock)


def _run_locked(run_dir: Path, deps: LeadAuthorDeps, *, box: Any = None) -> int:
    if _done_sentinel(run_dir).is_file():
        _log("already processed (done sentinel exists) — nothing to do")
        return 0

    if not deps.systems:
        # RF6, at this lane's own boundary: an empty declared set is not spendable as an
        # ordinary membership "no" — that would refuse every path one at a time and the tick
        # would report a clean no-op, which is precisely the failure O4 names. Refused loudly,
        # before the agent is ever spawned and regardless of what work this tick would
        # otherwise have found.
        raise LeadAuthorError(
            f"lead-author refused: {deps.paths.repo_root} declares no systems (empty "
            "adapter glob and no committed execution.md); refusing to run the lane"
        )

    try:
        joined_leads, executed = deps.extract(run_dir)
    except (FileNotFoundError, ValueError) as e:
        _log(f"FATAL: cannot extract leads: {e}")
        return 2

    catalog = lead_neighbors.load_catalog(deps.paths.catalog_dir)

    synth = deps.synthesize(
        executed, catalog_dir=deps.paths.catalog_dir, catalog=catalog, systems=deps.systems,
    )
    if synth:
        _log(
            f"synthesized {len(synth)} draft(s) for uncatalogued verbs: "
            + ", ".join(p.name for p in synth)
        )
    # Captured between the mint and the agent: these drafts are UNTRACKED, so if the agent
    # removes one the commit gate has neither a `git status` record nor a HEAD pre-image to
    # recover the identities it recorded (`_departed_drafts`).
    minted = _minted_identities(synth)

    collected_marker = _state_dir(run_dir) / "pitfalls_collected"
    if not collected_marker.is_file():
        failures = collect_general_failures(
            executed, run_dir, catalog_dir=deps.paths.catalog_dir, catalog=catalog
        )
        if failures:
            _loop_persist.append_pitfalls(failures, paths=deps.paths)
            # Both numbers: the failures are what the run did, the distinct count is how many
            # mistakes THIS RUN made once its repeats collapse (#840) — not what the curation
            # threshold will see, which merges this run's rows against every row already
            # queued. A lead that loops makes the gap large, and that gap is the signal.
            distinct = len(_loop_persist.merge_pitfalls(failures))
            _log(
                f"collected {len(failures)} general failure(s) into the queue "
                f"({distinct} distinct mistake(s) in this run)"
            )
        _write_state(collected_marker, _loop_config.now_iso() + "\n")

    repo_root = deps.paths.repo_root
    baseline_stray = _author_shared.changes_outside(repo_root, SKILLS_REL)

    if synth:
        catalog = lead_neighbors.load_catalog(deps.paths.catalog_dir)
    handoffs, pending_drafts, rc = _prepare_handoffs(
        run_dir, deps, executed, joined_leads, catalog=catalog
    )
    if rc is not None:
        return rc
    _log(
        f"built {len(handoffs)} executed-template handoff(s) and "
        f"{len(pending_drafts)} pending system-skill draft(s)"
    )

    rc = deps.invoke_agent(run_dir, handoffs, pending_drafts, box=box)
    if rc != 0:
        _log(f"FATAL: lead-author spawn exited rc={rc}; see the trace under {run_dir} (drain will quarantine)")
        return 2

    changed = _verify_skills_state(
        repo_root, baseline_stray, systems=deps.systems, minted=minted
    )
    sha = _author_shared.commit_corpus(
        repo_root, repo_root / "defender" / "skills",
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
    *, catalog: list | None = None,
) -> tuple[list, list, int | None]:
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
        handoffs = deps.build_handoff(run_dir, executed, joined_leads, catalog=catalog)
    except LeadAuthorError as e:
        _log(f"FATAL: cannot build handoffs: {e}")
        return [], [], 2

    if not handoffs and not pending_drafts:
        _log(
            f"none of the {len(executed)} extracted lead(s) resolved to a catalog "
            "template (unresolved query_id, or a `∅.` sentinel routed to the pitfalls "
            "residue) and there are no pending drafts — nothing to do"
        )
        _write_state(
            _done_sentinel(run_dir),
            f"commit: none\nat: {_loop_config.now_iso()}\ncommit_made: False\n",
        )
        return [], [], 0

    return handoffs, pending_drafts, None




_HELP_EPILOG = """\
The agent runs no git; the loop commits. Invoked directly this commits onto the
current branch/worktree's HEAD — in production the lead-author drain
(``loop.py --lead-author-drain``) runs it inside a fresh ``lead-author/<id>``
worktree and opens the PR.

Preconditions
  * No other lead-author tick may be running (per-author queue lock at
    defender/learning/_pending_leads/.lock). Violating it is not silent: this returns
    rc=3 without serving, and the drain puts the request back on the queue untouched
    for the next tick rather than counting the skip as a serve.
  * ``<run_dir>/executed_queries.jsonl`` and ``<run_dir>/gather_raw/``
    (the two tables) must exist — written live during the run by
    record_query.py + record_lead.py.

State files written under ``<run_dir>/lead_author/``
  done           sentinel on successful completion; makes the run a no-op.

On a per-run fault this returns rc=2 and the lead-author drain quarantines the run's
marker to the author-queue's ``failed/`` dir (surfaced for a human, not dropped); the
per-spawn RequestLogger trace under the run dir is the diagnostic. (A systemic config
fault — no key / unroutable model / bad effort — propagates from the in-process engine
as exit 2 instead, halting the drain rather than quarantining every marker.)

Environment
  LEAD_AUTHOR_MODEL                          in-process model id (default glm-5.2; any
                                             provider providers.provider_for routes)
  LEAD_AUTHOR_EFFORT                          reasoning effort (default low)
  LEAD_AUTHOR_TIMEOUT_SECONDS                per-spawn wall-clock ceiling (default 1800)
  LEAD_AUTHOR_REQUEST_LIMIT                   tool-loop request cap (default 250)
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
