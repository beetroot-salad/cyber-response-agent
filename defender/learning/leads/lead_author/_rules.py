"""The verification rules a produced edit has to survive before it is allowed to land.

Split out of `lead_author.py` at 1017 lines. Each rule is a refusal with a reason, and the
drain treats any of them firing as "revert, do not commit".
"""
#!/usr/bin/env python3
from __future__ import annotations

import functools
import sys
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _corpus
from defender import _git
from defender import _scaffold_rules
from defender.learning.leads import lead_neighbors

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
    _loop_commit_body,
    _verify_corpus_scope,
)


def _membership_segment(path: str) -> str:
    """The segment the rule keys membership on: catalog paths key on the segment after
    `queries/`, hopping over `_draft`; system-skill and system-draft paths key on the
    segment after `defender/skills/`."""
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
    """The content half of the promotion gate: `connect`'s invariants (e.g. every
    `${placeholder}` is a param its verb declares), which `validate_scaffold` does not reach
    because it excludes `_draft/` — the only directory this lane mints into.

    Fires at PROMOTION, the same seam the half-promote guard below sits at, and not at the
    lane's `_draft/` writes: a draft is auto-minted from a query that really ran, and refusing
    the batch over one would discard signal the loop wanted. That split is safe because the
    minter emits a conformant skeleton (`draft_synthesis._draft_frontmatter`), so a promotion
    starts from a file that already passes this.
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
        # NOT a skip. A template under a system with no importable adapter is a phantom system
        # wearing a catalog path, and "could not check" silently accepted is the exact defect
        # this gate closes.
        raise LeadAuthorError(
            f"agent wrote {path}, whose system could not be resolved ({e}); refusing to commit"
        ) from e
    _refuse(path, _scaffold_rules.check_template(template, verbs))


def _skills_content_rule(
    repo_root: Path, resolver: _scaffold_rules.VerbResolver, xy: str, path: str,
) -> None:
    """The content half of the gate, split out from the path half above it.

    Everything above answers "may the agent touch this path", everything here "is what it
    wrote well-formed" — which is why only this half needs the resolver, and why it runs
    last, on paths the path half has already admitted.
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
    # lane can never get committed — the marker's integrity IS the commit gate, so this keys
    # on the BASENAME rather than on which in-scope form owns the path.
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
    # Membership fires BEFORE the delete-prohibition, so a `D` record under an undeclared
    # directory is reported by NAME with the registry reason, never absorbed into a deletion
    # complaint about a directory that should never have been written to.
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
    # The frontmatter `id:` prefix must agree with the directory it sits in, closing the
    # CONTENT channel alongside the directory channel — an idless in-scope file (a system
    # `SKILL.md`, `SCHEMA.md`) is spared.
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
    """The whole per-path gate: the path half, then the content half on what it admitted —
    ordered so the content half never reads a path the path half has already refused.
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

    Read HERE, between the mint and the agent, because afterwards the answer may no longer be
    on disk and there is nowhere else to get it: a draft this tick minted is untracked, so
    deleting it before the commit leaves git neither a porcelain record nor a HEAD pre-image.
    That is the common case, not a corner one — `_run_locked` mints and then hands the same
    draft to the author in the same tick, so a bare discard of a just-minted draft is the
    usual shape of what `_covers_rule`'s transfer half refuses.
    """
    out: dict[Path, tuple[str, ...]] = {}
    for path in created:
        template = _corpus.read_query_template(path)[0]
        if template is not None and template.covers:
            out[path] = template.covers
    return out


def _answered_after_batch(repo_root: Path) -> set[str]:
    """Every identity the catalog answers once this batch lands, through the mint's OWN reader.

    Read off the working tree, so it already includes whatever the agent just wrote. The
    transfer rule below asks exactly one question — "will this identity be re-minted next
    run?" — and the only thing entitled to answer it is the function the mint asks:
    `answered_identities`, ids UNION `covers:`, over the whole catalog (drafts included,
    since a draft can be the wide neighbor). Score against a narrower set and the gate
    discards a whole tick's batch over a delete that costs nothing.
    """
    return answered_identities(lead_neighbors.load_catalog(repo_root / CATALOG_REL))


def _refuse_half_promote(repo_root: Path, taken_over: set[str]) -> None:
    """The other side of transfer: an identity may not land on an established template while the
    draft that recorded it is still on disk.

    `_skills_content_rule`'s half-promote probe derives the twin from the BASENAME
    (`_draft_twin`), which a promote no longer shares: the draft's name is a digest and the
    established file's is the author's. So it cannot see established + draft both landing
    because the promote's `rm` never happened. The surviving draft is unchanged, so no `git
    status` record carries it — only a filesystem probe can.
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
    exactly the batch it was written for.
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
    # reports, this one the absolute `Path` the mint returned — the point of this loop is that
    # they are not interchangeable.
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

    Both exist because a draft's basename is not derivable from its content: the author names
    the established file for what it measures, so `covers:` is the only thing tying draft and
    promoted template together, and it has to be carried rather than merely encouraged.

    **Transfer.** A draft that leaves the tree must have its identities land somewhere. Both
    dispositions `lead_author.md` gives satisfy this — a promote writes them onto the new file,
    a discard-into-widen adds them to the template it widened. What it refuses is the bare
    discard, and the refusal names the alternative: a draft you cannot attribute to any
    template is one to SKIP, not to delete. Unenforced, the omission is silent and self-
    repeating — the identity is re-minted the next time a run coins it, the author discards it
    again, and nothing reports that the loop is going in circles. Scored against the whole tree
    (`_answered_after_batch`) rather than this batch's edits, because that is the question
    `synthesize_drafts` will ask next run. Both provenances of a departed draft are read — the
    committed one out of git, the one this tick minted out of `minted`, which git cannot see
    (`_departed_drafts`). Its mirror is `_refuse_half_promote`: an identity that lands on a
    template while its draft is still on disk is the takeover half-done.

    **Monotonicity.** An established template may gain identities and may never lose them, and
    its `id:` may not change under an edit. This is the collision detector: the write lane
    admits any `{system}/{name}.md` and overwriting an established template is a legal FOLD, so
    an author who picks a name that already exists gets no error — it silently replaces a
    different measurement, taking that template's own `covers:` down with it. Losing provenance
    is the observable that separates a clobber from a widen.
    """
    # `_is_catalog_template` is already draft-excluding (it is the predicate the content rule
    # uses to decide what may be READ as a template), so this is the established half by
    # construction; a second `_under_draft` test would add nothing.
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

    # The tree walk is behind the `if`: `_answered_after_batch` parses the whole catalog, and
    # the question it answers is only ever asked about a draft that left. A batch that
    # deleted none pays nothing.
    if departed := _departed_drafts(repo_root, minted, records):
        covered = _answered_after_batch(repo_root)
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


def _repairs_the_id(
    before: _corpus.QueryTemplate, after: _corpus.QueryTemplate,
) -> bool:
    """Is this `id:` change the REPAIR of an id that disagreed with its directory?

    Without this the two rules deadlock, and the deadlock has no exit. A template filed at
    `queries/{system}/{name}.md` while calling itself `{other}.{name}` is refused by
    `check_template`'s `id-system-mismatch` on every edit — with a message telling the author
    the id must start with `{system}`. The author does exactly that, and the monotonicity rule
    refuses the batch for "rewriting the identity of an established template". Moving the file
    instead is refused by the delete-prohibition. Every tick that touches the file discards its
    whole batch, following two instructions that contradict each other.

    Narrow on purpose: the id must have been wrong BEFORE and right AFTER. A change between two
    well-formed ids is still the clobber the rule is here to catch, and a change that swaps one
    mismatch for another is not a repair.
    """
    def _prefix(t: _corpus.QueryTemplate) -> str:
        return t.id.split(".", 1)[0] if "." in t.id else ""

    return _prefix(before) != before.system and _prefix(after) == after.system


def _refuse_lost_provenance(
    path: str, before: _corpus.QueryTemplate | None, after: _corpus.QueryTemplate,
) -> None:
    """The monotonicity half of `_covers_rule`, on ONE established template — the only part
    of the rule that compares a file against its own pre-image. The pre-image is passed IN
    rather than read here, because the caller needs it too and re-reading costs a second `git
    show` per changed template for an answer that cannot have moved.
    """
    if before is None:
        return
    if before.id != after.id and not _repairs_the_id(before, after):
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
