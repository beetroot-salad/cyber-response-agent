"""The verification rules a produced edit has to survive before it is allowed to land.

Each rule is a refusal with a reason; the drain treats any of them firing as "revert, do not
commit".
"""
#!/usr/bin/env python3
from __future__ import annotations

import functools
import posixpath
import sys
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _corpus
from defender import _git
from defender import _scaffold_rules
from defender._io import ENTRY_DIR, ENTRY_FILE, Bound
from defender.learning.core.lane_trees import KIND_ABSENT, TreeFor, kind_at, read_at, view_at
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


def _template_in_tree(
    repo_root: Path, tree_for: TreeFor, path: str,
) -> tuple[_corpus.QueryTemplate | None, str]:
    """`read_query_template` of the working-copy `path`, through the lane's held mount when
    `tree_for` places it in one (#1134), its `path` spelled `repo_root / path` as today; outside
    the lane's mounts, its plain path (the box's read-only area, D3)."""
    full = repo_root / path
    hit = tree_for(full)
    if hit is None:
        return _corpus.read_query_template(full)
    held, name = hit
    folder, leaf = posixpath.split(name)
    return _corpus.read_query_template(view_at(held, folder or "."), leaf, where=full.parent)


def _frontmatter_id(repo_root: Path, path: str, *, tree_for: TreeFor) -> str | None:
    from defender._frontmatter import parse_frontmatter_or_none

    if kind_at(repo_root, tree_for, path) != ENTRY_FILE:
        return None
    text, _reason = read_at(repo_root, tree_for, path)
    if text is None:
        return None
    fm = parse_frontmatter_or_none(text)
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
    repo_root: Path, resolver: _scaffold_rules.VerbResolver, path: str, *, tree_for: TreeFor,
) -> None:
    """The content half of the promotion gate: `connect`'s invariants (e.g. every
    `${placeholder}` is a param its verb declares), which `validate_scaffold` doesn't reach
    because it excludes `_draft/`.

    Fires at promotion, not on `_draft/` writes: a draft is auto-minted from a query that
    really ran, and refusing the batch over one would discard signal. The minter emits a
    conformant skeleton, so a promotion starts from a file that already passes.
    """
    template, reason = _template_in_tree(repo_root, tree_for, path)
    if template is None:
        raise LeadAuthorError(
            f"agent wrote {path}, which is not a readable query template ({reason}); "
            "refusing to commit"
        )
    try:
        verbs = resolver.verbs(template.system)
    except _scaffold_rules.ScaffoldRuleError as e:
        # Not a skip: a template under a system with no importable adapter is a phantom
        # system, and "could not check" must refuse.
        raise LeadAuthorError(
            f"agent wrote {path}, whose system could not be resolved ({e}); refusing to commit"
        ) from e
    _refuse(path, _scaffold_rules.check_template(template, verbs))


def _still_there(repo_root: Path, tree_for: TreeFor, path: str) -> bool:
    """Does an entry the content rule must read still stand at `path`: anything but absent or a
    folder. Today's `is_file()` answered true for a link to a file and so checked what it
    pointed at; judged without following, a link is still there and its check refuses it."""
    return kind_at(repo_root, tree_for, path) not in (KIND_ABSENT, ENTRY_DIR)


def _skills_content_rule(
    repo_root: Path, resolver: _scaffold_rules.VerbResolver, xy: str, path: str,
    *, tree_for: TreeFor,
) -> None:
    """The content half of the gate: is what the agent wrote well-formed? Runs only on paths
    the path half admitted. Every probe and read goes through the lane's held mount
    (`tree_for`), so nothing below the mount point is followed (#1134).
    """
    if _is_catalog_path(path) and not _under_draft(path) and not _is_schema_md(path):
        twin = _draft_twin(path)
        # Anything standing at the twin's name — a file, a folder, a link — is a twin left behind.
        if kind_at(repo_root, tree_for, twin) != KIND_ABSENT:
            raise LeadAuthorError(
                f"half-promote: established template {path} was written but its draft "
                f"twin {twin} still exists; refusing to commit (the promote's `rm` "
                "didn't happen — established + draft would both land)"
            )
        # Only on an entry still there (not absent, not a folder); the path half already refused
        # deletes. Whatever else stands at the name — a plain file, or a link the box left —
        # reaches the read, which refuses anything but a plain file (#1134 O5.1): a link is
        # refused, never committed unchecked and never followed.
        #
        # `_is_catalog_template`, not `_is_catalog_path`: the catalog also holds non-template
        # files (a `{system}/README.md`, a root note) that the template rule would wrongly refuse.
        if "D" not in xy and _still_there(repo_root, tree_for, path) and _is_catalog_template(path):
            _check_promoted_template(repo_root, resolver, path, tree_for=tree_for)
    if _is_system_skill_md(path) and "D" not in xy and _still_there(repo_root, tree_for, path):
        system = Path(path).parent.name
        hit = tree_for(repo_root / path)
        _refuse(
            path,
            _scaffold_rules.check_system_skill(repo_root / path, system) if hit is None
            else _scaffold_rules.check_system_skill(hit[0].view(), system, hit[1]),
        )


def _skills_path_rule(
    repo_root: Path, xy: str, path: str, *, systems: frozenset[str], tree_for: TreeFor,
) -> None:
    # `execution.md` is never committable by this lane at any depth, so this keys on the
    # basename rather than on which in-scope form owns the path.
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
    # Membership before the delete-prohibition, so a `D` under an undeclared directory is
    # reported with the registry reason, not as a deletion.
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
    # The frontmatter `id:` prefix must agree with the directory; idless in-scope files (a
    # system `SKILL.md`, `SCHEMA.md`) are spared.
    ident = _frontmatter_id(repo_root, path, tree_for=tree_for)
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
    tree_for: TreeFor,
) -> None:
    """The whole per-path gate: the path half, then the content half on what it admitted."""
    _skills_path_rule(repo_root, xy, path, systems=systems, tree_for=tree_for)
    _skills_content_rule(repo_root, resolver, xy, path, tree_for=tree_for)


def _template_at_head(repo_root: Path, path: str) -> _corpus.QueryTemplate | None:
    """The template `path` was at HEAD, or `None` if HEAD did not carry it or it did not parse.

    An unparseable pre-image fails open: no invariant held before this batch either, so
    refusing would punish the author for the tree they were handed."""
    text = _git.git_show_head(repo_root, path)
    if text is None:
        return None
    template, _reason = _corpus.parse_query_template(text, repo_root / path)
    return template


#: The mint wrote nothing this tick — the default for callers other than `_run_locked`. A
#: frozen mapping rather than `None` or a mutable `{}` default.
_NO_MINTED: Mapping[Path, tuple[str, ...]] = MappingProxyType({})


def _minted_identities(
    skills: Bound, created: list[Path], *, where: Path,
) -> Mapping[Path, tuple[str, ...]]:
    """`{draft path -> the identities it records}` for the drafts this tick's mint wrote.

    Read between the mint and the agent: a just-minted draft is untracked, so if the agent
    deletes it git has neither a porcelain record nor a HEAD pre-image. That is the common case
    `_covers_rule`'s transfer half must catch.

    `created` is `synthesize_drafts`' return, each spelled `where / name`; each is read through
    the held `skills/` mount's view `skills` (#1134).
    """
    out: dict[Path, tuple[str, ...]] = {}
    for path in created:
        template = _corpus.read_query_template(
            skills, path.relative_to(where).as_posix(), where=where,
        )[0]
        if template is not None and template.covers:
            out[path] = template.covers
    return out


def _catalog_in_tree(repo_root: Path, tree_for: TreeFor) -> tuple[Bound | None, Path]:
    """The working copy's catalog: the view of it under the lane's held mount (`None` outside
    the lane's mounts, the box's read-only area, D3) and the Path it is spelled as."""
    where = repo_root / CATALOG_REL
    hit = tree_for(where)
    if hit is None:
        return None, where
    held, name = hit
    return view_at(held, name), where


def _answered_after_batch(repo_root: Path, *, tree_for: TreeFor) -> set[str]:
    """Every identity the catalog answers once this batch lands, through the mint's own reader.

    Read off the working tree, through the lane's held mount (#1134). The transfer rule asks
    "will this identity be re-minted next run?", so it must use the mint's `answered_identities`
    (ids plus `covers:`, drafts included); a narrower set would refuse harmless deletes.
    """
    view, where = _catalog_in_tree(repo_root, tree_for)
    if view is None:
        return answered_identities(lead_neighbors.load_catalog(where))
    return answered_identities(lead_neighbors.load_catalog(view, where=where))


def _catalog_drafts(repo_root: Path, tree_for: TreeFor) -> list[_corpus.QueryTemplate]:
    """Every readable `<system>/_draft/*.md` template in the working copy's catalog, in path
    order; one that does not read or parse is passed over.

    Listed and read through the lane's held mount, by the catalog readers' own selection
    (`_corpus._template_names`, the catalog's fixed three-level listing): a link is never
    entered or read, a linked, non-directory or refused `<sys>` or `_draft` folder is skipped and
    warned exactly as they skip it, and one found gone is passed over silently (#1134 O5.5).
    Outside the lane's mounts, the plain path's glob (D3)."""
    view, where = _catalog_in_tree(repo_root, tree_for)
    if view is None:
        found = [_corpus.read_query_template(p)[0] for p in sorted(where.glob("*/_draft/*.md"))]
    else:
        names = [
            name for name in _corpus._template_names(view, where)
            if len(parts := name.split("/")) == 3 and parts[1] == "_draft"
        ]
        found = [_corpus.read_query_template(view, name, where=where)[0] for name in names]
    return [t for t in found if t is not None]


def _refuse_half_promote(repo_root: Path, taken_over: set[str], *, tree_for: TreeFor) -> None:
    """The other side of transfer: an identity may not land on an established template while the
    draft that recorded it is still on disk.

    `_skills_content_rule`'s probe derives the twin from the basename, which a promote doesn't
    share (the draft's name is a digest, the established file's the author's). The surviving
    draft is unchanged, so no `git status` record carries it — only a filesystem probe finds it.
    """
    if not taken_over:
        return
    for template in _catalog_drafts(repo_root, tree_for):
        if stranded := sorted(set(template.covers) & taken_over):
            rel = template.path.relative_to(repo_root).as_posix()
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
    *,
    tree_for: TreeFor,
) -> list[tuple[str, tuple[str, ...]]]:
    """`(path, identities)` for every draft no longer in the tree.

    A committed draft departs as a `D` record, with identities from its HEAD pre-image. A draft
    this tick minted is untracked, so its identities come from `minted` instead.
    """
    out: list[tuple[str, tuple[str, ...]]] = []
    for xy, path in records:
        # `_under_draft`, since `_is_catalog_template` excludes drafts. Protected non-template
        # files (`_draft/README.md`, `SCHEMA.md`) carry no `covers:` and are skipped.
        if "D" not in xy or not _under_draft(path):
            continue
        if _is_draft_readme(path) or _is_schema_md(path):
            continue
        draft = _template_at_head(repo_root, path)
        if draft is not None and draft.covers:
            out.append((path, draft.covers))
    # `draft_path` is the absolute `Path` the mint returned, not the repo-relative `str` git
    # reports.
    for draft_path, identities in minted.items():
        # Departed only when nothing at all stands at its name: a link or a folder planted there
        # is not the draft, but it is not a departure either (#1134).
        if kind_at(repo_root, tree_for, draft_path) != KIND_ABSENT:
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
    *,
    tree_for: TreeFor,
) -> None:
    """The two whole-batch invariants on `covers:` — the identities a template accounts for.

    The author names the established file for what it measures, so `covers:` is the only link
    between a draft and its promoted template.

    Transfer: a draft that leaves the tree must have its identities land somewhere (a promote
    writes them onto the new file; a discard-into-widen adds them to the widened template). A
    bare discard is refused — an unattributable draft should be skipped, since deleting it just
    gets it re-minted next run, silently looping. Scored against the whole tree, the question
    `synthesize_drafts` asks next run. Its mirror is `_refuse_half_promote`.

    Monotonicity: an established template may gain identities but never lose them, and its
    `id:` may not change. Overwriting an established template is a legal fold, so a name
    collision would otherwise silently replace a different measurement; lost provenance is what
    separates a clobber from a widen.
    """
    # `_is_catalog_template` already excludes drafts.
    established = [p for xy, p in records if "D" not in xy and _is_catalog_template(p)]
    # Identities newly moved onto an established template (`after` minus `before`), so the
    # half-promote probe fires only on a takeover.
    taken_over: set[str] = set()
    for path in established:
        after = _template_in_tree(repo_root, tree_for, path)[0]
        if after is None:
            # Already refused by `_check_promoted_template` on the per-path pass.
            continue
        before = _template_at_head(repo_root, path)
        _refuse_lost_provenance(path, before, after)
        taken_over.update(set(after.covers) - set(before.covers if before is not None else ()))

    # `_answered_after_batch` parses the whole catalog, so only pay for it when a draft left.
    if departed := _departed_drafts(repo_root, minted, records, tree_for=tree_for):
        covered = _answered_after_batch(repo_root, tree_for=tree_for)
        for path, identities in departed:
            if orphaned := sorted(set(identities) - covered):
                raise LeadAuthorError(
                    f"agent deleted draft {path} without attributing it: {orphaned} is covered "
                    "by no established template; refusing to commit (a promote carries "
                    "`covers:` onto the new file and a discard-into-widen adds it to the "
                    "template it widened — a draft that fits neither is one to leave alone and "
                    "SKIP, because deleting it here only means minting it again next run)"
                )

    _refuse_half_promote(repo_root, taken_over, tree_for=tree_for)


def _repairs_the_id(
    before: _corpus.QueryTemplate, after: _corpus.QueryTemplate,
) -> bool:
    """Is this `id:` change the repair of an id that disagreed with its directory?

    Without it, `check_template`'s `id-system-mismatch` demands the fix, monotonicity refuses
    the id change, and the delete-prohibition refuses moving the file — a deadlock on every
    tick that touches it. Narrow: the id must be wrong before and right after.
    """
    def _prefix(t: _corpus.QueryTemplate) -> str:
        return t.id.split(".", 1)[0] if "." in t.id else ""

    return _prefix(before) != before.system and _prefix(after) == after.system


def _refuse_lost_provenance(
    path: str, before: _corpus.QueryTemplate | None, after: _corpus.QueryTemplate,
) -> None:
    """The monotonicity half of `_covers_rule`, on one established template against its
    pre-image (passed in, since the caller needs it too).
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
    tree_for: TreeFor, minted: Mapping[Path, tuple[str, ...]] = _NO_MINTED,
) -> list[str]:
    # One resolver for the batch, built on the tree being committed rather than the process's
    # own checkout: the drain runs this against a `lead-author/<id>` worktree, and
    # `_load_adapter_module` caches by resolved absolute path.
    #
    # The resolver fails at construction over an unreadable adapters directory; re-raised as
    # `LeadAuthorError`, the class every other refusal here dead-letters under.
    try:
        resolver = _scaffold_rules.VerbResolver(repo_root / "defender")
    except _scaffold_rules.ScaffoldRuleError as e:
        raise LeadAuthorError(
            f"the tree's systems could not be resolved ({e}); refusing to commit"
        ) from e
    return _verify_corpus_scope(
        repo_root, baseline_stray, actor="agent",
        rule=functools.partial(
            _skills_rule, repo_root, resolver, systems=systems, tree_for=tree_for,
        ),
        batch_rule=functools.partial(_covers_rule, repo_root, minted, tree_for=tree_for),
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
