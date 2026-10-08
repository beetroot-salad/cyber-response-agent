"""Retrieve defender lessons by frontier containment — what the investigation has not settled.

The signature lane (`runtime/orient.py`) greps `source_signature:.*<rule.id>` once, before the
investigation exists. That suits coverage lessons ("this rule is blind to X") but not
observable-semantics lessons ("`loginuid=-1` licenses only non-interactive automated context"),
whose trigger is holding the field, not which rule fired.

This keys on the open set instead (`skills/invlang/frontier.py`), on two axes matching invlang's
two closure mechanisms:

  * NODE — `(vertex type, class pattern, slot)`, for lessons about what a field licenses or
    how to close a slot. Closed by `:R attr_updates`.
  * EDGE — `(rel, auth_kind, anchor_kind)`, for lessons about what an authorization check
    can and cannot conclude. Closed by `:R authz`.

Both are optional lesson frontmatter (`frontier_nodes`, `frontier_edges`). A lesson declaring
neither is simply not on this lane; SKILL.md routes it through the signature block and
`defender-lessons`. Selectors are not required, since a procedure-triggered lesson has no
truthful selector to write.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import field, replace
from pathlib import Path

from defender._corpus import PROVENANCE_KEYS
from defender._model import model
from defender._untrusted import wrap_fresh
from defender.runtime.lessons_engine._lessons_common import (
    as_list,
    iter_lessons,
    resolve_corpus,
    use_utf8_stdio,
)
from defender.skills.invlang.frontier import (
    Frontier,
    HeldFact,
    OpenContract,
    OpenSlot,
)
from defender.skills.invlang import vocab
from defender.skills.invlang.validate import (
    ATTR_PREFIX,
    OPEN_MARKER,
    class_slots,
    is_open_slot,
)
from defender import _yaml
from defender._git import REPO_ROOT
from defender._knowledge import KnowledgePaths

DEFAULT_CORPUS = KnowledgePaths.of_defender_dir(REPO_ROOT / "defender").lessons_dir
CORPUS_NAME = DEFAULT_CORPUS.name

#: Selectors are hidden from the rendered block: the `matched` line already names the vertex
#: and value that hit.
SELECTOR_KEYS = frozenset({"frontier_nodes", "frontier_edges", "observed_nodes"})

#: Everything the injected block leaves out: bookkeeping plus mechanism.
HIDDEN_KEYS = PROVENANCE_KEYS | SELECTOR_KEYS

DEFAULT_TOP_K = 3

WILDCARD = "*"

# The scale
#
# One scale across both lanes, because `_best_match` pools them into one `max` and
# `match_loaded` cuts one ranked list at `top_k`. A count of declared fields is not a measure
# of specificity: with `type` and `slot` mandatory every node selector would score 2 (leaving
# the top-k to the alphabetical tiebreak), and the edge lane, with only `anchor_kind`
# mandatory, could never outrank any node match.
#
# So the weights are per component, set by how much matching it narrows the frontier:
#
#   1. `class` and `ident` are universal cells (every vertex has one of each), so matching one
#      only says "a vertex of type T exists". `attrs.<name>` constrains what the document
#      holds. Hence `ATTR_SLOT_WEIGHT` > `UNIVERSAL_SLOT_WEIGHT`.
#   2. Real runs carry 13-28 node cells against 0-2 open contracts, which exist only once a
#      hypothesis declares authz. Matching one of ~2 contracts under a named anchor says far
#      more than matching one of ~25 node cells. Hence `ANCHOR_KIND_WEIGHT` = 3.
#
# The ranges overlap on purpose: well-formed node scores run 2..6 and edge scores 3..5, so
# neither lane can shut the other out. The node ceiling depends on the document:
# `_class_pins` widens arity to fit a mis-authored cell, so 6 is the well-formed ceiling, not
# a bound.
#
# Ties between floor-level selectors are inherent; `_spread_over_items` breaks them by
# coverage rather than by name.
#: Conditioned on being declared: an omitted `type` constrains nothing.
TYPE_WEIGHT = 1
#: A `class` or `ident` slot — one cell on every vertex of the matched type.
UNIVERSAL_SLOT_WEIGHT = 1
#: An `attrs.<name>` slot — only vertices CARRYING that attribute have the cell.
ATTR_SLOT_WEIGHT = 2
#: Each class slot the selector pinned by equality. See `_class_pins` for what counts.
CLASS_PIN_WEIGHT = 1
#: `anchor_kind` — mandatory on an edge selector; see (2) above.
ANCHOR_KIND_WEIGHT = 3
#: The two optional edge fields, each one more thing the contract had to agree on.
REL_WEIGHT = 1
AUTH_KIND_WEIGHT = 1


@model(frozen=True)
class Hit:
    #: `frontmatter` is `compare=False`: as a dict it would make the frozen `__hash__` raise.
    #: Excluding it from both `__eq__` and `__hash__` keeps value comparison for the rest.
    path: Path
    name: str
    frontmatter: dict = field(compare=False)
    score: int
    matched: str


@model(frozen=True)
class _NodeSelector:
    type: str
    class_pattern: str
    slot: str

    @property
    def fixed_specificity(self) -> int:
        """The `type` and `slot` part of the score — independent of what the class pattern pins.

        Each term is conditioned on being declared, since an omitted field constrains nothing.
        The slot term separates universal cells (`class`, `ident`) from `attrs.<name>`; see
        the scale above.
        """
        return (TYPE_WEIGHT if self.type else 0) + self._slot_weight

    @property
    def _slot_weight(self) -> int:
        # `ATTR_PREFIX` comes from `validate`, which enforces the `:R attr_updates` key grammar.
        if not self.slot:
            return 0
        return ATTR_SLOT_WEIGHT if self.slot.startswith(ATTR_PREFIX) else UNIVERSAL_SLOT_WEIGHT


@model(frozen=True)
class _EdgeSelector:
    rel: str
    auth_kind: str
    anchor_kind: str

    @property
    def specificity(self) -> int:
        """Same scale as `_NodeSelector`, not a count of declared fields; see the scale above."""
        return (
            (ANCHOR_KIND_WEIGHT if self.anchor_kind else 0)
            + (REL_WEIGHT if self.rel else 0)
            + (AUTH_KIND_WEIGHT if self.auth_kind else 0)
        )


@model
class _Selectors:
    nodes: list[_NodeSelector] = field(default_factory=list)
    edges: list[_EdgeSelector] = field(default_factory=list)
    observed: list[_NodeSelector] = field(default_factory=list)


def _candidate_members(slot: str) -> frozenset[str]:
    """The values a `{a, b}` slot enumerates — empty for any other spelling.

    No nested-brace handling (the grammar has none), and an unterminated `{` is not a set, so a
    dropped `}` cannot name a value nothing can equal.
    """
    v = slot.strip()
    if not (v.startswith("{") and v.endswith("}")):
        return frozenset()
    return frozenset(part.strip() for part in v[1:-1].split(",") if part.strip())


def _class_pins(selector_class: str, case_class: str, vertex_type: str) -> int | None:
    """How many class slots this selector pinned about this cell — `None` on a miss.

    A slot matches when the selector names `*`, the same value, or the case slot is still open.
    A slot that matched only because the case slot was open discriminated nothing, so it earns
    no credit; otherwise a `class=??` vertex would rank every guessed class above a selector
    naming the exact open attribute.

    Anchored, not per-slot: a pattern with no equality match anywhere pins nothing, but once one
    slot matches by equality, its other named slots are credited (`ip-only/internet` beats
    `ip-only` against `ip-only/??/??`). Two mutually exclusive guesses at one open slot tie.
    """
    sel = class_slots(selector_class)
    case = class_slots(case_class)  # a fresh list per call, so the padding below may mutate it

    # Arity comes from the vertex type (`vocab.CLASS_GRAMMAR`), not from the cell: a cell naming
    # fewer slots left the rest open. Guessing from the cell was non-monotonic — recording more
    # about slot 0 could lose a selector the vaguer cell had matched.
    #
    # Widened to `len(case)`, never truncated: a cell with too many slots is mis-authored, but
    # dropping what it says would let a selector match through the hole. This also handles an
    # unknown `type` (`class_arity` answers 1).
    #
    # The case's openness must not widen further: that would let an over-long selector match a
    # wholly open cell and then stop matching once the cell was refined.
    arity = max(vocab.class_arity(vertex_type), len(case))
    # A selector naming more slots than the type has is mis-authored and matches nothing.
    if len(sel) > arity:
        return None
    case += [OPEN_MARKER] * (arity - len(case))

    pinned = 0
    anchored = False
    for i, s in enumerate(sel):
        if not s or s == WILDCARD:
            continue
        # An unresolved selector slot earns no pin and no anchor; otherwise `??/internet/novel`
        # against `??/??/??` would anchor on slot 0 and score a full triple while agreeing with
        # the document about nothing. `is_open_slot` covers both unresolved spellings.
        #
        # They constrain differently in a selector:
        #   * `??` constrains nothing, like `*`. Refusing on it would lose the selector once the
        #     document settled that slot (see
        #     `test_recording_more_about_a_class_slot_never_loses_a_selector`).
        #   * `{internal, dmz}` is a disjunction: it refuses a slot settled outside its members,
        #     as a concrete value would. Losing a selector the document contradicts is correct.
        #     Refinement within the set (`??` -> `{internal, dmz}` -> `internal`) stays matched.
        if is_open_slot(s):
            members = _candidate_members(s)
            if members and not is_open_slot(case[i]) and case[i] not in members:
                return None
            continue
        pinned += 1
        if s == case[i]:
            anchored = True
        elif not is_open_slot(case[i]):
            return None
    return pinned if anchored else 0


def _node_match_score(sel: _NodeSelector, item: OpenSlot | HeldFact) -> int | None:
    """How precisely this selector speaks to this node cell — `None` when it does not match.

    Serves both node lanes (`OpenSlot` and `HeldFact` share the fields). Note that
    `frontier._node_state` copies the vertex's class tuple onto every cell, so a settled attrs
    cell on an unclassified vertex carries `??/??/??` and a class-scoped attrs selector matches
    through it. No shipped lesson pairs a class pattern with an attrs slot yet.

    Scored on the match, so components that constrained nothing earn nothing.
    """
    if sel.type and sel.type != item.type:
        return None
    if sel.slot and sel.slot != item.slot:
        return None
    # `item.type`: equal to `sel.type` when declared, and always populated.
    pinned = _class_pins(sel.class_pattern, item.class_tuple, item.type)
    if pinned is None:
        return None
    return sel.fixed_specificity + pinned * CLASS_PIN_WEIGHT


def _edge_matches(sel: _EdgeSelector, contract: OpenContract) -> bool:
    """Conjunctive over the fields the selector declares; an omitted field constrains nothing.

    A contract on an unobserved edge has `None` for `rel`/`auth_kind`, so a selector naming
    either cannot match it — there is no relation there.
    """
    declared = (
        (sel.anchor_kind, contract.anchor_kind),
        (sel.rel, contract.rel or ""),
        (sel.auth_kind, contract.auth_kind or ""),
    )
    return all(want == got for want, got in declared if want)


def _node_selector(raw: object) -> _NodeSelector | None:
    """One node selector, or `None` if it omits a mandatory field or is mis-shaped. Shared by
    `frontier_nodes` and `observed_nodes`."""
    if not isinstance(raw, dict):
        return None
    # A non-scalar cell (`type: [process]`) would stringify into a selector that silently
    # matches nothing, so it drops like a missing field.
    fields = {k: raw.get(k) for k in ("type", "class", "slot")}
    if any(v is not None and not isinstance(v, str) for v in fields.values()):
        return None
    sel = _NodeSelector(
        type=(fields["type"] or "").strip(),
        class_pattern=(fields["class"] or WILDCARD).strip(),
        slot=(fields["slot"] or "").strip(),
    )
    return sel if sel.type and sel.slot else None


def _parse_selectors(fm: dict) -> _Selectors:
    """The lesson's declared selectors, dropping any entry that omits a required field.

    Nothing validates frontmatter at authoring time, and an omitted field constrains nothing,
    so `frontier_edges: [{}]` or a typo'd key would match every contract in every document
    forever and take a `top_k` slot. Dropping it only takes the lesson off this lane.
    """
    out = _Selectors()
    for raw in as_list(fm.get("frontier_nodes")):
        if (node := _node_selector(raw)) is not None:
            out.nodes.append(node)
    for raw in as_list(fm.get("observed_nodes")):
        if (node := _node_selector(raw)) is not None:
            out.observed.append(node)
    for raw in as_list(fm.get("frontier_edges")):
        if not isinstance(raw, dict):
            continue
        cells = {k: raw.get(k) for k in ("rel", "auth_kind", "anchor_kind")}
        if any(v is not None and not isinstance(v, str) for v in cells.values()):
            continue  # a non-scalar cell is a mis-authored selector
        edge = _EdgeSelector(
            rel=(cells["rel"] or "").strip(),
            auth_kind=(cells["auth_kind"] or "").strip(),
            anchor_kind=(cells["anchor_kind"] or "").strip(),
        )
        if edge.anchor_kind:
            out.edges.append(edge)
    return out


def _best_match(selectors: _Selectors, frontier: Frontier) -> tuple[int, tuple[str, ...]] | None:
    """This lesson's best score against the frontier, and every item it reaches that score on.

    Best, not sum: five loose selectors should not outrank one naming the exact slot in play.
    All lanes share one scale (see above) because `max` compares them regardless; open slots
    and held facts are weighted equally since lessons about known values matter as much.
    """
    scored: list[tuple[int, str]] = [
        (score, f"{item.vertex_id} {item.type} {item.slot}={item.value}")
        for sels, items in (
            (selectors.nodes, frontier.slots),
            (selectors.observed, frontier.held),
        )
        for node_sel in sels
        for item in items
        if (score := _node_match_score(node_sel, item)) is not None
    ]
    scored += [
        (
            edge_sel.specificity,
            f"{contract.contract_id} on {contract.hypothesis_id} "
            f"anchor={contract.anchor_kind}",
        )
        for edge_sel in selectors.edges
        for contract in frontier.contracts
        if _edge_matches(edge_sel, contract)
    ]
    if not scored:
        return None
    best = max(score for score, _ in scored)
    # Every item at the best score, sorted, so the result depends on the frontier's content
    # rather than on vertex declaration order; `_spread_over_items` places lessons by item, and
    # ties across cells are common.
    return best, tuple(sorted({item for score, item in scored if score == best}))


def match_lessons(
    frontier: Frontier, corpus: Path, *, top_k: int = DEFAULT_TOP_K
) -> list[Hit]:
    """The `top_k` lessons the block is built from — the head of `_spread_over_items`' order,
    which covers distinct frontier items before giving any item a second slot."""
    # A negative `top_k` would slice off the tail instead of capping. Checked here too so an
    # empty answer skips the corpus walk.
    if frontier.is_empty() or top_k <= 0:
        return []
    return match_loaded(frontier, list(iter_lessons(corpus)), top_k=top_k)


def match_loaded(
    frontier: Frontier, lessons: list, *, top_k: int = DEFAULT_TOP_K
) -> list[Hit]:
    """`match_lessons` over an already-loaded corpus, so `runtime/tools._frontier_recall` can
    score the pre- and post-write documents off one `iter_lessons` walk (the lane's dominant
    cost).
    """
    if frontier.is_empty() or top_k <= 0:
        return []
    # Materialized: a generator would be empty on the second scoring, making the comparison
    # never equal and re-emitting the block on every write.
    lessons = list(lessons)
    hits: list[Hit] = []
    candidate_items: list[tuple[str, ...]] = []
    for lesson in lessons:
        fm = lesson.fm  # lint-lesson-text: ok — matched by selectors; printed only by render(), inside its untrusted frame
        match = _best_match(_parse_selectors(fm), frontier)
        if match is None:
            continue
        score, candidates = match
        # Placeholder: `_spread_over_items` picks the final item and rewrites `matched`.
        candidate_items.append(candidates)
        hits.append(Hit(
            path=lesson.path,
            name=str(fm.get("name") or lesson.path.stem),
            frontmatter=fm,
            score=score,
            matched=candidates[0],
        ))
    # Name is the last tiebreak so the order is total; a changing top-k would churn the block.
    # Sorted together so each hit keeps its candidates.
    ranked = sorted(
        zip(hits, candidate_items, strict=True),
        key=lambda pair: (-pair[0].score, pair[0].name),
    )
    return _spread_over_items(ranked)[:top_k]


def _spread_over_items(ranked: list[tuple[Hit, tuple[str, ...]]]) -> list[Hit]:
    """The ranked hits, re-ordered so the head covers distinct frontier items before doubling up:
    the best lesson about each item first, then the second-best about each, and so on, score
    order within each pass. Each hit is recorded against the item it was placed on.

    Needed alongside the scale: floor-level selectors are equally specific, and without this
    two lessons about one contract could take two of three slots and evict a lesson about a
    different open item. A lesson tied across several items is placed on the least-covered one.

    Deterministic: `ranked` is sorted by `(-score, name)`, candidates are sorted, and placement
    is a single forward pass. The emitted order depends on coverage, not just score, which is
    why `runtime/tools._frontier_recall` compares a sorted set of (lesson, score) rather than
    the list.
    """
    used: dict[str, int] = {}
    keyed: list[tuple[int, int, Hit]] = []
    for position, (hit, candidates) in enumerate(ranked):
        # The least-covered tied item; ties broken by the sorted candidate order.
        item = min(candidates, key=lambda c: (used.get(c, 0), c))
        pass_index = used.get(item, 0)
        used[item] = pass_index + 1
        # `position` keeps the incoming order within a pass.
        keyed.append((pass_index, position, replace(hit, matched=item)))
    keyed.sort(key=lambda k: (k[0], k[1]))
    return [hit for _, _, hit in keyed]


def _render_frontmatter(fm: dict) -> str:
    """The lesson's frontmatter, minus bookkeeping and selectors, indented under its path.

    YAML rather than `str(value)` so lists appear in the spelling the model reads elsewhere.
    """

    kept = {k: v for k, v in fm.items() if k not in HIDDEN_KEYS}
    # `safe_dump({})` renders `{}`; show nothing instead.
    if not kept:
        return ""
    # Unbounded `width` keeps `description` (what the model judges relevance from) on one line.
    #
    # `default_flow_style=None` (unlike `build_corpus_manifest`'s `False`): leaf lists render
    # as `[a, b]`, the one-line spelling both prompts require lesson files to use, and it
    # saves ~12 of a 3-hit block's ~30 lines.
    dumped = _yaml.safe_dump(
        kept, sort_keys=True, default_flow_style=None, allow_unicode=True, width=10**9
    )
    return "\n".join(f"  {line}" for line in dumped.strip().splitlines())


#: Shared by both leads. The read discipline lives here rather than in SKILL.md because it is
#: about the block in front of the model. "your record", not "the open frontier": this fires on
#: settled cells too.
_READ_DISCIPLINE = (
    "Precedent, not evidence: judge each from its `description`, Read only the bodies that fit."
)
#: The `append_block` / `fix_row` return's lead: the write that just landed moved the record.
WRITE_RETURN_LEAD = (
    "### Lessons matched against your record — pushed because this write moved it. "
    + _READ_DISCIPLINE
)
#: The compaction fold's lead: the frontier row carries the top matches for the record now,
#: derived fresh (so it may name lessons never shown). Different wording from the write return
#: so the model does not look for a write that did not happen.
FOLD_LEAD = (
    "### Lessons matched against your record as it stands — your history was folded, and "
    "this is what the record matches now. " + _READ_DISCIPLINE
)


def render(hits: list[Hit], *, lead: str = WRITE_RETURN_LEAD) -> str:
    """The injected block, or `""` when nothing matched (the caller decides whether silence
    is right). `lead` is the first line: the write return's by default, `FOLD_LEAD` for the fold.

    Paths are absolute because MAIN's cwd anchor is the run dir: a relative
    `defender/lessons/<name>.md` would be rebased and denied by `decide_read`. Absolute operands
    bypass the anchor, as `lessons_fm._emit_match` also relies on.
    """
    if not hits:
        return ""
    # The block is re-injected often, so every line counts.
    lines = []
    for hit in hits:
        # `matched` is the model's only account of why this lesson was pushed.
        lines.append(f"- {hit.path.resolve()} — matched {hit.matched}")
        if body := _render_frontmatter(hit.frontmatter):  # lint-lesson-text: ok — inside the untrusted frame below
            lines.append(body)
    # The lead is host text; the hits are lesson text a model wrote, framed as the alert is
    # (`defender._corpus`'s rule), so a description cannot read as a section of this message.
    return lead + "\n" + wrap_fresh("\n".join(lines), "untrusted")


def _positive_int(raw: str) -> int:
    """Reject `--top-k` below 1 (argparse accepts `-N` as this option's value)."""
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more (got {value})")
    return value


def main(argv: list[str]) -> int:
    use_utf8_stdio()
    ap = argparse.ArgumentParser(
        prog="lessons_frontier.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--investigation", required=True, help="Path to the investigation.md to derive the frontier from")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    ap.add_argument("--top-k", type=_positive_int, default=DEFAULT_TOP_K, help=f"How many lessons to return (default {DEFAULT_TOP_K})")
    ap.add_argument("--corpus", help=f"Relocated {CORPUS_NAME} directory (worktree or fixture); the leaf name must still be {CORPUS_NAME}")
    ns = ap.parse_args(argv[1:])

    corpus = resolve_corpus(ns.corpus, DEFAULT_CORPUS, ap)
    # Report a missing corpus: `resolve_corpus` checks only the leaf name and
    # `iter_lesson_paths` answers `[]`, so a mistyped path would look like "nothing matched".
    if not corpus.is_dir():
        print(f"error: no {CORPUS_NAME} corpus at {corpus}", file=sys.stderr)
        return 2
    from defender._io import read_text_soft
    from defender.skills.invlang.frontier import frontier_from_text

    # Reported, not swallowed: empty output means "nothing matched".
    text, err = read_text_soft(Path(ns.investigation))
    if text is None:
        print(f"error: cannot read {ns.investigation}: {err}", file=sys.stderr)
        return 2
    out = render(match_lessons(frontier_from_text(text), corpus, top_k=ns.top_k))
    if out:
        print(out)
    return 0


if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    sys.exit(main(sys.argv))
