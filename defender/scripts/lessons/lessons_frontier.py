#!/usr/bin/env python3
"""Retrieve defender lessons by FRONTIER containment — what the investigation has not settled.

The shipped retrieval keys on the alert signature: `runtime/orient.py` greps
`source_signature:.*<rule.id>` once, before the investigation exists. That is the right key
for a coverage lesson ("this rule is blind to X") and the wrong key for an
observable-semantics lesson ("`loginuid=-1` licenses only non-interactive automated
context"), whose trigger condition is *holding the field*, not *which rule fired*. #919's
motivating case missed exactly that lesson, because it was born under a different rule.

So this keys on the open set instead (`skills/invlang/frontier.py`), on two axes matching
invlang's two closure mechanisms:

  * NODE — `(vertex type, class pattern, slot)`, for lessons about what a field licenses or
    how to close a slot. Closed by `:R attr_updates`.
  * EDGE — `(rel, auth_kind, anchor_kind)`, for lessons about what an authorization check
    can and cannot conclude. Closed by `:R authz`.

Both are declared on the lesson as OPTIONAL frontmatter (`frontier_nodes`,
`frontier_edges`). A lesson declaring neither has nothing for `_best_match` to score, so it
is simply not on THIS lane — SKILL.md routes it through the other two (the signature block
at orientation, and `defender-lessons` widening). That is why this ships no "empty selectors
are invalid" gate: a lesson whose trigger is a procedure rather than an open slot has no
truthful selector to write, and a birth-time gate would only buy fabricated ones.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import PROVENANCE_KEYS
from defender.scripts.lessons._lessons_common import (
    as_list,
    iter_lessons,
    reexec_into_venv,
    resolve_corpus,
    use_utf8_stdio,
)

if __name__ == "__main__":
    reexec_into_venv(__file__)

import argparse

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

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CORPUS = REPO_ROOT / "defender" / "lessons"
CORPUS_NAME = DEFAULT_CORPUS.name

#: The selectors are the QUERY, not the answer. Echoing a lesson's own matching key back to
#: the model costs six lines per hit and tells it nothing the `matched` line does not already
#: say more precisely — that one names the vertex and value that actually hit.
SELECTOR_KEYS = frozenset({"frontier_nodes", "frontier_edges", "observed_nodes"})

#: Everything the injected block leaves out: bookkeeping plus mechanism.
HIDDEN_KEYS = PROVENANCE_KEYS | SELECTOR_KEYS

DEFAULT_TOP_K = 3

WILDCARD = "*"

# THE SCALE (#935)
#
# One scale across both lanes, because `_best_match` pools them into one `max` and
# `match_loaded` cuts one ranked list at `top_k`. It used to be a COUNT OF DECLARED FIELDS on
# each side, and a count is not a measure of specificity: the fields are not comparable, and
# the mandatory ones are not comparable ACROSS the lanes at all. Two things followed, both
# measured on the corpus as merged rather than latent. (#935's third defect is the class match
# guessing arity from the cell, which is `_class_pins`' business, not this scale's — the three
# share a cause, not a site.)
#
#   * Every node selector scored exactly 2. `type` and `slot` are both mandatory
#     (`_node_selector` drops a selector missing either) and most shipped selectors omit the
#     optional `class`, so the whole node lane was one flat value and the `name` tiebreak in
#     `match_loaded` picked the top-3 alphabetically. On a two-vertex document holding
#     `loginuid=-1`, two lessons keyed on a bare `slot: ident` — a cell EVERY vertex carries —
#     cut the one naming `attrs.loginuid`, because `c` sorts before `f`.
#   * The edge lane could not compete. `anchor_kind` is its only mandatory field, so every
#     shipped `frontier_edges` selector floored at 1 against a node floor of 2 and ANY node
#     match outranked it. Replaying `golden-sshpivot-ab3` and `turnN-A` fence by fence, the
#     block where `contracts` goes 0 -> 2 — exactly when "what this anchor can and cannot
#     conclude" is worth reading — emitted the same three node lessons as the block before it,
#     so `_frontier_recall`'s diff emitted NO block at all on the append that opened the
#     authorization question.
#
# So the weights below are per-COMPONENT, and each is set by how much matching that component
# narrows the frontier items it could have hit — not by how many cells the author filled in.
# Two facts about the populations do the work, and both are measured on the runs in hand:
#
#   1. `class` and `ident` are UNIVERSAL cells — every vertex carries exactly one of each — so
#      matching one says only "this document has a vertex of type T". `attrs.<name>` is a
#      constraint on what the document actually HOLDS, and it is the shape #919 was filed
#      about. Hence `ATTR_SLOT_WEIGHT` over `UNIVERSAL_SLOT_WEIGHT`.
#   2. The two lanes' item populations differ by an order of magnitude. Those two runs carry
#      13-28 node cells apiece against 0 or 2 open contracts, and the contracts exist only
#      once a hypothesis declares authz. Matching one of ~2 open contracts under a NAMED
#      anchor is a far stronger statement about this document than matching one of ~25 node
#      cells by type plus a universal cell — and the count-of-fields scale encoded exactly the
#      opposite. Hence `ANCHOR_KIND_WEIGHT` at 3.
#
# The ranges overlap on purpose: on a well-formed document node runs 2..6 (`type` + an attrs
# slot + up to a pinned class triple) and edge runs 3..5. The node lane still FLOORS lower —
# 2 against 3 — and that is the point rather than an oversight: what the old scale got wrong
# was that the edge lane could never reach a node match at all, and what matters is that
# neither lane can now shut the other out. The overlap is where that is written.
#
# The node CEILING is a property of the document, not of this table: `_class_pins` widens
# arity to `max(the type's grammar, what the cell declares)`, so a mis-authored class cell
# carrying five slots against a five-slot selector pins 5 and scores 8. Both sides have to be
# wrong for that, and nothing validates class arity — so read 6 as the well-formed ceiling,
# not as a bound.
#
# WEIGHTS ARE HALF OF IT. Two selectors at their lanes' floors are genuinely equally specific
# and no honest weight orders them, so ties are a permanent feature of any scale here rather
# than a defect this one removed. `_spread_over_items` is what decides those, on what the block
# is FOR, instead of leaving them to the alphabet.
#: `type` is mandatory, so this is the node lane's floor contribution — and it is conditioned
#: on being declared anyway, because an omitted `type` constrains nothing and crediting it
#: would rank a match-any-vertex selector level with one that named the type.
TYPE_WEIGHT = 1
#: A `class` or `ident` slot — one cell on every vertex of the matched type.
UNIVERSAL_SLOT_WEIGHT = 1
#: An `attrs.<name>` slot — only vertices CARRYING that attribute have the cell.
ATTR_SLOT_WEIGHT = 2
#: Each class slot the selector pinned by equality. See `_class_pins` for what counts.
CLASS_PIN_WEIGHT = 1
#: `anchor_kind` — mandatory on an edge selector, and see (2) above for why it is not 1.
ANCHOR_KIND_WEIGHT = 3
#: The two optional edge fields, each one more thing the contract had to agree on.
REL_WEIGHT = 1
AUTH_KIND_WEIGHT = 1


@dataclass(frozen=True)
class Hit:
    #: `frontmatter` is `compare=False` because it is a dict: the frozen default would
    #: advertise a `__hash__` over it that raises the moment anyone puts a `Hit` in a set.
    #: Excluding it from BOTH `__eq__` and `__hash__` keeps the value comparison the rest of
    #: the tuple already supports — `eq=False` would silently leave identity semantics, so a
    #: `set(hits)` dedupe would keep duplicates rather than raise.
    path: Path
    name: str
    frontmatter: dict = field(compare=False)
    score: int
    matched: str


@dataclass(frozen=True)
class _NodeSelector:
    type: str
    class_pattern: str
    slot: str

    @property
    def fixed_specificity(self) -> int:
        """The `type` and `slot` half of the score — the components that do not depend on
        what the class pattern managed to pin against a particular case.

        Both are conditioned on being DECLARED: an omitted field constrains nothing
        (`_node_match_score` skips an empty comparison), so crediting it would rank a
        match-any-vertex selector level with one that named the type. In practice
        `_node_selector` drops a selector missing either, so both terms are always paid — the
        conditioning is what keeps this honest if that ever loosens.

        The slot term is where the node lane got the resolution it was missing (#935): `class`
        and `ident` are cells EVERY vertex carries, so matching one narrows the frontier to
        "a vertex of this type", while `attrs.<name>` narrows it to the vertices that hold
        that attribute. Scoring the two the same is what made the whole lane a flat 2 and
        handed the top-3 to an alphabetical tiebreak — cutting the exact lesson #919 exists
        for. See THE SCALE above.
        """
        return (TYPE_WEIGHT if self.type else 0) + self._slot_weight

    @property
    def _slot_weight(self) -> int:
        # `ATTR_PREFIX` is imported from `validate` rather than spelled here, because that is
        # where the `:R attr_updates` key grammar is enforced and where the walk that REPORTS
        # these slots lives. The corpus writes `slot: attrs.loginuid` as free YAML; a second
        # copy of the prefix is how the two sides of that join drift.
        if not self.slot:
            return 0
        return ATTR_SLOT_WEIGHT if self.slot.startswith(ATTR_PREFIX) else UNIVERSAL_SLOT_WEIGHT


@dataclass(frozen=True)
class _EdgeSelector:
    rel: str
    auth_kind: str
    anchor_kind: str

    @property
    def specificity(self) -> int:
        """Same scale as `_NodeSelector`, and NOT a count of declared fields (#935).

        `anchor_kind` is the only mandatory field, so a count floored this whole lane at 1
        against a node floor of 2 — and since `_best_match` pools both lanes into one `max`,
        any node match at all outranked any edge match. The append where the first
        authorization contract opens is exactly when a lesson about what an anchor can and
        cannot conclude is worth reading, and it was the append on which no block was emitted.
        `ANCHOR_KIND_WEIGHT` carries why 3 is the honest weight rather than the fix's floor.
        """
        return (
            (ANCHOR_KIND_WEIGHT if self.anchor_kind else 0)
            + (REL_WEIGHT if self.rel else 0)
            + (AUTH_KIND_WEIGHT if self.auth_kind else 0)
        )


@dataclass
class _Selectors:
    nodes: list[_NodeSelector] = field(default_factory=list)
    edges: list[_EdgeSelector] = field(default_factory=list)
    observed: list[_NodeSelector] = field(default_factory=list)


def _candidate_members(slot: str) -> frozenset[str]:
    """The values a `{a, b}` slot enumerates — empty for any other spelling.

    Split on the commas the SKILL's own `{a, b, c}` form writes, and no deeper: a nested brace
    is not a shape the class grammar has, and treating an unterminated `{` as a one-member set
    would let a dropped `}` name a value nothing can equal. `is_open_slot` has already said
    this slot is unresolved; this only asks WHICH of the two unresolved spellings it is.
    """
    v = slot.strip()
    if not (v.startswith("{") and v.endswith("}")):
        return frozenset()
    return frozenset(part.strip() for part in v[1:-1].split(",") if part.strip())


def _class_pins(selector_class: str, case_class: str, vertex_type: str) -> int | None:
    """How many class slots this selector actually PINNED about this cell — `None` on a miss.

    A slot MATCHES when the selector names `*`, names the same value, or the case slot is
    still open. That last clause is the inversion, and it is why this is a second matcher
    rather than an edit to `lessons_env_retrieve._class_match`: that one wildcards on the
    SELECTOR side only, which is right for the actors it serves and exactly backwards
    here. The SCORE is the part that has to be about the
    match rather than about the selector: a slot that matched only THROUGH the inversion
    (the case slot was `??`) discriminated nothing, because the same selector would have
    matched any class at all there.

    Crediting it inverted the ranking on the most common early-investigation shape. A vertex
    declared `class=??` is matched by `{class: bastion}` and `{class: ip-only}` and
    `{class: client-cert}` alike; crediting those put them ABOVE a selector naming the exact
    open `attrs.loginuid` — so on the append that opened #919's own motivating slot the top-3
    was saturated by lessons the document says nothing about, the loginuid lesson was cut,
    and (because `_frontier_recall` diffs the rendered block) no lessons block was emitted at
    all. The numbers moved with THE SCALE (#935); the rule did not.

    ANCHORED, not per-slot, and the distinction is the whole rule — read it before "fixing"
    the `pinned += 1` below. The no-credit clause above applies to a pattern that matched
    NOWHERE by equality; once ONE slot matches by equality the pattern is tied to this cell,
    and the further slots it names ARE credited, because on an anchored cell they are the extra
    precision the ranking is for (`ip-only/internet` over `ip-only` against `ip-only/??/??`).
    A pattern with no equality anywhere pins nothing, exactly as a bare `*` does. The cost is
    known and accepted: two mutually exclusive guesses at the same open slot tie, and the
    `name` tiebreak picks between them.
    """
    sel = class_slots(selector_class)
    case = class_slots(case_class)  # a fresh list per call, so the padding below may mutate it

    # NORMALISED TO THE TYPE, not guessed from the cell (#935). Class-tuple arity is a
    # documented function of the vertex TYPE (SKILL.md §Classification grammar, now readable as
    # `vocab.CLASS_GRAMMAR`), and `_node_match_score` has already agreed on the type before it
    # calls here — so a cell that names FEWER slots than its type has is a cell that left the
    # rest open, and padding says so.
    #
    # Guessing from the cell was non-monotonic across arity, which is the defect this fixes:
    # for `sel="ip-only/internet/novel"`, case `??` and `??/??` both matched (they say nothing
    # about their own arity, so the old code widened to the selector), and `ip-only/??/??`
    # matched — but `ip-only/??` MISSED, because it was concrete enough to be taken at its
    # length. Recording more about slot 0 of a two-slot tuple LOST a selector the vaguer
    # document matched one write earlier, and nothing validates class arity, so that cell is
    # diagnostic-clean.
    #
    # WIDENED, never truncated, and the widening is `len(case)`: a cell declaring MORE slots
    # than the grammar allows is mis-authored, but truncating it would silently drop what the
    # author did say and let a selector match through the hole. The extra slots stay, and a
    # selector still has to agree with them. This is also what keeps an off-vocabulary `type`
    # working: `vocab.class_arity` answers 1 for a type it does not know, and the cell's own
    # length takes over.
    #
    # The case's OPENNESS is not a second widening, and it must not be. Padding to the type
    # already admits an explicit triple against `??` or `??/??` on a three-slot type, so the
    # only selector a "wholly-open case widens to the selector" clause ever reached was one
    # naming MORE slots than the type has — and it reached that selector only while the cell
    # was wholly open. `class: bash/child` on a `process` (one slot) matched `class=??` at 0
    # and then returned `None` the moment the run settled the image basename to `bash`: the
    # retrieval going dark on the write that made the document more specific, which is the
    # exact non-monotonicity this whole function was rewritten to remove, one arity over.
    arity = max(vocab.class_arity(vertex_type), len(case))
    # A selector naming more slots than the type HAS is mis-authored — the same class of fault
    # `_node_selector` drops a non-scalar cell for — and it matches nothing, at every stage of
    # the cell's refinement rather than at some of them.
    if len(sel) > arity:
        return None
    case += [OPEN_MARKER] * (arity - len(case))

    pinned = 0
    anchored = False
    for i, s in enumerate(sel):
        if not s or s == WILDCARD:
            continue
        # An UNRESOLVED selector slot earns NO pin and NO anchor. It used to anchor: `??`
        # compares equal to an open case slot, so `??/internet/novel` against `??/??/??`
        # anchored on slot 0 and then collected slots 1 and 2 as pins — a selector agreeing
        # with the document about nothing scoring a full pinned triple and outranking every
        # honest match. That is the inversion this function exists to refuse, wearing the open
        # marker instead of a class literal. `is_open_slot`, not `s == OPEN_MARKER`, because
        # the marker is one spelling of unresolved and the candidate set is the other, and a
        # quoted `'{internal, dmz}/internet'` against a case still carrying that set is the
        # identical fabrication one spelling over.
        #
        # WHAT THEY CONSTRAIN IS WHERE THE TWO SPELLINGS PART, and reading them as one thing
        # was wrong (#935 review). In a DOCUMENT both mean "not settled" and the candidate set
        # is the richer of the two. In a SELECTOR the author is stating a scope, so:
        #
        #   * `??` constrains NOTHING — the same non-statement `*` makes, and skipped by the
        #     same `continue`. Refusing on it made the marker non-monotonic: a lesson keyed
        #     `??/internet/novel` matched `??/??/??` and returned `None` once a refinement
        #     settled slot 0, so retrieval went dark on the write that made the document MORE
        #     specific — what `test_recording_more_about_a_class_slot_never_loses_a_selector`
        #     forbids. A slot that says nothing cannot also refuse.
        #   * `{internal, dmz}` is a DISJUNCTION — "this lesson is about internal or dmz
        #     hosts". Treating it as `*` too let that lesson match, and score a pin against, a
        #     `bastion` vertex. So it still refuses a slot settled outside its members, and
        #     that refusal is not the non-monotonicity above: a selector naming `bastion`
        #     against a cell settled to `ip-only` refuses for the same reason, and
        #     `test_a_settled_slot_still_refuses_a_selector_that_disagrees_with_it` pins it.
        #     Losing a selector the document CONTRADICTS is correct; losing one it merely
        #     refined is the bug.
        #
        # It admits a member (`internal`) where the pre-#935 code refused even that — it
        # compared the whole `{...}` string to the cell — so the refinement path INSIDE the
        # set stays monotonic: `??` -> `{internal, dmz}` -> `internal` all match, at 0.
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

    Serves BOTH node lanes. `OpenSlot` and `HeldFact` carry the same five fields, and the same
    `_class_pins` call scores either.

    Its open-case-slot wildcard DOES still fire on a held fact, and that is worth knowing
    rather than assuming away: `frontier._node_state` copies the vertex's class tuple onto
    EVERY cell, so a settled `attrs.<name>` or `ident` cell on an unclassified vertex carries
    `class_tuple='??/??/??'`. A selector scoped `{type: compute, class: bastion,
    slot: attrs.pty}` therefore matches a `pty` the run has settled on a host it has not
    classified — the class half wildcards through, and only the `class` SLOT of a held fact is
    settled by definition. Nothing in the shipped corpus pairs a class pattern with an attrs
    slot yet, so this is latent; it is a limitation of carrying one class tuple per cell, not
    of the scoring.

    Scored on the MATCH rather than on the selector, so a component that constrained nothing
    (an omitted `type`, a class slot that landed on a `??`) earns nothing. See `_class_pins`.
    """
    if sel.type and sel.type != item.type:
        return None
    if sel.slot and sel.slot != item.slot:
        return None
    # `item.type`, not `sel.type`: the two are equal by the guard above whenever the selector
    # declares one, and `item` is the side that is always populated.
    pinned = _class_pins(sel.class_pattern, item.class_tuple, item.type)
    if pinned is None:
        return None
    return sel.fixed_specificity + pinned * CLASS_PIN_WEIGHT


def _edge_matches(sel: _EdgeSelector, contract: OpenContract) -> bool:
    """Conjunctive over the fields the selector DECLARES; an omitted field constrains nothing.

    `rel` and `auth_kind` fall back to `""` because a contract on an unobserved edge carries
    `None` for both — so a selector naming either cannot match a proposed-edge contract, which
    is right: there is no relation there to match against.
    """
    declared = (
        (sel.anchor_kind, contract.anchor_kind),
        (sel.rel, contract.rel or ""),
        (sel.auth_kind, contract.auth_kind or ""),
    )
    return all(want == got for want, got in declared if want)


def _node_selector(raw: object) -> _NodeSelector | None:
    """One node selector, or `None` if it omits a field the prompt declares mandatory.

    Shared by `frontier_nodes` and `observed_nodes`: the two differ in WHICH half of the
    state they are matched against, never in how they are spelled or validated."""
    if not isinstance(raw, dict):
        return None
    # `str()` on a non-scalar is the SHAPE half of the same failure the drop covers for a
    # missing field: `type: [process]` becomes the selector `"['process']"`, which passes the
    # `sel.type and sel.slot` guard below and then matches nothing, forever, silently — the
    # exact outcome `learning/author/lessons/prompt.md` warns a typo produces. A YAML list or
    # int in one of these cells is a mis-authored selector, so it drops like a missing one.
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
    """The lesson's declared selectors, DROPPING any entry that omits a required field.

    `learning/author/lessons/prompt.md` calls `type`/`slot` mandatory on a node selector and
    `anchor_kind` mandatory on an edge one, and nothing validates the frontmatter at authoring
    time — so the drop is the only thing standing between a one-character key typo and a
    match-everything selector. An omitted field CONSTRAINS NOTHING here: `_node_match_score`
    skips an empty comparison and `_edge_matches`' `all(... if want)` over no declared field is
    vacuously True, so `frontier_edges: [{}]` — or `- {anchor: iam-policy}`, or a key the LLM
    curator emitted with an empty value — would hit every open contract in every document,
    forever, at score 0, and take a `top_k` slot from a lesson that actually speaks to the
    case. A dropped entry is a lesson off THIS lane, which is the failure the schema already
    admits for an unselectored lesson; a kept one is a permanent false positive.
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
            continue  # see `_node_selector` — a non-scalar cell is a mis-authored selector
        edge = _EdgeSelector(
            rel=(cells["rel"] or "").strip(),
            auth_kind=(cells["auth_kind"] or "").strip(),
            anchor_kind=(cells["anchor_kind"] or "").strip(),
        )
        if edge.anchor_kind:
            out.edges.append(edge)
    return out


def _best_match(selectors: _Selectors, frontier: Frontier) -> tuple[int, tuple[str, ...]] | None:
    """This lesson's best score against the frontier, and EVERY item it reaches that score on.

    BEST, not sum: a lesson declaring five loose selectors should not outrank one that
    declares the exact slot in play. Scoring the winner makes the rank mean "how precisely
    does this lesson speak to something the run is dealing with", which is the question the
    ordering is for.

    The two node lanes share one scale on purpose. An open question is not inherently more
    lesson-worthy than a settled fact — the corpus's most valuable lesson is about what a
    KNOWN `loginuid` licenses — so tilting toward either half would bury one kind of advice
    behind the other rather than ranking by how precisely each speaks to this document.

    ALL THREE lanes share it, and the edge lane only really does since #935. The `max` below
    is what makes that a requirement rather than a nicety: two scores computed on scales that
    are not comparable still compare, silently, and the answer is whichever scale ran hotter.
    THE SCALE at the top of this module is the one place the weights are set, for exactly
    that reason.
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
    # EVERY item at the best score, not the first of them (#935 review). This used to be a
    # `max`, which returns the FIRST maximal element — so when a lesson tied across two cells,
    # which cell it was recorded against came down to the order the vertices happen to be
    # declared in. That was harmless while the answer was only rendered. `_spread_over_items`
    # made it load-bearing: it places a lesson by the item it matched, so an arbitrary winner
    # made block MEMBERSHIP a function of declaration order. The tie is not an edge case —
    # replayed over both committed runs it holds on nearly every fence, including for the
    # `attrs.loginuid` lesson this lane exists to retrieve, which ties across two cells on the
    # last two fences of `turnN-A`.
    #
    # SORTED, so the tuple is a function of the frontier's CONTENT rather than of the order it
    # was walked in — the same reason the ranking has a total tiebreak at all.
    return best, tuple(sorted({item for score, item in scored if score == best}))


def match_lessons(
    frontier: Frontier, corpus: Path, *, top_k: int = DEFAULT_TOP_K
) -> list[Hit]:
    """The `top_k` lessons the block is built from — the head of `_spread_over_items`' order.

    NOT simply "the `top_k` highest-scoring": the head covers as many DISTINCT frontier items as
    the matches allow before any one item takes a second slot, so a lower-scoring lesson about
    an unrepresented question outranks the runner-up on a question already covered (#935)."""
    # A NEGATIVE `top_k` would reach `hits[:top_k]` as a negative slice and return everything
    # BUT the last few — the opposite of a cap, on the one surface whose whole job is to bound
    # what the model is handed. Checked here as well as in `match_loaded` so an empty answer
    # costs no corpus walk.
    if frontier.is_empty() or top_k <= 0:
        return []
    return match_loaded(frontier, list(iter_lessons(corpus)), top_k=top_k)


def match_loaded(
    frontier: Frontier, lessons: list, *, top_k: int = DEFAULT_TOP_K
) -> list[Hit]:
    """`match_lessons` over an ALREADY-DRAINED corpus.

    Split out for the one caller that scores TWO frontiers — `runtime/tools._frontier_recall`
    asks the question again for the pre-write document to decide whether the block changed.
    `iter_lessons` re-opens and re-YAML-parses every file on every call, and it is the
    dominant cost of the whole lane, so the second score reads the first walk's bytes rather
    than re-reading files that cannot have changed in between.
    """
    if frontier.is_empty() or top_k <= 0:
        return []
    # MATERIALIZED, because `iter_lessons` is a GENERATOR and the caller that motivates this
    # split scores two frontiers off one walk. A generator passed here drains on the first
    # call and yields `[]` on the second, which makes `_frontier_recall`'s shape comparison
    # never equal and re-emits the block on every frontier-moving write — the churn the
    # second gate exists to prevent, with no error to notice it by.
    lessons = list(lessons)
    hits: list[Hit] = []
    candidate_items: list[tuple[str, ...]] = []
    for lesson in lessons:
        fm = lesson.fm
        match = _best_match(_parse_selectors(fm), frontier)
        if match is None:
            continue
        score, candidates = match
        # `candidates[0]` is a PLACEHOLDER — `_spread_over_items` picks which of the tied
        # items this lesson is finally recorded against, and rewrites `matched` to it.
        candidate_items.append(candidates)
        hits.append(Hit(
            path=lesson.path,
            name=str(fm.get("name") or lesson.path.stem),
            frontmatter=fm,
            score=score,
            matched=candidates[0],
        ))
    # Name is the LAST tiebreak so the order is total and stable: an unstable top-3 would make
    # the injected block churn between appends that changed nothing about the frontier.
    # Sorted TOGETHER, so each hit keeps its own candidate tuple across the reorder.
    # `strict`, because the two lists are built by one loop and a mismatch would silently
    # pair a hit with another lesson's candidate items rather than raise.
    ranked = sorted(
        zip(hits, candidate_items, strict=True),
        key=lambda pair: (-pair[0].score, pair[0].name),
    )
    return _spread_over_items(ranked)[:top_k]


def _spread_over_items(ranked: list[tuple[Hit, tuple[str, ...]]]) -> list[Hit]:
    """The ranked hits, re-ordered so the head COVERS distinct frontier items before it doubles
    up on one — the best lesson about each item first, then the second-best about each, and so
    on, score order inside every pass. Each hit is recorded against the item it was PLACED on.

    THE OTHER HALF OF THE REBALANCE (#935), and the scale alone is not enough without it. Two
    selectors at their lanes' floors are genuinely equally specific — `{type: T, slot: class}`
    says "this run has a vertex of type T" and `{anchor_kind: iam-policy}` says "this run has an
    undischarged contract anchored on iam-policy" — and no honest weight orders them. Only the
    `name` tiebreak could, which is how #919's motivating lesson got cut in the first place, and
    reweighting alone just changes WHICH lesson the alphabet evicts: against the real corpus on
    `turnN-A`, the two lessons keyed on `iam-policy` both matched the SAME contract `ac2`, took
    two of three slots between them, and cut the `attrs.loginuid` lesson a second time.

    So the ordering answers the question the block is actually for. It is three lines in front
    of a model that has to decide what to read; two lessons about one contract is strictly less
    of the frontier covered than one about the contract and one about the open attribute, and
    the second lesson on an item is not thereby lost — it is behind the first lesson on every
    OTHER item, which is where it belongs.

    EVERY item a lesson tied on, not one of them, and that is not a refinement (#935 review).
    A lesson frequently reaches its best score on several cells at once, and `_best_match` used
    to hand over whichever the walk saw first — so placing a lesson by its item made block
    MEMBERSHIP depend on the order vertices were declared in. Choosing the least-covered of a
    lesson's tied items instead makes the block a function of the frontier's content, and it is
    also simply the better answer: a lesson that CAN speak to something nothing else in the
    block covers should be recorded against that.

    TOTAL AND STABLE: `ranked` arrives sorted by `(-score, name)`, each candidate tuple is
    itself sorted, and the placement below is a single forward pass — so two calls on one
    frontier cannot disagree.

    Stable is NOT the same as order-insensitive, and the difference is a gate.
    `runtime/tools._frontier_recall` decides whether to inject by comparing WHICH lessons at
    WHICH scores, and it SORTS that comparison because this function makes the emitted order a
    property of coverage rather than of score alone; do not "simplify" it back to a list
    comparison, which would re-staple a byte-identical set of lessons whenever coverage
    reshuffled them.
    """
    used: dict[str, int] = {}
    keyed: list[tuple[int, int, Hit]] = []
    for position, (hit, candidates) in enumerate(ranked):
        # The least-covered of this lesson's tied items, ties inside that broken by the
        # candidate tuple's own sorted order — never by how the frontier was walked.
        item = min(candidates, key=lambda c: (used.get(c, 0), c))
        pass_index = used.get(item, 0)
        used[item] = pass_index + 1
        # `position` preserves the incoming `(-score, name)` order within a pass rather than
        # re-deriving it, so this function owns exactly one rule and cannot drift from the sort.
        keyed.append((pass_index, position, replace(hit, matched=item)))
    keyed.sort(key=lambda k: (k[0], k[1]))
    return [hit for _, _, hit in keyed]


def _render_frontmatter(fm: dict) -> str:
    """The lesson's frontmatter, minus bookkeeping, indented under its path.

    YAML rather than `str(value)` because the values are lists, and a Python repr keeps
    the brackets and quotes intact — which is not the spelling the model reads
    everywhere else. `build_corpus_manifest` dumps the same shape for the curator and drops
    the same `_corpus.PROVENANCE_KEYS`; this one drops the selectors on top, since the
    matching key is the QUERY and the `matched` line already says what actually hit.
    """
    import yaml

    kept = {k: v for k, v in fm.items() if k not in HIDDEN_KEYS}
    # `yaml.safe_dump({})` is the literal `{}`, so a lesson carrying only selectors and
    # bookkeeping would render one line of pure noise under its path. The `matched` line above
    # already says everything that lesson has to say here.
    if not kept:
        return ""
    # `width` is effectively unbounded so a long `description` stays on ONE physical line.
    # safe_dump's 80-column default folds it and the 2-space indent below then lands on the
    # continuation lines too, so the one field SKILL.md tells the model to judge relevance from
    # arrives looking like a nested YAML block under its own key.
    #
    # `default_flow_style=None` — INLINE for the leaf lists, block for the mapping. This is the
    # one place this dump diverges from `build_corpus_manifest`'s `False`, and deliberately:
    # the dimension lists are spelled `[a, b]` on one physical line in every lesson file, and
    # both prompts REQUIRE that spelling (`SKILL.md` §Lessons, `learning/author/lessons/
    # prompt.md`) so a single grep matches. Exploding them into block sequences showed the
    # model a form it is told never to write, and cost ~12 of a 3-hit block's ~30 lines —
    # on a surface this function's own comment calls out as paid for many times per run.
    dumped = yaml.safe_dump(
        kept, sort_keys=True, default_flow_style=None, allow_unicode=True, width=10**9
    )
    return "\n".join(f"  {line}" for line in dumped.strip().splitlines())


def render(hits: list[Hit]) -> str:
    """The injected block. Empty string when nothing matched — the caller decides whether
    silence or a loud-empty is right for its surface.

    The path is ABSOLUTE, and that is a gate requirement rather than a style choice. MAIN's
    `cwd_anchor` is the RUN DIR (`MAIN_DEF` sets no `anchors_on_tree`), so `_resolve_operand`
    rebases a relative operand onto the run dir and `decide_read` refuses
    `defender/lessons/<name>.md` outright — `test_grant_gate_575.py::test_a11` pins that
    spelling as DENY, noting "nothing hands MAIN that spelling any more". This block is the
    second thing that hands MAIN a lesson path, so it emits what the first one does:
    `lessons_fm._emit_match` prints `path.resolve()` for exactly this reason, and an absolute
    operand bypasses every anchor, which is how the lessons lane works at all.
    """
    if not hits:
        return ""
    # The read discipline lives HERE rather than in SKILL.md because it is about the block in
    # front of the model: which of these to open, and what a hit does and does not license. The
    # spec keeps only what is true when NO block arrives, which a return cannot say.
    # "your record", not "the open frontier" — this fires on settled cells too.
    # ONE line, and the hits start at index 1 — `test_the_block_hands_main_a_path_its_own_gate
    # _will_read` reads the first hit positionally, and this block is re-injected on every
    # frontier-moving write, so every line here is paid for many times per run.
    lines = [
        "### Lessons matched against your record — pushed because this write moved it. "
        "Precedent, not evidence: judge each from its `description`, "
        "Read only the bodies that fit.",
    ]
    for hit in hits:
        # `matched` is the model's ONLY account of why this lesson was pushed: `HIDDEN_KEYS`
        # strips the selectors, so without this line the block is an unexplained list.
        lines.append(f"- {hit.path.resolve()} — matched {hit.matched}")
        if body := _render_frontmatter(hit.frontmatter):
            lines.append(body)
    return "\n".join(lines)


def _positive_int(raw: str) -> int:
    """`--top-k 0` returns nothing and `--top-k -1` used to return everything but the last
    hit; argparse takes a leading `-N` as this option's value, so the bound has to be here."""
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
    ap.add_argument("--investigation", required=True, help="Path to the investigation.md to derive the frontier from")
    ap.add_argument("--top-k", type=_positive_int, default=DEFAULT_TOP_K, help=f"How many lessons to return (default {DEFAULT_TOP_K})")
    ap.add_argument("--corpus", help=f"Relocated {CORPUS_NAME} directory (worktree or fixture); the leaf name must still be {CORPUS_NAME}")
    ns = ap.parse_args(argv[1:])

    corpus = resolve_corpus(ns.corpus, DEFAULT_CORPUS, ap)
    # The MISSING corpus is reported for the same reason the read error below is, and it is
    # the arm that was silent: `resolve_corpus` validates the leaf NAME only, and
    # `iter_lesson_paths` answers `[]` for a directory that is not there — so a mistyped
    # relocation exited 0 with no output, which is this tool's spelling of "nothing matched".
    # `runtime/tools._frontier_recall` already refuses to be quiet about the same fault.
    if not corpus.is_dir():
        print(f"error: no {CORPUS_NAME} corpus at {corpus}", file=sys.stderr)
        return 2
    from defender._io import read_text_soft
    from defender.skills.invlang.frontier import frontier_from_text

    # The read error is REPORTED, not swallowed: empty output already means "nothing open
    # matched", so a typo'd path or a run dir with no investigation.md yet would otherwise be
    # indistinguishable from a truthful answer.
    text, err = read_text_soft(Path(ns.investigation))
    if text is None:
        print(f"error: cannot read {ns.investigation}: {err}", file=sys.stderr)
        return 2
    out = render(match_lessons(frontier_from_text(text), corpus, top_k=ns.top_k))
    if out:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
