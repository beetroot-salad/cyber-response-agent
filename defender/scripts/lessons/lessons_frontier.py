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
from dataclasses import dataclass, field
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

from defender.skills.invlang.frontier import Frontier, OpenContract, OpenSlot
from defender.skills.invlang.validate import class_slots, has_open_slot

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CORPUS = REPO_ROOT / "defender" / "lessons"
CORPUS_NAME = DEFAULT_CORPUS.name

#: The selectors are the QUERY, not the answer. Echoing a lesson's own matching key back to
#: the model costs six lines per hit and tells it nothing the `matched` line does not already
#: say more precisely — that one names the vertex and value that actually hit.
SELECTOR_KEYS = frozenset({"frontier_nodes", "frontier_edges"})

#: Everything the injected block leaves out: bookkeeping plus mechanism.
HIDDEN_KEYS = PROVENANCE_KEYS | SELECTOR_KEYS

DEFAULT_TOP_K = 3

WILDCARD = "*"


@dataclass(frozen=True, eq=False)
class Hit:
    #: `eq=False` (so no `__hash__` either): `frontmatter` is a dict, so the frozen default
    #: would advertise a `__hash__` that raises the moment anyone puts a `Hit` in a set.
    path: Path
    name: str
    frontmatter: dict
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
        what the class pattern managed to pin against a particular case."""
        # ONE BOUND COMPONENT EACH, and `type` is conditioned exactly as `slot` is: an
        # omitted `type` constrains nothing (`_node_match_score` skips the comparison), so
        # crediting it would rank a match-any-vertex selector level with one that named the
        # type. `_EdgeSelector` has always counted only declared fields; this is the same rule.
        return (1 if self.type else 0) + (1 if self.slot else 0)


@dataclass(frozen=True)
class _EdgeSelector:
    rel: str
    auth_kind: str
    anchor_kind: str

    @property
    def specificity(self) -> int:
        return sum(1 for v in (self.rel, self.auth_kind, self.anchor_kind) if v)


@dataclass
class _Selectors:
    nodes: list[_NodeSelector] = field(default_factory=list)
    edges: list[_EdgeSelector] = field(default_factory=list)


def _slots(class_pattern: str) -> list[str]:
    """THE class split, borrowed from the validator rather than re-spelled.

    `validate.has_open_slot` uses `class_slots` to decide a class cell is open, and this
    module re-splits the same cell to decide which selector matches it. A plainer
    `split("/")` here made the two halves of one join disagree: the primary candidate-set
    form `{a/b/c, d/e/f}` is ONE unresolved slot to the validator and five fragments to a
    naive split (of which `b` reads as CONCRETE), and a `compute:` type prefix — a spelling
    `class_slots`'s own docstring says models reach for — survived to be compared against a
    selector that never carries one.
    """
    return class_slots(class_pattern)


def _is_open(slot_value: str) -> bool:
    """Is this ONE already-split slot unresolved — the same predicate that put it on the
    frontier. `has_open_slot` rather than a local `startswith("{")`: the local spelling read
    `{a} b` as open and missed nothing the anchored test misses, so the cell that decided the
    slot was open and the cell that wildcards it can no longer disagree."""
    return has_open_slot(slot_value)


def _class_pins(selector_class: str, case_class: str) -> int | None:
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
    `{class: client-cert}` alike; scoring those 3 put them above `{type: process,
    slot: attrs.loginuid}` at 2 — so on the append that opened #919's own motivating slot the
    top-3 was saturated by lessons the document says nothing about, the loginuid lesson was
    cut, and (because `_frontier_recall` diffs the rendered block) no lessons block was
    emitted at all.

    ANCHORED, not per-slot: once ONE slot matches by equality the pattern is tied to this
    cell, and the further slots it names are the extra precision the ranking is for
    (`ip-only/internet` over `ip-only` against `ip-only/??/??`). A pattern with no equality
    anywhere pins nothing, exactly as a bare `*` does.
    """
    sel = _slots(selector_class)
    case = _slots(case_class)
    if len(sel) > len(case):
        # A case class that is ONE wholly-open cell says nothing about its own arity either,
        # so refusing an explicit triple against it would make the MOST open cell match the
        # FEWEST selectors — the inverse of what the inversion exists for.
        if len(case) == 1 and _is_open(case[0]):
            case = case * len(sel)
        else:
            return None
    pinned = 0
    anchored = False
    for i, s in enumerate(sel):
        if not s or s == WILDCARD:
            continue
        pinned += 1
        if s == case[i]:
            anchored = True
        elif not _is_open(case[i]):
            return None
    return pinned if anchored else 0


def _node_match_score(sel: _NodeSelector, slot: OpenSlot) -> int | None:
    """How precisely this selector speaks to this open slot — `None` when it does not match.

    Scored on the MATCH rather than on the selector, so a component that constrained nothing
    (an omitted `type`, a class slot that landed on a `??`) earns nothing. See `_class_pins`.
    """
    if sel.type and sel.type != slot.type:
        return None
    if sel.slot and sel.slot != slot.slot:
        return None
    pinned = _class_pins(sel.class_pattern, slot.class_tuple)
    if pinned is None:
        return None
    return sel.fixed_specificity + pinned


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


def _parse_selectors(fm: dict) -> _Selectors:
    out = _Selectors()
    for raw in as_list(fm.get("frontier_nodes")):
        if not isinstance(raw, dict):
            continue
        out.nodes.append(_NodeSelector(
            type=str(raw.get("type") or "").strip(),
            class_pattern=str(raw.get("class") or WILDCARD).strip(),
            slot=str(raw.get("slot") or "").strip(),
        ))
    for raw in as_list(fm.get("frontier_edges")):
        if not isinstance(raw, dict):
            continue
        out.edges.append(_EdgeSelector(
            rel=str(raw.get("rel") or "").strip(),
            auth_kind=str(raw.get("auth_kind") or "").strip(),
            anchor_kind=str(raw.get("anchor_kind") or "").strip(),
        ))
    return out


def _best_match(selectors: _Selectors, frontier: Frontier) -> tuple[int, str] | None:
    """The single most specific selector this lesson has that the frontier satisfies.

    BEST, not sum: a lesson declaring five loose selectors should not outrank one that
    declares the exact slot in play. Scoring the winner makes the rank mean "how precisely
    does this lesson speak to something open", which is the question the ordering is for.
    """
    scored: list[tuple[int, str]] = [
        (score, f"{slot.vertex_id} {slot.type} {slot.slot}={slot.value}")
        for node_sel in selectors.nodes
        for slot in frontier.slots
        if (score := _node_match_score(node_sel, slot)) is not None
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
    # `max` with a key returns the FIRST maximal element, which is the tie-break the two
    # hand-rolled `>` accumulators had — one rule now instead of two that can drift apart.
    return max(scored, key=lambda m: m[0], default=None)


def match_lessons(
    frontier: Frontier, corpus: Path, *, top_k: int = DEFAULT_TOP_K
) -> list[Hit]:
    """The `top_k` lessons that speak most precisely to something still open."""
    # A NEGATIVE `top_k` would reach `hits[:top_k]` as a negative slice and return everything
    # BUT the last few — the opposite of a cap, on the one surface whose whole job is to bound
    # what the model is handed.
    if frontier.is_empty() or top_k <= 0:
        return []
    hits: list[Hit] = []
    for lesson in iter_lessons(corpus):
        fm = lesson.fm
        match = _best_match(_parse_selectors(fm), frontier)
        if match is None:
            continue
        score, why = match
        hits.append(Hit(
            path=lesson.path,
            name=str(fm.get("name") or lesson.path.stem),
            frontmatter=fm,
            score=score,
            matched=why,
        ))
    # Name is the tiebreak so the order is total and stable: an unstable top-3 would make the
    # injected block churn between appends that changed nothing about the frontier.
    hits.sort(key=lambda h: (-h.score, h.name))
    return hits[:top_k]


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
    dumped = yaml.safe_dump(
        kept, sort_keys=True, default_flow_style=False, allow_unicode=True
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
    lines = [
        "### Lessons for the open frontier "
        "(precedent, not evidence — Read the body before you rely on one)",
    ]
    for hit in hits:
        # `matched` is the model's ONLY account of why this lesson was pushed: `HIDDEN_KEYS`
        # strips the selectors, so without this line the block is an unexplained list.
        lines.append(f"- {hit.path.resolve()} — matched {hit.matched}")
        lines.append(_render_frontmatter(hit.frontmatter))
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
