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
`frontier_edges`). A lesson declaring neither is not excluded — it simply scores zero and
sorts last, which is why this ships no "empty selectors are invalid" gate: two lessons in
the sibling environment corpus are legitimately unscoped, and a birth-time gate would only
buy fabricated selectors.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._tsv import flatten_cell
from defender.scripts.lessons._lessons_common import (
    as_list,
    iter_lessons,
    reexec_into_venv,
    rel_to_repo,
    resolve_corpus,
    use_utf8_stdio,
)

if __name__ == "__main__":
    reexec_into_venv(__file__)

import argparse

from defender.skills.invlang.frontier import Frontier, OpenContract, OpenSlot

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CORPUS = REPO_ROOT / "defender" / "lessons"
CORPUS_NAME = DEFAULT_CORPUS.name

#: Bookkeeping keys the model gains nothing from. The same set `learning/author/shared.py`
#: drops when it renders the corpus manifest into the curator prompt — one definition of
#: "provenance, not content" rather than two that can drift.
PROVENANCE_KEYS = frozenset(
    {"source_finding_ids", "source_observation_ids", "created_at", "recorded_at"}
)

#: The selectors are the QUERY, not the answer. Echoing a lesson's own matching key back to
#: the model costs six lines per hit and tells it nothing the `matched` line does not already
#: say more precisely — that one names the vertex and value that actually hit.
SELECTOR_KEYS = frozenset({"frontier_nodes", "frontier_edges"})

#: Everything the injected block leaves out: bookkeeping plus mechanism.
HIDDEN_KEYS = PROVENANCE_KEYS | SELECTOR_KEYS

DEFAULT_TOP_K = 3

WILDCARD = "*"


@dataclass(frozen=True)
class Hit:
    path: Path
    name: str
    description: str
    frontmatter: dict
    score: int
    matched: str


@dataclass(frozen=True)
class _NodeSelector:
    type: str
    class_pattern: str
    slot: str

    @property
    def specificity(self) -> int:
        # The type and the slot are one bound component each; the class contributes one per
        # slot it actually pins. A bare `*` pins nothing and is worth nothing, which is what
        # makes `(type, class, slot)` outrank `(type, slot)` without a tuning constant.
        bound = sum(1 for s in _slots(self.class_pattern) if s and s != WILDCARD)
        return 1 + bound + (1 if self.slot else 0)


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
    return [s.strip() for s in (class_pattern or "").split("/")]


def _is_open(slot_value: str) -> bool:
    v = (slot_value or "").strip()
    return v == "??" or v.startswith("{")


def class_match(selector_class: str, case_class: str) -> bool:
    """Slot-wise containment, with the OPEN case slot as a wildcard.

    The environment corpus's matcher (`lessons_env_retrieve.py:_class_match`) wildcards on
    the SELECTOR side only, so a case vertex carrying `??` matches nothing — and
    `learning/core/prologue.py` states that assumption outright: "an unresolved slot cannot
    satisfy a selector anyway". True there, and exactly backwards here. This retrieval exists
    to serve the slots that are still OPEN, so an open case slot has to match any selector:
    the whole point is to hand over the lesson that says what closing it would license.

    That inversion is why this is a second matcher rather than an edit to the first. Changing
    the environment one would change what the benign and malicious ACTORS retrieve, which is
    a different mechanism serving different callers and no part of this change.

    Fewer selector slots still match more (`web-server` matches `web-server/internal/x`).
    """
    sel = _slots(selector_class)
    case = _slots(case_class)
    if len(sel) > len(case):
        return False
    return all(
        s == WILDCARD or _is_open(case[i]) or s == case[i]
        for i, s in enumerate(sel)
        if s
    )


def _node_matches(sel: _NodeSelector, slot: OpenSlot) -> bool:
    if sel.type and sel.type != slot.type:
        return False
    if sel.slot and sel.slot != slot.slot:
        return False
    return class_match(sel.class_pattern, slot.class_tuple)


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
    best: tuple[int, str] | None = None
    for node_sel in selectors.nodes:
        for slot in frontier.slots:
            if _node_matches(node_sel, slot):
                cand = (
                    node_sel.specificity,
                    f"{slot.vertex_id} {slot.type} {slot.slot}={slot.value}",
                )
                if best is None or cand[0] > best[0]:
                    best = cand
    for edge_sel in selectors.edges:
        for contract in frontier.contracts:
            if _edge_matches(edge_sel, contract):
                cand = (
                    edge_sel.specificity,
                    f"{contract.contract_id} on {contract.hypothesis_id} "
                    f"anchor={contract.anchor_kind}",
                )
                if best is None or cand[0] > best[0]:
                    best = cand
    return best


def match_lessons(
    frontier: Frontier, corpus: Path, *, top_k: int = DEFAULT_TOP_K
) -> list[Hit]:
    """The `top_k` lessons that speak most precisely to something still open."""
    if frontier.is_empty():
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
            description=flatten_cell(str(fm.get("description") or "")).strip(),
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
    everywhere else. `build_corpus_manifest` dumps the same frontmatter the same way for the
    curator; one rendering of a lesson's keys rather than two.
    """
    import yaml

    kept = {k: v for k, v in fm.items() if k not in HIDDEN_KEYS}
    dumped = yaml.safe_dump(
        kept, sort_keys=True, default_flow_style=False, allow_unicode=True
    )
    return "\n".join(f"  {line}" for line in dumped.strip().splitlines())


def render(hits: list[Hit], *, repo_root: Path = REPO_ROOT) -> str:
    """The injected block. Empty string when nothing matched — the caller decides whether
    silence or a loud-empty is right for its surface."""
    if not hits:
        return ""
    lines = [
        "### Lessons for the open frontier "
        "(precedent, not evidence — Read the body before you rely on one)",
    ]
    for hit in hits:
        lines.append(f"- {rel_to_repo(hit.path, repo_root)} — matched {hit.matched}")
        lines.append(_render_frontmatter(hit.frontmatter))
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    use_utf8_stdio()
    ap = argparse.ArgumentParser(
        prog="lessons_frontier.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--investigation", required=True, help="Path to the investigation.md to derive the frontier from")
    ap.add_argument("--top-k", type=int, default=DEFAULT_TOP_K, help=f"How many lessons to return (default {DEFAULT_TOP_K})")
    ap.add_argument("--corpus", help=f"Relocated {CORPUS_NAME} directory (worktree or fixture); the leaf name must still be {CORPUS_NAME}")
    ns = ap.parse_args(argv[1:])

    corpus = resolve_corpus(ns.corpus, DEFAULT_CORPUS, ap)
    from defender._io import read_text_soft
    from defender.skills.invlang.frontier import frontier_from_text

    text, _err = read_text_soft(Path(ns.investigation))
    frontier = frontier_from_text(text) if text is not None else Frontier((), ())
    out = render(match_lessons(frontier, corpus, top_k=ns.top_k))
    if out:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
