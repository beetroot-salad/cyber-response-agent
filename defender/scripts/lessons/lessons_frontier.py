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

from defender.skills.invlang.frontier import (
    Frontier,
    HeldFact,
    OpenContract,
    OpenSlot,
)
from defender.skills.invlang.validate import class_slots, is_open_slot

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
        what the class pattern managed to pin against a particular case."""
        # ONE BOUND COMPONENT EACH, and `type` is conditioned exactly as `slot` is: an
        # omitted `type` constrains nothing (`_node_match_score` skips the comparison), so
        # crediting it would rank a match-any-vertex selector level with one that named the
        # type. `_EdgeSelector` has always counted only declared fields; this is the same rule.
        #
        # KNOWN IMBALANCE, not a knob: `_node_selector` DROPS a selector missing `type` or
        # `slot`, so in practice this is a constant 2 — the node lane's floor — while an
        # `anchor_kind`-only edge selector (every shipped `frontier_edges` entry, and the only
        # shape available for a contract on a proposed edge) floors at 1. `_best_match` pools
        # both lanes into one `max` and `match_loaded` cuts at `top_k`, so an edge lesson is
        # outranked by ANY node match, and held facts accumulate — the edge lane goes dark
        # once three node selectors match. Raising the edge floor is not the fix on its own:
        # at 2 it TIES with a bare node match and the `name` tiebreak then evicts whichever
        # lesson sorts later. Both lanes need more resolution than "2", which is #919
        # follow-up work rather than a knob to turn here.
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
    observed: list[_NodeSelector] = field(default_factory=list)


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
    case = class_slots(case_class)
    if len(sel) > len(case):
        # A WHOLLY-open case class says nothing about its own arity either, so refusing an
        # explicit triple against it would make the MOST open cell match the FEWEST selectors
        # — the inverse of what the inversion exists for. Keyed on "every slot is open"
        # rather than on "exactly one slot": `??/??` is as silent about its arity as `??` is,
        # and gating on the length made the match NON-MONOTONIC — a document refined from
        # `??` to `??/??` lost a three-slot selector that the less-informative `??` matched.
        #
        # STILL NON-MONOTONIC one arity over, and this branch cannot fix it: for
        # `sel="ip-only/internet/novel"`, case `??/??` matches but `ip-only/??` falls to the
        # `return None` below, so refining slot 0 of a SHORT tuple drops a selector the
        # document matched one write earlier. The real answer is that class-tuple arity is a
        # documented function of the vertex TYPE (SKILL.md §Classification grammar,
        # `vocab.SLOTS`) and `_node_match_score` has already agreed on the type before it gets
        # here — so both sides should be normalized to the type's arity in the frontier rather
        # than guessed at from the cell. #919 follow-up.
        if all(is_open_slot(c) for c in case):
            case = list(case) + ["??"] * (len(sel) - len(case))
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
    pinned = _class_pins(sel.class_pattern, item.class_tuple)
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


def _best_match(selectors: _Selectors, frontier: Frontier) -> tuple[int, str] | None:
    """The single most specific selector this lesson has that the frontier satisfies.

    BEST, not sum: a lesson declaring five loose selectors should not outrank one that
    declares the exact slot in play. Scoring the winner makes the rank mean "how precisely
    does this lesson speak to something the run is dealing with", which is the question the
    ordering is for.

    The two node lanes share one scale on purpose. An open question is not inherently more
    lesson-worthy than a settled fact — the corpus's most valuable lesson is about what a
    KNOWN `loginuid` licenses — so tilting toward either half would bury one kind of advice
    behind the other rather than ranking by how precisely each speaks to this document.
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
    # `max` with a key returns the FIRST maximal element, which is the tie-break the two
    # hand-rolled `>` accumulators had — one rule now instead of two that can drift apart.
    return max(scored, key=lambda m: m[0], default=None)


def match_lessons(
    frontier: Frontier, corpus: Path, *, top_k: int = DEFAULT_TOP_K
) -> list[Hit]:
    """The `top_k` lessons that speak most precisely to something still open."""
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
    for lesson in lessons:
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
