"""The FRONTIER of a live investigation — what the document has not settled yet.

Retrieval that keys on the alert signature asks "which rule fired". A lesson about what
an observation *licenses* has a trigger condition that has nothing to do with which rule
fired: it is relevant once the field is in hand. This module answers the other question —
"what is still open, right now" — so retrieval can key on that instead (#919).

invlang closes open things two ways, and the frontier is typed to match (SKILL.md):

  * a `??` / `{a, b}` slot on a `:V` vertex — its class tuple, its `ident`, or an
    `attrs.<name>` value — closed by a `:R attr_updates` row. NODE-anchored.
  * an `ac<n>` authorization contract declared under `:H h-NNN.authz`, closed by a
    `:R authz` row carrying an `authorized` verdict. EDGE-anchored, via `edge_ref`.

Impact contracts (`ip*`) are deliberately absent: SKILL.md:19 names them in prose, but
there is no `ip` sub-block in the parser's `_HYP_PREFIX_RE`, no TypedDict, and
`COMMITMENT_ID_RE` does not admit the id — only the `:R impact` RESOLUTION side exists.
There is nothing to compute an unfulfilled impact contract from.

DERIVED, NEVER STORED. Every entry point takes the document (or its parse) and returns a
fresh answer, mirroring the discipline `runtime/tools.py` states for the repair window: a
frontier that is recomputed cannot go stale or disagree with the file.

BOTH AXES CALL THE GATE'S OWN WALK rather than restating it — `_open_contracts` calls
`outstanding_authz_contracts`, `_node_state` calls `iter_vertex_cells` (PR-930). So the two
KNOWN DIVERGENCES below are no longer two implementations that happen to differ; each is one
explicit knob on a shared walk, and neither can drift.

  1. `ident` is INCLUDED here and EXCLUDED there (`IDENT_REFINEMENT_KEY` notes why) — the
     shared walk's `include_ident` flag. Deliberate: an unresolved identifier is the single
     most retrieval-worthy open slot there is — "which host is this IP" is exactly the question
     a standing deployment fact answers — while the disposition gate has its own reasons for
     not blocking a close on it.
  2. A `:R attr_updates` row may legally target an EDGE (`l-001|e-001|attrs.auth_method|??`;
     see `_check_attr_update_targets`). The gate reads that as an open slot and blocks; this
     module DROPS it, because an `OpenSlot` carries a vertex `type` for a selector to match
     and an `:E` row has no such type. So an authz question opened on an edge attribute
     recalls nothing. NOT deliberate — a limitation of the node axis's shape, which is why it
     is a filter in `_node_state` and not a flag on the shared walk: the gate must keep
     blocking on those cells, so the walk has to keep reporting them.

This module must never be wired into that gate.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

from . import _walkers, vocab
from .parser import INVLANG_FENCE_RE
from .schema import CompanionBody
from .validate import (
    auth_kind_of,
    iter_vertex_cells,
    outstanding_authz_contracts,
)

#: The `slot` spellings an `OpenSlot` can carry — `class`, `ident`, `attrs.<name>` — are NOT
#: re-exported here. They are `validate.SLOT_CLASS` / `SLOT_IDENT` / `ATTR_PREFIX`, owned there
#: because that is where the `:R attr_updates` key grammar is enforced
#: (`_is_legal_refinement_key`) and where the walk that reports these slots lives. A re-export
#: with no importer is a second name for one constant, which is the drift it would claim to
#: prevent. Nor does anything downstream import them: a lesson's `slot:` is authored YAML and
#: `lessons_frontier` compares it to `cell.slot` with `!=`, so the join is held by the corpus
#: matching the walk, not by a shared symbol.
__all__ = [
    "Frontier",
    "FrontierAt",
    "HeldFact",
    "OpenContract",
    "OpenSlot",
    "derive_frontier",
    "frontier_at",
    "frontier_from_text",
]

# A contract counts as still-open unless a `:R authz` row DISCHARGES it, and only an
# `authorized` verdict discharges.
#
# The frontier does not re-decide that: `_open_contracts` CALLS
# `validate.outstanding_authz_contracts`, so the two read one definition rather than two that
# agree by inspection. That matters because the rule is not "is there an `authorized` row for
# this id" — a shared `ac*` id (legal once the other declarer is refuted) is scoped by ANCHOR
# KIND, so an `iam-policy` row does not discharge an `approved-source-list` contract that
# happens to carry the same number. It also lands where the lessons are: a verdict that
# forces escalation is exactly when "what this anchor can and cannot conclude" is worth
# reading.


@dataclass(frozen=True)
class OpenSlot:
    """One unresolved cell on one vertex, after every `:R attr_updates` row has been applied."""

    vertex_id: str
    type: str
    class_tuple: str
    slot: str
    value: str


@dataclass(frozen=True)
class HeldFact:
    """One cell on one vertex that the document has SETTLED — the mirror of `OpenSlot`.

    Why the retrieval needs both halves. An open slot is a question the run has not answered;
    a held fact is one it has. Lessons divide the same way, and the corpus is mostly the
    second kind: "`loginuid=-1` licenses non-interactive automated context and nothing more"
    is advice about a value you are HOLDING, and it is worthless while the field is unknown.
    Keying only on open slots made #919's own motivating lesson unreachable — the alert
    carries `loginuid=-1` concretely, so the slot it keys on never opens.

    Same shape as `OpenSlot` so one matcher serves both: `_class_pins`' open-slot wildcard
    simply never fires on these, and degrades to ordinary equality, which is what a settled
    class wants anyway.

    Held facts accumulate as open slots close, so in practice this half of the state grows on
    almost every write. NOT a monotonicity guarantee: `_seed_vertex_state`'s attributes arm is
    an unconditional last-wins `update`, so a re-observation carrying `attrs.kind=??` turns a
    held fact back into an open slot (and re-blocks a benign close). Emission is gated on the
    rendered recall CHANGING rather than on the state being non-empty or larger, which is
    correct either way — see `runtime/tools._frontier_recall`.
    """

    vertex_id: str
    type: str
    class_tuple: str
    slot: str
    value: str


@dataclass(frozen=True)
class OpenContract:
    """One declared authorization contract with no discharging `:R authz` row.

    `rel` and `auth_kind` are resolved from the `:E` row `edge_ref` names, and are `None`
    when it names none — which is the ordinary case, since `edge_ref` defaults to
    `vocab.UNOBSERVED_EDGE_REF` ("proposed") for a contract on an edge nobody observed yet.
    A selector naming `rel` therefore cannot match a proposed-edge contract, which is
    correct: there is no relation to match against.
    """

    contract_id: str
    hypothesis_id: str
    anchor_kind: str
    edge_ref: str
    rel: str | None
    auth_kind: str | None


@dataclass(frozen=True)
class Frontier:
    """The investigation's retrieval state: what is still open, and what it now holds."""

    slots: tuple[OpenSlot, ...]
    contracts: tuple[OpenContract, ...]
    held: tuple[HeldFact, ...] = ()

    def is_empty(self) -> bool:
        return not self.slots and not self.contracts and not self.held


def _edge_index(companion: CompanionBody) -> dict[str, tuple[str | None, str | None]]:
    """Each `:E` id → `(relation, authority kind)`, first NON-EMPTY declaration winning.

    Per-FIELD rather than per-ROW, which is the one place this departs from
    `validate._by_id_first` and `_walkers.vertex_types`. Those index whole records, and a whole
    record is the right unit when the question is "what did the declaring site say". Here the
    question is "what does the document know about this edge", and an `:E` row may leave the
    authority column empty and have a later `observations.edges` row supply it — legal,
    diagnostic-free, and exactly the shape a lesson about anchor strength keys on. A value the
    first row already filled is still immutable.

    (`_check_strong_move_provenance` builds its own LAST-wins `auth_by_edge`; the two agree on
    every document where a field is declared once, which is all of them today, and reconciling
    the wins policy is out of scope here.)
    """
    index: dict[str, tuple[str | None, str | None]] = {}
    for e in _walkers.all_edges(companion):
        eid = e.get("id")
        if not isinstance(eid, str):
            continue
        kind = auth_kind_of(e)
        rel = e.get("relation")
        rel = rel if isinstance(rel, str) else None
        kind = kind if isinstance(kind, str) else None
        # FIRST-WINS on the VALUE, not on the ROW. A re-observation is how an append-only
        # document SUPPLIES a field the declaring row left blank — an `:E` row whose authority
        # column was empty in the prologue and carries `authoritative-source:cmdb` in a lead's
        # `observations.edges` is legal, draws no diagnostic, and is exactly the shape where
        # the authority is worth keying on. Refusing the whole later row would leave
        # `auth_kind=None` forever and make every `frontier_edges` selector naming `auth_kind`
        # miss on the documents that learned it. A field the first row already filled is still
        # immutable here.
        #
        # ONE expression for the rule, first row included: the seed is `(None, None)`, so a
        # new id takes `(rel, kind)` by the same coalesce a later row does.
        first_rel, first_kind = index.get(eid, (None, None))
        index[eid] = (first_rel or rel, first_kind or kind)
    return index


def _node_state(companion: CompanionBody) -> tuple[list[OpenSlot], list[HeldFact]]:
    """Both halves of the node axis, over `validate.iter_vertex_cells` — the ONE node walk.

    CALLED, not restated, the way `_open_contracts` calls `outstanding_authz_contracts`: the
    open/held boundary and the gate's blocking boundary are now the same code reading the same
    fold, so they cannot drift. What stays here is only what this axis adds — the vertex `type`
    a selector matches against, and the drop that needing one forces.

    The two lists are complements over the POPULATED cells, not over every cell: a `VertexCell`
    may be `CELL_EMPTY`, which is neither an open question nor a held fact."""
    types = _walkers.vertex_types(companion)
    open_out: list[OpenSlot] = []
    held_out: list[HeldFact] = []
    for cell in iter_vertex_cells(companion, include_ident=True):
        # `effective_vertex_state` fabricates an entry for any `:R attr_updates` TARGET, and
        # the validator admits an `e-*` there — so an id with no `:V` row is an edge or a typo,
        # and either way carries no vertex type to match a selector against. The shared walk
        # still REPORTS those cells, because the benign gate blocks on them; dropping them is
        # this axis's business, and the module docstring records what it costs.
        typ = types.get(cell.vertex_id)
        if typ is None:
            continue
        if cell.is_open:
            open_out.append(
                OpenSlot(cell.vertex_id, typ, cell.classification, cell.slot, cell.value)
            )
        elif cell.is_held:
            held_out.append(
                HeldFact(cell.vertex_id, typ, cell.classification, cell.slot, cell.value)
            )
    return open_out, held_out


def _open_contracts(companion: CompanionBody) -> list[OpenContract]:
    # `outstanding_authz_contracts` IS the gate's definition, called rather than restated, so
    # the two cannot disagree about which contracts are still owed an answer. It already
    # applies both scopes this lane needs — LIVE hypotheses only (a refuted declarer's
    # contract blocks nothing and owes nothing), and `authorized`-only discharge with a SHARED
    # `ac*` id resolved by anchor kind. A local bare-id discharge set got that last part
    # wrong: one `iam-policy` row cleared a same-numbered `approved-source-list` contract the
    # gate was still blocking on, and the frontier reported settled what the close could not.
    #
    # This walk adds only what the EDGE axis keys on and the gate has no use for: the
    # `edge_ref`, and the `rel` / `auth_kind` read off the `:E` row it names.
    edges = _edge_index(companion)
    out: list[OpenContract] = []
    for hid, c, _why in outstanding_authz_contracts(companion):
        cid = c.get("id")
        if not isinstance(cid, str) or not cid:
            continue
        # `edge_ref` is anchored at the PARSE boundary — `parser._hyp_sub_authz_row` writes
        # `rec.get("edge_ref", UNOBSERVED_EDGE_REF) or UNOBSERVED_EDGE_REF`, and
        # `AuthorizationContract` types the key non-optional. This read MIRRORS that expression
        # rather than half of it: `.get(k, default)` alone does not fire when the key is present
        # and falsy, and a `None`/`""` `edge_ref` reaching `edges.get(...)` misses every `:E`
        # row, so a contract on a fully observed edge reports `rel=None, auth_kind=None` and
        # reads as PROPOSED — silently withholding it from every selector naming either field.
        edge_ref = c.get("edge_ref") or vocab.UNOBSERVED_EDGE_REF
        rel, auth_kind = edges.get(edge_ref, (None, None))
        out.append(OpenContract(
            contract_id=cid,
            hypothesis_id=hid,
            anchor_kind=(c.get("anchor_kind") or "").strip(),
            edge_ref=edge_ref,
            rel=rel,
            auth_kind=auth_kind,
        ))
    return out


def derive_frontier(companion: CompanionBody) -> Frontier:
    """The open set for an already-parsed document."""
    slots, held = _node_state(companion)
    return Frontier(
        slots=tuple(slots),
        contracts=tuple(_open_contracts(companion)),
        held=tuple(held),
    )


def frontier_from_text(text: str) -> Frontier:
    """Parse and derive in one step. NEVER raises.

    The callers are a live tool return and a retrieval shim, both of which run against a
    document the model is still writing. `parse_dense_companion` is already total — every
    `RowError` is caught and demoted to a `ParseWarning` — but a half-written block can
    still project a shape the walkers read oddly, and no partial document is worth turning
    into a failed tool call on a write that already landed. An empty frontier is the honest
    answer to "what is open here" when the document cannot be read.

    LOUD on stderr, though. Failing open silently makes a bug in this module indistinguishable
    from "nothing is open" — the feature would disable itself on every append, forever, with
    no test red and no operator signal. The write still succeeds; only the log knows.
    `derive_frontier({})` already answers the empty-companion case, so one try and one
    sentinel cover both arms.
    """
    from .parser import parse_dense_companion

    try:
        companion, _warnings = parse_dense_companion(text)
        return derive_frontier(companion)
    except Exception as e:  # noqa: BLE001 — see docstring; an unreadable document is not open
        print(
            f"[invlang] frontier derivation failed, treating it as empty: {e!r}",
            file=sys.stderr,
        )
        return Frontier(slots=(), contracts=(), held=())


@dataclass(frozen=True)
class FrontierAt:
    """The frontier as of block `n`, and an honest account of which `n` that actually was."""

    frontier: Frontier
    #: The block count actually used, after snapping into range.
    n: int
    #: How many ````invlang` blocks the document has in total.
    total: int
    #: What the caller asked for, unclamped — `snapped` is the two disagreeing.
    requested: int

    @property
    def snapped(self) -> bool:
        return self.n != self.requested


def frontier_at(text: str, n: int) -> FrontierAt:
    """The frontier as the document stood after its first `n` ````invlang` blocks (PR-930).

    WHY A PREFIX AT ALL. The key a lesson should carry is the frontier at the moment the
    pitfall was live, not at the moment the run finished: by the close, the open slots the
    lesson needs to fire on are closed, because closing them is what finishing means. Measured
    on the runs in hand, a terminal document holds ~2 open slots against ~21 held facts, while
    the same document three blocks earlier holds 6 open against 7 — the first is barely a key
    and the second is one. Under the turn-N branch
    (`docs/learning-architecture-redesign.md`) a finding is BORN at a branch point, where the
    discriminator is open by construction, and this is how a curator reads that state back.

    COARSE, AND IT SAYS SO. The frontier moves only when a block lands, so `n` counts invlang
    FENCES — one per `append_block` on the ordinary authoring path — not messages. Many
    message-level branch points therefore share one frontier (the turn-N experiment forked at
    message 59; the document distinguishes a handful of states, not 59). A caller holding a
    message index maps it to a fence itself, because only the run's trace can do that.

    SNAPPED, NOT RAISED, and reported either way. An out-of-range `n` clamps into `[0, total]`
    and the result carries both what was asked and what was answered, because the failure to
    avoid is silent: a curator who asks for block 12 of a 4-block document and is handed the
    terminal frontier has been handed the one state that keys nothing, and needs to see that
    rather than infer it. `n=0` is the empty frontier — the document before anything landed —
    which is also the honest answer for a fence-less document.

    The prefix is REBUILT from the fence bodies rather than sliced out of `text`, so whatever
    prose sits between two blocks cannot change the answer. `parse_dense_companion` reads
    fences and ignores the rest, so this only makes that explicit.

    NEVER RAISES, inheriting `frontier_from_text`'s guarantee.
    """
    bodies = INVLANG_FENCE_RE.findall(text)
    total = len(bodies)
    resolved = max(0, min(n, total))
    prefix = "\n\n".join(f"```invlang\n{body}\n```" for body in bodies[:resolved])
    return FrontierAt(
        frontier=frontier_from_text(prefix),
        n=resolved,
        total=total,
        requested=n,
    )
