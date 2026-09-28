"""The frontier of a live investigation: what the document has not settled yet.

Retrieval keyed on the alert signature asks "which rule fired"; a lesson about what an
observation licenses is relevant once the field is in hand. This module answers "what is
still open right now" so retrieval can key on that instead.

invlang closes open things two ways, and the frontier is typed to match (SKILL.md):

  * a `??` / `{a, b}` slot on a `:V` vertex (its class tuple, `ident`, or an `attrs.<name>`
    value), closed by a `:R attr_updates` row. Node-anchored.
  * an `ac<n>` authorization contract declared under `:H h-NNN.authz`, closed by a
    `:R authz` row with an `authorized` verdict. Edge-anchored, via `edge_ref`.

A `??` `:H parent_class` is not included: no row can close it. Impact predictions (`ip*`)
are not included either: nothing models an unfulfilled impact contract.

Derived, never stored: every entry point recomputes from the document, so it cannot go stale.

Both axes call the disposition gate's own walks (`outstanding_authz_contracts`,
`iter_vertex_cells`), with two known divergences:

  1. `ident` is included here and excluded by the gate (`include_ident`): an unresolved
     identifier is among the most retrieval-worthy open slots.
  2. A `:R attr_updates` row may target an edge; the gate treats it as open, but this module
     drops it, since an `OpenSlot` needs a vertex `type`. So an authz question opened on an
     edge attribute recalls nothing. A limitation, not a design choice.

This module must never be wired into that gate.
"""
from __future__ import annotations

import sys

from defender._model import model

from . import _walkers, vocab
from .parser import scan_fences
from .schema import CompanionBody
from .validate import (
    _cell,
    auth_kind_of,
    exhausted_contract_ids,
    iter_vertex_cells,
    outstanding_authz_contracts,
)

#: The `slot` spellings (`class`, `ident`, `attrs.<name>`) are owned by `validate`, where the
#: `:R attr_updates` key grammar is enforced; they are deliberately not re-exported here.
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


@model(frozen=True)
class OpenSlot:
    """One unresolved cell on one vertex, after every `:R attr_updates` row has been applied."""

    vertex_id: str
    type: str
    class_tuple: str
    slot: str
    value: str


@model(frozen=True)
class HeldFact:
    """One cell on one vertex that the document has settled; the mirror of `OpenSlot`.

    Most lessons are advice about a value already held (e.g. `loginuid=-1`), which would never
    match if retrieval keyed only on open slots. Same shape as `OpenSlot` so one matcher serves
    both. Not monotonic: a re-observation carrying `??` turns a held fact back into an open slot.
    """

    vertex_id: str
    type: str
    class_tuple: str
    slot: str
    value: str


@model(frozen=True)
class OpenContract:
    """One declared authorization contract with no discharging `:R authz` row.

    `rel` and `auth_kind` come from the `:E` row `edge_ref` names, and are `None` for the
    ordinary unobserved (`proposed`) edge, so a selector naming them cannot match it.
    """

    contract_id: str
    hypothesis_id: str
    anchor_kind: str
    edge_ref: str
    rel: str | None
    auth_kind: str | None


@model(frozen=True)
class Frontier:
    """The investigation's retrieval state: what is still open, and what it now holds."""

    slots: tuple[OpenSlot, ...]
    contracts: tuple[OpenContract, ...]
    held: tuple[HeldFact, ...] = ()

    def is_empty(self) -> bool:
        return not self.slots and not self.contracts and not self.held


def _edge_index(companion: CompanionBody) -> dict[str, tuple[str | None, str | None]]:
    """Each `:E` id → `(relation, authority kind)`, first non-empty value per field winning.

    Per field, not per row: a later `observations.edges` row may legally supply an authority
    the declaring row left blank. A value already filled is never overwritten.
    (`_check_strong_move_provenance` uses last-wins; they agree whenever a field is set once.)
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
        first_rel, first_kind = index.get(eid, (None, None))
        index[eid] = (first_rel or rel, first_kind or kind)
    return index


def _node_state(companion: CompanionBody) -> tuple[list[OpenSlot], list[HeldFact]]:
    """Open slots and held facts, over the gate's own walk `validate.iter_vertex_cells`.

    Adds the vertex `type` selectors match on. Empty cells are neither open nor held."""
    types = _walkers.vertex_types(companion)
    open_out: list[OpenSlot] = []
    held_out: list[HeldFact] = []
    for cell in iter_vertex_cells(companion, include_ident=True):
        # An id with no `:V` row (an edge target or a typo) has no type to match; dropped here
        # though the gate still blocks on it.
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
    # The gate's own definition of "still owed an answer" (live hypotheses only; shared ids
    # scoped by anchor kind), plus the edge fields this axis keys on.
    edges = _edge_index(companion)
    # A contract whose `:R authz` row carries a verified `basis=exhausted` has had every
    # applicable registry queried, so it leaves the frontier (retrieval cannot help). The gate
    # still blocks on it. Keyed per contract, so one exhausted claim clears only its own.
    exhausted = exhausted_contract_ids(companion)
    out: list[OpenContract] = []
    for hid, c, _why in outstanding_authz_contracts(companion):
        cid = c.get("id")
        if not isinstance(cid, str) or not cid:
            continue
        # Unquoted via `_cell`, as `exhausted_contract_ids` keyed the set; `cid` stays raw
        # because selectors and lessons address contracts by it.
        if _cell(c, "id") in exhausted:
            continue
        # `or`, not a `.get` default, mirroring the parser: a present-but-empty value must
        # also fall back.
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
    """Parse and derive in one step. Never raises.

    Callers run against a document the model is still writing, and a partial document must not
    fail a write that already landed; an empty frontier is returned instead. The failure is
    reported on stderr so a bug here is not indistinguishable from "nothing is open".
    """
    from .parser import parse_dense_companion

    try:
        companion, _warnings = parse_dense_companion(text)
        return derive_frontier(companion)
    except Exception as e:  # noqa: BLE001 — an unreadable partial document is not open
        print(
            f"[invlang] frontier derivation failed, treating it as empty: {e!r}",
            file=sys.stderr,
        )
        return Frontier(slots=(), contracts=(), held=())


@model(frozen=True)
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
    """The frontier as the document stood after its first `n` ````invlang` blocks.

    A lesson should key on the frontier while the pitfall was live; by the close, the slots it
    fires on are closed. `n` counts fences, not messages, so many branch points share one
    frontier. A caller holding a message index maps it to a fence itself, because only the
    run's trace can do that.

    An out-of-range `n` is clamped into `[0, total]`, and the result reports both the requested
    and the used `n` so the snap is visible. The prefix is rebuilt from fence bodies, so prose
    between blocks cannot affect it. Never raises.
    """
    bodies = scan_fences(text).bodies
    total = len(bodies)
    resolved = max(0, min(n, total))
    prefix = "\n\n".join(f"```invlang\n{body}\n```" for body in bodies[:resolved])
    return FrontierAt(
        frontier=frontier_from_text(prefix),
        n=resolved,
        total=total,
        requested=n,
    )
