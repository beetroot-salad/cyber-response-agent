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

TWO KNOWN DIVERGENCES from the benign-disposition gate (`validate._check_benign_open_slots`),
both on the NODE axis. The contract axis has none — `_open_contracts` calls the gate's own
`outstanding_authz_contracts` rather than restating it.

  1. `ident` is INCLUDED here and EXCLUDED there (`IDENT_REFINEMENT_KEY` notes why).
     Deliberate: an unresolved identifier is the single most retrieval-worthy open slot there
     is — "which host is this IP" is exactly the question a standing deployment fact answers —
     while the disposition gate has its own reasons for not blocking a close on it.
  2. A `:R attr_updates` row may legally target an EDGE (`l-001|e-001|attrs.auth_method|??`;
     see `_check_attr_update_targets`). The gate reads that as an open slot and blocks; this
     module DROPS it, because an `OpenSlot` carries a vertex `type` for a selector to match
     and an `:E` row has no such type. So an authz question opened on an edge attribute
     recalls nothing. NOT deliberate — a limitation of the node axis's shape, recorded here
     rather than hidden in `_open_slots`'s inline comment.

This module must never be wired into that gate.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

from . import _walkers, vocab
from .schema import CompanionBody
from .validate import (
    auth_kind_of,
    effective_vertex_state,
    has_open_slot,
    is_unresolved,
    outstanding_authz_contracts,
)

#: The three `slot` spellings an `OpenSlot` can carry. `class` and `ident` are whole-cell;
#: an attribute is namespaced `attrs.<name>`, matching the `:R attr_updates` key grammar so
#: a selector is written in the same spelling the resolving row would use.
SLOT_CLASS = "class"
SLOT_IDENT = "ident"
ATTR_PREFIX = "attrs."

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
    slots: tuple[OpenSlot, ...]
    contracts: tuple[OpenContract, ...]

    def is_empty(self) -> bool:
        return not self.slots and not self.contracts


def _edge_index(companion: CompanionBody) -> dict[str, tuple[str | None, str | None]]:
    """Each `:E` id → `(relation, authority kind)`, FIRST declaration winning.

    First-wins matches `validate._by_id_first` and `_walkers.vertex_types`: the declaring site
    is the immutable one, and a later re-observation adds ids rather than re-typing them.
    (`_check_strong_move_provenance` builds its own last-wins `auth_by_edge`; that one is the
    outlier, and reconciling it is out of scope here.)
    """
    index: dict[str, tuple[str | None, str | None]] = {}
    for e in _walkers.all_edges(companion):
        eid = e.get("id")
        if not isinstance(eid, str) or eid in index:
            continue
        kind = auth_kind_of(e)
        rel = e.get("relation")
        index[eid] = (rel if isinstance(rel, str) else None,
                      kind if isinstance(kind, str) else None)
    return index


def _open_slots(companion: CompanionBody) -> list[OpenSlot]:
    types = _walkers.vertex_types(companion)
    out: list[OpenSlot] = []
    for vid, st in effective_vertex_state(companion).items():
        # `effective_vertex_state` fabricates an entry for any `:R attr_updates` TARGET,
        # and the validator admits an `e-*` there — so an id with no `:V` row is an edge or
        # a typo, and either way carries no vertex type to match a selector against.
        if vid not in types:
            continue
        typ = types[vid]
        cls = st.get("classification") or ""
        if has_open_slot(cls):
            out.append(OpenSlot(vid, typ, cls, SLOT_CLASS, cls))
        ident = st.get("identifier") or ""
        if is_unresolved(ident):
            out.append(OpenSlot(vid, typ, cls, SLOT_IDENT, ident))
        for name, val in (st.get("attributes") or {}).items():
            if is_unresolved(val):
                out.append(OpenSlot(vid, typ, cls, f"{ATTR_PREFIX}{name}", val))
    return out


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
    return Frontier(
        slots=tuple(_open_slots(companion)),
        contracts=tuple(_open_contracts(companion)),
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
        return Frontier(slots=(), contracts=())
