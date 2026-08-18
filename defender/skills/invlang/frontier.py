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

`ident` is INCLUDED here and EXCLUDED from the benign-disposition gate
(`validate._check_benign_open_slots`, and `IDENT_REFINEMENT_KEY`'s note on why). That
divergence is deliberate, not an oversight: an unresolved identifier is the single most
retrieval-worthy open slot there is — "which host is this IP" is exactly the question a
standing deployment fact answers — while the disposition gate has its own reasons for
not blocking a close on it. This module must never be wired into that gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import _walkers, vocab
from .schema import CompanionBody
from .validate import effective_vertex_state, has_open_slot, is_unresolved

#: The three `slot` spellings an `OpenSlot` can carry. `class` and `ident` are whole-cell;
#: an attribute is namespaced `attrs.<name>`, matching the `:R attr_updates` key grammar so
#: a selector is written in the same spelling the resolving row would use.
SLOT_CLASS = "class"
SLOT_IDENT = "ident"
ATTR_PREFIX = "attrs."

#: A contract counts as still-open unless a `:R authz` row DISCHARGES it, and only an
#: `authorized` verdict discharges.
#:
#: That is the SAME line `validate._check_benign_authz` draws, deliberately: it blocks a
#: benign close on any contract whose fulfilling row is not `authorized`, treating
#: `unauthorized` and `indeterminate` as questions the investigation still owes an answer
#: for rather than as answers. Reading the frontier the other way would put the two in
#: disagreement about what "settled" means, and the disposition gate is the one that has to
#: be right. It also lands where the lessons are: a verdict that forces escalation is
#: exactly when "what this anchor can and cannot conclude" is worth reading.
DISCHARGING_VERDICT = "authorized"


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
    index: dict[str, tuple[str | None, str | None]] = {}
    for e in _walkers.all_edges(companion):
        eid = e.get("id")
        if not isinstance(eid, str) or eid in index:
            continue
        authority = e.get("authority")
        kind = authority.get("kind") if isinstance(authority, dict) else None
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


def _discharged_contract_ids(companion: CompanionBody) -> set[str]:
    discharged: set[str] = set()
    for row in _walkers.iter_authz_resolutions(companion):
        cid = row.get("fulfills_contract")
        verdict = (row.get("verdict") or "").strip()
        if isinstance(cid, str) and cid and verdict == DISCHARGING_VERDICT:
            discharged.add(cid)
    return discharged


def _open_contracts(companion: CompanionBody) -> list[OpenContract]:
    # Walked directly rather than through `validate._declarers_by_contract_id`, which
    # collapses each contract to `(hypothesis, anchor_kind)` and drops the `edge_ref` the
    # edge axis is keyed on.
    discharged = _discharged_contract_ids(companion)
    edges = _edge_index(companion)
    # LIVE declarers only, for the same reason the discharge test is `authorized` only:
    # `_check_benign_authz` walks live hypotheses, so a contract whose hypothesis has been
    # refuted blocks nothing and owes nothing. Leaving it on the frontier would keep pushing
    # lessons about a question the investigation already abandoned — and would put this in
    # disagreement with the gate about which contracts are still outstanding.
    live = set(_walkers.live_hypothesis_ids(companion))
    out: list[OpenContract] = []
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        if hid not in live:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if not isinstance(cid, str) or not cid or cid in discharged:
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
    """
    from .parser import parse_dense_companion

    try:
        companion, _warnings = parse_dense_companion(text)
    except Exception:  # noqa: BLE001 — see docstring; an unreadable document is not open
        return Frontier(slots=(), contracts=())
    if not companion:
        return Frontier(slots=(), contracts=())
    try:
        return derive_frontier(companion)
    except Exception:  # noqa: BLE001
        return Frontier(slots=(), contracts=())
