"""Authorization-contract declarations, obligations, and grounding."""
from __future__ import annotations


from typing import Any


from defender.skills.invlang import _walkers
from defender.skills.invlang.schema import AuthorizationContract, CompanionBody
from defender.skills.invlang.validate._structure import _cell



def _anchor_kind(record: Any) -> str:
    """The anchor kind a `:H h-NNN.authz` contract or a `:R authz` row carries, normalized.

    Through `_cell` (unquoted) because both sides copy the cell verbatim, and a contract and its
    row must compare equal when the author quotes uniformly.
    """
    return _cell(record, "anchor_kind") if isinstance(record, dict) else ""




def _declarers_by_contract_id(
    companion: CompanionBody,
) -> dict[str, list[tuple[str, str]]]:
    """Every `(hypothesis, anchor kind)` declaring each `ac*` id, live or not.

    Unlike `_check_authz_contract_ids`, refuted declarers count: a `:R authz` row carries no
    hypothesis column, so a refuted declarer competes for the row like a live one.
    """
    declared_by: dict[str, list[tuple[str, str]]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            # `_cell` (unquoted): readers match this against a `fulfills` cell read through
            # `_cell`, so a quoted declaring id would otherwise be undischargeable.
            cid = _cell(c, "id")
            if cid:
                declared_by.setdefault(cid, []).append((hid, _anchor_kind(c)))
    return declared_by




def _authz_contract_error(
    hid: str,
    contract: AuthorizationContract,
    declarers: dict[str, list[tuple[str, str]]],
    verdicts: dict[str, list[tuple[str, str, bool]]],
) -> str | None:
    """Why this ONE contract on this LIVE hypothesis does not close benign — or `None`."""
    cid = _cell(contract, "id") or "?"
    anchor = _anchor_kind(contract)
    competing = [(h, a) for h, a in declarers.get(cid, []) if h != hid]
    candidates = verdicts.get(cid) or []

    if competing:
        # The anchor kind is always present (`_hyp_sub_authz_row` requires it), which makes it
        # usable as a discriminator.
        twins = sorted(h for h, a in competing if a == anchor)
        if twins:
            return (
                f"disposition benign blocked: authz contract {cid} on live hypothesis "
                f"{hid} shares BOTH its id and its anchor kind {anchor!r} with a contract "
                f"on {', '.join(twins)} — a `:R authz` row names only the contract it "
                f"fulfills, so no row can be attributed to this one and none discharges "
                f"it; number `ac*` across the document, not per hypothesis"
            )
        rows = [(v, cited) for v, a, cited in candidates if a == anchor]
        if not rows:
            return (
                f"disposition benign blocked: authz contract {cid} on live hypothesis "
                f"{hid} asks an {anchor!r} question, and {cid} is also declared by "
                f"{', '.join(sorted(h for h, _a in competing))} — so only a `:R authz` row "
                f"carrying anchor kind {anchor!r} discharges it, and the document has none"
            )
    else:
        rows = [(v, cited) for v, _a, cited in candidates]

    if not rows:
        return (
            f"disposition benign blocked: authz contract {cid} on "
            f"live hypothesis {hid} resolved 'no fulfilling :R authz "
            f"row', not 'authorized' — benign requires every contract "
            f"authorized"
        )
    # A list, not `next(..., None)`: `None` is a verdict a row can carry, and would be
    # indistinguishable from "no row".
    bad = [v for v, _cited in rows if v != "authorized"]
    if bad:
        return (
            f"disposition benign blocked: authz contract {cid} on "
            f"live hypothesis {hid} resolved {bad[0]!r}, not 'authorized' "
            f"— benign requires every contract authorized"
        )
    # Spec rule #27: a past case (an earlier run's verdict) is precedent, never the whole of
    # an authorization. A row is a past case when it cites one (`cites_past_case`), whatever
    # its grounding word says: a filled cell cannot be misspelled into an empty one.
    if all(cited for _v, cited in rows):
        return (
            f"disposition benign blocked: authz contract {cid} on live hypothesis {hid} is "
            f"authorized only by rows citing a past case (`cites_past_case`) — a past case is an earlier "
            f"run's verdict, and benign cannot rest on past cases alone (rule #27). Resolve "
            f"{cid} on an authored record too (an iam-policy, a change-mgmt hit, a "
            f"tacit-knowledge registry entry), or leave it `indeterminate`"
        )
    return None




def outstanding_authz_contracts(
    companion: CompanionBody,
) -> list[tuple[str, AuthorizationContract, str]]:
    """Every `(hypothesis, contract, why)` on a live hypothesis that no `:R authz` row
    discharges — the definition of "this authorization question is still open".

    Public so `_check_benign_authz` and `frontier._open_contracts` share one answer. A second
    reading of "discharged" — a bare `fulfills_contract` id set, say — silently disagrees with
    this one on every shared id, and in the harmful direction: the frontier would drop the
    contract that is actually wedging the close. A shared id is scoped by anchor kind
    (`_authz_contract_error`).
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    hyps = _walkers.all_hypotheses(companion)
    declarers = _declarers_by_contract_id(companion)

    verdicts: dict[str, list[tuple[str, str, bool]]] = {}
    for row in _walkers.iter_authz_resolutions(companion):
        # `_cell` (unquoted), matching `_check_authz_contract_closure`; read raw, a quoted
        # `fulfills` would make the two disagree about whether the contract is discharged.
        cid = _cell(row, "fulfills_contract")
        if cid:
            verdicts.setdefault(cid, []).append(
                (row.get("verdict", "indeterminate"), _anchor_kind(row),
                 bool(_cell(row, "cites_past_case")))
            )

    out: list[tuple[str, AuthorizationContract, str]] = []
    for hid in sorted(live):
        hyp = hyps.get(hid)
        if hyp is None:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            found = _authz_contract_error(hid, c, declarers, verdicts)
            if found is not None:
                out.append((hid, c, found))
    return out




def _check_benign_authz(companion: CompanionBody) -> list[str]:
    """Every authz contract on a live hypothesis is discharged by an `authorized` row
    attributable to it.

    `_check_authz_contract_ids` exempts an id collision whose other declarer is refuted, since
    on an append-only document refuting is the only repair. That is sound for the contract but
    not the row: an `authorized` row written against the refuted declarer's `ac1` would also
    discharge the live one's. So a shared id is scoped by anchor kind, which keeps the rule
    repairable — appending a row with this contract's anchor kind discharges it. Two declarers
    sharing both id and anchor kind are refused outright. An unshared id is discharged by id
    alone.
    """
    return [why for _hid, _c, why in outstanding_authz_contracts(companion)]
