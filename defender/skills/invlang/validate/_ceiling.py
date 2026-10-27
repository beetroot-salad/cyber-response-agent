"""Ceiling receipts and the held capability roster."""
from __future__ import annotations


import re

from collections.abc import Mapping, Sequence

from typing import Any

from defender import _yaml


from defender._model import model



from defender.systems.verbs import RosterRead

from defender.skills.invlang.parser import is_conclude_empty_marker
from defender.skills.invlang.schema import CompanionBody, FindingRecord
from defender.skills.invlang.validate._refs import _leads

from defender.skills.invlang.validate._runtime_evidence import _REPORT_CLOSE_DELIMITER as _REPORT_CLOSE_DELIMITER




def _lead_retrieval_came_back(lead: FindingRecord) -> bool:
    """Did this lead's own retrieval return anything — an observation or an `:R attr_updates`
    row — as opposed to an analytical conclusion (`:R authz`/`anchor`/`impact`) about it.

    Narrower than `_lead_returned_a_result`, which also counts `resolutions` and is right for
    `entity_check`. A lead can resolve a contract `indeterminate` purely from absent telemetry
    (golden-v2sshd's `l-004`); counting that resolution as a result would make the most common
    real gap — a query that found nothing, with a conclusion drawn from the absence —
    unanchorable by any `ceiling_test` receipt.
    """
    outcome = lead.get("outcome")
    if not isinstance(outcome, dict):
        return False
    return bool(outcome.get("observations") or outcome.get("attribute_updates"))




#: The one lookup a `:L findings` lead reference resolves against, shared by `entity_check` and
#: a `ceiling_test` receipt's `ref`.
def _lead_by_id(companion: CompanionBody, lead_id: str) -> FindingRecord | None:
    return next((f for f in _leads(companion) if f.get("id") == lead_id), None)



def _row_renders_as_empty_marker(value: object) -> bool:
    """Does a `ceiling_test` row render as nothing or as the format's empty marker
    (`none`/`n/a`)? Such a row is the format's "no gap" spelling and is skipped, not refused."""
    return isinstance(value, str) and (not value.strip() or is_conclude_empty_marker(value))




#: The closed states a `ceiling_test` receipt may claim. A receipt is a pointer into this run's
#: own transcript, verified mechanically, never a judgment of prose.
#:
#: Three states because that is all current instrumentation distinguishes without reading the
#: model's words: `_lead_retrieval_came_back` splits "came back with something" from "did not",
#: and the presence (never content) of a lead's `fail_reason` splits "errored" from "empty".
#: `access-denied` / `out-of-retention` need a host-side signal that tells them apart from
#: `query-failed` mechanically (e.g. a distinct `error_class` for a permission refusal, or an
#: adapter reporting before-retention) before they can be added.
CEILING_QUERY_FAILED = "query-failed"


CEILING_QUERY_EMPTY = "query-empty"


CEILING_NOTHING_TO_TRY = "nothing-to-try"


CEILING_STATES: tuple[str, ...] = (
    CEILING_QUERY_FAILED, CEILING_QUERY_EMPTY, CEILING_NOTHING_TO_TRY,
)



#: The states that anchor to a lead this run dispatched. `nothing-to-try` has no call to point
#: at: the capability does not exist.
_LEAD_ANCHORED_STATES: tuple[str, ...] = (CEILING_QUERY_FAILED, CEILING_QUERY_EMPTY)



#: The shape of a `:L findings` lead id (`l-<alphanumeric>`). A receipt's `ref` is checked
#: against it before the lookup: `:L findings` ids are unconstrained free text, so exact
#: membership alone would accept a delimiter-shaped id a model declared.
_LEAD_REF_RE = re.compile(r"l-[A-Za-z0-9]+")




@model(frozen=True)
class CeilingReceipt:
    """One parsed `ceiling_test` row.

    `state`/`ref`/`cap` are the structured half, mechanically checked against this run's own
    transcript, and the only part that goes into the report frontmatter (`ceiling_test_block`).
    `note` is free text for the human analyst: checked only for the report delimiter and a total
    size bound, rendered into the report body, and passed verbatim (inside the untrusted frame)
    to the ceiling review composer."""

    state: str
    ref: str | None
    cap: str | None
    note: str
    raw: str




#: `state=... [ref=...] [cap=...] note=<free text>`. `note=` is always last and takes the rest
#: of the line, so it needs no quoting. The other fields are `\S+` tokens compared by exact
#: membership, so a homoglyph or zero-width variant simply fails to match.
_RECEIPT_ROW_RE = re.compile(r"^(?P<fields>(?:\S+=\S+\s+)*)note=(?P<note>.*)$")


_RECEIPT_FIELD_RE = re.compile(r"(\S+)=(\S+)")


_RECEIPT_FIELD_NAMES = frozenset({"ref", "state", "cap"})




def _parse_ceiling_row(row: str) -> CeilingReceipt | None:
    """Parse one `ceiling_test` row, or `None` if it is not receipt-shaped at all. `None` is not
    itself a refusal; the caller decides what it costs."""
    m = _RECEIPT_ROW_RE.match(row.strip())
    if not m:
        return None
    fields = dict(_RECEIPT_FIELD_RE.findall(m.group("fields")))
    if not fields or set(fields) - _RECEIPT_FIELD_NAMES or "state" not in fields:
        return None
    return CeilingReceipt(
        state=fields["state"], ref=fields.get("ref"), cap=fields.get("cap"),
        note=m.group("note").strip(), raw=row,
    )




#: The closed universe of `(system, verb)` pairs this codebase's adapters declare
#: (`defender/integrations/*_adapter.py`), which `nothing-to-try` is checked against. Closed
#: by construction: code this repo owns, never a catalogue of real-world data sources.
#:
#: Held, never fetched: the process's composition root reads the roster once and hands it over
#: through `hold_capabilities` before any validation. Reading lazily here would make whichever
#: document-path guard asked first catch the host's fault and blame the document. Holds the
#: `RosterRead` itself, the same object the run's registry holds.
_CHECKOUT_ROSTER: RosterRead | None = None




class CapabilitiesNotRead(RuntimeError):
    """`known_capabilities` was called before `hold_capabilities`: a composition-root defect,
    not a document diagnostic."""




def hold_capabilities(roster: RosterRead) -> None:
    """Hand the gate the checkout's roster (`read_roster(DefenderPaths(REPO_ROOT).adapters_dir)`,
    or the run's own when its tree is the checkout). Called once at process start; a later call
    replaces it, which only tests driving several checkouts rely on."""
    if not isinstance(roster, RosterRead):
        raise TypeError(
            f"hold_capabilities takes the RosterRead `read_roster` produced, got "
            f"{type(roster).__name__}"
        )
    global _CHECKOUT_ROSTER
    _CHECKOUT_ROSTER = roster




def release_capabilities() -> None:
    """Forget the held roster, so a test can observe the unheld state or avoid leaking a
    fixture roster to the next test."""
    global _CHECKOUT_ROSTER
    _CHECKOUT_ROSTER = None




def known_capabilities() -> Mapping[str, frozenset[str]]:
    """System -> the verb names its adapter declares, for this process's checkout. Raises
    `CapabilitiesNotRead` if `hold_capabilities` was never called.

    The checkout's tree (`REPO_ROOT`), not the run's `defender_dir`: the price is closed over what
    this repository owns. A failed or absent roster read fails at the composition root as
    `RegistryError`, never inside a guard on the document's path, which would blame the model for
    the host's fault."""
    if _CHECKOUT_ROSTER is None:
        raise CapabilitiesNotRead(
            "the checkout's adapters roster was never read: the process's composition root "
            "must `read_roster` it once and `hold_capabilities` the value before any "
            "document is validated"
        )
    return _CHECKOUT_ROSTER.verbs




def _capability_exists(cap: str) -> bool:
    """Does `cap` name a REAL `system` or `system.verb` this deployment's adapters declare?
    `nothing-to-try` pays only when this is False."""
    known = known_capabilities()
    system, sep, verb = cap.partition(".")
    if sep:
        return verb in known.get(system, frozenset())
    return cap in known




def _cap_is_identifier_shaped(cap: str) -> bool:
    """Is `cap` shaped like `<system>` or `<system.verb>`, rather than arbitrary text?

    `cap` is the one receipt field checked by absence (`not _capability_exists`), which any
    non-capability string satisfies, `</report>` included. `ref` and `state` are checked by exact
    membership, which already refuses non-members. Uses `systems.verbs`' system-name alphabet for
    both halves, since verb names share it."""
    from defender.kit.verbs import SYSTEM_PATTERN, is_system_name

    system, sep, verb = cap.partition(".")
    if not is_system_name(system):
        return False
    return not sep or bool(re.fullmatch(SYSTEM_PATTERN, verb))




def ceiling_test_block(receipts: Sequence[CeilingReceipt]) -> str:
    """@owns ceiling_test

    The `ceiling_test:` frontmatter block for `receipts` — `ref`/`state`/`cap` only, never the
    `note`. The one renderer, so the gate that bounds it (`_check_inconclusive_gating`) and
    `close_tool.render_report`, which emits it, measure the same bytes. Dumped through PyYAML
    because `ref`/`cap` are model-cited tokens in a host-owned file."""
    if not receipts:
        return ""
    rows: list[dict[str, str]] = []
    for r in receipts:
        row: dict[str, str] = {"state": r.state}
        if r.ref is not None:
            row["ref"] = r.ref
        if r.cap is not None:
            row["cap"] = r.cap
        rows.append(row)
    return _yaml.safe_dump(
        {"ceiling_test": rows},
        allow_unicode=True, default_flow_style=False, sort_keys=False, width=10**9,
    )




def _check_lead_anchored_receipt(companion: CompanionBody, receipt: CeilingReceipt) -> str | None:
    """The `query-failed`/`query-empty` half of `_check_ceiling_receipt`: `ref` must name a lead
    this run dispatched whose own retrieval came back with nothing, and the state must match
    whether that lead recorded a `fail_reason`."""
    if receipt.cap is not None:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state={receipt.state}` takes `ref=`, "
            f"not `cap=` — a call that was actually dispatched points at the lead that "
            f"made it"
        )
    if not receipt.ref:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state={receipt.state}` needs "
            f"`ref=<lead-id>` naming the `:L findings` row that made the attempt"
        )
    if not _LEAD_REF_RE.fullmatch(receipt.ref):
        # `:L findings` ids have no shape rule (a lead named `</report>` parses cleanly), so
        # exact membership alone does not constrain shape. Checked before the lookup so a
        # hostile id cannot be planted and then cited.
        return (
            f"`ceiling_test` row {receipt.raw!r}: `ref={receipt.ref}` is not shaped like a "
            f"`:L findings` lead id (`l-<alphanumeric>`)"
        )
    lead = _lead_by_id(companion, receipt.ref)
    if lead is None:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `ref={receipt.ref}` is not a lead in "
            f"`:L findings`"
        )
    if _lead_retrieval_came_back(lead):
        return (
            f"`ceiling_test` row {receipt.raw!r}: lead {receipt.ref} actually retrieved "
            f"something (an observation, an updated attribute) — a receipt cannot claim a "
            f"gap for a call that came back with data. An analytical CONCLUSION about the "
            f"lead (an authz/anchor/impact resolution) does not by itself disqualify it — "
            f"only retrieved data does; see `_lead_retrieval_came_back`"
        )
    outcome = lead.get("outcome")
    errored = isinstance(outcome, dict) and bool(outcome.get("failure_reason"))
    if receipt.state == CEILING_QUERY_FAILED and not errored:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state=query-failed` but lead "
            f"{receipt.ref} records no `fail_reason` in `:L findings` — write "
            f"`state=query-empty` for a call that ran clean and came back with nothing, "
            f"or add the lead's `fail_reason`"
        )
    if receipt.state == CEILING_QUERY_EMPTY and errored:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state=query-empty` but lead "
            f"{receipt.ref} records a `fail_reason` in `:L findings` — write "
            f"`state=query-failed` for a call that errored"
        )
    return None




def _check_nothing_to_try_receipt(receipt: CeilingReceipt) -> str | None:
    """The `nothing-to-try` half of `_check_ceiling_receipt`: `cap` must name a capability the
    closed verb roster does not declare."""
    if receipt.ref is not None:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state=nothing-to-try` takes `cap=`, not "
            f"`ref=` — nothing was dispatched, so there is no lead to point at"
        )
    if not receipt.cap:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state=nothing-to-try` needs "
            f"`cap=<system>` or `cap=<system.verb>` naming the missing capability"
        )
    if not _cap_is_identifier_shaped(receipt.cap):
        return (
            f"`ceiling_test` row {receipt.raw!r}: `cap={receipt.cap}` is not shaped like "
            f"`<system>` or `<system.verb>` — lowercase letters, digits and hyphens only, one "
            f"optional `.verb` segment. `cap` is checked by ABSENCE from the closed roster, "
            f"which cannot constrain an arbitrary string on its own; rewrite it as the "
            f"capability's actual system[.verb] name"
        )
    if _capability_exists(receipt.cap):
        return (
            f"`ceiling_test` row {receipt.raw!r}: `cap={receipt.cap}` names a capability this "
            f"deployment DOES provide — `nothing-to-try` is for a capability that does not "
            f"exist at all. If the call was made and failed or came back empty, use "
            f"`state=query-failed`/`state=query-empty` with `ref=<lead-id>` instead"
        )
    return None




def _check_ceiling_receipt(companion: CompanionBody, receipt: CeilingReceipt) -> str | None:
    """Is `receipt` consistent with this run's own transcript: a foreign-key and
    closed-vocabulary check, never a judgment of the note. Returns the refusal, or `None` when
    the receipt pays."""
    if receipt.state not in CEILING_STATES:
        return (
            f"`ceiling_test` row {receipt.raw!r}: `state={receipt.state}` is not one of "
            f"{CEILING_STATES}"
        )
    if _REPORT_CLOSE_DELIMITER in receipt.note:
        return (
            f"`ceiling_test` row {receipt.raw!r}: the `note` carries the literal "
            f"{_REPORT_CLOSE_DELIMITER!r}, which the committed report may not carry — "
            f"rewrite the note without it"
        )
    if receipt.state in _LEAD_ANCHORED_STATES:
        return _check_lead_anchored_receipt(companion, receipt)
    return _check_nothing_to_try_receipt(receipt)




@model(frozen=True)
class _CeilingWalk:
    """One walk of a `:T conclude.ceiling_test` list: the paying rows (document order, deduped)
    and every row-level complaint. Shared by the gate (`_check_inconclusive_gating`) and the
    report reader (`conclude_ceiling_test_rows`), so a row the gate refused never reaches
    `report.md` and one it accepted is never dropped."""

    paying: tuple[CeilingReceipt, ...]
    errors: tuple[str, ...]




def _walk_ceiling_rows(companion: CompanionBody, rows: Any) -> _CeilingWalk:
    paying: list[CeilingReceipt] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    # `isinstance(list)`, not `rows or []`: iterating a string would walk its characters.
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, str) or _row_renders_as_empty_marker(row):
            continue
        receipt = _parse_ceiling_row(row)
        if receipt is None:
            # Silent: a row not even shaped like a receipt states nothing to price. The
            # aggregate "no receipt pays" message carries the guidance if nothing else pays.
            continue
        identity = (
            receipt.state, receipt.ref if receipt.ref is not None else (receipt.cap or ""),
        )
        if identity in seen:
            errors.append(
                f"`ceiling_test` row {row!r} repeats an earlier gap — each row must name a "
                f"DISTINCT gap; repetition does not pay for a second one"
            )
            continue
        seen.add(identity)
        problem = _check_ceiling_receipt(companion, receipt)
        if problem is not None:
            errors.append(problem)
            continue
        paying.append(receipt)
    return _CeilingWalk(paying=tuple(paying), errors=tuple(errors))




#: Bound on the frontmatter receipt block (`ref`/`state`/`cap` only). Charged on the rendered
#: block (`ceiling_test_block`) because PyYAML quoting changes the size, and a measurement that
#: disagrees with the renderer can pass here what the commit refuses. Well under
#: `_artifact_schema.REPORT_FRONTMATTER_MAX` (512); it guards against an unreasonable number of
#: receipts rather than any one receipt's size.
_MAX_CEILING_FRONTMATTER_BYTES = 300



#: Bound on the rendered `ceiling_test` note lines in the report body (`ceiling_note_block`).
#: Without it a large note passes this gate and then strands the run at
#: `_artifact_schema.validate_report`'s whole-file cap, after the review has been spent. Sized
#: like `_MAX_RUNTIME_EVIDENCE_BODY_BYTES`: 300 + 2048 + 2048 stays well under
#: `_artifact_schema.REPORT_FILE_MAX` (8192).
_MAX_CEILING_NOTE_BYTES = 2048




def ceiling_note_block(receipts: Sequence[CeilingReceipt]) -> str:
    """The `report.md` body lines for the receipts' notes: one per receipt that has one, naming
    its state and its `ref` or `cap`, then the free text. The one renderer, so the bounding gate
    and `close_tool.render_report` measure the same bytes. Each line starts with a newline;
    empty when no receipt has a note."""
    return "".join(
        f"\nceiling_test ({r.state}, {r.ref or r.cap}): {r.note}" for r in receipts if r.note
    )




def _check_inconclusive_gating(companion: CompanionBody) -> list[str]:
    """`inconclusive` owes at least one `ceiling_test` row that is a valid receipt.

    A `query-failed`/`query-empty` receipt must `ref` a lead this run dispatched whose own
    retrieval is consistent with the state; a `nothing-to-try` receipt must `cap` a capability
    absent from the closed verb roster. Rows must be distinct, and the rendered frontmatter and
    note text are bounded. Collected at both the write gate and the close via
    `_DISPOSITION_GATES`."""
    conclude = companion.get("conclude") or {}
    walk = _walk_ceiling_rows(companion, conclude.get("ceiling_test"))
    errors = [f"disposition inconclusive blocked: {e}" for e in walk.errors]
    total_bytes = len(ceiling_test_block(walk.paying).encode("utf-8"))
    if total_bytes > _MAX_CEILING_FRONTMATTER_BYTES:
        errors.append(
            f"disposition inconclusive blocked: the accumulated `ceiling_test` receipts are "
            f"{total_bytes} bytes, over the {_MAX_CEILING_FRONTMATTER_BYTES}-byte bound — "
            f"name fewer, more specific gaps rather than every one in full"
        )
    note_bytes = len(ceiling_note_block(walk.paying).encode("utf-8"))
    if note_bytes > _MAX_CEILING_NOTE_BYTES:
        errors.append(
            f"disposition inconclusive blocked: the accumulated `ceiling_test` notes render "
            f"{note_bytes} bytes of `report.md` body, over the {_MAX_CEILING_NOTE_BYTES}-byte "
            f"bound — shorten the "
            f"notes; they are free text for the human analyst, never required to make a "
            f"receipt pay"
        )
    if not walk.paying:
        errors.append(
            "disposition inconclusive blocked: no `ceiling_test` row is a receipt that pays "
            "— write `state=query-failed ref=<lead-id> note=<text>` or "
            "`state=query-empty ref=<lead-id> note=<text>` naming a `:L findings` lead this "
            "run dispatched that failed or came back empty, or `state=nothing-to-try "
            "cap=<system[.verb]> note=<text>` naming a capability this deployment does not "
            "provide."
        )
    return errors




def conclude_ceiling_test_rows(companion: CompanionBody) -> tuple[CeilingReceipt, ...]:
    """The `:T conclude.ceiling_test` receipts that pay, in document order.

    Public because `report.md` is written from the close's disposition argument and never
    re-reads the companion, so the close carries these into the report itself. Uses the gate's
    own walk so the rows that ship are exactly the rows the gate priced and bounded.

    Takes the parsed companion: the close has already parsed it once, inside the guard that
    turns a parse fault into a refusal (`_refuse_if_entry_price_is_owed`)."""
    conclude = companion.get("conclude") or {}
    return _walk_ceiling_rows(companion, conclude.get("ceiling_test")).paying
