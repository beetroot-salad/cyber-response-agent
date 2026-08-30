"""What a disposition costs.

One family of `validate.py`'s rules, split out at 4038 lines: benign grounding, the
false-positive gate, the screen's structure, and the severity ceiling. A conclusion that
has not paid its price is refused here.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import yaml

from defender._text import strip_zero_width
from defender._vocab import DISPOSITION_ENUM
from .. import _walkers, vocab
from ..parser import (
    is_conclude_empty_marker,
    parse_dense_companion,
)
from ..schema import (
    CompanionBody,
    FindingRecord,
)
from ._diag import REFUTED_WEIGHT
from ._refs import _HYPOTHESIS_DECLARING_BLOCKS, _known_ids, _leads
from ._structure import _cell
from ._state import _check_benign_authz, _check_benign_open_slots


def _rendered_disposition(value: object) -> str | None:
    """What `value` renders as, FORGIVINGLY — zero-width stripped, exact membership beneath
    that. #923's write-side price dispatch: it must keep failing CLOSED on a zero-width-laced
    spelling of a priced keyword (still owes), which is the opposite direction from
    `defender._vocab.normalized_disposition`'s #923 change (which stops coercing on the READ
    side, so a laced keyword no longer reads back as the clean member it resembles). The two
    normalizers now disagree on purpose — the write side may still recognize a keyword through
    an invisible character in order to hold it to a stricter obligation; the read side must
    never recognize one in order to hand back a clean answer."""
    if not isinstance(value, str):
        return None
    candidate = strip_zero_width(value).strip()
    # lint-vocabulary: ok — deliberately NOT `_vocab.normalized_disposition`: that reader is
    # exact-only after #923 (the READ side must never coerce a malformed verdict), and this
    # WRITE-side price dispatch needs the opposite — it must keep recognizing a zero-width-laced
    # spelling of a priced keyword so it keeps failing CLOSED on one. See this function's own
    # docstring.
    return candidate if candidate in DISPOSITION_ENUM else None




def _row_states_something(value: Any) -> bool:
    """A `:T conclude` scalar that actually SAYS something — present, non-blank, and not the
    format's own "nothing to say" marker, which only the parser gets to define."""
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not is_conclude_empty_marker(value)
    )


def _lead_returned_a_result(lead: FindingRecord) -> bool:
    """Did this lead come back with a RESULT — not merely with a record that it ran.

    Deliberately stricter than `_check_loop_close`'s committed test, which counts ANY outcome:
    `:L findings`' `fail_reason` column projects into `outcome` as `failure_reason`, so a lead
    whose only recorded outcome is "the query errored" reads as committed there. For closing a
    loop that is right — the loop was worked. Here it is the shape the gate exists to reject:
    a failed query tested the alerted entity for nothing.
    """
    if lead.get("resolutions"):
        return True
    outcome = lead.get("outcome")
    if not isinstance(outcome, dict):
        return False
    return bool(set(outcome) - {"failure_reason"})


def _lead_retrieval_came_back(lead: FindingRecord) -> bool:
    """Did anything ACTUALLY come back for this lead's own RETRIEVAL — an observation the run
    recorded (`:V`/`:E l-NNN.observations.*`) or an attribute it updated (`:R attr_updates`) —
    as opposed to an ANALYTICAL CONCLUSION (a `:R authz`/`anchor`/`impact` resolution) the model
    reached ABOUT it, which may or may not have been grounded in any data.

    Deliberately NOT `_lead_returned_a_result`, and this is a narrower, ceiling_test-specific
    question, not a second spelling of that one. `_lead_returned_a_result` counts EITHER an
    outcome key OR a `resolutions` entry as a result, because for `entity_check` — the question
    it answers — reaching any conclusion at all is "the lead tested something", which is right
    for `entity_check` and stays unchanged there.

    A `ceiling_test` receipt asks the narrower question: did the underlying RETRIEVAL produce
    anything. A lead can resolve an authz contract to `indeterminate` from the ABSENCE of
    telemetry alone — golden-v2sshd's `l-004` resolves `ac2` "indeterminate" with the reasoning
    "process-exec telemetry unavailable: auditd not collected... cannot be identified from
    available data sources", and carries no `:V`/`:E`/`:R attr_updates` of its own at all. Under
    `_lead_returned_a_result` that resolution alone makes `l-004` read identically to a lead
    that resolved from data it actually retrieved — which made the most common real gap shape in
    this corpus (a query that ran, found nothing, and the model drew a conclusion from that
    absence anyway) unanchorable by any receipt. Checked against `outcome`'s two
    retrieval-populated keys alone (`observations`, `attribute_updates`) and never
    `resolutions` — a CONCLUSION populates `resolutions` whether or not any data backed it, so
    its presence answers nothing about whether the retrieval itself came back with something.
    """
    outcome = lead.get("outcome")
    if not isinstance(outcome, dict):
        return False
    return bool(outcome.get("observations") or outcome.get("attribute_updates"))


#: THE one FK lookup a `:L findings` reference is resolved against. `entity_check`
#: (`_check_false_positive_gating`, below) and a `ceiling_test` receipt's `ref` (#923's
#: redesign) both resolve a model-cited lead id here — a second, independently-written lookup
#: is exactly the duplicated-derivation shape that redesign exists to remove.
def _lead_by_id(companion: CompanionBody, lead_id: str) -> FindingRecord | None:
    return next((f for f in _leads(companion) if f.get("id") == lead_id), None)


def _check_false_positive_gating(companion: CompanionBody) -> list[str]:
    """`false-positive` is the one disposition that closes a case on a claim about the RULE, so
    it is the one that has to prove it also looked at the entity.

    Three things are checked, each a way the exit could otherwise be faked:

      * `detection_notes` — an FP close with no stated defect is a close with no reason, and
        `none` is not a defect: the format's empty marker is rejected here, not read as prose;
      * `entity_check` names a lead that EXISTS and RETURNED A RESULT — a planned-but-never-
        dispatched lead is the shape of an investigation that stopped at the plan, and a lead
        carrying only a `fail_reason` is the shape of one whose query never landed;
      * that lead targets a vertex the PROLOGUE carried — an entity the ALERT named, not one
        the refutation introduced.

    TWO things it does NOT check, both about the QUESTION the named lead asked:

      * whether it was a good one. Distinguishing "read authorized_keys for the service account"
        from "…for root" is a question about query parameters, which never reach this layer;
      * whether it was INDEPENDENT of the alert's claim. Nothing here separates the lead that
        tested the host for its own suspicion from the lead that refuted the correlation, so a
        run can satisfy this gate with work it had already done before the refutation landed.

    Closing either gap means a fixed indicator set the runtime executes rather than the model
    choosing; this gate is the structural half, and its limits are recorded here so the next
    author does not read a passing gate as a swept host.
    """
    conclude = companion.get("conclude") or {}
    errors: list[str] = []

    notes = conclude.get("detection_notes")
    if not _row_states_something(notes):
        errors.append(
            "disposition false-positive blocked: no `detection_notes` row — the "
            "close rests on a claim about the rule, so the defect has to be stated"
        )

    lead_id = conclude.get("entity_check")
    if not (isinstance(lead_id, str) and lead_id.strip()):
        return errors + [
            "disposition false-positive blocked: no `entity_check` row — name the "
            "`:L findings` lead that tested the alerted entity for suspicion "
            "independent of the alert's claim, or conclude in another vocabulary"
        ]
    lead_id = lead_id.strip()

    lead = _lead_by_id(companion, lead_id)
    if lead is None:
        return errors + [
            f"disposition false-positive blocked: `entity_check` names {lead_id!r}, "
            f"which is not a lead in `:L findings`"
        ]

    if not _lead_returned_a_result(lead):
        errors.append(
            f"disposition false-positive blocked: `entity_check` lead {lead_id} "
            f"committed no result — a lead that was planned and never resolved, or "
            f"whose only outcome is a `fail_reason`, did not test anything"
        )

    prologue_vertices = {
        v.get("id") for v in (companion.get("prologue") or {}).get("vertices") or []
    }
    target = lead.get("target")
    if target not in prologue_vertices:
        errors.append(
            f"disposition false-positive blocked: `entity_check` lead {lead_id} "
            f"targets {target!r}, which the prologue does not carry — the check has "
            f"to be against an entity the ALERT named, not one the refutation "
            f"introduced"
        )

    return errors


def _check_benign_grounding(companion: CompanionBody) -> list[str]:
    """`benign` needs a log that recorded WHAT THE ALERT WAS ABOUT.

    The other two benign checks refuse CONTRADICTIONS — an unresolved slot, an unfulfilled
    contract — which is the right shape for a log that did the work, and vacuous for one that
    did not: a document with no vertices has no slot to be open and no hypothesis to carry a
    contract, so it clears a price it never paid. Absent, empty, whitespace-only and fence-less
    `investigation.md` files all reach the close that way.

    So the prologue has to carry a vertex, and the point is what that does to the two checks
    beside it: once a vertex is guaranteed, `_check_benign_open_slots` has something to check
    on every benign close, and "the classification is resolved" stops being a claim a document
    can satisfy by staying silent. ORIENT writes this block before PLAN runs, so every real run
    clears it long before it can conclude anything.

    Deliberately NOT a demand for leads, committed or declared. How much measurement a
    disposition needs is a judgment about the case, which the review gate makes; this is the
    structural floor beneath it, and a trivially-benign alert closed off the payload alone is a
    run this must not refuse.
    """
    if not (companion.get("prologue") or {}).get("vertices"):
        return [
            "disposition benign blocked: no `:V prologue.vertices` row — benign says the "
            "alerted activity was accounted for, so the log has to name the entity the "
            "alert was about. An `investigation.md` that records no vertex records no "
            "investigation; conclude `inconclusive` instead."
        ]
    return []


def _check_benign_gating(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    errors += _check_benign_grounding(companion)
    errors += _check_benign_open_slots(companion)
    errors += _check_benign_authz(companion)
    return errors


@dataclass(frozen=True)
class _Price:
    """What a keyword costs, and why it costs it.

    Two columns because the price has two audiences. `check` answers whether THIS document has
    paid, and its strings name the blocking vertex, contract or row. `rationale` answers why
    the price exists at all — what a refused model needs in order to choose between paying it
    and concluding in another vocabulary. The rationale is a property of the KEYWORD, equally
    true at either boundary, so it belongs beside the check rather than in a second
    keyword-keyed table at whichever boundary happens to print it.
    """

    check: Callable[[CompanionBody], list[str]]
    rationale: str


#: The structural price of a keyword, keyed by the keyword. Two dispositions carry one; the
#: rest carry none. A table rather than a guard clause inside each gate, so a third priced
#: keyword is a row here and not a third copy of the "is this my disposition" preamble that
#: has to get the keyword normalization right every time.
#:
#: Two readers dispatch on it and both must, because a price owed by the document alone is not
#: owed at all: `_check_disposition_gating` on what `:T conclude` says, and
#: `disposition_entry_price` on what the close is about to commit. Adding a row arms both.
#:
#: The rationale rides in the row so a new keyword cannot be collected but left unexplained —
#: `lint_half_read_table`'s documented blind spot is a consumer that enumerates EVERY key, so
#: a second `{keyword: prose}` table elsewhere would not be caught drifting.
#:
#: Each row is BOUND TO A NAME rather than built inline, and that is load-bearing:
#: `lint_half_read_table` recognizes a keyed gate table only when every value is a
#: `Name`/`Attribute`/`Lambda`, so writing these as `_Price(...)` calls in the literal makes
#: the table invisible to the gate that watches it and drops its other findings too.
_BENIGN_PRICE = _Price(
    check=_check_benign_gating,
    rationale=(
        "`benign` says the alerted activity was accounted for, which an unresolved slot or "
        "an unfulfilled authorization contract on a live hypothesis directly contradicts, "
        "and which a log that never named the alerted entity does not support at all — so "
        "it is reachable only from an `investigation.md` that recorded the entity and "
        "settled what it left open."
    ),
)
_FALSE_POSITIVE_PRICE = _Price(
    check=_check_false_positive_gating,
    rationale=(
        "`false-positive` says the RULE misfired, which is no evidence about the alerted "
        "entity — so it is reachable only from an `investigation.md` that states the defect "
        "and names the lead that checked the entity anyway."
    ),
)

def _row_renders_as_empty_marker(value: object) -> bool:
    """Does a `ceiling_test` row render as the format's own empty marker (`none`/`n/a`) — or as
    nothing at all? A row this is True for STATES NOTHING and is silently skipped: it is not a
    malformed receipt, it is the format's own "no gap" spelling."""
    return isinstance(value, str) and (not value.strip() or is_conclude_empty_marker(value))


#: The closed states a `ceiling_test` receipt may claim (#923 §7 round 4 REPLACEMENT: the
#: free-text "does this sentence name a source or capability" judgment — which measurably
#: refused three-letter telemetry sources (`EDR`, `WMI`, `ETW`) while `unknown` bought a close
#: outright — is gone, not kept alongside anything). A receipt is a pointer into this run's OWN
#: transcript the host verifies MECHANICALLY, never a judgment of prose.
#:
#: Three states, because three are all today's instrumentation can tell apart WITHOUT reading
#: the model's own words: `_lead_retrieval_came_back` (below) splits "this lead's own RETRIEVAL
#: came back with something" from "it did not" — a resolution reached from absent data does
#: not, by itself, count as "something came back" — and a `:L findings` row's `fail_reason`
#: cell — checked for PRESENCE, never CONTENT — splits "errored" from "ran clean and got
#: nothing". `access-denied`
#: and `out-of-retention` are deliberately NOT here: nothing in this deployment's
#: instrumentation distinguishes either of them from an ordinary failure short of parsing
#: `fail_reason`'s free text, which is exactly the judgment call this redesign exists to
#: delete. Add either only once a host-side signal exists that tells it apart from
#: `query-failed` mechanically — e.g. the query tool recording its own distinct `error_class`
#: for a permission refusal (today `circuit_breaker.error_class_for_exit` has only `infra` and
#: `agent-fixable`), or an adapter distinguishing an explicit before-retention response from an
#: ordinary empty one.
CEILING_QUERY_FAILED = "query-failed"
CEILING_QUERY_EMPTY = "query-empty"
CEILING_NOTHING_TO_TRY = "nothing-to-try"
CEILING_STATES: tuple[str, ...] = (
    CEILING_QUERY_FAILED, CEILING_QUERY_EMPTY, CEILING_NOTHING_TO_TRY,
)

#: The two states that anchor to a lead THIS RUN dispatched. `nothing-to-try` is the one lane
#: with no call to point at — a capability that does not exist at all, so nothing was
#: dispatchable — which is why it is the only state NOT in this set.
_LEAD_ANCHORED_STATES: tuple[str, ...] = (CEILING_QUERY_FAILED, CEILING_QUERY_EMPTY)

#: The shape a `:L findings` lead id takes everywhere this format declares one — the id
#: fragment `_tokenize._LEAD_PREFIX_RE` anchors its sub-block headers on (`l-<alphanumeric>`).
#: A `ceiling_test` receipt's `ref` is checked against this BEFORE the FK lookup, because the
#: lookup alone (exact membership in `:L findings`) does not constrain shape: that table's own
#: `id` cell is unquoted free text with no shape rule anywhere in the parser, so "exact
#: membership" is satisfied by a lead a model declared with a delimiter-shaped id just as
#: readily as by an ordinary one.
_LEAD_REF_RE = re.compile(r"l-[A-Za-z0-9]+")


@dataclass(frozen=True)
class CeilingReceipt:
    """One parsed `ceiling_test` row. `state`/`ref`/`cap` are the STRUCTURED half — closed
    vocabulary plus an id, mechanically checked against this run's own transcript — and the
    only part that rides into the committed report's frontmatter (`ceiling_test_block`). `note`
    is free text FOR THE HUMAN ANALYST: it gates NOTHING (`_check_ceiling_receipt` never reads
    it for anything but the one injection check every model-authored report field gets) and
    rides into the report BODY, never the frontmatter — because it gates nothing, it can never
    strand a run on a value the write gate accepted and the close then refused."""

    state: str
    ref: str | None
    cap: str | None
    note: str
    raw: str


#: `state=... [ref=...] [cap=...] note=<free text>` — `note=` is always LAST and consumes the
#: rest of the line, so it needs no quoting or escaping: nothing follows it for a delimiter to
#: protect. `ref`/`state`/`cap` are `\S+` tokens compared for EXACT membership (a closed enum,
#: an existing `:L findings` id, a real `system[.verb]`) — unlike the retired free-text
#: predicate, nothing here needs confusable or zero-width folding: a homoglyph'd token simply
#: fails the exact-match check it is compared against, rather than needing to be defended
#: against passing one.
_RECEIPT_ROW_RE = re.compile(r"^(?P<fields>(?:\S+=\S+\s+)*)note=(?P<note>.*)$")
_RECEIPT_FIELD_RE = re.compile(r"(\S+)=(\S+)")
_RECEIPT_FIELD_NAMES = frozenset({"ref", "state", "cap"})


def _parse_ceiling_row(row: str) -> CeilingReceipt | None:
    """Parse one `ceiling_test` row into a receipt, or `None` when the row is not shaped like
    one at all — free prose, the retired format, a typo. `None` is not itself a refusal; the
    caller decides what an unparseable row costs."""
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


#: `defender/scripts/adapters/*_adapter.py` — the closed universe of `(system, verb)` pairs
#: this codebase can dispatch through AT ALL, read COLD (no adapter imported) the same way
#: `runtime.verb_roster`'s own audit reads it. This is the roster `nothing-to-try` is checked
#: against, and it is closed BY CONSTRUCTION: it is code this repo owns, never a catalogue of
#: data sources that exist in the world — enumerating those (internal applications included) is
#: exactly what the #923 design discussion rejected as unmaintainable.
@lru_cache(maxsize=1)
def _known_capabilities() -> Mapping[str, frozenset[str]]:
    from defender._git import REPO_ROOT
    from defender.runtime.verbs import (
        ADAPTER_SUFFIX,
        _system_of,
        declared_verb_names,
        is_system_name,
    )

    adapters_dir = REPO_ROOT / "defender" / "scripts" / "adapters"
    if not adapters_dir.is_dir():
        return {}
    systems = {
        _system_of(p) for p in adapters_dir.glob("*" + ADAPTER_SUFFIX)
        if is_system_name(_system_of(p))
    }
    return {s: declared_verb_names(adapters_dir, s) for s in systems}


def _capability_exists(cap: str) -> bool:
    """Does `cap` name a REAL `system` or `system.verb` this deployment's adapters declare?
    `nothing-to-try` pays only when this is False."""
    known = _known_capabilities()
    system, sep, verb = cap.partition(".")
    if sep:
        return verb in known.get(system, frozenset())
    return cap in known


def _cap_is_identifier_shaped(cap: str) -> bool:
    """Is `cap` actually shaped like `<system>` or `<system.verb>` — the shape its own refusal
    text already claims — rather than arbitrary text?

    `cap` is the ONE receipt field checked by ABSENCE (`not _capability_exists`, above), and a
    negative existence check cannot constrain shape: it is satisfied by ANY string that happens
    not to name a real capability, `</report>` and `disposition:malicious` included — measured,
    `yaml.safe_dump` quotes some of those on the way into the frontmatter and leaves others
    (the delimiter among them) bare, which is the dumper saving the day, not the gate. `ref` and
    `state` need no twin of this: both are checked by PRESENCE — exact membership in this run's
    own `:L findings` table, exact membership in `CEILING_STATES` — and presence-checking an
    arbitrary string against a closed set already refuses everything that is not a member.

    Reuses `runtime.verbs.is_system_name`/`SYSTEM_PATTERN` — the SAME alphabet a real system or
    verb name is drawn from — rather than a second, locally-invented shape; there is no
    `is_verb_name` to call, so the verb half is matched against the identical pattern
    `is_system_name` checks the system half with (`runtime.verb_roster`'s own comment: "verb
    names share this alphabet")."""
    from defender.runtime.verbs import SYSTEM_PATTERN, is_system_name

    system, sep, verb = cap.partition(".")
    if not is_system_name(system):
        return False
    return not sep or bool(re.fullmatch(SYSTEM_PATTERN, verb))


#: `_artifact_schema.REPORT_CLOSE_DELIMITER`, spelled here rather than imported (that module
#: imports THIS package). A NOTE carrying it clears every structural check below and then
#: breaks the judge's own report-block boundary once it rides into `report.md`'s BODY — the
#: same "refused for a file the model cannot write" trap the retired free-text row's own check
#: existed to avoid, so it is refused HERE, before the document lands.
_REPORT_CLOSE_DELIMITER = "</report>"


def ceiling_test_block(receipts: Sequence[CeilingReceipt]) -> str:
    """@owns ceiling_test

    The `ceiling_test:` frontmatter block for `receipts` — `ref`/`state`/`cap` ONLY, never
    the `note` (the report BODY's, not the frontmatter's; see `CeilingReceipt`). THE one
    renderer, so the gate that BOUNDS this (`_check_inconclusive_gating`) and
    `close_tool.render_report`, which EMITS it, measure and write the same bytes. Goes through
    PyYAML's own dumper rather than an f-string for the same reason the retired free-text
    renderer did: `ref`/`cap` are model-cited tokens in a host-owned file."""
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
    return yaml.safe_dump(
        {"ceiling_test": rows},
        allow_unicode=True, default_flow_style=False, sort_keys=False, width=10**9,
    )


def _check_lead_anchored_receipt(companion: CompanionBody, receipt: CeilingReceipt) -> str | None:
    """The `query-failed`/`query-empty` half of `_check_ceiling_receipt`: `ref` has to resolve
    to a `:L findings` lead THIS RUN dispatched whose own RETRIEVAL — not any conclusion drawn
    about it — came back with nothing (`_lead_retrieval_came_back`), and the claimed state has
    to match whether that lead's own row recorded a `fail_reason`."""
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
        # `ref` is checked by PRESENCE — exact membership in `:L findings` — which reads as
        # closed, but the TABLE it is exact-matched against is not: a `:L findings` row's `id`
        # cell is unquoted free text with no shape rule of its own anywhere in this parser (a
        # lead literally named `</report>` parses with zero warnings). So "exact membership"
        # alone does not constrain SHAPE here, exactly the way `_capability_exists` alone did
        # not for `cap` — a `ref` naming a lead that happens to exist AND happens to be
        # delimiter-shaped would still strand a run. Checked against the shape this format
        # ships everywhere a lead is declared (`l-<alnum>`, `_LEAD_PREFIX_RE`'s own id
        # fragment), ahead of the lookup, so a hostile id cannot be planted and then cited.
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
    """The `nothing-to-try` half of `_check_ceiling_receipt`: no call was dispatchable, so
    there is nothing to point `ref` at — `cap` has to name a capability the closed verb roster
    genuinely does not declare."""
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
    """Is `receipt` CONSISTENT with what this run's OWN transcript says happened — a
    foreign-key check and a closed-vocabulary check, never a judgment of what the note says.
    Returns the refusal text, or `None` when the receipt PAYS."""
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


@dataclass(frozen=True)
class _CeilingWalk:
    """The result of walking a `:T conclude.ceiling_test` list once: every row that PAYS, in
    document order and deduplicated, and every row-level complaint. THE one walk — the gate
    that prices these rows (`_check_inconclusive_gating`) and the reader that carries them into
    the committed report (`conclude_ceiling_test_rows`) share this result, so a row the gate
    refused can never ride into `report.md` and a row it accepted can never be silently dropped
    on the way there."""

    paying: tuple[CeilingReceipt, ...]
    errors: tuple[str, ...]


def _walk_ceiling_rows(companion: CompanionBody, rows: Any) -> _CeilingWalk:
    paying: list[CeilingReceipt] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    # `isinstance(list)`, not `rows or []`: the projector always hands this key a list, but a
    # bare `for row in rows` over a STRING would walk its characters one letter at a time.
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, str) or _row_renders_as_empty_marker(row):
            continue
        receipt = _parse_ceiling_row(row)
        if receipt is None:
            # SILENT, like the retired free-text predicate's "does not pay": a row that is not
            # even shaped like a receipt attempt is not a fault to name, it simply states
            # nothing this gate can price. The aggregate "no receipt pays" message below is
            # where the guidance lives, and it fires whenever THIS row is the only one written
            # — a receipt written beside it still clears, exactly as an ordinary non-paying
            # sentence used to beside a paying one.
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


#: The bound on the FRONTMATTER receipt block a priced `inconclusive` close may carry — the
#: `ref`/`state`/`cap` triples alone, never the notes (which live in the report BODY and gate
#: nothing: a size cap on ungated text is itself a gate). Charged on the RENDERED block
#: (`ceiling_test_block`), never a raw-text estimate, for the same reason
#: `_artifact_schema._utf8_len` measures bytes: PyYAML quotes and escapes what it emits, and a
#: measurement that disagrees with the renderer can pass a document here that the commit then
#: refuses anyway. Deliberately WELL under `_artifact_schema.REPORT_FRONTMATTER_MAX` (512
#: bytes). In practice this is now far from a real limit — one receipt is a handful of short
#: tokens — and exists as insurance against a run naming an unreasonable NUMBER of receipts
#: rather than against any one receipt's size.
_MAX_CEILING_FRONTMATTER_BYTES = 300


def _check_inconclusive_gating(companion: CompanionBody) -> list[str]:
    """`inconclusive` owes a named gap (O1, #923 §7 round 4 REPLACEMENT): at least one
    `ceiling_test` row that is a valid RECEIPT. A row pays when it is a
    `state=query-failed`/`state=query-empty` receipt whose `ref` resolves to a `:L findings`
    lead THIS RUN dispatched and whose own RETRIEVAL — not any conclusion drawn about it — is
    consistent with the claimed state (a foreign-key lookup — `_lead_by_id`, the SAME one
    `entity_check` uses — plus a consistency check against `outcome`'s retrieval-populated
    keys, `_lead_retrieval_came_back`), or a `state=nothing-to-try`
    receipt whose `cap` names a capability that does not exist anywhere in this codebase's
    closed verb roster. Rows must be DISTINCT, and the accumulated FRONTMATTER receipt text is
    BOUNDED. Both fire at both boundaries this check is collected from (the `investigation.md`
    write gate and the close), because the table (`_DISPOSITION_GATES`) is collected at both
    from one definition."""
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


_INCONCLUSIVE_PRICE = _Price(
    check=_check_inconclusive_gating,
    rationale=(
        "`inconclusive` says the investigating model could not settle the case, which is "
        "worth nothing to an analyst unless the report names what specifically it could not "
        "check — so it is reachable only from a `:T conclude` naming at least one "
        "`ceiling_test` RECEIPT: `state=query-failed`/`state=query-empty` pointing (`ref=`) at "
        "a `:L findings` lead this run dispatched that failed or came back empty, consistent "
        "with that lead's own recorded outcome, or `state=nothing-to-try` naming (`cap=`) a "
        "capability that does not exist anywhere in this deployment. Mechanically verified "
        "against the run's own transcript — never a judgment of prose."
    ),
)

_DISPOSITION_GATES: dict[str, _Price] = {
    "benign": _BENIGN_PRICE,
    "false-positive": _FALSE_POSITIVE_PRICE,
    "inconclusive": _INCONCLUSIVE_PRICE,
}


@dataclass(frozen=True)
class EntryPrice:
    """What a close still owes for its keyword, and why that keyword owes anything.

    Both halves come back from ONE dispatch so a caller cannot look the second up on a
    differently-normalized value than the first — which would lose the refusal's explanation on
    exactly the zero-width-laced keyword normalization exists for.
    """

    owed: tuple[str, ...]
    rationale: str

    def __bool__(self) -> bool:
        """Truthy when something is owed, so `if price:` reads as "is anything outstanding".
        An unpriced keyword and a paid document are both falsy — the caller does not care
        which, and neither blocks a close."""
        return bool(self.owed)


def conclude_ceiling_test_rows(companion_text: str) -> tuple[CeilingReceipt, ...]:
    """The `:T conclude.ceiling_test` receipts a companion wrote that this module PRICED, in
    document order.

    Public alongside `disposition_entry_price` for the same reason that one is: `report.md` is
    written from the close's disposition ARGUMENT and never re-reads the companion, so the
    close carries these into the committed report itself (#923's coverage channel) by calling
    this — `ref`/`state` are the one place model-CHOSEN structure belongs in a host-rendered
    report's frontmatter, and `note` the one place model-authored TEXT belongs in its body.

    Reuses `_check_inconclusive_gating`'s OWN walk (`_walk_ceiling_rows`) rather than
    re-deriving which rows pay, because the receipts it hands back are the receipts that ride
    into the frontmatter, and the bound the gate charges is only a bound on what ships if the
    two are the same set — a reader that re-derived "paying" independently could disagree with
    the gate that already ran and carry a row into `report.md` the gate never priced."""
    companion, _ = parse_dense_companion(companion_text)
    conclude = companion.get("conclude") or {}
    return _walk_ceiling_rows(companion, conclude.get("ceiling_test")).paying


def disposition_entry_price(disposition: str, companion_text: str) -> EntryPrice:
    """What `disposition` still owes, read off an `investigation.md` — nothing owed when it
    owes nothing, and nothing owed for the keywords `_DISPOSITION_GATES` prices at nothing.

    Public because a price has to be collected at BOTH boundaries. This module gates the
    `investigation.md` write; `report.md` is written by `close_investigation`, which takes its
    disposition as a tool argument and never reads the companion. Without a second reader an
    entry price is bypassable by writing `:T conclude` with a cheaper keyword — or none — and
    passing the priced one to the close, which is the artifact the learning loop, the evals and
    the ticket lane all actually read.

    The mirror of `_check_disposition_gating`, and deliberately the same table read: that one
    dispatches on the disposition the DOCUMENT wrote, this one on the disposition the CALLER is
    about to commit, so a row added to `_DISPOSITION_GATES` is collected at both.

    `disposition` is normalized through `_rendered_disposition` — the module's own FORGIVING
    normalizer, not `defender._vocab.normalized_disposition` (#923 makes that one exact-only,
    since the READ side must stop coercing a malformed verdict) — for the same reason the
    write-side dispatch is: a keyword is judged on what it RENDERS as, so a zero-width
    character cannot turn a gate off. Typed `str` rather than `object` even though the
    normalizer accepts anything: an unrecognized value takes the unpriced branch, so this
    dispatch fails OPEN on a wrong one, and `object` would let the type checker pass a caller
    that swapped these two arguments — both are `str` — and silently waive the price. (The
    write-side dispatch reads a value off a parsed DOCUMENT and keeps the wider type honestly.)

    What each price means about an ABSENT companion is the gate's own business, and both priced
    ones answer it the same way for different reasons: `false-positive` demands stated content,
    so nothing written owes everything, and `benign` demands a prologue vertex beneath its
    contradiction checks (`_check_benign_grounding`), which are vacuous over a document with no
    vertices.
    """
    priced = _rendered_disposition(disposition)
    price = _DISPOSITION_GATES.get(priced) if priced else None
    if price is None:
        return EntryPrice(owed=(), rationale="")
    companion, _ = parse_dense_companion(companion_text)
    return EntryPrice(owed=tuple(price.check(companion)), rationale=price.rationale)


def _check_disposition_gating(companion: CompanionBody) -> list[str]:
    """Run the structural checks this run's disposition is priced at, and only those.

    Dispatched on what the value RENDERS as, FORGIVINGLY (`_rendered_disposition`) — this is
    the ONE branch that decides whether a disposition's structural checks run at all, so a
    zero-width character clinging to the keyword would turn them all off — a gate failing open
    on an invisible character in model-authored text. `_check_conclude_vocab` denies the laced
    spelling separately, and the two rules stay independent on purpose: either alone would
    leave a hole. Deliberately NOT `defender._vocab.normalized_disposition` — #923 makes that
    reader exact-only (the READ side must not coerce a malformed verdict); this WRITE-side
    dispatch keeps its own forgiving normalizer so it still fails closed on one.
    """
    disposition = _rendered_disposition(
        (companion.get("conclude") or {}).get("disposition")
    )
    price = _DISPOSITION_GATES.get(disposition) if disposition else None
    return price.check(companion) if price is not None else []




#: `:L findings`' `mode` cell for a fast-path screen lead, and the `screen_result` that says
#: the screen HIT. The only two cell values the SCREEN rule turns on — every other mode and
#: every other result passes through it untouched.
SCREEN_MODE = "screen"
SCREEN_MATCH = "match"


def _check_screen_structure(companion: CompanionBody) -> list[str]:
    """A `screen_result` is a SCREEN lead's verdict, and two ways a document can carry one
    that decides nothing.

    On a lead with no `mode: screen` it is a verdict about a screen that never ran, written in
    the slot every reader takes for the run's fast-path answer. A `match` beside a `hypothesize`
    block is the second, and the only one with a disposition behind it — a matched screen ENDS
    the run on the fast path, so a companion that then enumerates hypotheses claims both that
    no investigation was needed and that one happened. WHICH of its two repairs is reachable
    depends on which half the document wrote first, and one of them always is — that is the
    whole of why this arm survives the strike below and the intermediate arm did not. Leads
    first (the shape the arm was written against): the `:L findings` cell is committed and "do
    not write the block" is the reachable repair. `:H hypothesize.hypotheses` first, which is
    the ORDINARY phase order: the block is committed and "record the screen as `no_match`" is
    the reachable one. Either way the trigger is the write in hand, which is what the
    intermediate arm never had.

    THE ONE ORDERING WHERE NEITHER IS: a `match` committed on an earlier screen, then a later
    screen in the same loop falling through and a `:H` block beside it. The run's answer is the
    last screen's `no_match`, so hypothesizing is right — and this arm still names the earlier
    committed `match` cell, which no write can withdraw. Recorded in the enforcement ramp as
    the wedge v2.22 leaves open; closing it wants the arm to read the loop's LAST
    `screen_result`, which is the `:L findings` document order `companion["findings"]` does not
    carry.

    THE INTERMEDIATE ARM IS GONE, and it is not coming back in this shape. The spec's third
    clause reads a `screen_result` on any screen lead that a later same-loop screen follows as
    a partial answer in the sequence's slot. The reading is defensible and the refusal is not
    reachable: whether a screen is the last one is a fact about leads not yet written, so the
    author cannot know it when writing the row, and by the time a second screen makes the first
    intermediate the first is a committed `:L findings` cell no legal write can withdraw. The
    arm named that earlier lead and offered "only its final lead carries the result", which is
    an instruction to have written a different row — and unlike the `match` arm it offered no
    second repair the proposed write could take. An earlier revision carved `match` out of this
    arm for exactly that reason, and the carve-out was the whole rule. What is lost is real —
    an early `no_match` still reads as the sequence's answer to a careless reader — and it is a
    reader-side concern that `:L findings` DOCUMENT order and the `loop` column answer for a
    human. Not for a programmatic one: `companion["findings"]` is the projector's lead buckets
    in FIRST-MENTION order, so a `:T resolutions` head naming a lead ahead of its `:L findings`
    row reorders the list and "the last `screen_result` in the loop" is not the last one
    written. Recorded in the enforcement ramp.

    Read off `findings[].screen_result`, which is where the `:L findings` column projects. The
    spec spells the field `outcome.screen_result`, from the pre-dense envelope; the projection
    has never nested it.

    NOT checked: whether the verdict is the right one, or whether the indicators it claims to
    rest on were retrieved. `screen_result` is a scalar the model writes and nothing beneath it
    is projected — the same limit `_check_false_positive_gating` records for `entity_check`.
    """
    leads = _leads(companion)
    # LOWERCASED at the read, because both cells are compared against a closed value and
    # neither is checked by any `_check_vocab_*` arm: `Screen` read raw fails CLOSED (a row
    # refused for a mode it spells correctly, with advice the author already followed) and
    # `Match` read raw fails OPEN (the fast-path arm below never fires).
    #
    # `screen_result` is the only one of the two folded across the whole document, and only to
    # buy the early return. `mode` is read PER ROW inside the loop: both surviving arms ask it
    # of the row they are judging, and the parallel-list shape the struck intermediate arm
    # needed (it scanned `modes[j]` for every `j > i`) is an invitation to reach across leads
    # again, which is the reading that arm was struck for.
    results = [_cell(lead, "screen_result").lower() for lead in leads]
    if not any(results):
        # Before the per-lead fold. No `screen_result` anywhere is every document in the tree
        # today, and every run that never takes the fast path.
        return []
    first_match = ""
    errors: list[str] = []
    for lead, result in zip(leads, results, strict=True):
        # `none` / `n/a` is the format's empty-cell spelling, not a verdict — the same reading
        # `_check_refutation_scope` takes of a `refutes` cell. Writing it in an unused trailing
        # column is the shipped convention (`defender/examples/example-b-parallel-iam-cmdb.md`
        # does it in `window`), so reading it as a screen result refuses a row that says
        # "nothing here" and offers "drop the cell" as the repair.
        if not result or is_conclude_empty_marker(result):
            continue
        lid = lead.get("id", "?")
        mode = _cell(lead, "mode").lower()
        # The matched-screen arm below speaks only for leads that ACTUALLY screened. A
        # `match` on a lead with no `mode: screen` is one defect — the mode arm's — and
        # letting it reach the fast-path arm too tells the same author, in the same pass, to
        # set the mode cell AND to delete a legitimate hypothesize block over a screen that
        # never ran.
        if mode != SCREEN_MODE:
            errors.append(
                f"lead {lid}: `screen_result: {result}` on a lead whose mode is {mode!r} — "
                f"the column records a SCREEN's verdict; set `mode: screen` on the lead that "
                f"ran the screen, or drop the cell"
            )
        elif result == SCREEN_MATCH and not first_match:
            # FIRST in `companion["findings"]` order, which is the projector's lead buckets in
            # FIRST-MENTION order rather than `:L findings` order — so with two matched screens
            # and a `:T resolutions` head naming the later one ahead of its row, the message
            # names the later-written cell. Same limit the docstring records for reading "the
            # loop's last `screen_result`", and it bites here for the same reason.
            first_match = str(lid)
    if first_match and _walkers.all_hypotheses(companion):
        errors.append(
            f"lead {first_match}: `screen_result: {SCREEN_MATCH}` closes the run on the fast "
            f"path, but {_HYPOTHESIS_DECLARING_BLOCKS} enumerates hypotheses — a matched "
            f"screen and an investigation are two different runs; drop the block, or record "
            f"the screen as `no_match` and keep investigating"
        )
    return errors


def _weight_text(weight: Any) -> str:
    """A hypothesis weight as the FORMAT spells it, for a message the author has to act on.

    `_hypothesis_record` maps the `weight null` cell to Python `None`, and an omitted cell
    leaves the key off — so `{weight!r}` renders `None` for exactly the hypothesis a
    persistence refusal is about. `null` is what the author wrote and what they can search for.
    """
    return repr(weight if isinstance(weight, str) and weight else vocab.NULL_WEIGHT)


def _check_hypothesis_persistence(companion: CompanionBody) -> list[str]:
    """A close that ENUMERATES its survivors enumerates all of them. A hypothesis the run
    neither refuted nor listed was dropped, and nothing else on disk says so.

    The failure is grading blindness papered over by silence: a hypothesis declared in loop 1,
    never moved off `null`, and left out of the close reads exactly like one that was never
    proposed. The document then concludes over a smaller mechanism set than it opened with,
    and no reader can tell which one went missing.

    Two discharges. Final effective weight `--` — the run refuted it — or a
    `:T conclude.surviving` row naming it. What was not refuted is what the run is still
    carrying, and naming it is the whole price. #933 retired the third, a `:T shelved` row:
    no investigation on record ever wrote one, and an escape hatch the injected SKILL.md never
    taught was reachable only by a run that guessed its grammar.

    A close that writes NO surviving table is out of scope, and that is a measured concession
    rather than an oversight. The table is omittable by construction — `_project_surviving_block`
    projects it "checkable, not authoritative" and benign gating computes survival from the
    resolution record precisely so a run may leave it out — so an absent table is read as the
    document deferring to that record, under which every non-refuted hypothesis IS surviving and
    nothing is dropped. Reading an absent table as an empty one instead would refuse seven of
    the eight ```invlang documents in the tree, both shipped goldens among them; making the
    table mandatory is a spec decision about what ANALYZE must write, not a validator decision
    about what this document says. The rule bites where the author made the claim: writing the
    table and leaving a live hypothesis out of it.

    NOT a claim that the table is TRUE. It is read as an ASSERTION the author made, never as
    evidence — which is what lets this demand the row without the row buying anything, and what
    keeps benign gating's independent computation of survival independent.

    v2.17: the spec's other two discharge arms are excised. `termination.rationale` is free text
    and `termination.category` an unchecked scalar, so "cited as the termination target" was
    never a projected hypothesis reference; and `matched_archetype` — "the matched archetype's
    mechanism" — is a `schema.Conclude` scalar no production code reads, resolved against an
    archetype catalog that does not exist. Neither was checkable, and an escape hatch that
    cannot be checked is one every document holds open.
    """
    conclude = companion.get("conclude") or {}
    # KEY presence, not row count. `_project_surviving_block` opens the bucket before it reads
    # a row, so an absent `:T conclude.surviving` block leaves the key off entirely while a
    # table written as the empty-array marker (`none`) leaves it present and empty — and the
    # second is a claim that NOTHING survived, which a live hypothesis contradicts.
    if "surviving_hypotheses" not in conclude:
        return []
    surviving = {
        row["hypothesis"] for row in conclude["surviving_hypotheses"]
        if isinstance(row, dict) and isinstance(row.get("hypothesis"), str)
    }
    return [
        f"conclude: hypothesis {hid} is neither refuted nor carried into the close — its "
        f"final weight is {_weight_text(weight)} and the `:T conclude.surviving` table, "
        f"which names {_known_ids(surviving)}, omits it. Resolve it to "
        f"{REFUTED_WEIGHT!r}, or add its row; a hypothesis declared and then dropped reads "
        f"like one that was never proposed"
        for hid, weight in _walkers.final_weights(companion).items()
        if weight != REFUTED_WEIGHT and hid not in surviving
    ]


#: The `termination.category` that makes rule #13 engage. A free-text scalar with NO closed
#: vocabulary anywhere in the system — `_check_vocab` has nothing to hand for it, and the
#: four-value enum the spec states (`trust-root`, `adversarial-refuted`, `severity-ceiling`,
#: `exhaustion-escalation`) is contradicted on disk by `data-ceiling` and
#: `adversarial-confirmed` in the two shipped e2e goldens. See
#: `_check_ceiling_test_scope` for what that costs the rule and why the vocabulary was not
#: closed here.
SEVERITY_CEILING = "severity-ceiling"


def _check_ceiling_test_scope(companion: CompanionBody) -> list[str]:
    """A run that terminates on a SEVERITY CEILING names the check it could not make.

    `severity-ceiling` is the strongest termination the language has that is not a refutation:
    live hypotheses remain and their critical edges cannot be tested with available tools. It
    is the one category that ends a run by declaring the question unanswerable, so it is the
    one that most needs a receipt — without `ceiling_test`, "severity ceiling" is a phrase, and
    the reader cannot tell a run that hit a real tooling boundary from one that stopped.

    The receipt is `ceiling_test`: one row per unreachable check, naming the host and the data
    source (`skills/invlang/SKILL.md` §`:T conclude`). The empty marker `none` projects as
    absence, so "wrote the row and said there was no ceiling" and "wrote no row" are the same
    document here, which is right — both claim no gap while the termination claims one.

    HALF the spec rule, deliberately. #13 also says `ceiling_test` is FORBIDDEN under any other
    termination, and that half is not implemented and should not be:

      * The field it forbids is not the field the spec was written about. The pilot spec's
        `ceiling_test` was `{kind, subject}` — THE out-of-band step that would resolve the
        ceiling, so "only under a ceiling" follows. The shipped field is the list of checks the
        run could not make, and eleven checked-in lessons instruct writing it whenever a source
        was out of reach ("name them by host and source type in `ceiling_test`"). Forbidding it
        elsewhere would refuse a run for obeying a lesson, which is the one failure
        `learning/core/persist.py` turns into a discarded run.
      * Measured: it would fire on the runs that name a telemetry gap and terminate on
        something else, which is the ordinary shape — `golden-v2sshd` names two such gaps in
        its prose and terminates `data-ceiling`.

    The TRIGGER is unbacked and this rule fails silent because of it. `termination.category` is
    free text with no vocabulary, so `severity_ceiling` or `severity-celing` disables this
    check with nothing said. That direction is the safe one — a typo costs a miss, never a
    wrongful refusal — but it is a real limit and not a rounding error. Closing the vocabulary
    would fix it and was NOT done here: the spec's four values are contradicted by both shipped
    e2e goldens (`data-ceiling`, `adversarial-confirmed`) and by three test corpora
    (`exhaustion`, `adversarial-confirmed`, `natural`), so closing it is a spec-owner decision
    with its own measurement, filed in the enforcement ramp rather than taken here.
    """
    conclude = companion.get("conclude") or {}
    category = (conclude.get("termination") or {}).get("category")
    # `_row_states_something` per row, not truthiness of the list. `ceiling_test  ""` projects
    # as a one-element list holding the empty string — truthy, and a receipt that names no
    # gap. The honest `ceiling_test  none` projects as absence and IS refused, so a bare
    # truthiness test makes the blank strictly easier to get past than the honest marker.
    if category != SEVERITY_CEILING or any(
        _row_states_something(t) for t in conclude.get("ceiling_test") or []
    ):
        return []
    return [
        f"conclude: `termination.category {SEVERITY_CEILING}` with no `ceiling_test` — the "
        f"category says live hypotheses remain and their critical edges cannot be tested, so "
        f"the close owes the specific check it could not make. Add one "
        f"`ceiling_test  state=query-failed ref=<lead-id> note=<text>` (or "
        f"`state=query-empty`) row per gap to `:T conclude` (repeat the key; the SKILL's "
        f"§`:T conclude` has the shape). If you wrote a `:T conclude.ceiling_test "
        f"[kind|subject]` sub-table, that is the RETIRED spelling from "
        f"`docs/dense-investigation-format.md` — the parser recognizes it and projects "
        f"nothing, so its rows never reach this rule; re-send them as flat rows. If nothing "
        f"was actually out of reach, this run did not hit a ceiling — terminate on the "
        f"category that describes what happened."
    ]
