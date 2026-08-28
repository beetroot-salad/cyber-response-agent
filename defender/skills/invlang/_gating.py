"""What a disposition costs.

One family of `validate.py`'s rules, split out at 4038 lines: benign grounding, the
false-positive gate, the screen's structure, and the severity ceiling. A conclusion that
has not paid its price is refused here.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from defender._vocab import normalized_disposition
from . import _walkers, vocab
from .parser import (
    is_conclude_empty_marker,
    parse_dense_companion,
)
from .schema import (
    CompanionBody,
    FindingRecord,
)
from ._diag import REFUTED_WEIGHT
from ._refs import _HYPOTHESIS_DECLARING_BLOCKS, _known_ids, _leads
from ._structure import _cell
from ._state import _check_benign_authz, _check_benign_open_slots




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

    lead = next(
        (f for f in _leads(companion) if f.get("id") == lead_id), None
    )
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

_DISPOSITION_GATES: dict[str, _Price] = {
    "benign": _BENIGN_PRICE,
    "false-positive": _FALSE_POSITIVE_PRICE,
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

    `disposition` is normalized through `normalized_disposition` for the same reason the
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
    priced = normalized_disposition(disposition)
    price = _DISPOSITION_GATES.get(priced) if priced else None
    if price is None:
        return EntryPrice(owed=(), rationale="")
    companion, _ = parse_dense_companion(companion_text)
    return EntryPrice(owed=tuple(price.check(companion)), rationale=price.rationale)


def _check_disposition_gating(companion: CompanionBody) -> list[str]:
    """Run the structural checks this run's disposition is priced at, and only those.

    Dispatched on what the value RENDERS as. This is the ONE branch that decides whether a
    disposition's structural checks run at all, so a zero-width character clinging to the
    keyword would turn them all off — a gate failing open on an invisible character in
    model-authored text. `_check_conclude_vocab` denies the laced spelling separately, and the
    two rules stay independent on purpose: either alone would leave a hole.
    """
    disposition = normalized_disposition(
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
        f"`ceiling_test  \"<host> <data source> not retrieved\"` row per gap to `:T conclude` "
        f"(repeat the key; the SKILL's §`:T conclude` has the shape), naming the source "
        f"rather than the shape of the question. If you wrote a `:T conclude.ceiling_test "
        f"[kind|subject]` sub-table, that is the RETIRED spelling from "
        f"`docs/dense-investigation-format.md` — the parser recognizes it and projects "
        f"nothing, so its rows never reach this rule; re-send them as flat rows. If nothing "
        f"was actually out of reach, this run did not hit a ceiling — terminate on the "
        f"category that describes what happened."
    ]
