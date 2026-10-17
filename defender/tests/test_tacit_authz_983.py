"""#983 mechanism A/B write gate: an authz contract resolved by convention must cite its own lead's recorded registry hit (a miss, a telemetry baseline, a stale window cannot ground it); baseline consultations; the `indeterminate` basis (retry vs exhausted, with exhausted paid for in the transcript); and that none of it changes the verdict or escalation."""

from __future__ import annotations

from defender.skills.invlang import _walkers, vocab
from defender.skills.invlang.frontier import derive_frontier
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import outstanding_authz_contracts, validate_companion
from defender.skills.invlang.validate._gating import disposition_entry_price
from defender.tests import _tacit983 as scene


def _errors(text: str) -> list[str]:
    """The validator's ERROR-severity refusals over a whole document — the surface every
    production caller reads. Bound to the public entry point rather than to a private check,
    so the tests survive the check being wired in wherever `diagnose` wants it."""
    return validate_companion(text, None)


def _mentioning(errors: list[str], *needles: str) -> list[str]:
    return [e for e in errors if all(n in e for n in needles)]


def _anchor_kind_systems() -> dict[str, str]:
    """`vocab.ANCHOR_KIND_SYSTEMS` — anchor kind → the gather system that answers it."""
    return vocab.ANCHOR_KIND_SYSTEMS


def _authz_rows(companion) -> list[dict]:
    return list(_walkers.iter_authz_resolutions(companion))


def _consultation_rows(companion) -> list[dict]:
    return list(_walkers.iter_anchor_consultations(companion))


def _consultation_doc(row: str) -> str:
    """The scene with ONE `:R consultations` row and an `iam-policy` contract."""
    return scene.document(
        rows=scene.consult_block(row), contract_anchor_kind="iam-policy", system="identity",
    )


# ---------------------------------------------------------------- the vocabularies


# ---------------------------------------------------------------- demand #0: the row shapes


def test_tacit_knowledge_authz_row_shape():
    """The CELLS of a discharging `:R authz` row: `verdict=authorized`,
    `anchor_kind=tacit-knowledge`, `grounding_kind=org-authority`, an `anchor_id` naming the
    registry entry and a `fulfills` naming the `ac<n>` it closes — parsed and accepted"""
    doc = scene.document(rows=scene.authorized_rows())
    assert _errors(doc) == []

    companion, warnings = parse_dense_companion(doc)
    assert warnings == []
    (row,) = _authz_rows(companion)
    assert row["verdict"] == "authorized"
    assert row["anchor_kind"] == "tacit-knowledge"
    assert row["grounding_kind"] == "org-authority"
    assert row["anchor_id"] == scene.ENTRY_ID
    assert row["fulfills_contract"] == "ac1"
    assert row["resolved_by_lead"] == scene.LEAD


def test_authz_anchor_id_must_match_its_own_leads_recorded_hit():
    """A `tacit-knowledge` `:R authz` row's `anchor_id` has to equal an `anchor_id` the lead
    named by its OWN `resolved_by_lead` recorded as a lookup outcome. A citation no lead
    produced is refused, and a benign close resting on it does not commit"""
    good = scene.benign_document(rows=scene.authorized_rows(baseline=True))
    assert _errors(good) == [], "positive control: the cited entry is the one the lead found"
    assert disposition_entry_price("benign", good).owed == (), (
        "a receipted registry hit did not pay benign's entry price — O1 stays blocked"
    )

    fabricated = scene.benign_document(
        rows=scene.authorized_rows(baseline=True, cited_id=scene.FABRICATED_ENTRY_ID))
    errors = _errors(fabricated)
    assert _mentioning(errors, scene.FABRICATED_ENTRY_ID), (
        "a `:R authz` row cited a registry entry its own lead never came back with, and the "
        "close was priced as though a human had authored the sanction"
    )
    assert disposition_entry_price("benign", fabricated).owed, (
        "the fabricated citation still paid benign's entry price — the check refuses the "
        "document at the write gate and lets the close through, which is the half of the "
        "price that the learning loop and the ticket lane actually read"
    )

    other_leads = scene.benign_document(
        rows=scene.authorized_rows(baseline=True, hit_by=scene.UNDISPATCHED_LEAD))
    assert _mentioning(_errors(other_leads), scene.ENTRY_ID), (
        f"the hit was recorded by {scene.UNDISPATCHED_LEAD} and cited by a row resolved by "
        f"{scene.LEAD} — the check is searching the whole document rather than the row's own "
        f"lead, so any lead's finding backs any row"
    )

    unrecorded = scene.benign_document(rows=scene.authz_block(scene.authz_row()))
    assert _mentioning(_errors(unrecorded), scene.ENTRY_ID), (
        "an `authorized` tacit-knowledge row whose lead recorded no lookup at all was "
        "accepted — the id is unbacked text, which is the whole of the gap O2 names"
    )


def test_a_missed_lookup_cannot_be_cited_as_a_hit():
    """A lead that recorded a MISS backs no citation: the `:R authz` row citing an entry id
    beside its own lead's empty-handed lookup is refused (demand `authz_anchor_id_is_receipted`)."""
    missed = scene.document(
        rows=scene.consult_block(scene.lookup_miss_row())
        + scene.authz_block(scene.authz_row()),
    )
    assert _mentioning(_errors(missed), scene.ENTRY_ID), (
        "a lookup that came back empty backed an `authorized` verdict citing an entry id — "
        "the row was checked for the PRESENCE of a consultation rather than for the id it "
        "carries"
    )

    honest = scene.document(
        rows=scene.consult_block(scene.lookup_miss_row())
        + scene.authz_block(scene.authz_row(
            verdict="indeterminate", grounding="", anchor_id="", basis="retry")),
        settled=False,
    )
    assert _errors(honest) == [], (
        "positive control: recording the miss and resolving `indeterminate` is the legal "
        "shape, and the check may not refuse the document that tells the truth"
    )


def test_a_telemetry_baseline_cannot_ground_an_authz_row():
    """`grounding_kind: telemetry-baseline` is consultation-only: a `:R authz` row carrying it
    is refused, whatever verdict it claims (demand `no_statistical_self_authorization`, O2)."""
    grounded_on_density = scene.document(
        rows=scene.consult_block(scene.consultation_row())
        + scene.authz_block(scene.authz_row(
            anchor_kind="runtime-evidence", grounding="telemetry-baseline",
            anchor_id="tk-baseline-30d",
            reasoning="1500 occurrences over 30d with nothing adverse in the window")),
    )
    errors = _errors(grounded_on_density)
    assert _mentioning(errors, "telemetry-baseline") or _mentioning(errors, "runtime-evidence"), (
        "a month of quiet recurrence authorized itself by being written into the `:R authz` "
        "bucket instead of the `:R consultations` one — the middle design this issue's own "
        "discussion discarded, reachable by moving one row"
    )
    assert disposition_entry_price("benign", scene.benign_document(
        rows=scene.consult_block(scene.consultation_row())
        + scene.authz_block(scene.authz_row(
            anchor_kind="runtime-evidence", grounding="telemetry-baseline",
            anchor_id="tk-baseline-30d")),
    )).owed, (
        "a telemetry-grounded `:R authz` row paid benign's entry price"
    )


def test_baseline_consultation_row_shape():
    """A baseline consultation is a `:R consultations` row with `anchor_kind=runtime-evidence`
    and `grounding_kind=telemetry-baseline`, carrying the window, the occurrence count and the
    adverse-outcome finding — and NO `fulfills` cell, because `AnchorConsultation` has no"""
    good = _consultation_doc(scene.consultation_row())
    assert _errors(good) == []

    companion, _ = parse_dense_companion(good)
    (row,) = _consultation_rows(companion)
    assert row["anchor_kind"] == "runtime-evidence"
    assert row["grounding_kind"] == "telemetry-baseline"
    assert row["effective_window"] == scene.WINDOW_BEFORE_ALERT
    assert "fulfills_contract" not in row, (
        "a consultation that can name a contract can discharge one — the shape of the row is "
        "what makes mechanism A context-only, not a convention about how it is used"
    )

    bad_kind = _consultation_doc(scene.consultation_row(anchor_kind="not-an-anchor-kind"))
    assert _mentioning(_errors(bad_kind), "anchor_kind", "not-an-anchor-kind"), (
        "an off-vocabulary anchor kind on a `:R consultations` row was accepted"
    )

    bad_grounding = _consultation_doc(scene.consultation_row(grounding="past-case"))
    assert _mentioning(_errors(bad_grounding), "past-case"), (
        "a consultation grounded outside `CONSULTATION_GROUNDING` was accepted"
    )


def test_indeterminate_authz_row_carries_basis():
    """A `:R authz` row whose verdict is `indeterminate` carries a `basis` cell that is one of
    `retry` or `exhausted`; an absent cell reads as `retry`, and any other value is refused
    (demand `indeterminate_basis_qualifier`, fork F3)."""
    for basis in vocab.AUTHZ_INDET_BASIS:
        row = scene.authz_row(verdict="indeterminate", basis=basis, grounding="", anchor_id="")
        assert _errors(scene.document(rows=scene.authz_block(row), settled=False)) == [], basis

    absent = scene.authz_row(verdict="indeterminate", basis="", grounding="", anchor_id="")
    assert _errors(scene.document(rows=scene.authz_block(absent), settled=False)) == [], (
        "an absent `basis` is legal and reads as `retry` — the default costs nothing to write"
    )

    junk = scene.authz_row(verdict="indeterminate", basis="whenever", grounding="", anchor_id="")
    assert _mentioning(
        _errors(scene.document(rows=scene.authz_block(junk), settled=False)),
        "basis", "whenever",
    ), (
        "an off-vocabulary `basis` was accepted — a misspelling would then be the cheapest way "
        "to claim `exhausted` without paying for it, exactly as an off-vocabulary weight cell "
        "used to be the cheapest way to skip every gate that reads the grade"
    )


# ---------------------------------------------------------------- mechanism A's guards


def test_window_must_predate_the_alerted_event():
    """A baseline consultation whose `effective_window` does not END STRICTLY BEFORE the
    alerted event is refused — a pattern that begins with the incident IS the incident (demand
    `consultation_window_predates_alert`)."""
    ok = _consultation_doc(scene.consultation_row(window=scene.WINDOW_BEFORE_ALERT))
    assert _errors(ok) == [], "positive control: a window that closes before the alert is legal"

    for label, window in (
        ("opens on the alerted event", scene.WINDOW_STARTING_AT_ALERT),
        ("opens one second after it", scene.WINDOW_STARTING_JUST_AFTER_ALERT),
        ("opens long before and closes long after", scene.WINDOW_SPANNING_THE_ALERT),
        ("closes on the alerted instant", scene.WINDOW_ENDING_AT_ALERT),
        ("cannot be parsed as a window at all", scene.WINDOW_UNPARSEABLE),
    ):
        doc = _consultation_doc(scene.consultation_row(window=window))
        assert _mentioning(_errors(doc), "effective_window"), (
            f"a baseline window that {label} ({window}) was accepted as context about what "
            f"PRECEDED the alert — the incident vouching for itself"
        )

    hit_row = scene.document(rows=scene.authorized_rows())
    assert _mentioning(_errors(hit_row), "effective_window") == [], (
        "the registry-hit consultation was refused for carrying the ENTRY's validity span, "
        "which brackets the alert on every unexpired entry — the guard is about a "
        "`runtime-evidence` baseline and has been applied to every consultation"
    )


def test_a_consultation_alone_cannot_buy_benign():
    """A document whose only authorization-shaped evidence is a `runtime-evidence`
    `:R consultations` row does not pay benign's entry price: the benign gate reads authz
    resolutions and never walks `anchor_consultations` (demand"""
    assert "telemetry-baseline" in vocab.CONSULTATION_GROUNDING

    doc = scene.document(rows=scene.consult_block(scene.consultation_row()), settled=False)
    assert _errors(doc) == [], "the consultation-only document is itself well formed"

    price = disposition_entry_price("benign", doc)
    assert price.owed, (
        "a dense baseline consultation paid benign's entry price — a type with no "
        "`fulfills_contract` field discharged a contract"
    )
    assert any("ac1" in owed for owed in price.owed)


def test_a_single_tacit_knowledge_row_is_full_authority():
    """One `tacit-knowledge` `:R authz` row classified `grounding_kind: org-authority` is
    sufficient ON ITS OWN to satisfy benign's entry price for its contract — no rule-27-shaped
    "never sole grounding" cap, and no forced `authority_for_question: partial`"""
    doc = scene.benign_document(rows=scene.authorized_rows())
    assert _errors(doc) == []
    assert disposition_entry_price("benign", doc).owed == (), (
        "one authored registry entry did not carry its own contract — a cap was applied to a "
        "source the design deliberately left uncapped"
    )
    assert outstanding_authz_contracts(parse_dense_companion(doc)[0]) == []


# ---------------------------------------------------------------- mechanism C


def test_exhausted_must_be_paid_for_in_the_transcript():
    """`basis=exhausted` is refused unless the row's own `resolved_by_lead` names a `:L findings`
    lead THIS RUN dispatched AGAINST THE SYSTEM the contract's anchor kind maps to — verified
    the way a `ceiling_test` receipt's `ref` is (demand `exhausted_checked_against_transcript`,"""
    paid = scene.authz_row(
        verdict="indeterminate", basis="exhausted", grounding="", anchor_id="",
        resolved_by=scene.LEAD,
    )
    assert _errors(scene.document(rows=scene.authz_block(paid), settled=False)) == [], (
        "positive control: the lead that actually ran the lookup may claim `exhausted`"
    )

    unpaid = scene.authz_row(
        verdict="indeterminate", basis="exhausted", grounding="", anchor_id="",
        resolved_by=scene.UNDISPATCHED_LEAD,
    )
    assert _mentioning(
        _errors(scene.document(rows=scene.authz_block(unpaid), settled=False)),
        "exhausted", scene.UNDISPATCHED_LEAD,
    ), (
        "`basis=exhausted` was accepted on a lead this run never dispatched — the claim that "
        "every applicable registry was actually queried was taken on the model's word"
    )

    wrong_system = scene.document(
        rows=scene.authz_block(paid), settled=False, system="host-state",
    )
    assert _mentioning(_errors(wrong_system), "exhausted"), (
        "`basis=exhausted` on a `tacit-knowledge` contract was paid for by a lead whose own "
        "`:L findings` row says it queried host-state — an unrelated attribute update on any "
        "lead buys the claim, which is the check being satisfied by 'the lead did something'"
    )
    assert _mentioning(
        _errors(wrong_system), _anchor_kind_systems()["tacit-knowledge"],
    ), "the refusal does not name the system the contract's anchor kind wanted queried"

    retry = scene.authz_row(
        verdict="indeterminate", basis="retry", grounding="", anchor_id="",
        resolved_by=scene.UNDISPATCHED_LEAD,
    )
    assert _errors(scene.document(rows=scene.authz_block(retry), settled=False)) == [], (
        "`retry` claims nothing about what was dispatched, so it owes no receipt"
    )


def test_exhausted_falls_back_to_the_loose_check_on_an_unmapped_kind():
    """On a contract whose anchor kind `ANCHOR_KIND_SYSTEMS` does not cover, `basis=exhausted`
    falls back to "this lead's own retrieval came back with something" — the looser check, kept
    deliberately and PINNED so the limitation is documented rather than discovered."""
    mapping = _anchor_kind_systems()
    unmapped = next(k for k in vocab.ANCHOR_KINDS if k not in mapping)

    doc = scene.document(
        contract_anchor_kind=unmapped, system="host-state", settled=False,
        rows=scene.authz_block(scene.authz_row(
            verdict="indeterminate", anchor_kind=unmapped, basis="exhausted",
            grounding="", anchor_id="", resolved_by=scene.LEAD)),
    )
    assert _errors(doc) == [], (
        f"`basis=exhausted` was refused on a {unmapped!r} contract, which no system mapping "
        f"covers — the fallback has to stay reachable or O4 is unavailable for every anchor "
        f"kind outside the mapping"
    )

    never_dispatched = scene.document(
        contract_anchor_kind=unmapped, system="host-state", settled=False,
        rows=scene.authz_block(scene.authz_row(
            verdict="indeterminate", anchor_kind=unmapped, basis="exhausted",
            grounding="", anchor_id="", resolved_by=scene.UNDISPATCHED_LEAD)),
    )
    assert _mentioning(_errors(never_dispatched), "exhausted", scene.UNDISPATCHED_LEAD), (
        "the fallback stopped checking anything at all — an unmapped anchor kind still owes "
        "the retrieval half of the receipt"
    )


def test_basis_does_not_change_the_verdict_or_the_escalation():
    """Both values of `basis` leave `verdict: indeterminate` and its forced `on_indet`
    escalation exactly as they are — a `basis=exhausted` row still blocks a benign close
    (demand `indeterminate_escalation_unchanged`)."""
    for basis in vocab.AUTHZ_INDET_BASIS:
        doc = scene.document(
            rows=scene.authz_block(scene.authz_row(
                verdict="indeterminate", basis=basis, grounding="", anchor_id="")),
            settled=False,
        )
        assert _errors(doc) == [], basis

        companion, _ = parse_dense_companion(doc)
        (row,) = _authz_rows(companion)
        assert row["verdict"] == "indeterminate", f"basis={basis!r} rewrote the verdict"

        outstanding = outstanding_authz_contracts(companion)
        assert [c.get("id") for _h, c, _w in outstanding] == ["ac1"], (
            f"basis={basis!r} moved the benign gate — the contract is no longer outstanding"
        )
        assert disposition_entry_price("benign", doc).owed, (
            f"basis={basis!r} bought a benign close that an indeterminate contract must block"
        )


def test_exhausted_contract_is_not_looped_back():
    """An `indeterminate` contract carrying `basis=exhausted` is not re-dispatched, while an
    otherwise identical contract carrying `basis=retry` is (demand
    `exhausted_is_not_redispatched`)."""
    def contracts(basis: str) -> list[str]:
        doc = scene.document(
            rows=scene.authz_block(scene.authz_row(
                verdict="indeterminate", basis=basis, grounding="", anchor_id="")),
            settled=False,
        )
        assert _errors(doc) == [], basis
        return [c.contract_id for c in derive_frontier(parse_dense_companion(doc)[0]).contracts]

    assert contracts("retry") == ["ac1"], (
        "positive control: a contract that simply has not been checked yet stays on the "
        "frontier, so the run is pushed back to work it"
    )
    assert contracts("") == ["ac1"], "an absent basis reads as `retry` on the frontier too"
    assert contracts("exhausted") == [], (
        "a registry that structurally cannot ever hold the answer consumed the same retry "
        "budget as one that simply has not been checked yet — O4's burned loop"
    )


def test_exhausted_drops_only_its_own_contract():
    """With TWO live contracts and `basis=exhausted` on a row fulfilling ONE of them, only that
    contract leaves the frontier; the other stays on it (demand `exhausted_is_not_redispatched`)."""
    doc = scene.document(
        second_contract=True, settled=False,
        rows=scene.authz_block(
            scene.authz_row(
                verdict="indeterminate", fulfills="ac1", basis="exhausted",
                grounding="", anchor_id=""),
            scene.authz_row(
                verdict="indeterminate", fulfills="ac2", anchor_kind="change-mgmt",
                basis="", grounding="", anchor_id="",
                reasoning="change-mgmt has not been queried for this window yet"),
        ),
    )
    assert _errors(doc) == [], "fixture control: the two-contract document is well formed"

    companion, _ = parse_dense_companion(doc)
    assert sorted(
        c.get("id") for _h, c, _w in outstanding_authz_contracts(companion)
    ) == ["ac1", "ac2"], (
        "fixture control: neither contract is discharged — both rows are `indeterminate`"
    )

    assert [c.contract_id for c in derive_frontier(companion).contracts] == ["ac2"], (
        "one `basis=exhausted` row cleared the whole open-contracts frontier rather than its "
        "own contract — the run stops being pushed at a `change-mgmt` question that was never "
        "asked, on the strength of a claim about the tacit-knowledge registry"
    )


def test_exhausted_is_well_defined_without_the_registry():
    """With no tacit-knowledge entry in play, `basis=exhausted` still means every anchor kind
    applicable to the predicate was tried: C's meaning narrows when B is absent but does not
    become undefined (demand `exhausted_degrades_without_b`, a survival demand)."""
    assert _anchor_kind_systems()["iam-policy"] == "identity"
    doc = scene.document(
        contract_anchor_kind="iam-policy", system="identity",
        rows=scene.authz_block(scene.authz_row(
            verdict="indeterminate", anchor_kind="iam-policy", basis="exhausted",
            grounding="", anchor_id="")),
        settled=False,
    )
    assert _errors(doc) == [], (
        "`basis=exhausted` was refused on a contract with no tacit-knowledge involvement — C "
        "cannot be coupled to B's shipping"
    )
    assert derive_frontier(parse_dense_companion(doc)[0]).contracts == ()
