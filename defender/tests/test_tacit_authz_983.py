"""#983 — authorization by convention, and the structural-vs-retriable split for `indeterminate`.

The invlang half: the two new closed vocabularies, the `tacit-knowledge` anchor kind, and the
three checks that make the new cells mean something. The registry file and its loader are
`test_tacit_knowledge_registry_983.py`; the `report.md` carrier is
`test_runtime_evidence_report_983.py`; the outcome-level scenarios are
`e2e/test_tacit_authz_e2e_983.py`.

WHERE THIS DEVIATES FROM `.spec-flow/frontiers/20-demands.md`'s PROVISIONAL READINGS — each
found by reading the seam, not by preference:

  * **F1 (registry location).** The frontier's provisional home was
    `skills/invlang/tacit_knowledge_registry.yaml`. Moved to
    `skills/tacit-knowledge/registry.yaml`, the per-system directory convention
    `defender/CLAUDE.md` documents and `runtime.verb_roster.model_read_surfaces` already
    enumerates: the registry is a SYSTEM's data, queried through a gather verb, not a
    vocabulary of the invlang module. The `id` eighth field is kept.
  * **F8 (what `basis=exhausted` is checked against).** The frontier's provisional reading was
    a predicate-scoped roster of gather systems verified against the run's executed queries.
    No anchor-kind→system mapping exists anywhere in the tree, and minting one is a second
    closed vocabulary to drift. `basis=exhausted` is instead checked against the row's OWN
    mandatory `resolved_by_lead` — the same `:L findings` foreign key a `ceiling_test`
    receipt's `ref` resolves through (`_gating._lead_by_id`).
  * **The `_lead_by_id` lookup is VACUOUS ON ITS OWN**, which the interface contract could not
    have known: `_check_lead_refs` already refuses any `:R` row whose `resolved_by` names a
    lead no `:L findings` row declares, and the row itself lands on the named lead's
    `outcome`, so `_lead_returned_a_result` is true by construction. The discriminating half
    is `_lead_retrieval_came_back` — the SAME predicate `_check_lead_anchored_receipt` uses, at
    the opposite polarity: a lead that actually dispatched a registry query recorded an
    observation or an attribute update; a lead that exists only as a name in a `resolved_by`
    cell recorded neither. `test_exhausted_must_be_paid_for_in_the_transcript` is written
    against that.
  * **`consultation_window_predates_alert` is NOT in the interface contract** handed to this
    suite. It is mechanism A's first stated guard in the design doc and a `form: test` demand
    in the frontier, so it is written here and flagged: an implementer working from the
    interface contract alone will not have built it.
  * **`exhausted_is_not_redispatched` has no literal carrier.** "Loop back to PLAN" is prose at
    `defender/SKILL.md:470` and nothing in the runtime reads it. The one mechanical surface
    that answers "which authz contracts is this run still expected to go work" is
    `skills/invlang/frontier.derive_frontier(...).contracts`, so that is what the test binds
    to. Note `frontier.py`'s own closing line — "this module must never be wired into that
    gate" — the demand is that `basis` moves the FRONTIER and leaves the GATE alone, which is
    exactly the pair asserted here and in
    `test_basis_does_not_change_the_verdict_or_the_escalation`.

TWO SHIPPED FIXTURES THE NEW CHECKS BREAK, for whoever implements them:
  * `tests/test_invlang_parser_characterization.py:337` projects a `:R consultations` row
    carrying `anchor_kind: cmdb` — not an `ANCHOR_KINDS` member. Arming the anchor-kind walk
    over consultations refuses it. That fixture is about PROJECTION, so the repair is to give
    it a real anchor kind, not to weaken the check.
  * `tests/test_invlang_vocab.py::test_list_slots_returns_sorted_strings` pins the `SLOTS` key
    set exactly; the two new slots are added to it in this change.
"""

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


def _authz_rows(companion) -> list[dict]:
    return list(_walkers.iter_authz_resolutions(companion))


def _consultation_rows(companion) -> list[dict]:
    return list(_walkers.iter_anchor_consultations(companion))


def _consultation_doc(row: str) -> str:
    """The scene with ONE `:R consultations` row and an `iam-policy` contract.

    Mechanism A's own tests take an anchor kind that predates this change, so a refusal they
    report is about the consultation row and never about `tacit-knowledge` not being in the
    enum yet — the isolation `_one_error`-style suites in this tree keep by hand."""
    return scene.document(
        rows=scene.consult_block(row), contract_anchor_kind="iam-policy", system="identity",
    )


# ---------------------------------------------------------------- the vocabularies


def test_tacit_knowledge_is_a_known_anchor_kind():
    """`tacit-knowledge` is a member of `ANCHOR_KINDS`, so `defender-invlang enum anchor-kinds`
    lists it and `_check_vocab_anchor_kinds` accepts it on BOTH an `:H h-NNN.authz` contract
    and the `:R authz` row that discharges it (demand `tacit_knowledge_in_anchor_kinds`).

    Both halves, because the checker walks both and the motivating case needs both: a contract
    declared under an anchor kind the enum refuses cannot be written at all, so the question it
    asks can never be posed, let alone answered."""
    assert "tacit-knowledge" in vocab.ANCHOR_KINDS
    assert vocab.SLOTS["anchor-kinds"] is vocab.ANCHOR_KINDS, (
        "the enum CLI must answer off the same tuple the checker reads — a second copy drifts"
    )

    doc = scene.document(rows=scene.authz_block(scene.authz_row()))
    assert _mentioning(_errors(doc), "anchor_kind", "tacit-knowledge") == [], (
        "a contract and a resolution both written under `tacit-knowledge` were refused"
    )


def test_the_two_new_slots_are_registered_and_closed():
    """`AUTHZ_INDET_BASIS` and `CONSULTATION_GROUNDING` exist, hold exactly what the design
    names, and are reachable through `defender-invlang enum` like every other closed set.

    Registered as well as declared: a vocabulary an author cannot look up is one the runtime
    prompt has to restate, which is the second-copy-goes-stale shape `vocab.SLOTS`' own comment
    exists to prevent."""
    assert vocab.AUTHZ_INDET_BASIS == ("retry", "exhausted")
    assert vocab.CONSULTATION_GROUNDING == ("org-authority", "telemetry-baseline")
    assert vocab.SLOTS["authz.basis"] is vocab.AUTHZ_INDET_BASIS
    assert vocab.SLOTS["consultation.grounding"] is vocab.CONSULTATION_GROUNDING
    assert "past-case" not in vocab.CONSULTATION_GROUNDING, (
        "a baseline consultation grounded on a past case is precedent-by-similarity wearing "
        "mechanism A's clothes — the non-obligation this design examined and rejected"
    )


# ---------------------------------------------------------------- demand #0: the row shapes


def test_tacit_hit_writes_org_authority_authz_row():
    """A scope-matching, unexpired registry entry resolves the authz contract as a `:R authz`
    row carrying `verdict=authorized`, `anchor_kind=tacit-knowledge`,
    `grounding_kind=org-authority`, an `anchor_id` naming the registry entry and a `fulfills`
    naming the `ac<n>` it closes — and the validator accepts every one of those cells
    (demand `authz_row_shape`).

    `grounding` and `anchor_id` are UNDOCUMENTED optional columns on the `:R authz` header
    (fork F5 / claim c10): the parser canonicalizes them today, but `skills/invlang/SKILL.md`
    names neither, so a model writing the row from the SKILL cannot emit them. Asserted on the
    PARSE rather than on silence, so the test says which cells actually landed."""
    doc = scene.document(rows=scene.authz_block(scene.authz_row()))
    assert _errors(doc) == []

    companion, warnings = parse_dense_companion(doc)
    assert warnings == []
    (row,) = _authz_rows(companion)
    assert row["verdict"] == "authorized"
    assert row["anchor_kind"] == "tacit-knowledge"
    assert row["grounding_kind"] == "org-authority"
    assert row["anchor_id"] == scene.ENTRY_ID
    assert row["fulfills_contract"] == "ac1"


def test_baseline_consultation_row_shape():
    """A baseline consultation is a `:R consultations` row with `anchor_kind=runtime-evidence`
    and `grounding_kind=telemetry-baseline`, carrying the window, the occurrence count and the
    adverse-outcome finding — and NO `fulfills` cell, because `AnchorConsultation` has no
    `fulfills_contract` field (demand `consultation_row_shape`, claim c2).

    The anchor kind is checked here and nowhere else today: `_check_vocab_anchor_kinds` walks
    the contract and the `:R authz` row and never the consultation, so `runtime-evidence` — the
    one anchor kind that ONLY a consultation may carry — is the enum member with no arm and no
    prose anywhere describing what discharges it (claim c1)."""
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
    (demand `indeterminate_basis_qualifier`, fork F3).

    Driven off `vocab.AUTHZ_INDET_BASIS` rather than off two literals — the `lint-vocabulary`
    shape: a test that spelled the members itself would keep passing while the enum said
    something else. Looped rather than parametrized so a missing enum FAILS rather than
    collecting zero cases and reading green."""
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
    """A consultation whose `effective_window` does not end before the alerted event is refused
    — a pattern that begins with the incident IS the incident (demand
    `consultation_window_predates_alert`).

    NOT IN THE INTERFACE CONTRACT this suite was handed; it is mechanism A's first stated guard
    in the design doc and a `form: test` demand in the frontier. See this module's docstring.
    The alerted moment is the `:E prologue.edges` `when` cell — the document's own record of
    when the thing being explained happened, so the check needs nothing from `alert.json`."""
    ok = _consultation_doc(scene.consultation_row(window=scene.WINDOW_BEFORE_ALERT))
    assert _errors(ok) == [], "positive control: a window that closes before the alert is legal"

    starts_at_the_alert = _consultation_doc(
        scene.consultation_row(window=scene.WINDOW_STARTING_AT_ALERT))
    assert _mentioning(_errors(starts_at_the_alert), "effective_window"), (
        "a baseline window opening on the alerted event was accepted as context about what "
        "preceded it — the incident vouching for itself"
    )


def test_a_consultation_alone_cannot_buy_benign():
    """A document whose only authorization-shaped evidence is a `runtime-evidence`
    `:R consultations` row does not pay benign's entry price: the benign gate reads authz
    resolutions and never walks `anchor_consultations` (demand
    `entry_price_ignores_consultations`, claim c13).

    A REGRESSION GUARD rather than new behavior, and that is the point — mechanism A adds a
    second companion-derived channel into `report.md`, and what must not travel with it is any
    reading of the consultation by the gate."""
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
    "never sole grounding" cap, and no forced `authority_for_question: partial`
    (demand `no_authority_cap_on_tacit_knowledge`, non-obligation 5).

    The rejection is observable, and a silently added cap would re-block exactly the case
    motivating the issue: a container-root contract has no second grounding to pair with, so a
    cap here is indistinguishable from refusing the mechanism outright."""
    doc = scene.benign_document(rows=scene.authz_block(scene.authz_row()))
    assert _errors(doc) == []
    assert disposition_entry_price("benign", doc).owed == (), (
        "one authored registry entry did not carry its own contract — a cap was applied to a "
        "source the design deliberately left uncapped"
    )
    assert outstanding_authz_contracts(parse_dense_companion(doc)[0]) == []


# ---------------------------------------------------------------- mechanism C


def test_exhausted_must_be_paid_for_in_the_transcript():
    """`basis=exhausted` is refused unless the row's own `resolved_by_lead` names a `:L findings`
    lead THIS RUN dispatched — verified the way a `ceiling_test` receipt's `ref` is
    (demand `exhausted_checked_against_transcript`, fork F8).

    `l-002` is declared in `:L findings` and never dispatched: it carries no `:V`/`:E`
    observations and no `:R attr_updates`, which is exactly the "nothing came back for this
    lead's own retrieval" question `_lead_retrieval_came_back` answers for a ceiling receipt.
    Existence alone cannot be the check — `_check_lead_refs` already refuses an undeclared
    `resolved_by`, so a check that only looked the id up would refuse nothing new. See this
    module's docstring."""
    paid = scene.authz_row(
        verdict="indeterminate", basis="exhausted", grounding="", anchor_id="",
        resolved_by="l-001",
    )
    assert _errors(scene.document(rows=scene.authz_block(paid), settled=False)) == [], (
        "positive control: the lead that actually ran the lookup may claim `exhausted`"
    )

    unpaid = scene.authz_row(
        verdict="indeterminate", basis="exhausted", grounding="", anchor_id="",
        resolved_by="l-002",
    )
    assert _mentioning(
        _errors(scene.document(rows=scene.authz_block(unpaid), settled=False)),
        "exhausted", "l-002",
    ), (
        "`basis=exhausted` was accepted on a lead this run never dispatched — the claim that "
        "every applicable registry was actually queried was taken on the model's word"
    )

    retry = scene.authz_row(
        verdict="indeterminate", basis="retry", grounding="", anchor_id="", resolved_by="l-002",
    )
    assert _errors(scene.document(rows=scene.authz_block(retry), settled=False)) == [], (
        "`retry` claims nothing about what was dispatched, so it owes no receipt"
    )


def test_basis_does_not_change_the_verdict_or_the_escalation():
    """Both values of `basis` leave `verdict: indeterminate` and its forced `on_indet`
    escalation exactly as they are — a `basis=exhausted` row still blocks a benign close
    (demand `indeterminate_escalation_unchanged`).

    The parity half of `test_exhausted_contract_is_not_looped_back`: `basis` may move the
    retrieval frontier and must not move the gate. A `basis` that quietly discharged a contract
    would turn "we asked everyone and nobody knew" into "authorized", which is the failure O2
    names in its own words."""
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
    `exhausted_is_not_redispatched`).

    Bound to `frontier.derive_frontier(...).contracts` — the one thing in the tree that answers
    "which authz contracts is this run still expected to go work". `defender/SKILL.md:470`'s
    loop-back sentence is prose nothing reads; see this module's docstring."""
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


def test_exhausted_is_well_defined_without_the_registry():
    """With no tacit-knowledge entry in play, `basis=exhausted` still means every anchor kind
    applicable to the predicate was tried: C's meaning narrows when B is absent but does not
    become undefined (demand `exhausted_degrades_without_b`, a survival demand).

    The contract here is declared under `iam-policy` — an anchor kind that predates this change
    entirely — so nothing in the check may reach for the tacit-knowledge registry."""
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
