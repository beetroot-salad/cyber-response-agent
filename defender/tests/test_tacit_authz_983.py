"""#983 — authorization by convention, and the structural-vs-retriable split for `indeterminate`.

The invlang half: the two new closed vocabularies, the `tacit-knowledge` anchor kind, and the
checks that make the new cells mean something. The registry file and its loader are
`test_tacit_knowledge_registry_983.py`; the `report.md` carrier is
`test_runtime_evidence_report_983.py`; the outcome-level scenarios are
`e2e/test_tacit_authz_e2e_983.py`.

THE ANCHOR RECEIPT — the interface contract this suite's hardening pass added, and the one an
implementer must build even though nothing in the original design doc spells it out.

O2 says authorization-by-convention comes only from an explicit, attributable, human-authored
record. Written as vocabulary alone that is unguarded: `verdict=authorized
anchor_kind=tacit-knowledge grounding=org-authority anchor_id=<anything>` closes benign on a
string the model chose, an expired entry's id and an entry nobody ever authored included.

So a `tacit-knowledge` authorization is checked the way a `ceiling_test` receipt is
(`validate/_gating._check_lead_anchored_receipt` / `_lead_by_id` /
`_lead_retrieval_came_back`), with the same division of labour:

  * the LEAD that ran `tacit-knowledge.lookup` records what came back as a `:R consultations`
    row on its own outcome — the existing `AnchorConsultation` shape, which already carries
    `anchor_kind`/`anchor_id`/`result` and structurally cannot discharge a contract
    (`schema.py`, claim c2), so recording the hit buys the document nothing by itself;
  * the `:R authz` row's `anchor_id` must EQUAL the `anchor_id` on such a row recorded by the
    lead its OWN `resolved_by_lead` cell names. Exact match, mechanically checked.

WHAT THAT DOES AND DOES NOT BUY, stated because a receipt that is read as more than it is
becomes the next gap. The validator never touches the filesystem and never re-runs the lookup
— exactly like `ceiling_test`, it cross-checks the DOCUMENT'S OWN recorded facts. So it
refuses the cheap fabrications (an id out of the air, an id another lead found, an id cited
where the lead recorded a miss) and it does NOT prove the registry really holds that entry;
that half is the e2e's, which drives the real adapter. What it buys structurally is that
faking an authorization now takes two coordinated rows instead of one cell, and the second row
is a claim about a retrieval that `executed_queries.jsonl` independently records.

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
    Two halves, and only the second is reachable from inside the document:
      - `_lead_retrieval_came_back` — the SAME predicate `_check_lead_anchored_receipt` uses,
        at the opposite polarity. A lead that dispatched something recorded an observation or
        an attribute update; a lead that exists only as a name in a `resolved_by` cell recorded
        neither. (`_lead_by_id` alone is VACUOUS: `_check_lead_refs` already refuses a
        `resolved_by` naming an undeclared lead, and the row lands on that lead's own
        `outcome`, so `_lead_returned_a_result` is true by construction.)
      - the lead's own `:L findings` `system` cell, which projects to
        `FindingRecord.query_details.system` — the document's record of WHICH system that lead
        went to. `executed_queries.jsonl` is the authoritative table and the invlang validator
        cannot see it (it is handed text, never a run dir), so this is the closest in-document
        signal and it is named as such rather than silently skipped.
    The join between them is `vocab.ANCHOR_KIND_SYSTEMS`, minted by this change and
    deliberately PARTIAL — see `test_anchor_kind_system_mapping_is_partial_and_real` for what
    an unmapped anchor kind falls back to and what that costs.
  * **`consultation_window_predates_alert` is NOT in the interface contract** handed to this
    suite. It is mechanism A's first stated guard in the design doc and a `form: test` demand
    in the frontier, so it is written here and flagged: an implementer working from the
    interface contract alone will not have built it. Its SCOPE is a second call this suite
    makes and states: the guard is on `runtime-evidence` rows only.
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


def _anchor_kind_systems() -> dict[str, str]:
    """`vocab.ANCHOR_KIND_SYSTEMS` — anchor kind → the gather system that answers it.

    Read through a function rather than at module import for the same reason the registry
    suite imports its adapter inside a call: a missing name at module scope is a COLLECTION
    error, and pytest aborts the whole run on one, so a red spec would take every other suite
    in the tree down with it instead of reporting its own failures beside them.
    """
    return vocab.ANCHOR_KIND_SYSTEMS


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
    asks can never be posed, let alone answered.

    NARROW ON PURPOSE, and named for what it checks: membership plus acceptance. That the
    accepted row also has to be BACKED is `test_authz_anchor_id_must_match_its_own_leads_recorded_hit`'s."""
    assert "tacit-knowledge" in vocab.ANCHOR_KINDS
    assert vocab.SLOTS["anchor-kinds"] is vocab.ANCHOR_KINDS, (
        "the enum CLI must answer off the same tuple the checker reads — a second copy drifts"
    )

    doc = scene.document(rows=scene.authorized_rows())
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


def test_anchor_kind_system_mapping_is_partial_and_real():
    """`vocab.ANCHOR_KIND_SYSTEMS` maps an anchor kind to the ONE gather system that can answer
    it, covers the three kinds this change actually reasons about, and is honestly PARTIAL.

    Minted by this change (F8): nothing in the tree joined an anchor kind to a system before,
    which is why `basis=exhausted` as first written was satisfied by any lead that did
    anything at all. Three properties, each a way the mapping could quietly stop meaning
    something:

      * every key is a real `ANCHOR_KINDS` member — a mapping keyed on a kind no contract can
        declare is a row that never fires;
      * every value is a real system name (`runtime.verbs.is_system_name`) — the check joins
        against `:L findings`' `system` cell, and a value nothing can be written in refuses a
        lead that queried the right place;
      * it does NOT cover every anchor kind, and the uncovered ones are named here rather than
        left to be discovered. `iam-policy`, `change-mgmt` and `tacit-knowledge` have one
        obvious system each; `gpo`, `other` and the rest do not, and inventing one per member
        is a second closed vocabulary to drift.

    THE BOUNDED LIMITATION, stated because it is the price of the partiality: an unmapped
    anchor kind falls back to the looser "this lead's retrieval came back with something"
    check, so `basis=exhausted` on such a contract is as weak as the original check was
    everywhere. `test_exhausted_falls_back_to_the_loose_check_on_an_unmapped_kind` pins that
    fallback so nobody reads a passing `exhausted` on a `gpo` contract as a checked one.
    """
    from defender.runtime.verbs import is_system_name

    mapping = _anchor_kind_systems()
    for kind, system in (
        ("iam-policy", "identity"),
        ("change-mgmt", "change-mgmt"),
        ("tacit-knowledge", "tacit-knowledge"),
    ):
        assert mapping.get(kind) == system, (
            f"anchor kind {kind!r} does not map to the system that answers it"
        )
    assert set(mapping) <= set(vocab.ANCHOR_KINDS), (
        "the mapping is keyed on something that is not an anchor kind — a row no contract "
        "can ever reach"
    )
    assert all(is_system_name(s) for s in mapping.values()), (
        "a mapped system is not a legal system name, so no `:L findings` `system` cell can "
        "ever equal it and every `exhausted` claim on that kind is refused"
    )
    assert set(vocab.ANCHOR_KINDS) - set(mapping), (
        "every anchor kind was given a system — the mapping was meant to cover the kinds with "
        "an obvious answer and to say so about the rest, not to mint a system per member"
    )


# ---------------------------------------------------------------- demand #0: the row shapes


def test_tacit_knowledge_authz_row_shape():
    """The CELLS of a discharging `:R authz` row: `verdict=authorized`,
    `anchor_kind=tacit-knowledge`, `grounding_kind=org-authority`, an `anchor_id` naming the
    registry entry and a `fulfills` naming the `ac<n>` it closes — parsed and accepted
    (demand `authz_row_shape`).

    A ROW-SHAPE test and named for it. It says nothing about whether the citation is backed;
    the version of this test that promised a "registry hit" and checked only a parser round
    trip is `test_authz_anchor_id_must_match_its_own_leads_recorded_hit` now.

    `grounding` and `anchor_id` are UNDOCUMENTED optional columns on the `:R authz` header
    (fork F5 / claim c10): the parser canonicalizes them today, but `skills/invlang/SKILL.md`
    names neither, so a model writing the row from the SKILL cannot emit them. Asserted on the
    PARSE rather than on silence, so the test says which cells actually landed."""
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
    produced is refused, and a benign close resting on it does not commit
    (demand `authz_anchor_id_is_receipted`, O2).

    THE check this suite exists for. Three fakes, each a document that is otherwise IDENTICAL
    to the one that works — every negative below is paired with its own corrected twin
    asserted clean, so a refusal cannot be coming from some unrelated defect the scenario
    dragged in.

      1. an `anchor_id` no lead recorded at all — the bare fabrication;
      2. an `anchor_id` a DIFFERENT lead recorded — the check has to be scoped to the row's
         own lead, and a document-wide search for "is this id anywhere" passes this fake;
      3. a row citing an id with no recorded lookup on its lead at all — the shape every
         pre-hardening test in this file wrote, which is why it is pinned rather than assumed.
    """
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
    beside its own lead's empty-handed lookup is refused (demand `authz_anchor_id_is_receipted`).

    The near-miss of the check above, and the one a lenient implementation passes: the lead DID
    dispatch the lookup, DID record a `tacit-knowledge` consultation, and the row's
    `resolved_by_lead` DOES name it — everything matches except the one cell that says which
    entry came back. A miss names no entry, so there is nothing for the citation to equal."""
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
    is refused, whatever verdict it claims (demand `no_statistical_self_authorization`, O2).

    NOT IN THE INTERFACE CONTRACT either, and the second guard this suite adds by reading the
    design doc: `anchor_consultations[].grounding_kind ∈ {org-authority, telemetry-baseline}`
    while `authorization_resolutions[].grounding_kind ∈ {org-authority, past-case}`
    (`docs/investigation-language.md:92`, claim c8) — telemetry-baseline is explicitly named as
    the one that never grounds an authorization. Unenforced, the discarded middle design
    (raw recurrence grounding authorization directly) is a one-cell edit away from being back:
    the model writes its density finding into a `:R authz` row instead of a `:R consultations`
    one and the entry price is paid.

    `runtime-evidence` as an authz row's `anchor_kind` is refused for the same reason and
    checked beside it: it is the anchor kind that exists so a BASELINE has one, and a verdict
    is not what a baseline produces."""
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
    """A baseline consultation whose `effective_window` does not END STRICTLY BEFORE the
    alerted event is refused — a pattern that begins with the incident IS the incident (demand
    `consultation_window_predates_alert`).

    NOT IN THE INTERFACE CONTRACT this suite was handed; it is mechanism A's first stated guard
    in the design doc and a `form: test` demand in the frontier. See this module's docstring.
    The alerted moment is the `:E prologue.edges` `when` cell — the document's own record of
    when the thing being explained happened, so the check needs nothing from `alert.json`.

    A REAL DATETIME COMPARISON ON THE WINDOW'S END, which is what the four refused windows
    below are for and what the first version of this test did not have. Written against the
    window's START as a string ("does the start equal the alert's `when`"), the check admits
    every window that matters: one that opens a second later, one that opens six months
    earlier and closes ten weeks after the alert, one that ends on the alerted instant itself,
    and one no parser can read. Each of those is spelled so that no substring of the alert's
    timestamp appears in it (`WINDOW_SPANNING_THE_ALERT` most of all), so a string-matching
    implementation cannot cheat its way past this test.

    SCOPED TO THE BASELINE KIND, and that scope is load-bearing rather than incidental: the
    `tacit-knowledge` consultation that records a registry hit carries the ENTRY's validity
    span, which brackets the alert by construction — a sanction that expired before the alert
    would not cover the alert. A guard applied to every `:R consultations` row refuses the one
    row mechanism B depends on.
    """
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
    cap here is indistinguishable from refusing the mechanism outright.

    "On its own" means one AUTHORIZATION, not one row: the lead's recorded lookup outcome rides
    with it (see this module's docstring) and cannot discharge anything by itself, so nothing
    here is a second grounding."""
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
    the way a `ceiling_test` receipt's `ref` is (demand `exhausted_checked_against_transcript`,
    fork F8).

    Three negatives, because `exhausted` is the claim "every anchor kind applicable to this
    predicate was actually queried and none answered", and each negative is a different way to
    make that claim for free:

      * `l-002` is declared in `:L findings` and never dispatched: no observations, no
        `:R attr_updates`, which is the "nothing came back for this lead's own retrieval"
        question `_lead_retrieval_came_back` answers for a ceiling receipt. Existence alone
        cannot be the check — `_check_lead_refs` already refuses an undeclared `resolved_by`.
      * `l-001` DID come back with something, but its `:L findings` `system` cell says it went
        to `host-state` while the contract is a `tacit-knowledge` one. This is the negative the
        first version of this test was missing entirely: `l-001` carries an ORIENT bookkeeping
        `:R attr_updates` row (`attrs.knowledge=full`), so "this lead did something" is true of
        it in EVERY scenario, and a check that stops there is satisfied by a lead that never
        went near the registry the claim is about.
      * `retry` claims nothing about what was dispatched, so it owes no receipt at all — the
        control that keeps the check from being "an indeterminate row needs a good lead".
    """
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
    deliberately and PINNED so the limitation is documented rather than discovered.

    The mapping covers the three kinds with one obvious system each (see
    `test_anchor_kind_system_mapping_is_partial_and_real`). For the rest there is no system to
    join against, and the alternatives are both worse than the gap: refusing `exhausted`
    outright on those kinds makes O4 unreachable for them, and inventing a system per anchor
    kind mints a second closed vocabulary that drifts against the adapter set.

    The kind is picked OFF the mapping rather than spelled here, so covering another kind
    later moves this test onto the next uncovered one instead of leaving it asserting the
    fallback for a kind that now has a real join."""
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


def test_exhausted_drops_only_its_own_contract():
    """With TWO live contracts and `basis=exhausted` on a row fulfilling ONE of them, only that
    contract leaves the frontier; the other stays on it (demand `exhausted_is_not_redispatched`).

    The discriminating half of the test above, which cannot tell "this row cleared its own
    contract" from "this row cleared the frontier" because the scene it runs on declares one
    contract. Clearing everything passes it and is a real defect twice over: `ac2` is a
    `change-mgmt` question nobody asked, and dropping it removes the only mechanical surface
    that pushes the run back to go work it (#919's whole lane), so a run stops retrieving with
    an unanswered authorization question and nothing on disk says so.

    `ac2` carries `indeterminate` with NO basis — a plain `retry`, the contract that simply has
    not been answered yet — so the pair differs in exactly the cell under test."""
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
    become undefined (demand `exhausted_degrades_without_b`, a survival demand).

    The contract here is declared under `iam-policy` — an anchor kind that predates this change
    entirely — so nothing in the check may reach for the tacit-knowledge registry. The lead's
    `system` cell is `identity`, which is what `ANCHOR_KIND_SYSTEMS` maps `iam-policy` to: the
    join is the same one B's contracts take, which is what "narrows but stays defined" means
    mechanically."""
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
