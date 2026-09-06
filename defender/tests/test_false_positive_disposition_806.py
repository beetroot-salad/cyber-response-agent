"""`disposition false-positive` and the entity check that makes it reachable (#806).

The disposition exists so a run can close a mis-keyed rule cheaply. The gate exists because
"cheaply" is one edit away from "without looking". Both halves are pinned here.

The fixtures are the shape of a real run, not a minimal one, because the failure this gate was
written for is a run that did plenty of work — `pr815-rerun-0808` refuted the alert's claim in
7 queries and then spent 124 more on the entities the refutation introduced, never asking about
the host it was paged for. A gate that only demanded "some committed lead" would have passed it.
"""
from __future__ import annotations

import pytest

from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang.validate import validate_companion

# v-001 is the alerted host, carried by the prologue — the entity the ALERT named.
# v-006 stands for what the refutation introduced: in the real run, the source IP whose failures
# the rule wrongly correlated. Both are legitimate investigation targets; only one of them
# answers "was the alerted host compromised anyway".
_PROLOGUE = (
    "```invlang\n"
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|compute|database-server/internal/known-corp|db-1|os=linux\n"
    "```\n"
)

_LEADS = (
    "```invlang\n"
    ":L findings [id|loop|name|target|tests|system|window]\n"
    "l-001|1|sshd-auth-events-detail|v-001||elastic|30d\n"
    "l-002|2|bruteforce-source-attribution|v-006||elastic|30d\n"
    "```\n"
)


def _outcome(lead_id: str, vertex: str) -> str:
    """A lead COMMITS by filing what it observed — the same shape a real run writes.

    The identity is EDGED to the alerted host (`v-001`, `_PROLOGUE`'s only vertex), not just
    declared: #993 refuses a lead-declared vertex no `:E` row ever names, and a bare identity
    row with no edge is exactly the shape that rule exists to catch."""
    return (
        "```invlang\n"
        f":V {lead_id}.observations.vertices [id|type|class|ident|attrs?]\n"
        f"{vertex}|identity|user/known-corp|svc.config-mgmt|\n"
        "\n"
        f":E {lead_id}.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
        f"e-001|attempted_auth|{vertex}|v-001||siem-event:elastic|\n"
        "```\n"
    )


def _conclude(**rows: str) -> str:
    body = "".join(f"{k:<22} {v}\n" for k, v in rows.items())
    return "```invlang\n:T conclude\n" + body + "```\n"


_NOTES = '"Claims a same-user brute-force success but groups by host, so the actor is untested."'


def _doc(*parts: str) -> str:
    return "".join(parts)


# the keyword exists

def test_false_positive_is_in_the_shared_vocabulary():
    """It has to be in `_vocab` rather than invlang-local: `report.md`'s frontmatter and the
    `conclude` block are validated by different schemas reading the same enum."""
    assert "false-positive" in DISPOSITION_ENUM


# the six ways the exit could be faked

_FAILED_LEAD = (
    "```invlang\n"
    ":L findings [id|loop|name|target|tests|system|window|fail_reason]\n"
    "l-003|1|db1-authorized-keys|v-001||elastic|30d|index unavailable\n"
    "```\n"
)


# Each row is one way the FP exit could be faked, and the fragment the resulting error must
# carry. `false-positive` is a claim about the RULE, so every row is a close that failed to
# earn that claim.
@pytest.mark.parametrize(("case", "parts", "conclude_kwargs", "fragment"), [
    # An FP close with no `detection_notes` is a close with no reason: if the run cannot say
    # what the rule got wrong, it has not made the claim.
    ("no-stated-defect", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"entity_check": "l-001"}, "detection_notes"),

    # `none` / `n/a` are what a conclude row writes where it has NOTHING to say, and the parser
    # strips them only from LIST rows — a scalar keeps them as literal text. A gate testing
    # `notes.strip()` alone therefore reads "no defect found" as a stated defect, which is the
    # emptiest possible FP close passing the check written to stop exactly that.
    ("empty-marker-none", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": "none", "entity_check": "l-001"}, "detection_notes"),
    ("empty-marker-n-a", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": "n/a", "entity_check": "l-001"}, "detection_notes"),
    ("empty-marker-capitalised", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": "None", "entity_check": "l-001"}, "detection_notes"),
    ("empty-marker-padded", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": "  N/A  ", "entity_check": "l-001"}, "detection_notes"),

    # Refuting the detector says nothing about the HOST. Without this the disposition is a
    # cheaper `benign` — the exact substitution that closed a host carrying three
    # `attacker@elsewhere` keys in root's `authorized_keys`.
    ("no-entity-check", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": _NOTES}, "entity_check"),

    # `:L findings`' `fail_reason` column projects into the lead's `outcome`, so a lead whose
    # query ERRORED reads as "committed" to the loose test `_check_loop_close` uses. For
    # closing a loop that is right — the loop was worked. Here it is the gate's own failure
    # mode: a query that never landed tested the alerted entity for nothing.
    ("lead-whose-only-outcome-is-a-failure", (_PROLOGUE, _FAILED_LEAD),
     {"detection_notes": _NOTES, "entity_check": "l-003"}, "committed no result"),

    # The named lead has to exist at all.
    ("named-lead-does-not-exist", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": _NOTES, "entity_check": "l-404"}, "not a lead in"),

    # A lead with no committed result is the shape of an investigation that stopped at the
    # PLAN. `l-002` is written into `:L findings` and never resolved.
    ("planned-but-undispatched-lead", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": _NOTES, "entity_check": "l-002"}, "committed no result"),

    # THE regression. `l-002` is committed and real work — it just tests the source the rule
    # wrongly implicated, not the host the alert was about. Every post-refutation lead in
    # `pr815-rerun-0808` but one had this shape, so a gate without the prologue clause passes
    # the run it was written for.
    ("lead-against-an-entity-the-refutation-introduced",
     (_PROLOGUE, _LEADS, _outcome("l-002", "v-012")),
     {"detection_notes": _NOTES, "entity_check": "l-002"}, "prologue does not carry"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and " " not in v else "")
def test_a_false_positive_exit_that_was_not_earned_is_rejected(
    case, parts, conclude_kwargs, fragment
):
    """The disposition is a claim about the RULE, and the close has to pay for it: a stated
    defect that is really stated, and an entity check carried by a lead that really ran
    against the entity the alert named. Each row here fakes one of those and is refused."""
    doc = _doc(*parts, _conclude(disposition="false-positive", **conclude_kwargs))
    errors = validate_companion(doc, None)
    assert any(fragment in e for e in errors), f"no error mentioned {fragment!r}"


# and the shape that is allowed through

def test_a_stated_defect_plus_a_committed_check_on_the_alerted_entity_closes():
    """The fast exit the disposition exists for: the defect is named, one lead tested the host
    the alert named, it came back, and the run stops without pricing a full investigation."""
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"),
               _conclude(disposition="false-positive", detection_notes=_NOTES,
                         entity_check="l-001"))
    assert validate_companion(doc, None) == []


def test_the_gate_is_scoped_to_the_keyword():
    """A `malicious` conclude carries no entity-check obligation — the gate is the price of the
    cheap exit, not a new requirement on every close."""
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"), _conclude(disposition="malicious"))
    assert validate_companion(doc, None) == []


@pytest.mark.parametrize("spelling", ["false-positive​", "​false-positive"])
def test_a_zero_width_character_cannot_switch_the_gate_off(spelling):
    """#722's mechanism inside a write gate: the branch decides whether the checks run at all,
    so it matches on what the value RENDERS as. Invisibly-laced, it must not read as a
    different, ungated keyword."""
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"), _conclude(disposition=spelling))
    errors = validate_companion(doc, None)
    # Asserted on the GATE's denial, not merely on `errors != []`. The vocabulary check denies
    # this too, for a different reason, so the weaker assertion passes whether or not the gate
    # ran — and the gate failing open on an invisible character is the whole risk here.
    assert any("false-positive blocked" in e for e in errors)


# the price is collected at BOTH boundaries

def _paid(**over: str) -> str:
    rows = {"disposition": "false-positive", "detection_notes": _NOTES,
            "entity_check": "l-001", **over}
    return _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"), _conclude(**rows))


def test_the_entry_price_is_readable_from_a_companion_document():
    """The write gate reads a parsed companion; the close reads a FILE. One function answers
    both, so the two boundaries cannot drift into disagreeing about what is owed."""
    from defender.skills.invlang.validate import disposition_entry_price

    assert disposition_entry_price("false-positive", _paid()).owed == ()
    assert disposition_entry_price("false-positive", "").owed    # nothing written owes everything
    assert disposition_entry_price("false-positive", _doc(_PROLOGUE, _LEADS)).owed


#: An `investigation.md` that pays NEITHER price: `v-001` carries an unresolved class and an
#: unresolved attribute (what `benign` owes), and the conclude block states no defect and names
#: no entity check (what `false-positive` owes). Concluded `inconclusive`, which is legitimately
#: unpriced — so the write gate passes it, and every denial below is the CLOSE's alone.
_UNPAID = _doc(
    "```invlang\n"
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|compute|??/??/??|db-1|os=??\n"
    "```\n",
    _conclude(disposition="inconclusive"),
)


def test_the_reader_is_the_gate_table_and_not_one_keyword():
    """#879: the close's reader dispatches on the same `_DISPOSITION_GATES` the write gate
    does, so EVERY priced keyword is COLLECTED here and the unpriced ones cost nothing.

    The iteration buys generic collection, not a generic fixture — `_UNPAID` is hand-built to
    owe both prices we have, and a third gate pricing something it happens to satisfy would
    need a row added to it. What must NOT be needed is a third branch at the close, which is
    the property `benign` lacked while the close read one row by literal."""
    from defender.skills.invlang.validate import (
        _DISPOSITION_GATES,
        disposition_entry_price,
    )

    assert set(_DISPOSITION_GATES) <= DISPOSITION_ENUM, "a price on a keyword nothing can close"
    for priced in _DISPOSITION_GATES:
        price = disposition_entry_price(priced, _UNPAID)
        assert price.owed, priced
        # Every priced keyword arrives EXPLAINED as well as collected. A row carrying a check
        # and no rationale would refuse the model without telling it why the price exists,
        # which is what it needs to choose between paying and re-concluding.
        assert priced in price.rationale, priced
    for unpriced in DISPOSITION_ENUM - set(_DISPOSITION_GATES):
        assert not disposition_entry_price(unpriced, _UNPAID).owed, unpriced

    # #722 reaches this dispatch the same way it reaches the write gate's: a keyword is judged
    # on what it RENDERS as, so lacing it must not buy the unpriced branch. The close's own
    # argument is enum-checked upstream, but this reader is public and the two rules stay
    # independent on purpose — either alone would leave a hole. The rationale comes back off
    # the SAME dispatch, so a laced keyword that owes is still explained — it cannot be looked
    # up on a differently-normalized value than the check was.
    laced = disposition_entry_price("benign\u200b", _UNPAID)
    assert laced.owed
    assert laced.rationale


def _close(tmp_path, companion: str, disposition: str):
    """Drive the real close far enough to reach (or clear) the entry price."""
    import asyncio

    from defender.agents import MAIN_DEF
    from defender.runtime import challenge_gate
    from defender.runtime.agent_definition import bind
    from defender.runtime.close_tool import _close_investigation_async
    from defender.tests._review_bundle import bundle as _bundle
    from defender.tests._review_bundle import composer_reply as _composer

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "investigation.md").write_text(companion, encoding="utf-8")
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    deps = bind(MAIN_DEF, run_dir, defender_dir=dfn)
    return asyncio.run(_close_investigation_async(
        deps, disposition, stages=_bundle(composer=_composer(finding="holds")),
        bounds=challenge_gate.default_bounds(),
    ))


_BYPASS = (
    "```invlang\n"
    ":T conclude\n"
    "disposition            benign\n"
    "```\n"
)


def test_the_close_cannot_be_reached_around_the_write_gate(tmp_path):
    """THE bypass. `report.md` is written from the close's ARGUMENT, and nothing else on that
    path reads the companion — so concluding under a cheaper keyword (or none) and passing
    `false-positive` to `close_investigation` would buy the exit for free, in the artifact the
    learning loop, the evals and the ticket lane actually read."""
    from pydantic_ai.exceptions import ModelRetry

    with pytest.raises(ModelRetry) as e:
        _close(tmp_path, _BYPASS, "false-positive")
    assert "close blocked" in str(e.value)
    assert "entity_check" in str(e.value)


def test_a_companion_that_paid_the_price_closes(tmp_path):
    """Positive control, asserted on the close COMMITTING rather than on the absence of one
    message: a price that denied everything would satisfy the test above just as well, and the
    exit this disposition exists for has to actually be reachable."""
    result = _close(tmp_path, _paid(), "false-positive")
    assert result.outcome == "stands"
    assert (tmp_path / "run" / "report.md").exists()


def test_benigns_price_is_collected_at_the_close_too(tmp_path):
    """#879, the mirror of the bypass above. `benign` was priced at the `investigation.md`
    write and collected NOWHERE at the close, so the same one-move exit was open in the other
    direction: conclude `inconclusive` — legitimately unpriced, so the write gate passes it —
    over a log whose slots are still `??`, then pass `benign` to `close_investigation`.

    Worse than the FP bypass in one respect: the `??` slots stay on disk, so only `report.md`
    disagrees with them, and `report.md` is what the learning loop reads — `directions_for`
    picks the FN-hunt leg alone for `benign` where the honest `inconclusive` picks both, and
    the case enters the corpus resolved.

    The surviving review gate is not a second collection point: it is a model judgment over
    projections, so it can uphold a close this table would refuse."""
    from pydantic_ai.exceptions import ModelRetry

    with pytest.raises(ModelRetry) as e:
        _close(tmp_path, _UNPAID, "benign")
    assert "close blocked" in str(e.value)
    assert "v-001" in str(e.value), "the refusal names the vertex still holding an open slot"
    assert not (tmp_path / "run" / "report.md").exists()


def test_an_absent_conclude_block_does_not_buy_a_benign_close(tmp_path):
    """The other half of the same move: an absent `:T conclude` is legal invlang, so `benign`'s
    price used to be dodged by simply not writing the block the write gate dispatches on. The
    close dispatches on its own ARGUMENT, so there is nothing to omit."""
    from pydantic_ai.exceptions import ModelRetry

    no_conclude = _doc(
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|compute|??/??/??|db-1|os=??\n"
        "```\n"
    )
    with pytest.raises(ModelRetry) as e:
        _close(tmp_path, no_conclude, "benign")
    assert "close blocked" in str(e.value)


#: A log that PAYS benign's price rather than merely never owing it: `v-001`'s class tuple and
#: attribute are both resolved, and `h-010` is live (`status active`, unrefuted) carrying an
#: authorization contract that an `:R authz` row discharges as `authorized`. Both halves of
#: `_check_benign_gating` therefore have something to evaluate and clear — a positive control
#: over a document with no hypothesis at all would leave `_check_benign_authz` returning `[]`
#: without reading a single contract, and a regression that refused every contract would still
#: pass it.
_PAID_BENIGN = (
    "```invlang\n"
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|compute|database-server/internal/known-corp|db-1|os=linux\n"
    ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-001|executed|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|\n"
    ":L findings [id|loop|name|target|tests|system|window]\n"
    "l-001|1|change-window-lookup|v-001|h-010|change-mgmt|30d\n"
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
    "h-010|?scheduled-maintenance|v-001|executed|process|unclassified-process||null|active\n"
    ":H h-010.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
    'ac1|e-001|change-mgmt|"a change record covers this window"|escalate|escalate\n'
    ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
    'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"\n'
    "```\n"
) + _conclude(disposition="benign")


def test_a_companion_that_paid_benigns_price_closes(tmp_path):
    """Benign's positive control. `benign` refuses CONTRADICTIONS — open slots, unfulfilled
    authorization contracts — so a log that settled both owes nothing, and the disposition the
    runtime reaches for most has to still be reachable. Asserted on the commit, because a
    price that denied everything would pass the two tests above just as well.

    Both halves of the gate are exercised, not just the slot half: see `_PAID_BENIGN`."""
    from defender.skills.invlang.validate import (
        _check_benign_authz,
        disposition_entry_price,
    )
    from defender.skills.invlang.parser import parse_dense_companion

    # The control on the control: assert the authz half actually had a live contract to clear,
    # so this cannot quietly decay into the no-hypothesis document it replaced.
    companion, _ = parse_dense_companion(_PAID_BENIGN)
    assert companion["hypothesize"]["hypotheses"][0]["authorization_contract"]
    assert _check_benign_authz(companion) == []
    assert disposition_entry_price("benign", _PAID_BENIGN).owed == ()

    result = _close(tmp_path, _PAID_BENIGN, "benign")
    assert result.outcome == "stands"
    assert (tmp_path / "run" / "report.md").exists()


@pytest.mark.parametrize(("companion", "shape"), [
    (None, "absent"),
    ("", "empty"),
    ("\n\n   \n", "whitespace only"),
    ("# Investigation\n\nThe host looked fine to me.\n", "prose, no invlang fence"),
    ("The class is ??/??/?? but no `:V` block was ever written.\n", "unresolved slots in PROSE"),
])
def test_a_log_that_recorded_nothing_cannot_close_benign(tmp_path, companion, shape):
    """#879's second half. `benign`'s other two checks refuse CONTRADICTIONS — an open slot, an
    unfulfilled contract — which is vacuous over a document that has neither because it has
    NOTHING: no vertex to hold a slot, no hypothesis to carry a contract. So collecting the
    price at the close still left the one-move exit open in a weaker form, and the weaker form
    is the cheaper one to reach — a run that writes no work log at all.

    The last fixture is the one that shows the clause is structural rather than textual: `??`
    appears in the document, and it is still not an open SLOT, because nothing parsed it into a
    vertex. A gate that grepped for the marker would pass this and refuse nothing real.

    Driven through the real close, and asserted on `report.md` staying absent — this is the
    artifact the learning loop reads, and the review gate downstream is a model judgment, not a
    second structural collection point."""
    from pydantic_ai.exceptions import ModelRetry

    import asyncio

    from defender.agents import MAIN_DEF
    from defender.runtime import challenge_gate
    from defender.runtime.agent_definition import bind
    from defender.runtime.close_tool import _close_investigation_async
    from defender.tests._review_bundle import bundle as _bundle
    from defender.tests._review_bundle import composer_reply as _composer

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    if companion is not None:
        (run_dir / "investigation.md").write_text(companion, encoding="utf-8")
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    deps = bind(MAIN_DEF, run_dir, defender_dir=dfn)

    with pytest.raises(ModelRetry) as e:
        asyncio.run(_close_investigation_async(
            deps, "benign", stages=_bundle(composer=_composer(finding="holds")),
            bounds=challenge_gate.default_bounds(),
        ))
    assert "prologue.vertices" in str(e.value), shape
    assert not (run_dir / "report.md").exists(), shape


def test_the_grounding_clause_is_what_makes_the_open_slot_check_bite(tmp_path):
    """Why the clause is worth having beyond the empty document: it is what guarantees
    `_check_benign_open_slots` has something to check.

    A prologue is the block ORIENT writes before PLAN runs, so requiring one costs a real run
    nothing — but it means "every vertex's classification is resolved" can no longer be
    satisfied by a document that declared no vertices. The pair is asserted here rather than
    separately: the same document is refused with no prologue, refused again with a prologue
    whose slots are open, and accepted only once both hold."""
    from defender.skills.invlang.validate import disposition_entry_price

    conclude = _conclude(disposition="benign")
    open_slot = (
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|compute|??/??/??|db-1|os=??\n"
        "```\n"
    ) + conclude

    assert "prologue.vertices" in disposition_entry_price("benign", conclude).owed[0]
    assert any("unresolved" in o for o in disposition_entry_price("benign", open_slot).owed)
    assert disposition_entry_price("benign", _PROLOGUE + conclude).owed == ()


def test_a_companion_that_cannot_be_read_refuses_the_close(tmp_path):
    """A gate that cannot look must not report clean (#618/#621/#652).

    Once every close reads this file, an I/O fault reaches a gate none of them used to — and
    swallowing it to `""` would not mean "nothing was written", it would mean "this gate did
    not run". That waives `benign`'s whole price, because that price refuses CONTRADICTIONS
    and an empty read carries none; `false-positive`'s would still be refused, so the two
    priced keywords would disagree about what a fault means. Induced through the real
    primitive — `investigation.md` as a DIRECTORY, so `read_text` raises a real `OSError`
    regardless of the uid running the suite (a chmod would not: CI is non-root, this container
    is not).

    Both priced keywords are driven, and the refusal is asserted to be the FAULT's rather than
    either price's — a test that only checked "something was refused" would pass against the
    fail-open code for `false-positive`."""
    import asyncio

    from pydantic_ai.exceptions import ModelRetry

    from defender.agents import MAIN_DEF
    from defender.runtime import challenge_gate
    from defender.runtime.agent_definition import bind
    from defender.runtime.close_tool import _close_investigation_async
    from defender.tests._review_bundle import bundle as _bundle
    from defender.tests._review_bundle import composer_reply as _composer

    for disposition in ("benign", "false-positive"):
        run_dir = tmp_path / disposition / "run"
        (run_dir / "gather_raw").mkdir(parents=True)
        (run_dir / "investigation.md").mkdir()          # the fault: a directory, not a file
        dfn = tmp_path / disposition / "defender"
        dfn.mkdir(exist_ok=True)
        deps = bind(MAIN_DEF, run_dir, defender_dir=dfn)
        with pytest.raises(ModelRetry) as e:
            asyncio.run(_close_investigation_async(
                deps, disposition, stages=_bundle(composer=_composer(finding="holds")),
                bounds=challenge_gate.default_bounds(),
            ))
        assert "could not be read" in str(e.value), disposition
        assert not (run_dir / "report.md").exists(), disposition


def test_an_absent_companion_is_not_a_fault(tmp_path):
    """The control that bounds the test above: NEVER WRITTEN and COULD NOT LOOK are different
    answers, and only the second is a fault. An unwritten log still owes `false-positive`'s
    whole price — it states no defect — and is refused on THAT, with the price's own words
    rather than the fault's."""
    from pydantic_ai.exceptions import ModelRetry

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)

    import asyncio

    from defender.agents import MAIN_DEF
    from defender.runtime import challenge_gate
    from defender.runtime.agent_definition import bind
    from defender.runtime.close_tool import _close_investigation_async
    from defender.tests._review_bundle import bundle as _bundle
    from defender.tests._review_bundle import composer_reply as _composer

    deps = bind(MAIN_DEF, run_dir, defender_dir=dfn)
    with pytest.raises(ModelRetry) as e:
        asyncio.run(_close_investigation_async(
            deps, "false-positive", stages=_bundle(composer=_composer(finding="holds")),
            bounds=challenge_gate.default_bounds(),
        ))
    assert "could not be read" not in str(e.value)
    assert "detection_notes" in str(e.value)


def test_an_unfulfilled_authz_contract_blocks_the_benign_close(tmp_path):
    """The authz half's negative, mirroring the slot half's above — and the discriminator for
    the positive control: drop the `:R authz` row that discharges `ac1` and the same document
    is refused, so the control proves the contract was CLEARED rather than never read."""
    from pydantic_ai.exceptions import ModelRetry

    unfulfilled = _PAID_BENIGN.replace(
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"\n',
        "",
    )
    assert unfulfilled != _PAID_BENIGN, "the fixture's authz row moved — this test is blind"
    with pytest.raises(ModelRetry) as e:
        _close(tmp_path, unfulfilled, "benign")
    assert "authz contract ac1" in str(e.value)


def test_a_vertex_from_an_earlier_prologue_block_is_still_the_alerted_entity():
    """The prologue clause reads a PROJECTION, so it inherits whatever that projection drops.

    Append-only forbids rewriting the loop-1 block, so a run that learns of a second alerted
    entity has exactly one way to record it: a second `:V prologue.vertices`. That block used to
    REPLACE the first, which made this gate deny an `entity_check` against the host the alert
    actually named — the model told to check the alerted entity, denied for having checked it,
    with no edit available that complies. #817 made the block accumulate; this pins the gate's
    dependence on that, which is not visible from either change alone.
    """
    two_blocks = _PROLOGUE + (
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-002|compute|workstation/internal/known-corp|office-ws-1|os=linux\n"
        "```\n"
    )
    doc = _doc(two_blocks, _LEADS, _outcome("l-001", "v-011"),
               _conclude(disposition="false-positive", detection_notes=_NOTES,
                         entity_check="l-001"))          # l-001 targets v-001, the FIRST block
    assert validate_companion(doc, None) == []
