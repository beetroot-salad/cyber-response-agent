"""disposition false-positive: shared vocabulary entry, the priced entity-check gate at write and at close, companion-read faults, benign's collected price."""
from __future__ import annotations

from dataclasses import replace as _with_live_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _live_run_1165

import pytest

from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang.validate import validate_companion

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
    """A lead COMMITS by filing what it observed — the same shape a real run writes."""
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


# the six ways the exit could be faked

_FAILED_LEAD = (
    "```invlang\n"
    ":L findings [id|loop|name|target|tests|system|window|fail_reason]\n"
    "l-003|1|db1-authorized-keys|v-001||elastic|30d|index unavailable\n"
    "```\n"
)


@pytest.mark.parametrize(("case", "parts", "conclude_kwargs", "fragment"), [
    # An FP close with no `detection_notes` is a close with no reason: if the run cannot say
    # what the rule got wrong, it has not made the claim.
    ("no-stated-defect", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"entity_check": "l-001"}, "detection_notes"),

    ("empty-marker-none", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": "none", "entity_check": "l-001"}, "detection_notes"),
    ("empty-marker-n-a", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": "n/a", "entity_check": "l-001"}, "detection_notes"),
    ("empty-marker-capitalised", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": "None", "entity_check": "l-001"}, "detection_notes"),
    ("empty-marker-padded", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": "  N/A  ", "entity_check": "l-001"}, "detection_notes"),

    ("no-entity-check", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": _NOTES}, "entity_check"),

    ("lead-whose-only-outcome-is-a-failure", (_PROLOGUE, _FAILED_LEAD),
     {"detection_notes": _NOTES, "entity_check": "l-003"}, "committed no result"),

    # The named lead has to exist at all.
    ("named-lead-does-not-exist", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": _NOTES, "entity_check": "l-404"}, "not a lead in"),

    # A lead with no committed result is the shape of an investigation that stopped at the
    # PLAN. `l-002` is written into `:L findings` and never resolved.
    ("planned-but-undispatched-lead", (_PROLOGUE, _LEADS, _outcome("l-001", "v-011")),
     {"detection_notes": _NOTES, "entity_check": "l-002"}, "committed no result"),

    ("lead-against-an-entity-the-refutation-introduced",
     (_PROLOGUE, _LEADS, _outcome("l-002", "v-012")),
     {"detection_notes": _NOTES, "entity_check": "l-002"}, "prologue does not carry"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and " " not in v else "")
def test_a_false_positive_exit_that_was_not_earned_is_rejected(
    case, parts, conclude_kwargs, fragment
):
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
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"), _conclude(disposition=spelling))
    errors = validate_companion(doc, None)
    assert any("false-positive blocked" in e for e in errors)


# the price is collected at BOTH boundaries

def _paid(**over: str) -> str:
    rows = {"disposition": "false-positive", "detection_notes": _NOTES,
            "entity_check": "l-001", **over}
    return _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"), _conclude(**rows))


_UNPAID = _doc(
    "```invlang\n"
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|compute|??/??/??|db-1|os=??\n"
    "```\n",
    _conclude(disposition="inconclusive"),
)


def test_the_reader_is_the_gate_table_and_not_one_keyword():
    """#879: the close's reader dispatches on the same `_DISPOSITION_GATES` the write gate does, so
    EVERY priced keyword is COLLECTED here and the unpriced ones cost nothing."""
    from defender.skills.invlang.validate import (
        _DISPOSITION_GATES,
        disposition_entry_price,
    )

    assert set(_DISPOSITION_GATES) <= DISPOSITION_ENUM, "a price on a keyword nothing can close"
    for priced in _DISPOSITION_GATES:
        price = disposition_entry_price(priced, _UNPAID)
        assert price.owed, priced
        assert priced in price.rationale, priced
    for unpriced in DISPOSITION_ENUM - set(_DISPOSITION_GATES):
        assert not disposition_entry_price(unpriced, _UNPAID).owed, unpriced

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
    from defender.tests.support.runtime.permissions._review_bundle import bundle as _bundle
    from defender.tests.support.runtime.permissions._review_bundle import composer_reply as _composer

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "investigation.md").write_text(companion, encoding="utf-8")
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    deps = _with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=dfn), run=_live_run_1165(run_dir))
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
    """THE bypass."""
    from pydantic_ai.exceptions import ModelRetry

    with pytest.raises(ModelRetry) as e:
        _close(tmp_path, _BYPASS, "false-positive")
    assert "close blocked" in str(e.value)
    assert "entity_check" in str(e.value)


def test_a_companion_that_paid_the_price_closes(tmp_path):
    result = _close(tmp_path, _paid(), "false-positive")
    assert result.outcome == "stands"
    assert (tmp_path / "run" / "report.md").exists()


def test_benigns_price_is_collected_at_the_close_too(tmp_path):
    """#879, the mirror of the bypass above."""
    from pydantic_ai.exceptions import ModelRetry

    with pytest.raises(ModelRetry) as e:
        _close(tmp_path, _UNPAID, "benign")
    assert "close blocked" in str(e.value)
    assert "v-001" in str(e.value), "the refusal names the vertex still holding an open slot"
    assert not (tmp_path / "run" / "report.md").exists()


def test_an_absent_conclude_block_does_not_buy_a_benign_close(tmp_path):
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
    """Benign's positive control."""
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
    """#879's second half."""
    from pydantic_ai.exceptions import ModelRetry

    import asyncio

    from defender.agents import MAIN_DEF
    from defender.runtime import challenge_gate
    from defender.runtime.agent_definition import bind
    from defender.runtime.close_tool import _close_investigation_async
    from defender.tests.support.runtime.permissions._review_bundle import bundle as _bundle
    from defender.tests.support.runtime.permissions._review_bundle import composer_reply as _composer

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    if companion is not None:
        (run_dir / "investigation.md").write_text(companion, encoding="utf-8")
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    deps = _with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=dfn), run=_live_run_1165(run_dir))

    with pytest.raises(ModelRetry) as e:
        asyncio.run(_close_investigation_async(
            deps, "benign", stages=_bundle(composer=_composer(finding="holds")),
            bounds=challenge_gate.default_bounds(),
        ))
    assert "prologue.vertices" in str(e.value), shape
    assert not (run_dir / "report.md").exists(), shape


def test_a_companion_that_cannot_be_read_never_commits_the_models_verdict(tmp_path):
    """A gate that cannot look must not report clean (#618/#621/#652)."""
    import asyncio

    from defender._io import ALIAS_READ_REFUSAL
    from defender._vocab import HOST_ONLY_DISPOSITION
    from defender.agents import MAIN_DEF
    from defender.runtime import challenge_gate
    from defender.runtime.agent_definition import bind
    from defender.runtime.close_tool import (
        CAUSE_REVIEW_INCOMPLETE, FORCED_INCONCLUSIVE, STAGE_ERROR, _close_investigation_async,
    )
    from defender.tests.support.runtime.permissions._review_bundle import bundle as _bundle
    from defender.tests.support.runtime.permissions._review_bundle import composer_reply as _composer
    from defender.tests.support.runtime.engine._spec992 import frontmatter, record

    for disposition in ("benign", "false-positive"):
        run_dir = tmp_path / disposition / "run"
        (run_dir / "gather_raw").mkdir(parents=True)
        (run_dir / "investigation.md").mkdir()          # the fault: a directory, not a file
        dfn = tmp_path / disposition / "defender"
        dfn.mkdir(exist_ok=True)
        deps = _with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=dfn), run=_live_run_1165(run_dir))
        result = asyncio.run(_close_investigation_async(
            deps, disposition, stages=_bundle(composer=_composer(finding="holds")),
            bounds=challenge_gate.default_bounds(),
        ))
        assert (result.outcome, result.failure_kind) == (FORCED_INCONCLUSIVE, STAGE_ERROR), disposition
        fm = frontmatter(run_dir)
        assert fm["disposition"] == HOST_ONLY_DISPOSITION, (disposition, fm)
        assert fm["cause"] == CAUSE_REVIEW_INCOMPLETE, (disposition, fm)
        rec = record(run_dir, 1)
        assert rec["reviewed_disposition"] == disposition
        assert ALIAS_READ_REFUSAL in rec["detail"], (disposition, rec)


def test_an_absent_companion_is_not_a_fault(tmp_path):
    """The control that bounds the test above: NEVER WRITTEN and COULD NOT LOOK are different
    answers, and only the second is a fault."""
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
    from defender.tests.support.runtime.permissions._review_bundle import bundle as _bundle
    from defender.tests.support.runtime.permissions._review_bundle import composer_reply as _composer

    deps = _with_live_run_1165(bind(MAIN_DEF, run_dir, defender_dir=dfn), run=_live_run_1165(run_dir))
    with pytest.raises(ModelRetry) as e:
        asyncio.run(_close_investigation_async(
            deps, "false-positive", stages=_bundle(composer=_composer(finding="holds")),
            bounds=challenge_gate.default_bounds(),
        ))
    assert "could not be read" not in str(e.value)
    assert "detection_notes" in str(e.value)


def test_an_unfulfilled_authz_contract_blocks_the_benign_close(tmp_path):
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
    """The prologue clause reads a PROJECTION, so it inherits whatever that projection drops."""
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
