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
    """A lead COMMITS by filing what it observed — the same shape a real run writes."""
    return (
        "```invlang\n"
        f":V {lead_id}.observations.vertices [id|type|class|ident|attrs?]\n"
        f"{vertex}|identity|user/known-corp|svc.config-mgmt|\n"
        "```\n"
    )


def _conclude(**rows: str) -> str:
    body = "".join(f"{k:<22} {v}\n" for k, v in rows.items())
    return "```invlang\n:T conclude\n" + body + "```\n"


_NOTES = '"Claims a same-user brute-force success but groups by host, so the actor is untested."'


def _doc(*parts: str) -> str:
    return "".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# the keyword exists
# ═══════════════════════════════════════════════════════════════════════════

def test_false_positive_is_in_the_shared_vocabulary():
    """It has to be in `_vocab` rather than invlang-local: `report.md`'s frontmatter and the
    `conclude` block are validated by different schemas reading the same enum."""
    assert "false-positive" in DISPOSITION_ENUM


# ═══════════════════════════════════════════════════════════════════════════
# the six ways the exit could be faked
# ═══════════════════════════════════════════════════════════════════════════

def test_a_stated_defect_is_required():
    """An FP close with no `detection_notes` is a close with no reason. The disposition is a
    claim about the rule; if the run cannot say what the rule got wrong, it has not made one."""
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"),
               _conclude(disposition="false-positive", entity_check="l-001"))
    errors = validate_companion(doc, None)
    assert any("detection_notes" in e for e in errors)


def test_an_entity_check_is_required():
    """Refuting the detector says nothing about the host. Without this the disposition is a
    cheaper `benign` — the exact substitution that closed a host carrying three
    `attacker@elsewhere` keys in root's `authorized_keys`."""
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"),
               _conclude(disposition="false-positive", detection_notes=_NOTES))
    errors = validate_companion(doc, None)
    assert any("entity_check" in e for e in errors)


@pytest.mark.parametrize("marker", ["none", "n/a", "None", "  N/A  "])
def test_the_formats_empty_marker_is_not_a_stated_defect(marker):
    """`none` / `n/a` are what a conclude row writes where it has NOTHING to say, and the
    parser strips them only from list rows — a scalar keeps them as the literal text. A gate
    testing `notes.strip()` alone therefore reads "no defect found" as a stated defect, which
    is the emptiest possible FP close passing the check written to stop exactly that."""
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"),
               _conclude(disposition="false-positive", detection_notes=marker,
                         entity_check="l-001"))
    errors = validate_companion(doc, None)
    assert any("detection_notes" in e for e in errors)


def test_a_lead_whose_only_outcome_is_a_failure_does_not_count():
    """`:L findings`' `fail_reason` column projects into the lead's `outcome`, so a lead whose
    query errored reads as "committed" to the loose test `_check_loop_close` uses. For closing
    a loop that is right — the loop was worked. Here it is the gate's own failure mode: a
    query that never landed tested the alerted entity for nothing."""
    failed_lead = (
        "```invlang\n"
        ":L findings [id|loop|name|target|tests|system|window|fail_reason]\n"
        "l-003|1|db1-authorized-keys|v-001||elastic|30d|index unavailable\n"
        "```\n"
    )
    doc = _doc(_PROLOGUE, failed_lead,
               _conclude(disposition="false-positive", detection_notes=_NOTES,
                         entity_check="l-003"))
    errors = validate_companion(doc, None)
    assert any("committed no result" in e for e in errors)


def test_the_named_lead_has_to_exist():
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"),
               _conclude(disposition="false-positive", detection_notes=_NOTES,
                         entity_check="l-404"))
    errors = validate_companion(doc, None)
    assert any("not a lead in" in e for e in errors)


def test_a_planned_but_undispatched_lead_does_not_count():
    """A lead with no committed result is the shape of an investigation that stopped at the
    plan. `l-002` is written into `:L findings` and never resolved."""
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"),
               _conclude(disposition="false-positive", detection_notes=_NOTES,
                         entity_check="l-002"))
    errors = validate_companion(doc, None)
    assert any("committed no result" in e for e in errors)


def test_a_lead_against_an_entity_the_refutation_introduced_does_not_count():
    """THE regression. `l-002` is committed and real work — it just tests the source the rule
    wrongly implicated, not the host the alert was about. Every post-refutation lead in
    `pr815-rerun-0808` but one had this shape, so a gate without the prologue clause passes the
    run it was written for."""
    doc = _doc(_PROLOGUE, _LEADS, _outcome("l-002", "v-012"),
               _conclude(disposition="false-positive", detection_notes=_NOTES,
                         entity_check="l-002"))
    errors = validate_companion(doc, None)
    assert any("prologue does not carry" in e for e in errors)


# ═══════════════════════════════════════════════════════════════════════════
# and the shape that is allowed through
# ═══════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════
# the price is collected at BOTH boundaries
# ═══════════════════════════════════════════════════════════════════════════

def _paid(**over: str) -> str:
    rows = {"disposition": "false-positive", "detection_notes": _NOTES,
            "entity_check": "l-001", **over}
    return _doc(_PROLOGUE, _LEADS, _outcome("l-001", "v-011"), _conclude(**rows))


def test_the_entry_price_is_readable_from_a_companion_document():
    """The write gate reads a parsed companion; the close reads a FILE. One function answers
    both, so the two boundaries cannot drift into disagreeing about what is owed."""
    from defender.skills.invlang.validate import false_positive_entry_price

    assert false_positive_entry_price(_paid()) == []
    assert false_positive_entry_price("") != []          # nothing written owes everything
    assert false_positive_entry_price(_doc(_PROLOGUE, _LEADS)) != []


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
    deps = bind(MAIN_DEF, run_dir, defender_dir=dfn, salt="sess-salt")
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
