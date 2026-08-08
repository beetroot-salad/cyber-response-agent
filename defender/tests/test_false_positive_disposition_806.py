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
    "l-001|1|sshd-auth-events-detail|v-001|h-001|elastic|30d\n"
    "l-002|2|bruteforce-source-attribution|v-006|h-002|elastic|30d\n"
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
# the four ways the exit could be faked
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
