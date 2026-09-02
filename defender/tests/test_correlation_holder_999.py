"""#999 — the turn-zero correlation grant is authored in the verb-disposition table.

THE DEFECT. #995 moved the gather and judge grants into `knowledge/environment/verb-grants.yaml`
and gated the table for totality over the adapters. One grant stayed in Python: the two pairs
the harness-dispatched correlation lead (`l-00c`) runs under, a `VerbGrant` literal in
`lead_zero/_spec.py`. Its dispatch wraps the production registry and swaps THAT grant in, so a
withholding written in the table — `elastic.alerts: {roles: []}` — is honoured by item 1 and
every model-dispatched lead and ignored by item 3. Two statements about one permission, one of
them obeyed; and the table could not even name the lead, so the withholding was inexpressible.

THE SHAPE (settled on the issue). The lead is NOT a role — it is bound from `GATHER_DEF`, so
its policy, trace and wire-log id are gather's — and it does not become one. It is a third
GRANT HOLDER the table may name, `CORRELATION_GRANT_HOLDER`, a plain constant beside the
ablation-lens precedent in `agent_role.py`. The loader owns two coherence rules about it: the
holder never holds a pair gather does not (it runs under gather's tools), and its rows reach at
most one system (it is dispatched against exactly one). A withholding degrades — item 3 is
neither claimed nor dispatched, and ORIENT says so — it never kills startup.

THE ORACLES. Conservation is asserted against `CORRELATION_CENSUS`, transcribed in
`_dispositions995.py` from the literal as it stood, never from the file under test. Every rule
is proved by a PLANTED table that violates it beside a positive control that does not.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender._paths import PATHS, adapters_under
from defender.runtime.agent_role import AgentRole
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import ModuleVerbRegistry
from defender.tests._dispositions995 import (
    CORRELATION_CENSUS,
    DispositionError,
    dispositions_path,
    grant_for,
    load_dispositions,
    planted_tree,
    write_table,
)

DEFENDER = PATHS.defender_dir
ADAPTERS = PATHS.adapters_dir

#: The holder's name as the table spells it. Written here as a LITERAL rather than imported,
#: so a rename on one side cannot silently pass on the other — the constant's own test below
#: compares the two.
HOLDER = "lead-zero-correlation"

BOTH = {"roles": ["gather", HOLDER]}
GATHER_ONLY = {"roles": ["gather"]}
WITHHELD = {"roles": [], "reason": "test: withheld from every holder"}


def _table(tmp_path: Path, rows: dict) -> Path:
    return write_table(
        tmp_path / "defender" / "knowledge" / "environment" / "verb-grants.yaml", rows,
    )


# =========================================================================================
# The holder exists, is not a role, and projects exactly what the literal held.
# =========================================================================================

def test_the_holder_is_a_known_name_and_not_an_agent_role():
    from defender.runtime.agent_role import CORRELATION_GRANT_HOLDER
    from defender.runtime.verb_dispositions import KNOWN_ROLES

    assert CORRELATION_GRANT_HOLDER == HOLDER
    assert CORRELATION_GRANT_HOLDER in KNOWN_ROLES
    # An enum key grants compiled policy and names a trace file (`agent_role.py`), and three
    # suites pin `set(AGENTS) == set(AgentRole)`. The lead runs under gather's key.
    assert CORRELATION_GRANT_HOLDER not in {r.value for r in AgentRole}


def test_the_projected_correlation_grant_is_exactly_the_historical_pairs():
    """Conservation: moving the grant into the table widened or narrowed it by nothing."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    granted = {(s, v) for s, v, _ in grant_for(HOLDER, rows).entries}
    assert granted == set(CORRELATION_CENSUS), (
        f"gained={sorted(granted - CORRELATION_CENSUS)} lost={sorted(CORRELATION_CENSUS - granted)}"
    )


def test_the_shipped_correlation_grant_is_the_tables_projection():
    """The wiring: `_spec.CORRELATION_GRANT` must be BUILT from the table, not merely agree
    with it today. Checked against the projection function over the shipped rows, so a
    leftover literal that happens to match is still caught the first time the table changes."""
    from defender.runtime.lead_zero import CORRELATION_GRANT, CORRELATION_SYSTEM
    from defender.runtime.lead_zero._spec import correlation_grant

    rows = load_dispositions(dispositions_path(DEFENDER))
    assert CORRELATION_GRANT.role == HOLDER
    assert set(CORRELATION_GRANT.entries) == set(correlation_grant(rows).entries)
    assert CORRELATION_SYSTEM == "elastic"


# =========================================================================================
# O1 / O6 — a withholding in the table reaches the lead, and the refusal points home.
# =========================================================================================

def test_a_withholding_from_every_holder_is_honoured_by_the_correlation_registry(tmp_path):
    """The reported defect, at the seam that produced it: item 3's registry is the production
    registry's verb resolution under the holder's own projection. Withhold the pair from every
    holder and the lead's registry must DENY it — and say where the decision lives."""
    from defender.runtime.lead_zero._items import _NarrowedRegistry
    from defender.runtime.lead_zero._spec import correlation_grant, correlation_system
    from defender.runtime.verb_dispositions import DISPOSITIONS_REL

    tree = planted_tree(tmp_path, {"alpha": "lookup"})
    adapters = adapters_under(tree / "defender")

    # Positive control: granted to both, the narrowed registry grants it.
    granted = load_dispositions(_table(tmp_path / "ok", {
        ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
    }))
    inner = ModuleVerbRegistry(adapters, grant_for("gather", granted))
    assert _NarrowedRegistry(inner, correlation_grant(granted)).decide("alpha", "lookup").outcome == "GRANTED"
    assert correlation_system(correlation_grant(granted)) == "alpha"

    # The withholding.
    withheld = load_dispositions(_table(tmp_path / "withheld", {
        ("alpha", "lookup"): WITHHELD, ("alpha", "health-check"): BOTH,
    }))
    inner = ModuleVerbRegistry(adapters, grant_for("gather", withheld))
    decision = _NarrowedRegistry(inner, correlation_grant(withheld)).decide("alpha", "lookup")
    assert decision.outcome == "DENIED", decision
    assert DISPOSITIONS_REL in (decision.refusal or ""), (
        f"the refusal must name the table the withholding was written in:\n{decision.refusal}"
    )
    assert correlation_system(correlation_grant(withheld)) is None


def test_the_narrowed_registry_points_at_the_table():
    from defender.runtime.lead_zero._items import _NarrowedRegistry
    from defender.runtime.verb_dispositions import DISPOSITIONS_REL

    assert _NarrowedRegistry.grant_home == DISPOSITIONS_REL


def test_a_denied_verb_names_the_table_for_gather_too():
    """M6 is not holder-specific: every registry over a table-projected grant tells a DENIED
    caller where the withholding is authored. Pinned on gather's own withheld pair."""
    from defender.runtime.verb_dispositions import DISPOSITIONS_REL

    rows = load_dispositions(dispositions_path(DEFENDER))
    decision = ModuleVerbRegistry(ADAPTERS, grant_for("gather", rows)).decide("cmdb", "list-roles")
    assert decision.outcome == "DENIED"
    assert DISPOSITIONS_REL in (decision.refusal or ""), decision.refusal


# =========================================================================================
# O3 / O7 — the loader's two coherence rules about the holder.
# =========================================================================================

def test_the_lead_may_not_hold_a_pair_gather_does_not(tmp_path):
    """The lead runs under gather's compiled policy and tools; a pair only it holds is
    incoherent, and it is the one shape a one-word table edit could use to widen a
    harness-dispatched lead past its role. Refused at load, naming the pair."""
    # Positive control: the same pair held by both loads.
    load_dispositions(_table(tmp_path / "ok", {
        ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
    }))
    with pytest.raises(DispositionError) as caught:
        load_dispositions(_table(tmp_path / "bad", {
            ("alpha", "lookup"): {"roles": [HOLDER]}, ("alpha", "health-check"): BOTH,
        }))
    message = str(caught.value)
    assert "alpha.lookup" in message, message
    assert "gather" in message, message


def test_a_holder_spanning_two_systems_is_refused_at_load(tmp_path):
    """The lead is dispatched against ONE system (it selects the template tier and the cache
    lane). A table that reaches two is an authoring ambiguity, refused where it was authored
    and naming both systems — not a `GrantError` out of `_spec.py` at import."""
    load_dispositions(_table(tmp_path / "ok", {
        ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
        ("beta", "lookup"): GATHER_ONLY, ("beta", "health-check"): GATHER_ONLY,
    }))
    with pytest.raises(DispositionError) as caught:
        load_dispositions(_table(tmp_path / "bad", {
            ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
            ("beta", "lookup"): BOTH, ("beta", "health-check"): BOTH,
        }))
    message = str(caught.value)
    assert "alpha" in message, message
    assert "beta" in message, message


# =========================================================================================
# O5 — a withholding degrades; it does not kill.
# =========================================================================================

def test_a_grant_with_no_query_verb_has_no_dispatch_target():
    """`correlation_system` replaces the sole-system helper, which RAISED on an empty grant — the one
    behaviour that made 'skip, do not die' impossible. Health-check alone is not a dispatch
    target either: the lead would spend its budget discovering nothing is runnable."""
    from defender.runtime.lead_zero._spec import correlation_system

    assert correlation_system(VerbGrant(role=HOLDER, entries=())) is None
    assert correlation_system(VerbGrant(role=HOLDER, entries=(("alpha", "health-check", "r"),))) is None
    assert correlation_system(VerbGrant(
        role=HOLDER, entries=(("alpha", "lookup", "r"), ("alpha", "health-check", "r")),
    )) == "alpha"


def test_a_withheld_lead_is_neither_claimed_nor_declared(tmp_path):
    """`prepare_correlation_lead` returns before `claim_lead`: no `l-00c` row lands in the
    leads table for a lead that will never run. The positive control claims."""
    from defender.runtime.lead_zero import STATUS_RESOLVED, prepare_correlation_lead

    alert = {"alert_timestamp": "2026-01-01T00:00:00Z"}
    lead_file = tmp_path / "gather_raw" / "l-00c.lead.json"

    assert prepare_correlation_lead(tmp_path, alert, "block", STATUS_RESOLVED, system=None) is None
    assert not lead_file.exists(), "a withheld lead must not claim its row"

    assert prepare_correlation_lead(tmp_path, alert, "block", STATUS_RESOLVED, system="alpha") is not None
    assert lead_file.exists(), "positive control: with a dispatch target the row is claimed"


def test_the_orient_heading_says_the_lead_was_withheld():
    """MAIN reads why `l-00c` is absent — a trusted line naming the table — rather than the
    ordinary 'if any'. With a target, the heading is exactly what it was."""
    from defender.runtime.lead_zero import L3, LeadZeroResult, render_orient_section
    from defender.runtime.verb_dispositions import DISPOSITIONS_REL

    result = LeadZeroResult(text="", status="resolved")
    withheld = render_orient_section(result, None, correlation_system=None)
    assert L3 in withheld, withheld
    assert DISPOSITIONS_REL in withheld, withheld
    assert DISPOSITIONS_REL not in render_orient_section(result, None, correlation_system="alpha")
