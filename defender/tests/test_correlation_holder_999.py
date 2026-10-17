"""The turn-zero correlation grant is authored in the verb-disposition table: projection, withholding, and load-time refusals."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _writer_run_1165

from pathlib import Path

import pytest

from defender._paths import PATHS, adapters_under
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import ModuleVerbRegistry
from defender.tests._dispositions995 import (
    DispositionError,
    dispositions_path,
    grant_for,
    load_dispositions,
    planted_tree,
    write_table,
)
from defender.runtime.verbs import read_roster
from defender.tests import _tenants1106 as T1106

ADAPTERS = PATHS.adapters_dir
#: The committed tenant's settings folder, where the shipped table lives since #1106.
SETTINGS = T1106.FIXTURE_SETTINGS

#: The holder's name as the table spells it. Written here as a LITERAL rather than imported,
#: so a rename on one side cannot silently pass on the other — the constant's own test below
#: compares the two.
HOLDER = "lead-zero-correlation"

BOTH = {"roles": ["gather", HOLDER]}
GATHER_ONLY = {"roles": ["gather"]}
WITHHELD = {"roles": [], "reason": "test: withheld from every holder"}


def _table(tmp_path: Path, rows: dict) -> Path:
    return write_table(
        tmp_path / "settings" / "verb-grants.yaml", rows,
    )


# =========================================================================================
# The holder exists, is not a role, and projects exactly what the literal held.
# =========================================================================================


def test_the_shipped_correlation_grant_is_the_tables_projection():
    """The wiring: the correlation grant must be BUILT from the table, not merely agree with it
    today."""
    from defender.runtime.lead_zero._spec import correlation_grant

    grants = T1106.run_grants(SETTINGS)
    rows = load_dispositions(dispositions_path(SETTINGS))
    assert grants.correlation.role == HOLDER
    assert set(grants.correlation.entries) == set(correlation_grant(rows).entries)
    assert grants.correlation_system == "elastic"


# =========================================================================================
# O1 / O6 — a withholding in the table reaches the lead, and the refusal points home.
# =========================================================================================

def test_a_withholding_from_every_holder_is_honoured_by_the_correlation_registry(tmp_path):
    """The reported defect, at the seam that produced it: item 3's registry is the production
    registry's verb resolution under the holder's own projection. Withhold the pair from every
    holder and the lead's registry must DENY it — and say where the decision lives."""
    from defender.runtime.lead_zero._items import _NarrowedRegistry
    from defender.runtime.lead_zero._spec import correlation_grant, correlation_system

    tree = planted_tree(tmp_path, {"alpha": "lookup"})
    adapters = adapters_under(tree / "defender")

    # Positive control: granted to both, the narrowed registry grants it.
    granted_table = _table(tmp_path / "ok", {
        ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
    })
    granted = load_dispositions(granted_table)
    inner = ModuleVerbRegistry(read_roster(adapters), grant_for("gather", granted),
                               grant_home=str(granted_table))
    assert _NarrowedRegistry(inner, correlation_grant(granted)).decide("alpha", "lookup").outcome == "GRANTED"
    assert correlation_system(correlation_grant(granted)) == "alpha"

    # The withholding.
    withheld_table = _table(tmp_path / "withheld", {
        ("alpha", "lookup"): WITHHELD, ("alpha", "health-check"): BOTH,
    })
    withheld = load_dispositions(withheld_table)
    inner = ModuleVerbRegistry(read_roster(adapters), grant_for("gather", withheld),
                               grant_home=str(withheld_table))
    decision = _NarrowedRegistry(inner, correlation_grant(withheld)).decide("alpha", "lookup")
    assert decision.outcome == "DENIED", decision
    # #1106 M4: the RUN's resolved table, not a repo-relative constant — and not the other
    # table this test also built.
    assert str(granted_table) not in (decision.refusal or ""), decision.refusal
    assert str(withheld_table) in (decision.refusal or ""), (
        f"the refusal must name the table the withholding was written in:\n{decision.refusal}"
    )
    assert correlation_system(correlation_grant(withheld)) is None


def test_a_denied_verb_names_the_table_for_gather_too():
    """M6 is not holder-specific: every registry over a table-projected grant tells a DENIED
    caller where the withholding is authored. Pinned on gather's own withheld pair."""
    table = dispositions_path(SETTINGS)
    rows = load_dispositions(table)
    decision = ModuleVerbRegistry(
        read_roster(ADAPTERS), grant_for("gather", rows), grant_home=str(table),
    ).decide("cmdb", "list-roles")
    assert decision.outcome == "DENIED"
    assert str(table) in (decision.refusal or ""), decision.refusal


# =========================================================================================
# O3 / O7 — the loader's three coherence rules about the holder.
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


def test_the_lead_may_not_hold_a_second_query_verb(tmp_path):
    """The safety case the table now owns. `esql` is granted to gather and is NOT run through
    `confine_index`, so a subset-of-gather test alone would let one word here hand a lead no
    model chose to spend an unconfined index verb. Refused at load, naming both pairs."""
    # Positive control: one query verb plus `health-check` is exactly the shipped shape.
    load_dispositions(_table(tmp_path / "ok", {
        ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
        ("alpha", "peek"): GATHER_ONLY,
    }))
    with pytest.raises(DispositionError) as caught:
        load_dispositions(_table(tmp_path / "bad", {
            ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
            ("alpha", "peek"): BOTH,
        }))
    message = str(caught.value)
    assert "alpha.lookup" in message, message
    assert "alpha.peek" in message, message


def test_a_health_check_on_a_second_system_is_not_a_second_dispatch_target(tmp_path):
    """`health-check` never selects the dispatched system (`correlation_system` filters it out
    before deriving one), so a row for it elsewhere is not the authoring ambiguity the one-system
    rule refuses — and refusing it would kill startup over a table whose target is unambiguous."""
    from defender.runtime.lead_zero._spec import correlation_grant, correlation_system

    rows = load_dispositions(_table(tmp_path / "ok", {
        ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
        ("beta", "lookup"): GATHER_ONLY, ("beta", "health-check"): BOTH,
    }))
    assert correlation_system(correlation_grant(rows)) == "alpha"


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
    """`run_correlation` returns the `withheld` ending before any claim: no `l-00c` row lands in the
    leads table for a lead that will never run."""
    import asyncio

    from defender.runtime.lead_zero import ENDING_WITHHELD, CorrelationDispatch, run_correlation

    lead_file = tmp_path / "gather_raw" / "l-00c.lead.json"
    withheld = CorrelationDispatch("alpha.correlate", None, VerbGrant(role=HOLDER, entries=()))

    from defender.runtime.run_state import RunState
    outcome = asyncio.run(run_correlation(
        run_state=RunState(tmp_path, "r"), defender_dir=tmp_path, verbs=None, limits={},
        make_model=None, logger=None, box=None, store=None,
        catalog=None, dispatch=withheld, tenant=None, deadline=1.0, run=_writer_run_1165(tmp_path)))

    assert outcome.ending == ENDING_WITHHELD, outcome
    assert outcome.summary is None, outcome
    assert not lead_file.exists(), "a withheld lead must not claim its row"


