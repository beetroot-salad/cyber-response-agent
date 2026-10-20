"""The turn-zero correlation grant is authored in the verb-disposition table: projection, withholding, and load-time refusals."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _writer_run_1165

from pathlib import Path

import pytest

from defender._paths import PATHS, adapters_under
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import ModuleVerbRegistry
from defender.tests.support.invlang.validation._dispositions995 import (
    DispositionError,
    dispositions_path,
    grant_for,
    load_dispositions,
    planted_tree,
    write_table,
)
from defender.runtime.verbs import read_roster
from defender.tests.support.tenancy import _tenants1106 as T1106

ADAPTERS = PATHS.adapters_dir
#: The committed tenant's settings folder, where the shipped table lives since #1106.
SETTINGS = T1106.FIXTURE_SETTINGS

HOLDER = "lead-zero-correlation"

BOTH = {"roles": ["gather", HOLDER]}
GATHER_ONLY = {"roles": ["gather"]}
WITHHELD = {"roles": [], "reason": "test: withheld from every holder"}


def _table(tmp_path: Path, rows: dict) -> Path:
    return write_table(
        tmp_path / "settings" / "verb-grants.yaml", rows,
    )


def test_the_shipped_correlation_grant_is_the_tables_projection():
    """The wiring: the correlation grant must be BUILT from the table, not merely agree with it
    today."""
    from defender.runtime.lead_zero._spec import correlation_grant

    grants = T1106.run_grants(SETTINGS)
    rows = load_dispositions(dispositions_path(SETTINGS))
    assert grants.correlation.role == HOLDER
    assert set(grants.correlation.entries) == set(correlation_grant(rows).entries)
    assert grants.correlation_system == "elastic"


def test_a_withholding_from_every_holder_is_honoured_by_the_correlation_registry(tmp_path):
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


def test_the_lead_may_not_hold_a_pair_gather_does_not(tmp_path):
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
    from defender.runtime.lead_zero._spec import correlation_grant, correlation_system

    rows = load_dispositions(_table(tmp_path / "ok", {
        ("alpha", "lookup"): BOTH, ("alpha", "health-check"): BOTH,
        ("beta", "lookup"): GATHER_ONLY, ("beta", "health-check"): BOTH,
    }))
    assert correlation_system(correlation_grant(rows)) == "alpha"


def test_a_grant_with_no_query_verb_has_no_dispatch_target():
    from defender.runtime.lead_zero._spec import correlation_system

    assert correlation_system(VerbGrant(role=HOLDER, entries=())) is None
    assert correlation_system(VerbGrant(role=HOLDER, entries=(("alpha", "health-check", "r"),))) is None
    assert correlation_system(VerbGrant(
        role=HOLDER, entries=(("alpha", "lookup", "r"), ("alpha", "health-check", "r")),
    )) == "alpha"


def test_a_withheld_lead_is_neither_claimed_nor_declared(tmp_path):
    run_dir = tmp_path / fixture_uuid("run")
    run_dir.mkdir()
    import asyncio

    from defender.runtime.lead_zero import ENDING_WITHHELD, CorrelationDispatch, run_correlation

    lead_file = run_dir / "gather_raw" / "l-00c.lead.json"
    withheld = CorrelationDispatch("alpha.correlate", None, VerbGrant(role=HOLDER, entries=()))

    from defender.runtime.run_state import RunState
    outcome = asyncio.run(run_correlation(
        run_state=RunState(run_dir, "r"), defender_dir=run_dir, verbs=None, limits={},
        make_model=None, logger=None, box=None, store=None,
        catalog=None, dispatch=withheld, tenant=None, deadline=1.0, run=_writer_run_1165(run_dir)))

    assert outcome.ending == ENDING_WITHHELD, outcome
    assert outcome.summary is None, outcome
    assert not lead_file.exists(), "a withheld lead must not claim its row"
