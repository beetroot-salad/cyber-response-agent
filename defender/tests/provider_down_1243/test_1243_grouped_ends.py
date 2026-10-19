from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.provider_down_1243 import _spec1243 as P

L3 = P.L3
LEAD = "l-001"
CORR = "CORR-1243: correlation summary delivered."
SHAPES = sorted(P.GROUPED_PROVIDER_DOWN)
CONTROL_SHAPES = sorted(P.GROUPED_WITHOUT_PROVIDER_DOWN)


def _grouped_down(shape: str) -> P.Recorded:
    """The `shape` group around a `ProviderDown` as the retrier raises it, recorded."""
    return P.Recorded(P.GROUPED_PROVIDER_DOWN[shape](P.provider_down_fault()))


def _store(stores: list) -> Path:
    assert stores, "the run opened no session store"
    return stores[-1].path


def _assert_fired_a_group(fault: P.Recorded, *, holding_provider_down: bool) -> BaseException:
    """The fault fired exactly once, as an exception group that does (or does not) hold a
    `ProviderDown`. This is the guard that the scenario put a group, not a bare failure, on its
    path."""
    assert len(fault.raised) == 1, (
        f"the grouped fault fired {len(fault.raised)} times; the scenario raises it once")
    group = fault.raised[0]
    assert isinstance(group, BaseExceptionGroup), f"the fault raised {group!r}, not a group"
    if holding_provider_down:
        assert P.carries(group, P.provider_down_cls()), group
    else:
        # Read without the coined class, so a control stands on today's code alone.
        assert all(isinstance(leaf, (RuntimeError, ValueError)) for leaf in _leaves(group)), group
    return group


def _leaves(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        return [leaf for inner in exc.exceptions for leaf in _leaves(inner)]
    return [exc]


def _assert_not_provider_down(d: S.Drive, stores: list) -> None:
    """The run did not end provider-down on any channel: summary, run-end record, exit code, or
    MAIN's session stamp."""
    assert (d.summary or {}).get("truncated_by") != P.PROVIDER_DOWN, d.summary
    rec = P.sidecar(d.folder)
    assert rec is None or rec["truncated_by"] != P.PROVIDER_DOWN, rec
    assert d.rc != P.PROVIDER_DOWN_EXIT, f"a run with no ProviderDown exited {d.rc}"
    assert P.sessions(_store(stores)).get("main") != P.PROVIDER_DOWN, (
        "MAIN's session is stamped provider-down by a group that holds no ProviderDown")


def _assert_escaped_as_itself(d: S.Drive, group: BaseException) -> None:
    """Today's behaviour at MAIN's loop for a group with no `ProviderDown` (and no
    `CallRecordWriteFailed`): `_drive_agent` re-raises it and the run crashes on it. The
    failures it carries still escape, none dropped or relabelled. Object identity of the group
    is not pinned; its member failures' identity is."""
    assert d.raised is not None, (
        "a group holding no ProviderDown was swallowed: the run did not crash on it "
        f"(summary {d.summary!r})")
    assert {id(e) for e in _leaves(d.raised)} == {id(e) for e in _leaves(group)}, (
        f"what escaped ({d.raised!r}) is not the group's own failures ({group!r})")


@pytest.mark.parametrize("shape", SHAPES)
def test_d6_main_request_down_inside_a_group_ends_the_run_provider_down(tmp_path: Path,
                                                                         shape: str) -> None:
    fault = _grouped_down(shape)
    stores: list = []
    main = S.MainScript([S.call("read_file", path="alert.json"), S.text(S.DONE)],
                        fault=S.LeadFault(raise_on=2, exc=fault))
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]},
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert main.requests == 2, f"MAIN made {main.requests} requests; the group is on its 2nd"
    _assert_fired_a_group(fault, holding_provider_down=True)
    P.assert_ended_provider_down(d)
    assert P.sessions(_store(stores)).get("main") == P.PROVIDER_DOWN, (
        "MAIN's session is not stamped provider-down")


def _lead_down_in_a_group(tmp_path: Path, shape: str) -> tuple[S.Drive, P.Recorded, list]:
    """MAIN dispatches one gather lead. The lead's second request raises the `shape` group
    around a `ProviderDown`."""
    fault = _grouped_down(shape)
    stores: list = []
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={L3: [S.text(CORR)], LEAD: [S.list_verbs("cmdb"), S.text("unreached")]},
        lead_faults={LEAD: S.LeadFault(raise_on=2, exc=fault)},
        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.requests(LEAD) == 2, "MAIN's lead never reached its failing request"
    _assert_fired_a_group(fault, holding_provider_down=True)
    return d, fault, stores


@pytest.mark.parametrize("shape", SHAPES)
def test_d6_a_main_lead_down_inside_a_group_ends_the_run_provider_down(tmp_path: Path,
                                                                        shape: str) -> None:
    d, _fault, stores = _lead_down_in_a_group(tmp_path, shape)
    P.assert_ended_provider_down(d)
    assert P.sessions(_store(stores)).get("main") == P.PROVIDER_DOWN, (
        "MAIN's session is not stamped provider-down")


@pytest.mark.parametrize("shape", SHAPES)
def test_d6_a_main_lead_down_inside_a_group_stamps_the_leads_session(tmp_path: Path,
                                                                      shape: str) -> None:
    d, _fault, stores = _lead_down_in_a_group(tmp_path, shape)
    assert d.raised is None, f"the run crashed instead of ending provider-down: {d.raised!r}"
    ended = P.sessions(_store(stores))
    assert ended.get(P.gather_agent(LEAD)) == P.PROVIDER_DOWN, (
        f"the lead's session reads {ended.get(P.gather_agent(LEAD))!r}, not provider-down")


@pytest.mark.parametrize("shape", SHAPES)
def test_d6_correlation_lead_down_inside_a_group_stops_before_main(tmp_path: Path,
                                                                   shape: str) -> None:
    fault = _grouped_down(shape)
    stores: list = []
    d = S.run_alert(tmp_path, leads={L3: [S.text(CORR)]},
                    lead_faults={L3: S.LeadFault(raise_on=1, exc=fault)},
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.dispatched(L3), "l-00c never ran"
    _assert_fired_a_group(fault, holding_provider_down=True)
    assert d.main.requests == 0, (
        f"MAIN was asked for {d.main.requests} turn(s) after the correlation lead's provider "
        "went down inside a group: the lead ended dispatch_raised and the run went on")
    P.assert_ended_provider_down(d)
    assert P.sessions(_store(stores)).get("main") == P.PROVIDER_DOWN, (
        "MAIN's session is not stamped provider-down")


@pytest.mark.parametrize("shape", CONTROL_SHAPES)
def test_d6_control_a_group_without_provider_down_still_escapes_mains_loop(tmp_path: Path,
                                                                          shape: str) -> None:
    fault = P.Recorded(P.GROUPED_WITHOUT_PROVIDER_DOWN[shape])
    stores: list = []
    main = S.MainScript([S.call("read_file", path="alert.json"), S.text(S.DONE)],
                        fault=S.LeadFault(raise_on=2, exc=fault))
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]},
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert main.requests == 2, f"MAIN made {main.requests} requests; the group is on its 2nd"
    group = _assert_fired_a_group(fault, holding_provider_down=False)
    _assert_escaped_as_itself(d, group)
    _assert_not_provider_down(d, stores)


def test_d6_control_a_group_without_provider_down_from_a_main_lead_still_escapes(
        tmp_path: Path) -> None:
    fault = P.Recorded(P.GROUPED_WITHOUT_PROVIDER_DOWN["flat"])
    stores: list = []
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={L3: [S.text(CORR)], LEAD: [S.list_verbs("cmdb"), S.text("unreached")]},
        lead_faults={LEAD: S.LeadFault(raise_on=2, exc=fault)},
        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.requests(LEAD) == 2, "MAIN's lead never reached its failing request"
    group = _assert_fired_a_group(fault, holding_provider_down=False)
    _assert_escaped_as_itself(d, group)
    _assert_not_provider_down(d, stores)
    assert P.sessions(_store(stores)).get(P.gather_agent(LEAD)) != P.PROVIDER_DOWN


def _correlation_ending(d: S.Drive) -> str:
    """The correlation section of MAIN's opening message, with the run folder and id
    normalised away. It holds the lead's framed summary or its one named ending."""
    assert d.run_dir is not None
    _heading, body = S.correlation_section(d.main.opening_message)
    return S.normalize(body, run_dir=d.run_dir, run_id=d.run_dir.name)


@pytest.mark.parametrize("shape", CONTROL_SHAPES)
def test_d6_control_a_group_without_provider_down_at_the_correlation_lead_is_dispatch_raised(
        tmp_path: Path, shape: str) -> None:
    tenant = S.plant_tenant()

    def drive(label: str, exc: P.Fault | None, stores: list) -> S.Drive:
        sub = tmp_path / label
        sub.mkdir()
        faults = {L3: S.LeadFault(raise_on=1, exc=exc)} if exc is not None else None
        return S.run_alert(sub, tenant=tenant, main=S.MainScript([S.text(S.DONE)]),
                           leads={L3: [S.text(CORR)]}, lead_faults=faults,
                           store_factory=S.store_factory(sub, sink=stores), stores=stores)

    summary = drive("summary", None, [])
    bare = drive("bare", P.ordinary_error(), [])
    fault = P.Recorded(P.GROUPED_WITHOUT_PROVIDER_DOWN[shape])
    stores: list = []
    d = drive("grouped", fault, stores)
    assert d.router.dispatched(L3), "l-00c never ran"
    _assert_fired_a_group(fault, holding_provider_down=False)
    assert d.raised is None, f"the run crashed on the lead's group: {d.raised!r}"
    assert d.main.requests == 1, (
        f"MAIN was asked {d.main.requests} time(s): the run stopped before MAIN on a group "
        "holding no ProviderDown")
    assert not (d.summary or {}).get("truncated_by"), f"the run was cut: {d.summary!r}"
    assert d.rc == 0, f"rc={d.rc!r}"
    _assert_not_provider_down(d, stores)
    named = _correlation_ending(d)
    assert named != _correlation_ending(summary), (
        "the grouped run's correlation section is the summary run's: the lead's failure was "
        "not named at all")
    assert named == _correlation_ending(bare), (
        "a correlation-lead group holding no ProviderDown is named differently from the same "
        f"bare error (dispatch_raised):\n  grouped: {named!r}\n  bare:    "
        f"{_correlation_ending(bare)!r}")
