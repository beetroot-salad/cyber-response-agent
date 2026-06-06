"""Unit tests for the deterministic oracle router (_oracle_router).

The router consumes the structured ``filters`` block recovered upstream
(``scripts/lead_filters.py``, tested separately) — never a raw query string.
"""
from _oracle_router import event_satisfies, route

WIN = {"start": "2026-06-04T14:00:00Z", "end": "2026-06-04T14:10:00Z"}


def _ls(*filter_lists):
    """Build a lead_sequence dict: one position per arg (a list of filter dicts).

    ``None`` in a list stands for an unrouted query (filters: null).
    """
    entries = []
    for i, filters in enumerate(filter_lists):
        entries.append({"position": i, "queries": [
            {"id": f"q{i}", "params": {}, "filters": f} for f in filters]})
    return {"entries": entries}


def _falco_container(cid):
    return {"index": "logs-falco.alerts-*", "window": WIN,
            "predicates": [{"event_attr": "container_id", "op": "eq", "value": cid}]}


# ---- event_satisfies -----------------------------------------------------

def test_eq_match_and_window():
    f = _falco_container("ffbff1299702")
    ev = {"container_id": "ffbff1299702", "data_source": "logs-falco.alerts",
          "when": "2026-06-04T14:00:54Z"}
    assert event_satisfies(ev, f) is True


def test_eq_excludes_other_value():
    f = _falco_container("ffbff1299702")
    ev = {"container_id": "<sidecar-container-id>", "data_source": "logs-falco.alerts",
          "when": "2026-06-04T14:04:10Z"}
    assert event_satisfies(ev, f) is False


def test_eq_excludes_event_missing_the_field():
    f = _falco_container("ffbff1299702")
    ev = {"data_source": "logs-falco.alerts", "when": "2026-06-04T14:00:54Z"}
    assert event_satisfies(ev, f) is False


def test_window_excludes_out_of_range():
    f = _falco_container("ffbff1299702")
    late = {"container_id": "ffbff1299702", "data_source": "logs-falco.alerts",
            "when": "2026-06-04T15:30:00Z"}
    assert event_satisfies(late, f) is False


def test_index_mismatch_excludes():
    f = {"index": "logs-system.auth-*",
         "predicates": [{"event_attr": "source_ip", "op": "eq", "value": "172.18.0.24"}]}
    falco_ev = {"source_ip": "172.18.0.24", "data_source": "logs-falco.alerts",
                "when": "2026-06-04T14:03:00Z"}
    assert event_satisfies(falco_ev, f) is False


def test_index_wildcard_matches_any():
    f = {"index": "logs-*",
         "predicates": [{"event_attr": "source_ip", "op": "eq", "value": "172.18.0.25"}]}
    ev = {"source_ip": "172.18.0.25", "data_source": "logs-zeek.connection"}
    assert event_satisfies(ev, f) is True


def test_set_predicate_any_member():
    f = {"index": "logs-falco.alerts-*",
         "predicates": [{"event_attr": "process", "op": "set",
                         "values": ["nc", "ncat", "socat"]}]}
    assert event_satisfies({"process": "socat", "data_source": "logs-falco.alerts"}, f) is True
    assert event_satisfies({"process": "python", "data_source": "logs-falco.alerts"}, f) is False


def test_substring_scans_event_blob_when_no_attr():
    f = {"index": "logs-system.auth-*",
         "predicates": [{"op": "substring", "value": "172.18.0.24"}]}
    ev = {"data_source": "logs-system.auth", "note": "Accepted publickey from 172.18.0.24"}
    assert event_satisfies(ev, f) is True
    assert event_satisfies({"data_source": "logs-system.auth", "note": "other"}, f) is False


def test_multi_attr_predicate_matches_either():
    f = {"index": "logs-*",
         "predicates": [{"event_attr": ["host_ip", "source_ip"], "op": "eq",
                         "value": "10.0.0.5"}]}
    assert event_satisfies({"source_ip": "10.0.0.5", "data_source": "logs-zeek"}, f) is True
    assert event_satisfies({"host_ip": "10.0.0.5", "data_source": "logs-zeek"}, f) is True


def test_unknown_op_is_non_discriminating():
    f = {"index": "logs-*", "predicates": [{"event_attr": "x", "op": "regex", "value": "y"}]}
    assert event_satisfies({"data_source": "logs-zeek", "z": "1"}, f) is True


# ---- the overload case (the whole point) ---------------------------------

def test_route_sends_sidecar_to_uncovered_not_overloaded():
    ls = _ls(
        [_falco_container("ffbff1299702")],
        [None],  # cmdb/host-state lookup, no contract -> unrouted, never covers
    )
    footprint = [
        {"attrs": {"container_id": "ffbff1299702", "rule": "Launch Suspicious Network Tool in Container",
                   "data_source": "logs-falco.alerts", "when": "2026-06-04T14:00:54Z"}},
        {"attrs": {"container_id": "<sidecar-container-id>", "rule": "Launch Privileged Container",
                   "data_source": "logs-falco.alerts", "when": "2026-06-04T14:04:10Z"}},
    ]
    out = route(footprint, ls)
    pos0 = next(p for p in out["projections"] if p["position"] == 0)["events"]
    assert len(pos0) == 1 and pos0[0]["rule"].startswith("Launch Suspicious")
    assert any(e["rule"] == "Launch Privileged Container" for e in out["uncovered"])
    assert all(e.get("container_id") != "<sidecar-container-id>" for e in pos0)


def test_route_reports_unrouted_lead():
    ls = _ls([None])
    footprint = [{"attrs": {"container_id": "x", "data_source": "logs-falco.alerts"}}]
    out = route(footprint, ls)
    assert out["unrouted_leads"] == [{"position": 0, "queries": [{"id": "q0", "params": {}}]}]
    # the position still projects (empty), and the event is uncovered-modulo-unrouted
    assert out["projections"] == [{"position": 0, "events": []}]
    assert len(out["uncovered"]) == 1


def test_route_event_covered_by_multiple_positions():
    f = _falco_container("ffbff1299702")
    ls = _ls([f], [f])  # two leads with the same filter both surface it
    footprint = [{"attrs": {"container_id": "ffbff1299702", "data_source": "logs-falco.alerts",
                            "when": "2026-06-04T14:00:54Z"}}]
    out = route(footprint, ls)
    assert len(out["projections"][0]["events"]) == 1
    assert len(out["projections"][1]["events"]) == 1
    assert out["uncovered"] == []
