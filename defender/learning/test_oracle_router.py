"""Unit tests for the deterministic oracle router (_oracle_router)."""
from _oracle_router import parse_query, event_satisfies, route

WIN = "2026-06-04T14:00:00Z TO 2026-06-04T14:10:00Z"


def _ls(*query_lists):
    """Build a lead_sequence dict: one position per arg (a list of (arg0,index))."""
    entries = []
    for i, qs in enumerate(query_lists):
        entries.append({"position": i, "queries": [
            {"params": {"arg0": a, "index": idx}} for a, idx in qs]})
    return {"entries": entries}


# ---- parse ---------------------------------------------------------------

def test_parse_field_eq_and_window():
    sc = parse_query(
        f'falco.output_fields.container.id: "ffbff1299702" AND @timestamp:[{WIN}]',
        "logs-falco.alerts-*")
    assert sc.eq["falco.output_fields.container.id"] == {"ffbff1299702"}
    assert sc.ts_lo and sc.ts_hi


def test_parse_or_within_field():
    sc = parse_query(
        'falco.output_fields.proc.name: "curl" OR falco.output_fields.proc.name: "nc"', "logs-falco.alerts-*")
    assert sc.eq["falco.output_fields.proc.name"] == {"curl", "nc"}


def test_parse_message_wildcard():
    sc = parse_query('message: *"Accepted"* AND message: *"172.18.0.24"*', "logs-system.auth-*")
    assert set(sc.substrings) == {"Accepted", "172.18.0.24"}


# ---- the overload case (the whole point) ---------------------------------

def test_sidecar_does_not_match_alert_container_lead():
    alert_lead = parse_query(
        'falco.output_fields.container.id: "ffbff1299702" AND @timestamp:[%s]' % WIN,
        "logs-falco.alerts-*")
    sidecar = {"container_id": "<sidecar-container-id>", "rule": "Launch Privileged Container",
               "data_source": "logs-falco.alerts", "when": "2026-06-04T14:04:10Z"}
    assert event_satisfies(sidecar, alert_lead) is False


def test_alert_event_matches_its_container_lead():
    lead = parse_query(
        'falco.output_fields.container.id: "ffbff1299702" AND @timestamp:[%s]' % WIN,
        "logs-falco.alerts-*")
    ev = {"container_id": "ffbff1299702", "rule": "Launch Suspicious Network Tool in Container",
          "data_source": "logs-falco.alerts", "when": "2026-06-04T14:00:54Z"}
    assert event_satisfies(ev, lead) is True


def test_route_sends_sidecar_to_uncovered_not_overloaded():
    ls = _ls(
        [('falco.output_fields.container.id: "ffbff1299702" AND @timestamp:[%s]' % WIN, "logs-falco.alerts-*")],
        [('ffbff1299702', "-")],  # host-state lookup, no index -> never covers
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


# ---- window / index discrimination ---------------------------------------

def test_window_excludes_out_of_range_event():
    lead = parse_query('falco.output_fields.container.id: "ffbff1299702" AND @timestamp:[%s]' % WIN,
                       "logs-falco.alerts-*")
    late = {"container_id": "ffbff1299702", "data_source": "logs-falco.alerts",
            "when": "2026-06-04T15:30:00Z"}
    assert event_satisfies(late, lead) is False


def test_index_mismatch_excludes():
    lead = parse_query('source.ip: "172.18.0.24"', "logs-system.auth-*")
    falco_ev = {"source_ip": "172.18.0.24", "data_source": "logs-falco.alerts",
                "when": "2026-06-04T14:03:00Z"}
    assert event_satisfies(falco_ev, lead) is False


def test_message_substring_match():
    lead = parse_query('host.name: "dev-ws-1" AND message: *"Accepted"*', "logs-system.auth-*")
    ev = {"host": "dev-ws-1", "process": "sshd", "note": "Accepted publickey for svc.monitoring",
          "data_source": "logs-system.auth", "when": "2026-06-04T14:03:51Z"}
    assert event_satisfies(ev, lead) is True
    ev_other_host = dict(ev, host="jump-box-1")
    assert event_satisfies(ev_other_host, lead) is False


def test_unmapped_field_is_non_discriminating():
    # a field we don't map must not cause a false exclusion
    lead = parse_query('weird.unknown.field: "x" AND source.ip: "1.2.3.4"', "logs-zeek.connection-*")
    ev = {"source_ip": "1.2.3.4", "data_source": "logs-zeek.connection", "when": "2026-06-04T14:03:00Z"}
    assert event_satisfies(ev, lead) is True
