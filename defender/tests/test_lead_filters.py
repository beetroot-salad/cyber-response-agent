"""Tests for vendor-neutral filter recovery (scripts/lead_filters.py).

Recovery lifts the bound ``${param}`` values back out of a rendered query by
aligning it against the *template that produced it* — no query-language grammar.
These exercise the real elastic templates in the catalog.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "lead_filters.py"
_spec = importlib.util.spec_from_file_location("lead_filters", _MODULE_PATH)
lf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lf)


def test_no_contract_for_ad_hoc():
    assert lf.recover_filters("ad-hoc", {"arg0": "anything"}) is None
    assert lf.recover_filters("elastic.coined-not-a-template", {"arg0": "x"}) is None
    assert lf.recover_filters("cmdb.host-trust-edges", {"arg0": "x"}) is None


def test_falco_container_eq_and_window():
    arg0 = ('falco.output_fields.container.id: "ffbff1299702" '
            'AND @timestamp:[2026-06-04T14:00:00Z TO 2026-06-04T14:10:00Z]')
    f = lf.recover_filters("elastic.falco-container-timeline", {"arg0": arg0})
    assert f["index"] == "logs-falco.alerts-*"
    assert f["window"] == {"start": "2026-06-04T14:00:00Z", "end": "2026-06-04T14:10:00Z"}
    assert f["predicates"] == [
        {"op": "eq", "event_attr": "container_id", "value": "ffbff1299702"}]


def test_constant_rule_predicate_passes_through():
    arg0 = ('falco.output_fields.container.id: "abc" AND '
            'falco.rule: "Launch Suspicious Network Tool in Container" AND '
            '@timestamp:[2026-06-04T14:00:00Z TO 2026-06-04T14:10:00Z]')
    f = lf.recover_filters("elastic.launch-network-tool-container", {"arg0": arg0})
    rules = [p for p in f["predicates"] if p["event_attr"] == "rule"]
    assert rules == [{"op": "eq", "event_attr": "rule",
                      "value": "Launch Suspicious Network Tool in Container"}]


def test_window_recovered_from_named_params_when_not_in_body():
    # cross-tier-alerts-window has no @timestamp in its body; window arrives as
    # --start/--end flags (recorded as named params).
    f = lf.recover_filters("elastic.cross-tier-alerts-window", {
        "arg0": 'kibana.alert.rule.rule_id: "v2-cross-tier-ssh-pivot"',
        "start": "2026-06-02T10:00:00Z", "end": "2026-06-02T14:00:00Z"})
    assert f["window"] == {"start": "2026-06-02T10:00:00Z", "end": "2026-06-02T14:00:00Z"}
    assert f["predicates"] == [
        {"op": "eq", "event_attr": "rule", "value": "v2-cross-tier-ssh-pivot"}]


def test_substring_param_recovered():
    f = lf.recover_filters("elastic.syslog-scanner-172-18-0-24",
                           {"arg0": 'message: *"172.18.0.99"*'})
    assert f["predicates"] == [{"op": "substring", "value": "172.18.0.99"}]


def test_source_ip_recovered_from_message_substring_template():
    # sshd-source-ip-activity filters via a message substring but declares the
    # semantic locator (source_ip eq); the value is lifted and stripped clean.
    f = lf.recover_filters("elastic.sshd-source-ip-activity", {
        "arg0": 'data_stream.dataset: "system.auth" AND process.name: "sshd" '
                'AND message: *"from 172.18.0.14"*'})
    assert f["predicates"] == [
        {"op": "eq", "event_attr": "source_ip", "value": "172.18.0.14"}]


def test_recovery_is_whitespace_insensitive():
    # extra spaces around the colon must not break the field anchor (regression
    # for the re.escape/whitespace double-escape bug).
    arg0 = 'host.ip:    "10.0.0.5"'
    f = lf.recover_filters("elastic.host-agent-by-ip", {"arg0": arg0})
    assert f["predicates"] == [{"op": "eq", "event_attr": "host_ip", "value": "10.0.0.5"}]


def test_local_anchor_survives_divergent_earlier_clause():
    # The model rendered `evt.type` where the template has
    # `falco.output_fields.evt.type`; the container_id predicate (a *later*
    # local token) must still recover.
    arg0 = ('falco.output_fields.container.id: "a36492b5172b" AND '
            'evt.type: "execve" AND @timestamp:[2026-06-02T21:14:26Z TO 2026-06-02T21:34:26Z]')
    f = lf.recover_filters("elastic.container-process-ancestry", {"arg0": arg0})
    assert {"op": "eq", "event_attr": "container_id", "value": "a36492b5172b"} in f["predicates"]


def test_unrecoverable_param_predicate_is_dropped_not_errored():
    # A query string that doesn't contain the templated field at all → the
    # predicate is dropped (non-discriminating), recovery still returns a dict.
    f = lf.recover_filters("elastic.falco-container-timeline",
                           {"arg0": "totally unrelated query text"})
    assert f == {"index": "logs-falco.alerts-*"}
