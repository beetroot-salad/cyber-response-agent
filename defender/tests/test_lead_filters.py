"""Tests for vendor-neutral filter recovery (scripts/lead_filters.py).

Recovery lifts the bound ``${param}`` values back out of a rendered query by
aligning it against the *template that produced it* — no query-language grammar.

The tests build a self-contained fixture catalog in a tmp dir and point
``lead_filters.QUERIES_DIR`` at it, so they exercise the recovery logic without
depending on any particular deployment's gather templates (the elastic catalog
on v2, the wazuh catalog on main, …).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "lead_filters.py"
_spec = importlib.util.spec_from_file_location("lead_filters", _MODULE_PATH)
lf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lf)


# A fixture catalog: {template-id: (filter_keys frontmatter, ## Query body)}.
_TEMPLATES = {
    "falco-timeline": (
        "filter_keys:\n"
        "  index: logs-falco.alerts-*\n"
        "  window: {start: start, end: end}\n"
        "  predicates:\n"
        "    - {event_attr: container_id, op: eq, param: container_id}\n",
        'falco.output_fields.container.id: "${container_id}" '
        "AND @timestamp:[${start} TO ${end}]",
    ),
    "launch-tool": (
        "filter_keys:\n"
        "  index: logs-falco.alerts-*\n"
        "  window: {start: start, end: end}\n"
        "  predicates:\n"
        "    - {event_attr: container_id, op: eq, param: container_id}\n"
        '    - {event_attr: rule, op: eq, value: "Launch Suspicious Network Tool in Container"}\n',
        'falco.output_fields.container.id: "${container_id}" AND '
        'falco.output_fields.evt.type: "execve" AND '
        "@timestamp:[${start} TO ${end}]",
    ),
    "syslog-scan": (
        "filter_keys:\n"
        "  index: logs-*\n"
        "  predicates:\n"
        "    - {op: substring, param: ip}\n",
        'message: *"${ip}"*',
    ),
    "sshd-srcip": (
        "filter_keys:\n"
        "  index: logs-system.auth-*\n"
        "  predicates:\n"
        "    - {event_attr: source_ip, op: eq, param: ip}\n",
        'data_stream.dataset: "system.auth" AND message: *"from ${ip}"*',
    ),
    "host-by-ip": (
        "filter_keys:\n"
        "  index: logs-*\n"
        "  predicates:\n"
        "    - {event_attr: host_ip, op: eq, param: ip}\n",
        'host.ip: "${ip}"',
    ),
    "alerts-window": (
        "filter_keys:\n"
        "  index: .internal.alerts-security.alerts-default-*\n"
        "  window: {start: start, end: end}\n"
        "  predicates:\n"
        "    - {event_attr: rule, op: eq, param: rule_id}\n",
        'kibana.alert.rule.rule_id: "${rule_id}"',
    ),
}


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    """Materialize the fixture catalog and point lead_filters at it."""
    elastic = tmp_path / "elastic"
    elastic.mkdir()
    for tid, (fk, body) in _TEMPLATES.items():
        (elastic / f"{tid}.md").write_text(
            f"---\nid: elastic.{tid}\n{fk}---\n\n## Query\n\n```\n{body}\n```\n"
        )
    monkeypatch.setattr(lf, "QUERIES_DIR", tmp_path)
    return tmp_path


def test_no_contract_for_ad_hoc(catalog):
    assert lf.recover_filters("ad-hoc", {"arg0": "anything"}) is None
    assert lf.recover_filters("elastic.not-a-template", {"arg0": "x"}) is None
    assert lf.recover_filters("cmdb.host-trust-edges", {"arg0": "x"}) is None


def test_falco_container_eq_and_window(catalog):
    arg0 = ('falco.output_fields.container.id: "ffbff1299702" '
            'AND @timestamp:[2026-06-04T14:00:00Z TO 2026-06-04T14:10:00Z]')
    f = lf.recover_filters("elastic.falco-timeline", {"arg0": arg0})
    assert f["index"] == "logs-falco.alerts-*"
    assert f["window"] == {"start": "2026-06-04T14:00:00Z", "end": "2026-06-04T14:10:00Z"}
    assert f["predicates"] == [
        {"op": "eq", "event_attr": "container_id", "value": "ffbff1299702"}]


def test_constant_rule_predicate_passes_through(catalog):
    arg0 = ('falco.output_fields.container.id: "abc" AND '
            'falco.output_fields.evt.type: "execve" AND '
            '@timestamp:[2026-06-04T14:00:00Z TO 2026-06-04T14:10:00Z]')
    f = lf.recover_filters("elastic.launch-tool", {"arg0": arg0})
    rules = [p for p in f["predicates"] if p["event_attr"] == "rule"]
    assert rules == [{"op": "eq", "event_attr": "rule",
                      "value": "Launch Suspicious Network Tool in Container"}]


def test_window_recovered_from_named_params_when_not_in_body(catalog):
    # alerts-window has no @timestamp in its body; window arrives as --start/--end
    # flags (recorded as named params).
    f = lf.recover_filters("elastic.alerts-window", {
        "arg0": 'kibana.alert.rule.rule_id: "v2-cross-tier-ssh-pivot"',
        "start": "2026-06-02T10:00:00Z", "end": "2026-06-02T14:00:00Z"})
    assert f["window"] == {"start": "2026-06-02T10:00:00Z", "end": "2026-06-02T14:00:00Z"}
    assert f["predicates"] == [
        {"op": "eq", "event_attr": "rule", "value": "v2-cross-tier-ssh-pivot"}]


def test_substring_param_recovered(catalog):
    f = lf.recover_filters("elastic.syslog-scan", {"arg0": 'message: *"172.18.0.99"*'})
    assert f["predicates"] == [{"op": "substring", "value": "172.18.0.99"}]


def test_source_ip_recovered_from_message_substring_template(catalog):
    # the query filters via a message substring but declares the semantic locator
    # (source_ip eq); the value is lifted and stripped clean.
    f = lf.recover_filters("elastic.sshd-srcip", {
        "arg0": 'data_stream.dataset: "system.auth" AND message: *"from 172.18.0.14"*'})
    assert f["predicates"] == [
        {"op": "eq", "event_attr": "source_ip", "value": "172.18.0.14"}]


def test_recovery_is_whitespace_insensitive(catalog):
    # extra spaces around the colon must not break the field anchor (regression
    # for the re.escape/whitespace double-escape bug).
    f = lf.recover_filters("elastic.host-by-ip", {"arg0": 'host.ip:    "10.0.0.5"'})
    assert f["predicates"] == [{"op": "eq", "event_attr": "host_ip", "value": "10.0.0.5"}]


def test_local_anchor_survives_divergent_earlier_clause(catalog):
    # The model rendered `evt.type` where the template has
    # `falco.output_fields.evt.type`; the container_id predicate (a *later* local
    # token) must still recover.
    arg0 = ('falco.output_fields.container.id: "a36492b5172b" AND '
            'evt.type: "execve" AND @timestamp:[2026-06-02T21:14:26Z TO 2026-06-02T21:34:26Z]')
    f = lf.recover_filters("elastic.launch-tool", {"arg0": arg0})
    assert {"op": "eq", "event_attr": "container_id", "value": "a36492b5172b"} in f["predicates"]


def test_unrecoverable_param_predicate_is_dropped_not_errored(catalog):
    # A query string that doesn't contain the templated field at all → the
    # predicate is dropped (non-discriminating), recovery still returns a dict.
    f = lf.recover_filters("elastic.falco-timeline", {"arg0": "totally unrelated query text"})
    assert f == {"index": "logs-falco.alerts-*"}
