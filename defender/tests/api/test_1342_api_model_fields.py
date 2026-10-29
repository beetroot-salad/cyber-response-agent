"""#1342 O14: the API's wire models agree with the job store's rows field for field."""
from __future__ import annotations

import datetime as dt
import inspect

from defender.api import models
from defender.api.ports import AlertsRepository

NOW = dt.datetime(2026, 10, 29, 12, 0, tzinfo=dt.UTC)


def _investigation(**extra):
    return models.Investigation(investigation_id="i-1", alert_id="a-1", status="failed", cost_usd=0.0,
                                created_at=NOW, **extra)


def test_o14_an_investigation_carries_its_request_key_attempt_and_failure_detail():
    """`request_key`, `attempt`, `failure_reason`, `failure_message` round-trip. (O14)"""
    inv = _investigation(request_key="k1", attempt=2, failure_reason="no_report",
                         failure_message="exited 7 without a report")
    dumped = inv.model_dump()
    assert {k: dumped[k] for k in ("request_key", "attempt", "failure_reason", "failure_message")} == {
        "request_key": "k1", "attempt": 2, "failure_reason": "no_report",
        "failure_message": "exited 7 without a report"}


def test_o14_alert_raw_is_the_exact_text_and_the_summary_has_a_description_not_severity_or_rule():
    """`Alert.raw` keeps the text as given (no parse); `AlertSummary` swaps severity/rule for description. (O14)"""
    raw = '{"b": 1.50,  "a": 1, "a": 2}'
    alert = models.Alert(alert_id="a-1", vendor="elastic", vendor_ticket_id="T-1", title="t",
                         description="d", fired_at=NOW, changed_at=NOW, received_at=NOW, raw=raw)
    assert alert.raw == raw
    assert alert.model_dump()["description"] == "d"
    assert not {"severity", "rule"} & set(models.AlertSummary.model_fields)


def test_o14_list_alerts_has_no_severity_filter():
    """`list_alerts` loses `severity`. (O14)"""
    assert "severity" not in inspect.signature(AlertsRepository.list_alerts).parameters

