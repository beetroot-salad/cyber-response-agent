"""#1342 O14/M11/O17: the API's wire models, ports and fakes agree with the job store's rows."""
from __future__ import annotations

import datetime as dt
import inspect
import re
import typing

import anyio
import pytest
from pydantic import ValidationError

from defender.api import models, ports
from defender.api.fakes import InMemoryStore
from defender.api.ports import AlertsRepository

NOW = dt.datetime(2026, 10, 29, 12, 0, tzinfo=dt.UTC)
FIELDS = ("request_key", "attempt", "failure_reason", "failure_message")


def _investigation(**extra):
    fields = {"cost_usd": 0.0, "cost_is_lower_limit": False, "request_key": "k1", "attempt": 1, **extra}
    return models.Investigation(investigation_id="b1000000-0000-4000-8000-000000000001", alert_id="a1000000-0000-4000-8000-000000000001", status="failed",
                                created_at=NOW, **fields)


def _alert(**extra):
    return dict(alert_id="a1000000-0000-4000-8000-000000000001", vendor="elastic", vendor_ticket_id="T-1", title="t", description="d",
                fired_at=NOW, changed_at=NOW, received_at=NOW, **extra)


def test_o14_an_investigation_carries_its_request_key_attempt_and_failure_detail():
    """`request_key`, `attempt`, `failure_reason`, `failure_message` round-trip, in the schema too. (O14)"""
    inv = _investigation(request_key="k1", attempt=2, failure_reason="no_report",
                         failure_message="exited 7 without a report")
    dumped = inv.model_dump(mode="json")
    assert {k: dumped[k] for k in FIELDS} == {
        "request_key": "k1", "attempt": 2, "failure_reason": "no_report",
        "failure_message": "exited 7 without a report"}
    assert models.Investigation.model_validate(dumped) == inv
    assert set(FIELDS) <= set(models.Investigation.model_json_schema()["properties"])


@pytest.mark.parametrize("field", ["request_key", "attempt"])
def test_o14_every_investigation_names_its_request_key_and_attempt(field):
    """A row always has its request key and attempt, so the wire model requires both. (O14)"""
    fields = {"cost_usd": 0.0, "cost_is_lower_limit": False, "request_key": "k1", "attempt": 1}
    del fields[field]
    with pytest.raises(ValidationError, match=field):
        models.Investigation(investigation_id="b1000000-0000-4000-8000-000000000001", alert_id="a1000000-0000-4000-8000-000000000001", status="queued", created_at=NOW, **fields)


def test_o14_cost_is_nullable_and_described_as_so_far_while_live():
    """`cost_usd=None` (unknown, R3) validates and serves null; the text says "so far" while live and final once ended, and null for unknown. (O14, M11, B12: conflict updated)"""
    inv = _investigation(cost_usd=None)
    assert inv.model_dump(mode="json")["cost_usd"] is None
    assert _investigation(cost_usd=1.25).cost_usd == 1.25  # control: a number still validates
    description = models.Investigation.model_fields["cost_usd"].description.lower()
    assert "so far" in description
    assert "final" in description
    assert "unknown" in description or "null" in description


def test_s2_cost_is_lower_limit_sits_beside_an_unchanged_cost_and_says_what_at_least_means():
    """`cost_is_lower_limit` round-trips beside `cost_usd`, whose type is unchanged; its text says the cost is a lower limit. (S2, S4)"""
    inv = _investigation(cost_usd=2.5, cost_is_lower_limit=True)
    dumped = inv.model_dump(mode="json")
    assert (dumped["cost_usd"], dumped["cost_is_lower_limit"]) == (2.5, True)
    assert models.Investigation.model_validate(dumped) == inv
    assert models.Investigation.model_fields["cost_usd"].annotation == float | None
    description = models.Investigation.model_fields["cost_is_lower_limit"].description.lower()
    assert "lower limit" in description
    assert "at least" in description


def test_s2_cost_is_lower_limit_is_required_on_the_wire_model_and_in_its_schema():
    """No default: a repository that forgot the field cannot serve a row, and the schema lists it as required. (S2, r4 API field)"""
    field = models.Investigation.model_fields["cost_is_lower_limit"]
    assert field.is_required()
    assert field.annotation is bool
    assert "cost_is_lower_limit" in models.Investigation.model_json_schema()["required"]
    fields = {"cost_usd": 0.0, "request_key": "k1", "attempt": 1}
    with pytest.raises(ValidationError, match="cost_is_lower_limit"):
        models.Investigation(investigation_id="b1000000-0000-4000-8000-000000000001", alert_id="a1000000-0000-4000-8000-000000000001", status="queued", created_at=NOW, **fields)


def test_s2_the_fake_creates_an_investigation_whose_cost_is_not_a_lower_limit():
    """The development fake carries the field: a new investigation's cost is 0 and exact. (S2, S4)"""
    async def run():
        store = InMemoryStore(lambda: NOW)
        store.add_alert("t", models.Alert(**_alert(raw="{}")))
        return await store.create_investigation("t", "a1000000-0000-4000-8000-000000000001", "req-9")

    inv, _ = anyio.run(run)
    assert (inv.cost_usd, inv.cost_is_lower_limit) == (0.0, False)


def test_b12_failure_reason_names_the_two_take_over_reasons_beside_the_old_ones():
    """The `failure_reason` text lists `lease_lapsed` and `retry_cap` and still `cancelled` and `worker_error`. (B12)"""
    description = models.Investigation.model_fields["failure_reason"].description
    assert all(f"`{reason}`" in description for reason in ("lease_lapsed", "retry_cap", "cancelled", "worker_error"))


def test_b12_the_cancel_port_says_it_aborts_a_running_investigation_and_names_a_live_retry():
    """The cancel docstring no longer says running is unsupported; it says queued or running is aborted and an ended attempt's `Conflict` names its live retry. (B12, B9)"""
    doc = " ".join(inspect.getdoc(ports.WriteTransaction.cancel_investigation).split()).lower()
    assert "not supported" not in doc
    assert "queued or running" in doc or "running or queued" in doc
    assert "retry" in doc


def test_o14_alert_raw_is_the_exact_text_and_a_parsed_object_is_refused():
    """`Alert.raw` keeps the text as given (no parse, duplicate keys and spacing kept); a dict is not text. (O14)"""
    raw = '{"b": 1.50,  "a": 1, "a": 2}\n'
    alert = models.Alert(**_alert(raw=raw))
    assert alert.raw == raw
    assert alert.model_dump(mode="json")["raw"] == raw
    with pytest.raises(ValidationError):
        models.Alert(**_alert(raw={"a": 1}))


def test_o14_the_summary_has_a_description_and_neither_severity_nor_rule():
    """`AlertSummary` fields are exactly the list plus `description`; `Alert` adds only `raw`. (O14)"""
    assert set(models.AlertSummary.model_fields) == {
        "alert_id", "vendor", "vendor_ticket_id", "title", "description", "fired_at", "changed_at",
        "received_at"}
    assert set(models.Alert.model_fields) == set(models.AlertSummary.model_fields) | {"raw"}
    assert models.AlertSummary(**_alert()).model_dump()["description"] == "d"
    with pytest.raises(ValidationError):
        models.AlertSummary(**{k: v for k, v in _alert().items() if k != "description"})


def test_o14_list_alerts_has_no_severity_filter_in_ports_fakes_and_the_route():
    """`list_alerts` loses `severity` in the port, the development fake and the published route. (O14)"""
    assert "severity" not in inspect.signature(AlertsRepository.list_alerts).parameters
    assert "severity" not in inspect.signature(InMemoryStore.list_alerts).parameters
    from defender.tests.api.test_api_stub import Api

    doc = Api().client.get("/openapi.json").json()
    names = {p["name"] for p in doc["paths"]["/tenants/{tenant_id}/alerts"]["get"]["parameters"]}
    assert "fired_after" in names  # control: the parameters are the ones we read
    assert "severity" not in names


def test_o14_the_fake_stamps_a_created_investigation_with_its_request_key_and_attempt_one():
    """The development fake follows the field change: a create carries the key it was given, attempt 1. (O14)"""
    async def run():
        store = InMemoryStore(lambda: NOW)
        store.add_alert("t", models.Alert(**_alert(raw="{}")))
        return await store.create_investigation("t", "a1000000-0000-4000-8000-000000000001", "req-9")

    inv, created = anyio.run(run)
    assert created is True
    assert (inv.request_key, inv.attempt) == ("req-9", 1)


def _cancel(status):
    """Cancel an investigation of this stage in a fresh fake; returns the store and the outcome or the error."""
    async def run():
        store = InMemoryStore(lambda: NOW)
        store.add_investigation("t", models.Investigation(
            investigation_id="b1000000-0000-4000-8000-000000000001", alert_id="a1000000-0000-4000-8000-000000000001", status=status, created_at=NOW,
            cost_usd=0.0, cost_is_lower_limit=False, request_key="k1", attempt=1))
        try:
            return store, await store.cancel_investigation("t", "b1000000-0000-4000-8000-000000000001")
        except ports.Conflict as conflict:
            return store, conflict

    return anyio.run(run)


def test_o9_the_fake_cancels_a_queued_investigation_as_aborted_with_reason_cancelled():
    """Queued becomes `aborted` with `failure_reason` `cancelled` and a finish time, as the job store's cancel does. (O9, O14)"""
    _, got = _cancel("queued")
    assert (got.status, got.failure_reason, got.finished_at) == ("aborted", "cancelled", NOW)


def test_o9_the_fake_cancels_a_running_investigation_as_aborted_with_reason_cancelled():
    """Running becomes `aborted`/`cancelled` with a finish time, as the job store's cancel does; no "not yet". (O9, O14, B9: conflict updated; the fake follows the port, which the design amends)"""
    store, got = _cancel("running")
    assert not isinstance(got, BaseException), got
    assert (got.status, got.failure_reason, got.finished_at) == ("aborted", "cancelled", NOW)
    assert anyio.run(store.get_investigation, "t", "b1000000-0000-4000-8000-000000000001").status == "aborted"


@pytest.mark.parametrize("status", ["completed", "unparseable", "failed", "aborted"])
def test_o9_the_fake_refuses_to_cancel_an_ended_investigation_and_leaves_it_as_it_was(status):
    """A terminal stage is a `Conflict` ("already ended"); the stored row keeps its stage. (O9, O14)"""
    store, got = _cancel(status)
    assert isinstance(got, ports.Conflict), got
    assert "already ended" in str(got)
    assert anyio.run(store.get_investigation, "t", "b1000000-0000-4000-8000-000000000001").status == status


def test_m11_the_client_request_id_describes_the_latest_attempt():
    """`ClientRequestId`'s text says it answers the latest attempt of the request the id started. (M11)"""
    description = typing.get_args(models.ClientRequestId)[1].description
    assert "the latest attempt of the request this id started" in description


def test_m11_investigations_repository_doc_is_restated_against_the_row():
    """The docstring no longer reasons from the run stamp; it names the refused-setup case. (M11, M6)"""
    doc = inspect.getdoc(ports.InvestigationsRepository)
    assert "stamp" not in doc
    assert "refused" in doc


_OLD = re.compile(r"soft delete|deleted\b.{0,60}\bleft out|for a deleted|deleted since|hidden from every read",
                  re.IGNORECASE | re.DOTALL)


def test_o17_the_ports_no_longer_describe_a_soft_delete():
    """No port docstring mentions soft delete, deleted rows left out, or a conflict for a deleted replay; §4.1 is still cited. (O17)"""
    assert _OLD.search("Soft delete: hidden from every read"), "control: the pattern sees the old text"
    docs = {name: inspect.getdoc(obj) or "" for name, obj in vars(ports).items()
            if inspect.isclass(obj) and obj.__module__ == ports.__name__}
    for name in list(docs):
        for member, fn in vars(getattr(ports, name)).items():
            if callable(fn) and not member.startswith("_"):
                docs[f"{name}.{member}"] = inspect.getdoc(fn) or ""
    assert [n for n, d in docs.items() if _OLD.search(d)] == []
    assert "§4.1" in docs["WriteTransaction.create_investigation"]


def test_o13_the_write_transaction_doc_says_audit_events_follow_the_commit():
    """The docstring no longer promises audit commits with the records; events are emitted after commit and can be lost. (O13)"""
    doc = " ".join(inspect.getdoc(ports.WriteTransaction).split())
    assert "after commit" in doc
    assert "lost" in doc
    assert "records and audit events" not in doc


def test_o13_the_audit_vocabulary_has_claim_and_finish():
    """The API's list of audit actions gains `investigation.claim` and `investigation.finish`. (O13)"""
    actions = set(typing.get_args(ports.AuditAction))
    assert {"investigation.claim", "investigation.finish"} <= actions


def test_b12_every_audit_vocabulary_gains_takeover_and_retry():
    """The API's list and the job store's own list both carry `investigation.takeover` and `investigation.retry`. (B12, B6)"""
    from defender.jobs.audit import AuditAction as JobsAuditAction

    new = {"investigation.takeover", "investigation.retry"}
    jobs = set(typing.get_args(JobsAuditAction))
    assert new <= set(typing.get_args(ports.AuditAction))
    assert new <= jobs
    assert jobs <= set(typing.get_args(ports.AuditAction)), "the job store emits an action the API's vocabulary lacks"



def test_s2_the_demo_investigations_carry_an_exact_mark_beside_a_number():
    """Both seeded demo investigations are built with `cost_is_lower_limit` (false), each beside a number. (S2, S4)"""
    from defender.api.demo import demo_deps, demo_id
    from defender.records.formats import InvestigationId, TenantId
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    tenant = fixture_uuid("tenant:t-one")

    async def run():
        deps = await demo_deps((tenant,), lambda: NOW)
        return [await deps.investigations.get_investigation(TenantId(tenant), demo_id(InvestigationId, tenant, name))
                for name in ("inv-completed", "inv-running")]

    seeded = anyio.run(run)
    assert [(i.cost_is_lower_limit, i.cost_usd is not None) for i in seeded] == [(False, True)] * 2
