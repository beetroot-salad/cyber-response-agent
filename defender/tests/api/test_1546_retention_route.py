# ruff: noqa: PT018
"""#1546 A-O7: a tenant's evidence retention is written through the API (`config.write`, audited) as both values together,
30-730 days each; the table is `tenancy.evidence_retention`. Postgres-gated, over the real server (#1470's `scripted`).

The tenants start with the values their create request carried (r9/D16: `CREATE_RETENTION`; `served_config` registers A and B
so): a write replaces them, a refused one leaves them, and there is no "no row" state to start from.

Pinned (the design names no route): `PUT /api/tenants/{T}/evidence-retention` with `{investigation_days, learning_days}`
answering 200 with the stored pair, `GET` of the same path answering it, audit action `evidence_retention.write` (actor the
member, tenant `T`, the two values in the event's words)."""
from __future__ import annotations

import logging

import pytest

from defender.tests.support.api._config1470 import audit_events, told
from defender.tests.support.api._server1083 import ANN, ORIGIN, A, B
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy._active1214 import CREATE_RETENTION

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BASELINE = [(CREATE_RETENTION["investigation_days"], CREATE_RETENTION["learning_days"])]
PATH = f"/api/tenants/{A}/evidence-retention"
ACTION = "evidence_retention.write"


def _stored(dsn: str, tenant: str = A) -> list[tuple[int, int]]:
    return execute(dsn, "SELECT investigation_days, learning_days FROM tenancy.evidence_retention WHERE tenant_id = %s",
                   (tenant,))  # type: ignore[return-value]


async def test_a_write_replaces_the_created_values_and_reads_back(scripted):
    """Ann's tenant starts at its created pair and a GET serves it; she writes 90 and 365: 200 with the pair, stored, GET
    serves it; a second write replaces both; the other tenant keeps its created pair. (A-O7)"""
    base = {"investigation_days": BASELINE[0][0], "learning_days": BASELINE[0][1]}
    assert _stored(scripted.dsn) == BASELINE, "premise: the created pair"
    assert (await scripted.client.get(PATH, headers=scripted.ann(write=False))).json() == base
    body = {"investigation_days": 91, "learning_days": 366}
    first = await scripted.client.put(PATH, headers=scripted.ann(), json=body)
    assert first.status_code == 200, first.text
    assert first.json() == body
    assert _stored(scripted.dsn) == [(91, 366)]
    assert (await scripted.client.get(PATH, headers=scripted.ann(write=False))).json() == first.json()
    second = await scripted.client.put(PATH, headers=scripted.ann(), json={"investigation_days": 30, "learning_days": 730})
    assert second.status_code == 200 and _stored(scripted.dsn) == [(30, 730)]
    assert _stored(scripted.dsn, B) == BASELINE


@pytest.mark.parametrize("field", ["investigation_days", "learning_days"])
@pytest.mark.parametrize(("days", "ok"), [(29, False), (30, True), (730, True), (731, False)])
async def test_each_value_is_accepted_at_30_and_730_and_refused_at_29_and_731(scripted, field, days, ok):
    """Either value at the boundary: 30 and 730 stored (200); 29 and 731 a 422 with nothing stored. (A-O7)"""
    body = {"investigation_days": 100, "learning_days": 100, field: days}
    answered = await scripted.client.put(PATH, headers=scripted.ann(), json=body)
    assert answered.status_code == (200 if ok else 422), answered.text
    assert _stored(scripted.dsn) == ([(body["investigation_days"], body["learning_days"])] if ok else BASELINE)


@pytest.mark.parametrize("body", [
    {"investigation_days": 90}, {"learning_days": 90}, {}, {"investigation_days": "90", "learning_days": 90},
    {"investigation_days": 90.5, "learning_days": 90}, {"investigation_days": True, "learning_days": 90},
    {"investigation_days": None, "learning_days": 90}, {"investigation_days": 90, "learning_days": 90, "extra": 1}])
async def test_a_write_missing_a_value_or_with_a_value_that_is_no_whole_number_is_refused_and_stores_nothing(scripted, body):
    """No partial write: a missing, null, string, fractional or boolean value, or an extra field, is a 422 and the created
    pair stays. (A-O7)"""
    answered = await scripted.client.put(PATH, headers=scripted.ann(), json=body)
    assert answered.status_code == 422, answered.text
    assert _stored(scripted.dsn) == BASELINE


async def test_only_a_member_with_config_write_may_write_membership_first(scripted, caplog):
    """A program of A (no `config.write`) is 403, another tenant's admin 404, an anonymous caller 401, each changing nothing;
    Ann is served (control). (A-O7, `config.write`)"""
    body = {"investigation_days": 90, "learning_days": 90}
    assert (await scripted.client.put(PATH, headers=scripted.program(), json=body)).status_code == 403
    assert (await scripted.client.put(PATH, headers=scripted.bob(), json=body)).status_code == 404
    assert (await scripted.client.put(PATH, headers={"Origin": ORIGIN}, json=body)).status_code == 401
    assert _stored(scripted.dsn) == BASELINE and _stored(scripted.dsn, B) == BASELINE
    assert (await scripted.client.put(PATH, headers=scripted.ann(), json=body)).status_code == 200


async def test_a_write_is_audited_once_by_the_member_and_a_refused_one_is_not(scripted, caplog):
    """An accepted write announces one `evidence_retention.write` naming Ann, the tenant and both values; a refused one
    (29 days) announces nothing. (A-O7, audited)"""
    caplog.set_level(logging.DEBUG)
    caplog.clear()
    refused = await scripted.client.put(PATH, headers=scripted.ann(), json={"investigation_days": 29, "learning_days": 90})
    assert refused.status_code == 422 and audit_events(caplog, ACTION) == []
    done = await scripted.client.put(PATH, headers=scripted.ann(), json={"investigation_days": 91, "learning_days": 366})
    assert done.status_code == 200
    [event] = audit_events(caplog, ACTION)
    assert (event.actor, event.tenant_id) == (scripted.user_id(ANN), A)
    assert "91" in told(event) and "366" in told(event)
