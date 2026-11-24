"""#1618 D10, owner ruling: a readiness result stored before #1618 that names the retired step `knowledge_copy` reads back
through the API's store port as `publish`, the step that replaced it. The API's step type itself does not list
`knowledge_copy` (`api/test_api_model_fields.py::test_d10_...`). Postgres-gated: the row is the store's own."""
from __future__ import annotations

import datetime as dt
import json

import pytest

from defender.tests.support.jobs._jobs1342 import T1, job_store, register_tenant
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


@pytest.fixture
def world(migrated_database: str) -> str:
    register_tenant(migrated_database, T1)
    return migrated_database


def _stored_refusal(dsn: str, request_id: str, step: str) -> None:
    """The row as a completed check stored it: its result names `step`."""
    result = {"outcome": "refused", "step": step, "sentence": "the knowledge could not be copied", "knowledge": None}
    now = dt.datetime.now(dt.UTC)
    execute(dsn, "UPDATE jobs.host_requests SET stage = 'completed', started_at = %s, finished_at = %s, result = %s "
            "WHERE id = %s", (now, now, json.dumps(result), request_id))


@pytest.mark.parametrize(("stored", "read"), [("knowledge_copy", "publish"), ("publish", "publish"),
                                              ("alert_mapping", "alert_mapping")])
async def test_1618_d10_a_stored_readiness_refusal_naming_the_retired_step_reads_back_as_publish(world, stored, read):
    """`knowledge_copy` reads as `publish`; the steps that survive read back as they were stored (controls)."""
    from defender.api.job_store import JobStorePorts

    async with job_store(world) as store:
        record, _ = await store.create_readiness(T1, actor="u-1")
        _stored_refusal(world, record.request_id, stored)
        saved = await JobStorePorts(store).get_readiness(T1, record.request_id)
    assert saved is not None
    assert saved.status == "completed", saved
    assert saved.result is not None, saved
    assert saved.result.outcome == "refused", saved.result
    assert saved.result.step == read, saved.result
