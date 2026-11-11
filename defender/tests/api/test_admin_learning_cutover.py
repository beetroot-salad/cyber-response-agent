"""#1278 Migration: the administrator queues a tenant's learning-state cutover like a rotation (the endpoint over the
tenant record's `request_learning_cutover`; the job's steps are driven by lifecycle_1214/test_learning_cutover_job.py)."""
from __future__ import annotations

import uuid
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import OPS, AuditLog, World  # noqa: E402


def test_the_cutover_is_queued_for_an_active_tenant_once_and_audited(caplog: Any) -> None:
    """202 with the host's `import` step pending, audited; a second request is a 409 and an unknown tenant a 404."""
    audit = AuditLog(caplog)
    world = World(administrators=[OPS])
    ops = world.sign_in_admin()
    tenant = str(uuid.uuid4())
    world.register(tenant)
    mark = audit.mark()

    asked = ops.post(f"/admin/tenants/{tenant}/cut-over-learning-state")

    assert asked.status_code == 202, asked.text
    item = asked.json()
    assert (item["state"], item["pending_action"], item["step"], item["step_actor"], item["failure"]) == (
        "active", "learning_cutover", "import", "host", None)
    assert [(e.action, e.target) for e in audit.since(mark) if e.action.startswith("tenant.")] == [
        ("tenant.learning_cutover", tenant)]
    assert ops.post(f"/admin/tenants/{tenant}/cut-over-learning-state").status_code == 409
    assert ops.post(f"/admin/tenants/{uuid.uuid4()}/cut-over-learning-state").status_code == 404
