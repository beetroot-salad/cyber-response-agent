"""#1485 O5: the #1278 learning cutover is retired. `python -m defender.lifecycle request-learning-cutover`, with the argv
an operator types today, is an unknown command and queues nothing; no model, repository, step table or audit action carries it."""
from __future__ import annotations

import inspect
import typing

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.lifecycle_1214.test_lifecycle_command import TENANT, _lifecycle

RETIRED = "learning_cutover"
SURVIVING_ACTIONS = {"create", "rotate", "offboard", "delete_repo"}


def test_o5_the_lifecycle_parser_lists_serve_and_no_longer_the_cutover_command():
    """`--help` lists `serve` (control) and not `request-learning-cutover`, nor its flags. (O5)"""
    done = _lifecycle("--help")
    assert done.returncode == 0, (done.returncode, done.stdout, done.stderr)
    assert "serve" in done.stdout, done.stdout
    assert "request-learning-cutover" not in done.stdout, done.stdout


@pytest.mark.postgres
@pytest.mark.parametrize("argv", [["--tenant", TENANT], ["--all"]])
def test_o5_request_learning_cutover_is_an_unknown_command_and_queues_nothing(migrated_database, argv):  # noqa: F811
    """With today's full argv and a database at head, the old command is refused as unknown (naming `serve` as a choice) and the tenant has nothing pending. (O5)"""
    register_tenant(migrated_database, TENANT)
    before = execute(migrated_database, "SELECT state, pending_action, step, step_actor, failure FROM tenancy.tenants WHERE id = %s", (TENANT,))
    assert before == [("active", None, None, None, None)], before
    done = _lifecycle("request-learning-cutover", *argv, dsn=migrated_database)
    assert "queued" not in done.stdout, done.stdout
    assert execute(migrated_database, "SELECT state, pending_action, step, step_actor, failure FROM tenancy.tenants WHERE id = %s", (TENANT,)) == before
    assert done.returncode == 2, (done.returncode, done.stdout, done.stderr)
    assert "invalid choice: 'request-learning-cutover'" in done.stderr, done.stderr
    assert "serve" in done.stderr, done.stderr  # the choices it lists: the parser still has its other command


def test_o5_pending_action_models_no_longer_admit_the_cutover():
    """`PendingAction`, the per-state allowed table and the declared tenants CHECKs drop `learning_cutover` and keep the other actions. (O5)"""
    from defender.tenancy.models import ALLOWED_ACTIONS, PendingAction, TenantRecord

    assert set(typing.get_args(PendingAction)) == SURVIVING_ACTIONS
    assert ALLOWED_ACTIONS["active"] == frozenset({None, "rotate"})
    assert RETIRED not in {a for actions in ALLOWED_ACTIONS.values() for a in actions}
    checks = {c.name: str(c.sqltext) for c in TenantRecord.__table__.constraints if hasattr(c, "sqltext")}
    assert {"ck_tenants_pending_action", "ck_tenants_state_allows_pending_action"} <= {str(c.name) for c in TenantRecord.__table__.constraints}
    assert all(RETIRED not in text for text in checks.values()), checks
    assert any("'rotate'" in text for text in checks.values())


def test_o5_the_apis_tenant_item_refuses_the_cutover_and_takes_rotate():
    """`TenantItem.pending_action` refuses `learning_cutover` and still takes `rotate`. (O5)"""
    from pydantic import ValidationError

    from defender.api.models import TenantItem

    row = {"tenant_id": TENANT, "state": "active", "step": None, "step_actor": None, "failure": None,
           "created_at": "2026-11-01T08:00:00Z"}
    assert TenantItem.model_validate({**row, "pending_action": "rotate"}).pending_action == "rotate"
    with pytest.raises(ValidationError):
        TenantItem.model_validate({**row, "pending_action": RETIRED})


@pytest.mark.parametrize("owner", ["tenancy.repository:TenantRepository", "tenancy.memory:InMemoryTenantRepository",
                                   "tenancy.postgres:PostgresTenantRepository"])
def test_o5_no_tenant_repository_can_request_the_cutover(owner):
    """The protocol and both implementations have no `request_learning_cutover` and still have `request_rotate`. (O5)"""
    import importlib

    module, name = owner.split(":")
    cls = getattr(importlib.import_module(f"defender.{module}"), name)
    assert hasattr(cls, "request_rotate")
    assert not hasattr(cls, "request_learning_cutover")


def test_o5_the_audit_actions_no_longer_include_the_cutover():
    """`tenant.learning_cutover` is not an audit action; `tenant.rotate` still is. (O5)"""
    from defender.identity.audit import AuditAction

    actions = set(typing.get_args(AuditAction))
    assert "tenant.rotate" in actions
    assert "tenant.learning_cutover" not in actions


def test_o5_the_job_step_table_and_the_host_actor_have_no_cutover_steps():
    """`NEXT` has the four surviving actions; the host actor has no import/cutover handler, `open_delivery` or `learning_delivery`. (O5)"""
    from defender.lifecycle._host import HostActor
    from defender.lifecycle._job import NEXT

    assert set(NEXT) == SURVIVING_ACTIONS
    assert hasattr(HostActor, "_teardown")
    for handler in ("_import_learning", "_cut_over_learning", "_read_learning", "_cut_over"):
        assert not hasattr(HostActor, handler), handler
    from defender.lifecycle import _process

    assert hasattr(_process, "forge_admin")
    assert not hasattr(_process, "learning_delivery")
    assert "open_delivery" not in inspect.signature(HostActor.__init__).parameters
    assert "clock" in inspect.signature(HostActor.__init__).parameters


@pytest.mark.parametrize("owner", ["defender.tenancy._tenant:Tenant", "defender.tenancy._tenant:_TenantLayout",
                                   "defender.tenancy._tenant:_TenantPaths"])
def test_o5_the_tenant_has_no_learning_folder_accessor(owner):
    """`Tenant`, `_TenantLayout` and its `_TenantPaths` subclass have no `learning` attribute; `scratch` is the control. (O5)"""
    import importlib

    module, name = owner.split(":")
    cls = getattr(importlib.import_module(module), name)
    assert hasattr(cls, "scratch")
    assert not hasattr(cls, "learning")
