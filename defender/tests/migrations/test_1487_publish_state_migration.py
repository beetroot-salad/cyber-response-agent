"""#1487 data model and O9: the revision after `0022_learning_causes` moves every `pending` learning-job publish state to
`refused`, reports how many per tenant in its log output, drops `pending` from the CHECK, adds the armed-while-held mark
to every clock row, and refuses nothing."""
from __future__ import annotations

import logging
import re

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

PRIOR = "0022_learning_causes"
A, B, C, D = (fixture_uuid(f"1487-mig-{n}") for n in "abcd")
COLS = ("id, tenant_id, alert_id, investigation_id, request_key, attempt, trigger, status, reason, message, "
        "created_at, finished_at, sibling_cost_usd, findings_count, publish_state")


def _revision_on_prior() -> str:
    from defender.migrations import _scripts

    found = [r.revision for r in _scripts().walk_revisions() if r.down_revision == PRIOR]
    assert len(found) == 1, f"one revision should sit directly on {PRIOR}, found {found}"
    return found[0]


def test_the_history_has_one_head_and_one_revision_on_the_learning_causes_revision():
    """One line of history; exactly one revision directly on `0022_learning_causes`, and the head is not behind it
    (later revisions may follow it). (data model: one migration)"""
    from defender.migrations import head, heads

    assert heads() == (head(),)
    child = _revision_on_prior()
    assert child == head() or child in revisions.ancestors(head())


def _plant(dsn: str, tenant: str, n: int, state: str, status: str = "completed") -> str:
    """One learning job of `tenant` at the prior revision with publish state `state` (and its alert and investigation)."""
    alert, inv, job = (fixture_uuid(f"1487-mig-{what}-{tenant}-{n}") for what in ("alert", "inv", "job"))
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, "
                 "title, description, raw) VALUES (%s, %s, 'elastic', %s, now(), now(), now(), 't', 'd', '\\x7b7d')",
            (alert, tenant, f"T-{tenant[:4]}-{n}"))
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 "started_at, finished_at, cost_usd, cost_is_lower_limit, update_ticket) VALUES (%s, %s, %s, 'k', 1, "
                 "'completed', now(), now(), now(), 1.5, false, false)", (inv, tenant, alert))
    execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, "
                 "trigger, status, reason, message, created_at, finished_at, sibling_cost_usd, findings_count, "
                 "publish_state) VALUES (%s, %s, %s, %s, 'k', 1, 'auto', %s, NULL, NULL, now(), now(), 0.25, %s, %s)",
            (job, tenant, alert, inv, status, n, state))
    return job


def _rows(dsn: str) -> dict[str, tuple]:
    return {r[0]: r for r in execute(dsn, f"SELECT {COLS} FROM jobs.learning_jobs ORDER BY id")}  # noqa: S608


@pytest.fixture
def at_prior(empty_database):
    dsn = empty_database
    _upgrade_to(dsn, PRIOR)
    states = {A: "active", B: "active", C: "offboarded", D: "active"}
    for tenant, state in states.items():
        execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), %s)", (tenant, state))
    return dsn


@pytest.mark.postgres
def test_every_pending_row_becomes_refused_the_others_and_every_other_column_stay(at_prior, caplog, capsys):
    """Pending rows of several tenants (an offboarded one's included) read `refused`; `done`, `none` and `refused` rows
    and every other column of every row are untouched; the upgrade stops for nothing. (Data model, O9)"""
    dsn = at_prior
    pending = [_plant(dsn, A, n, "pending") for n in range(3)] + [_plant(dsn, B, n, "pending") for n in range(7)]
    pending.append(_plant(dsn, C, 0, "pending"))
    pending.append(_plant(dsn, A, 10, "pending", status="failed"))
    kept = [_plant(dsn, A, 20, "done"), _plant(dsn, A, 21, "none", status="skipped"), _plant(dsn, D, 0, "refused")]
    before = _rows(dsn)

    caplog.set_level(logging.DEBUG)
    _upgrade_to(dsn, _revision_on_prior())

    after = _rows(dsn)
    publish = COLS.split(", ").index("publish_state")
    assert {j: r[publish] for j, r in after.items() if j in pending} == dict.fromkeys(pending, "refused")
    for job in kept:
        assert after[job] == before[job]
    for job in pending:
        assert after[job][:publish] + after[job][publish + 1:] == before[job][:publish] + before[job][publish + 1:]


@pytest.mark.postgres
def test_the_count_per_tenant_is_in_the_migrations_log_output(at_prior, caplog, capsys):
    """One line per tenant holding pending rows, naming the tenant and its own count (3 and 8), and none naming the
    other's count; a tenant with none needs no line. (O9: "per tenant, to the migration's log output")"""
    dsn = at_prior
    for n in range(3):
        _plant(dsn, A, n, "pending")
    for n in range(8):
        _plant(dsn, B, n, "pending")
    _plant(dsn, D, 0, "done")

    caplog.set_level(logging.INFO)
    _upgrade_to(dsn, _revision_on_prior())

    out = capsys.readouterr()
    lines = [*(r.getMessage() for r in caplog.records if not r.name.startswith("sqlalchemy")), *out.out.splitlines(), *out.err.splitlines()]
    mine = {t: [ln.replace(t, "<tenant>") for ln in lines if t in ln] for t in (A, B)}

    def counts(found: list[str]) -> set[int]:
        return {int(n) for ln in found for n in re.findall(r"(?<![\w.:-])\d+(?![\w.:-])", ln)}

    assert 3 in counts(mine[A]) and 8 not in counts(mine[A]), mine  # noqa: PT018
    assert 8 in counts(mine[B]) and 3 not in counts(mine[B]), mine  # noqa: PT018


@pytest.mark.postgres
def test_a_database_with_no_pending_row_upgrades_and_the_check_no_longer_takes_pending(at_prior):
    """Nothing to move is not a stop; afterwards `done`, `none` and `refused` are storable and `pending` is not.
    (Data model: `pending` dropped from the CHECK)"""
    import psycopg

    dsn = at_prior
    _upgrade_to(dsn, _revision_on_prior())
    jobs = [_plant_head(dsn, A, n, state) for n, state in enumerate(("none", "done", "refused"))]
    assert [r[0] for r in execute(dsn, "SELECT publish_state FROM jobs.learning_jobs ORDER BY findings_count")] == [
        "none", "done", "refused"], jobs
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(dsn, "UPDATE jobs.learning_jobs SET publish_state = 'pending' WHERE id = %s", (jobs[0],))


def _plant_head(dsn: str, tenant: str, n: int, state: str) -> str:
    """`_plant` on the upgraded schema (the same columns suffice)."""
    return _plant(dsn, tenant, n, state)


@pytest.mark.postgres
def test_a_clock_row_that_exists_at_upgrade_gets_the_mark_unset(at_prior):
    """A deployment's tenants already have check clocks (held, idle, due) when it upgrades: the upgrade adds the mark to
    each of them as not set, and the clock's own columns stay. (Data model: the migration adds the mark)"""
    dsn = at_prior
    execute(dsn, "INSERT INTO jobs.learning_checks (tenant_id, checked_at, idle) VALUES (%s, now(), true)", (A,))
    execute(dsn, "INSERT INTO jobs.learning_checks (tenant_id, checked_at, idle) VALUES (%s, now(), false)", (B,))
    execute(dsn, "INSERT INTO jobs.learning_checks (tenant_id, checked_at, idle, holder, checking_until) "
                 "VALUES (%s, now(), false, 'worker-1', now() + interval '1 hour')", (D,))
    before = {r[0]: r[1:] for r in execute(dsn, "SELECT tenant_id, idle, holder FROM jobs.learning_checks")}

    _upgrade_to(dsn, _revision_on_prior())

    after = execute(dsn, "SELECT tenant_id, armed_while_held, idle, holder FROM jobs.learning_checks")
    assert {r[0]: r[1] for r in after} == {A: False, B: False, D: False}
    assert {r[0]: r[2:] for r in after} == before
