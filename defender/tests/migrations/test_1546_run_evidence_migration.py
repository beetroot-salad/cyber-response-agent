"""#1546: the revision `*_run_evidence` (found by its suffix) makes `jobs.claims`, `jobs.staged_facts` and `jobs.uploads`,
gives investigations and learning jobs their `evidence_state` (and investigations `scrub`) with a check keyed on terminal
status, backfills `none`/`not_run` on already-terminal rows, and lets host requests be of kind `drain`. Rows are planted
at the revision before it (the head store cannot write them)."""
from __future__ import annotations

import datetime as dt
import uuid

import pytest

from defender.jobs.models import LEARNING_TERMINAL, TERMINAL
from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.migrations.test_1581_alert_outcome_migration import T0, _alert, _investigation, _tenants
from defender.tests.support.jobs._jobs1342 import T1
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute

SUFFIX = "_run_evidence"
CLAIMS = {"token", "tenant_id", "kind", "investigation_id", "learning_job_id", "host_request_id", "hold_tenant_id",
          "launch", "inputs", "created_at"}
FACTS = {"token", "name", "body", "staged_at"}
UPLOADS = {"token", "object", "size", "sha256", "wrapped_key", "status", "scrub", "accepted_at", "created_at"}


def _revision() -> str:
    return revisions.by_suffix(SUFFIX)


def _prior() -> str:
    return revisions.down_of(_revision())


def _columns(dsn: str, table: str) -> set[str]:
    return {c for (c,) in execute(dsn, "SELECT column_name FROM information_schema.columns WHERE table_schema = 'jobs' "
                                       "AND table_name = %s", (table,))}


def test_the_revision_is_on_one_line_of_history_after_the_host_requests_revision():
    """One head; the revision is the head or an ancestor of it and follows `_host_requests`. (data model)"""
    from defender.migrations import head, heads

    assert heads() == (head(),)
    assert _revision() == head() or _revision() in revisions.ancestors(head())
    assert revisions.by_suffix("_host_requests") in revisions.ancestors(_revision())


@pytest.mark.postgres
def test_the_revision_makes_the_three_tables_with_their_keys_and_only_the_claim_to_reference_foreign_keys(empty_database):
    """Columns; PK `(token, name)` and `(token, object)`; claim -> reference FKs, fact/upload -> claim FKs, no owner -> claim
    column or key, no ON DELETE action anywhere; `inputs` NOT NULL; the kind-to-reference check. (A-O3, PR7, lifecycle)"""
    dsn = empty_database
    _upgrade_to(dsn, _revision())
    assert (_columns(dsn, "claims"), _columns(dsn, "staged_facts"), _columns(dsn, "uploads")) == (CLAIMS, FACTS, UPLOADS)
    for table in ("investigations", "learning_jobs", "host_requests"):
        assert "claim_token" not in _columns(dsn, table), "owner -> claim is redundant (a row is claimed at most once)"
    fks = execute(dsn, "SELECT c.conrelid::regclass::text, c.confrelid::regclass::text, c.confdeltype FROM pg_constraint c "
                       "WHERE c.contype = 'f' AND (c.conrelid::regclass::text IN ('jobs.claims', 'jobs.staged_facts', "
                       "'jobs.uploads') OR c.confrelid::regclass::text = 'jobs.claims')")
    assert {(a, b) for a, b, _ in fks} == {
        ("jobs.claims", "jobs.investigations"), ("jobs.claims", "jobs.learning_jobs"),
        ("jobs.claims", "jobs.host_requests"), ("jobs.claims", "jobs.learning_checks"), ("jobs.claims", "tenancy.tenants"),
        ("jobs.staged_facts", "jobs.claims"), ("jobs.uploads", "jobs.claims")}
    assert {d for _, _, d in fks} == {"a"}, "no ON DELETE action exists (the delete removes its rows itself)"
    pks = dict(execute(dsn, "SELECT conrelid::regclass::text, pg_get_constraintdef(oid) FROM pg_constraint WHERE contype = 'p' "
                            "AND conrelid::regclass::text IN ('jobs.staged_facts', 'jobs.uploads')"))
    assert "(token, name)" in pks["jobs.staged_facts"]
    assert "(token, object)" in pks["jobs.uploads"]
    assert execute(dsn, "SELECT is_nullable FROM information_schema.columns WHERE table_schema = 'jobs' AND table_name = "
                        "'claims' AND column_name = 'inputs'") == [("NO",)]


@pytest.mark.postgres
def test_the_checks_tie_a_claim_kind_to_its_reference_and_bound_the_vocabularies(empty_database):
    """An investigation claim naming a learning job or nothing is refused, each kind's right reference is accepted; an
    upload status or scrub outside the vocabulary is refused; a host request may be of kind `drain`, with at most one queued or running
    per tenant. (A-O3, A-O10, D7)"""
    dsn = empty_database
    _upgrade_to(dsn, _revision())
    _tenants(dsn)
    alert = _alert(dsn, "a1")
    inv = str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 "cost_usd, cost_is_lower_limit, update_ticket) VALUES (%s, %s, %s, 'k', 1, 'queued', %s, 0, false, false)",
            (inv, T1, alert, T0))
    insert = "INSERT INTO jobs.claims (token, tenant_id, kind, {col}, inputs) VALUES (%s, %s, %s, %s, '[]'::jsonb)"
    with pytest.raises(Exception, match="check"):
        execute(dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, inputs) VALUES ('t0', %s, 'investigation', '[]')", (T1,))
    with pytest.raises(Exception, match="check"):
        execute(dsn, insert.format(col="hold_tenant_id"), ("t1", T1, "investigation", T1))
    execute(dsn, insert.format(col="investigation_id"), ("t2", T1, "investigation", inv))
    execute(dsn, "INSERT INTO jobs.learning_checks (tenant_id, checked_at, idle, armed_while_held) VALUES (%s, now(), false, false)",
            (T1,))
    execute(dsn, insert.format(col="hold_tenant_id"), ("t3", T1, "post-step", T1))
    up = "INSERT INTO jobs.uploads (token, object, size, sha256, wrapped_key, status, scrub, created_at) " \
         "VALUES ('t2', %s, 1, %s, 'k', %s, %s, now())"
    execute(dsn, up, ("bundle", "00" * 32, "pending", None))
    for obj, status, scrub in (("a", "gone", None), ("b", "uploaded", "dirty")):
        with pytest.raises(Exception, match="check"):
            execute(dsn, up, (obj, "00" * 32, status, scrub))
    execute(dsn, "INSERT INTO jobs.host_requests (id, tenant_id, kind, dedupe_key, requester, created_at, stage, "
                 "lease_expires_at) VALUES (%s, %s, 'drain', %s, 'op', now(), 'running', now() + interval '30 seconds')",
            (str(uuid.uuid4()), T1, T1))
    with pytest.raises(Exception, match="unique|duplicate"):
        execute(dsn, "INSERT INTO jobs.host_requests (id, tenant_id, kind, dedupe_key, requester, created_at, stage) VALUES "
                     "(%s, %s, 'drain', %s, 'op', now(), 'queued')", (str(uuid.uuid4()), T1, T1))


@pytest.mark.postgres
@pytest.mark.parametrize("stage", TERMINAL)
def test_an_already_terminal_investigation_is_backfilled_none_and_not_run_and_a_live_one_is_left_null(empty_database, stage):
    """Planted at the prior revision: every terminal stage reads `none`/`not_run` afterwards; queued and running rows
    keep NULLs. The check then refuses a terminal row with no state. (A-O4, migration backfill)"""
    dsn = empty_database
    _upgrade_to(dsn, _prior())
    _tenants(dsn)
    alert = _alert(dsn, "a1")
    done = _investigation(dsn, alert, "k-done", stage, "benign" if stage == "completed" else None, T0 + dt.timedelta(hours=1))
    alert2 = _alert(dsn, "a2")
    live = [_investigation(dsn, alert2, "k-run", "running", None, T0 + dt.timedelta(hours=2))]
    alert3 = _alert(dsn, "a3")
    live.append(_investigation(dsn, alert3, "k-q", "queued", None, T0 + dt.timedelta(hours=3)))
    _upgrade_to(dsn, _revision())
    assert execute(dsn, "SELECT evidence_state, scrub FROM jobs.investigations WHERE id = %s", (done,)) == [("none", "not_run")]
    for row in live:
        assert execute(dsn, "SELECT evidence_state, scrub FROM jobs.investigations WHERE id = %s", (row,)) == [(None, None)]
    with pytest.raises(Exception, match="check"):
        execute(dsn, "UPDATE jobs.investigations SET stage = 'failed', failure_reason = 'x', finished_at = now() "
                     "WHERE id = %s", (live[0],))


@pytest.mark.postgres
@pytest.mark.parametrize("status", LEARNING_TERMINAL)
def test_an_already_terminal_learning_job_is_backfilled_none_and_a_queued_running_or_handed_back_one_is_left_null(
        empty_database, status):
    """Terminal statuses read `none`; queued, running and a handed-back (`running` with `finished_at`) row keep NULL. (A-O4)"""
    dsn = empty_database
    _upgrade_to(dsn, _prior())
    _tenants(dsn)
    alert = _alert(dsn, "a1")
    source = _investigation(dsn, alert, "k", "completed", "benign", T0)

    def job(state: str, key: str, *, finished: bool = False) -> str:
        job_id = str(uuid.uuid4())
        lease = "now() + interval '30 seconds'" if state == "running" else "NULL"
        execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, "  # noqa: S608
                     "trigger, status, created_at, sibling_cost_usd, publish_state, finished_at, lease_expires_at) VALUES "
                     f"(%s, %s, %s, %s, %s, 1, 'auto', %s, now(), 0, 'none', {'now()' if finished or state not in ('queued', 'running') else 'NULL'}, {lease})",
                (job_id, T1, alert, source, key, state))
        return job_id

    ended = job(status, "k-end")
    others = [job("queued", "k-q"), job("running", "k-r"), job("running", "k-h", finished=True)]
    _upgrade_to(dsn, _revision())
    assert execute(dsn, "SELECT evidence_state, sibling_cost_is_lower_limit FROM jobs.learning_jobs WHERE id = %s",
                   (ended,)) == [("none", False)]
    for row in others:
        assert execute(dsn, "SELECT evidence_state, sibling_cost_is_lower_limit FROM jobs.learning_jobs WHERE id = %s",
                       (row,)) == [(None, False)]


@pytest.mark.postgres
def test_a_learning_job_gains_the_lower_limit_mark_of_its_sibling_cost_and_an_investigation_keeps_its_own(empty_database):
    """`learning_jobs.sibling_cost_is_lower_limit` is a boolean, NOT NULL, false by default (existing rows read exact);
    `investigations.cost_is_lower_limit` stays, still needing a cost. (D15)"""
    dsn = empty_database
    _upgrade_to(dsn, _revision())
    [(kind, nullable, default)] = execute(
        dsn, "SELECT data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = 'jobs' "
             "AND table_name = 'learning_jobs' AND column_name = 'sibling_cost_is_lower_limit'")
    assert (kind, nullable) == ("boolean", "NO")
    assert "false" in (default or "").lower()
    assert "cost_is_lower_limit" in _columns(dsn, "investigations")
