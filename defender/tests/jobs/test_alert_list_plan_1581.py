"""#1581 O2, Performance: under an outcome filter the list reads its page in order from `alerts_outcome_newest_first`, with no
Sort, where `none` is rare in one tenant and common in another (C8b).

Entry: `defender.jobs.JobStore.list_alerts` on a per-test migrated database with two tenants of 10,000 alerts planted by
SQL (the planner reads the table's statistics, which a store write per row would take too long to build), then `ANALYZE`.
The plan is PostgreSQL's `EXPLAIN` of the very statement the store runs, with its parameters (`support/jobs/_outcome1581.py`)."""
from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from defender._vocab import DISPOSITION_VALUES
from defender.tests.support.jobs._jobs1342 import NOW, T1, T2, register_tenant
from defender.tests.support.jobs._outcome1581 import alert_reads, no_outcome, planned
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

PER_TENANT = 10_000
NEWEST_FIRST = "alerts_newest_first"
OUTCOME_NEWEST_FIRST = "alerts_outcome_newest_first"
PAGE: dict[str, Any] = {"fired_after": None, "fired_before": None, "limit": 51}


def _plant(dsn: str, tenant: str, *, none_every: int, malicious_every: int) -> None:
    """`PER_TENANT` alerts a minute apart: every `none_every`th with no outcome, every `malicious_every`th (from the first)
    malicious, the rest benign, false-positive, inconclusive or unresolved in turn. By arithmetic on the alert's number, so the
    statistics the planner reads are the same every run. The outcome copy is planted whole (its source is a made-up id: only
    the statistics matter here)."""
    execute(dsn, f"""
        INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, title, description,
                                 raw, outcome, outcome_investigation_id, outcome_created_at)
        SELECT gen_random_uuid(), %s, 'elastic', 'T-' || g, ts, ts, ts, 'title', 'description', convert_to(repeat('x', 100), 'UTF8'),
               o, CASE WHEN o IS NULL THEN NULL ELSE gen_random_uuid() END, CASE WHEN o IS NULL THEN NULL ELSE ts END
        FROM generate_series(1, {PER_TENANT}) g,
             LATERAL (SELECT now() - g * interval '1 minute' AS ts) t,
             LATERAL (SELECT CASE WHEN g %% {none_every} = 0 THEN NULL WHEN g %% {malicious_every} = 1 THEN 'malicious'
                                  ELSE (ARRAY['benign', 'false-positive', 'inconclusive', 'unresolved'])[1 + g %% 4] END AS o) x""",  # noqa: S608 — constants
            (tenant,))


async def test_o2_the_outcome_filter_reads_each_page_from_the_outcome_index_with_no_sort_where_none_is_rare_in_one_tenant(
    migrated_database: str,
) -> None:
    """Over two tenants, `none` rare in the first (0.2%) and common in the second (10%), the statement for each of the six
    `outcome` values, first page and a later one, reads `jobs.alerts` by `alerts_outcome_newest_first` only, with no Sort between that read and the top Limit, however the
    `latest_status` lookup is written;
    control: without the leading order the planner walks `alerts_newest_first` for the rare `none`. (O2 Performance, C8b)"""
    from defender.jobs import JobStore

    dsn = migrated_database
    for tenant in (T1, T2):
        register_tenant(dsn, tenant)
    _plant(dsn, T1, none_every=500, malicious_every=500)
    _plant(dsn, T2, none_every=10, malicious_every=5)
    execute(dsn, "ANALYZE jobs.alerts")

    [(control,)] = execute(dsn, "EXPLAIN (FORMAT JSON) SELECT id FROM jobs.alerts WHERE tenant_id = %s AND outcome IS NULL "
                                "ORDER BY fired_at DESC, id DESC LIMIT 51", (T1,))
    walked = [n.get("Index Name") for n, _ in alert_reads(control[0]["Plan"])]
    assert walked == [NEWEST_FIRST], f"control: with no leading order the planner walks the newest-first index for the rare none: {walked}"

    store = JobStore(dsn, clock=lambda: dt.datetime.fromtimestamp(NOW.timestamp(), dt.UTC))
    try:
        for tenant in (T1, T2):
            first_page = await store.list_alerts(tenant, outcome=None, after=None, **PAGE)
            later = (first_page[-1].fired_at, first_page[-1].alert_id)
            for outcome in (no_outcome(), *DISPOSITION_VALUES):
                for after in (None, later):
                    with planned(store) as plans:
                        await store.list_alerts(tenant, outcome=outcome, after=after, **PAGE)
                    assert len(plans) == 1, f"premise: one statement: {plans}"
                    reads = alert_reads(plans[0])
                    where = f"tenant {tenant}, outcome {outcome!r}, after {after}: {reads}"
                    # the page is read from jobs.alerts once, by the outcome index, and the top Limit takes it with
                    # nothing between that sorts: however the statement looks up each row's latest_status
                    assert [n.get("Index Name") for n, _ in reads] == [OUTCOME_NEWEST_FIRST], where
                    [(_, above)] = reads
                    assert above[:1] == ("Limit",), where
                    assert not [t for t in above if "Sort" in t], where
    finally:
        await store.close()


#: The columns the `latest_status` lookup walks (r3.3): the tenant and alert it is for, then newest first by `(created_at, id)`.
LOOKUP_COLUMNS = "(tenant_id, alert_id, created_at DESC, id DESC)"


def _investigation_reads(plan: dict[str, Any], *, above: tuple[str, ...] = ()) -> list[tuple[dict[str, Any], tuple[str, ...]]]:
    """Every node reading `jobs.investigations`, at any depth, each with the node types between it and the nearest enclosing
    sub-plan (or the root when it is not under one): what sits above it in the lookup that is its own."""
    found = [(plan, above)] if plan.get("Relation Name") == "investigations" and plan.get("Schema", "jobs") == "jobs" else []
    for child in plan.get("Plans", []):
        path = () if child.get("Parent Relationship") in ("SubPlan", "InitPlan") else (*above, plan["Node Type"])
        found += _investigation_reads(child, above=path)
    return found


def _plant_investigations(dsn: str, tenant: str, *, every: int) -> None:
    """Two investigations (an earlier failed one, a later completed one) for every `every`th alert of the tenant, by SQL.
    #1546 (design "Evidence state": "A terminal row with no outcome reads `none`, `scrub = not_run`"): both ended rows carry
    them, as `_identity1306.World.plant_investigation` plants one."""
    execute(dsn, f"""
        INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, disposition, cost_usd,
                                         cost_is_lower_limit, update_ticket, evidence_state, scrub)
        SELECT gen_random_uuid(), a.tenant_id, a.id, 'k' || n, n, CASE n WHEN 1 THEN 'failed' ELSE 'completed' END,
               a.fired_at + n * interval '1 second', CASE n WHEN 1 THEN NULL ELSE 'benign' END, 0, false, false,
               'none', 'not_run'
        FROM (SELECT *, row_number() OVER (ORDER BY fired_at) AS r FROM jobs.alerts WHERE tenant_id = %s) a,
             generate_series(1, 2) n
        WHERE a.r %% {every} = 0""",  # noqa: S608 — constant
            (tenant,))


async def test_r33_every_latest_status_lookup_reads_the_alert_and_created_at_index_with_no_sort_though_most_alerts_have_no_investigation(
    migrated_database: str,
) -> None:
    """Two tenants of 10,000 alerts, one in twenty with investigations (the rest none), `ANALYZE`d: the store's list
    statement, with no filter and under an outcome filter, reads `jobs.investigations` only through an index whose columns
    are `(tenant_id, alert_id, created_at DESC, id DESC)` (found by its definition in `pg_indexes`, not by its name), and no
    Sort sits between that read and its own sub-plan's top. (r3.3 `latest_status` index)"""
    from defender.jobs import JobStore

    dsn = migrated_database
    for tenant in (T1, T2):
        register_tenant(dsn, tenant)
        _plant(dsn, tenant, none_every=10, malicious_every=5)
        _plant_investigations(dsn, tenant, every=20)
    execute(dsn, "ANALYZE jobs.alerts")
    execute(dsn, "ANALYZE jobs.investigations")
    [(planted,)] = execute(dsn, "SELECT count(*) FROM jobs.investigations")
    assert planted == 2 * (PER_TENANT // 20) * 2, "premise: the investigations were planted"

    lookup = [name for (name, definition) in execute(
        dsn, "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'jobs' AND tablename = 'investigations'")
        if LOOKUP_COLUMNS in definition]
    assert len(lookup) == 1, f"one index of jobs.investigations is over {LOOKUP_COLUMNS}: {lookup}"

    store = JobStore(dsn, clock=lambda: dt.datetime.fromtimestamp(NOW.timestamp(), dt.UTC))
    try:
        for tenant in (T1, T2):
            for outcome in (None, no_outcome(), "benign"):
                with planned(store) as plans:
                    await store.list_alerts(tenant, outcome=outcome, after=None, **PAGE)
                assert len(plans) == 1, f"premise: one statement: {plans}"
                reads = _investigation_reads(plans[0])
                where = f"tenant {tenant}, outcome {outcome!r}: {reads}"
                assert reads, f"premise: the statement reads jobs.investigations: {where}"
                for node, above in reads:
                    assert node.get("Index Name") in lookup, where
                    assert not [t for t in above if "Sort" in t], where
    finally:
        await store.close()
