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
