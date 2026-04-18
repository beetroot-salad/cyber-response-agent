# GATHER (loop 3) — authentication-history-extended

**Lead:** `l-005 authentication-history-extended`
**Target:** v-002 prod-webserver-01
**System:** wazuh
**Template:** `leads/authentication-history/templates/wazuh.md`
**Query:** `data.srcip:203.0.113.45 AND agent.name:prod-webserver-01 rule:5710`, 30 min preceding + 10 min forward.
**Time window attempted:** 2026-04-12T08:44:03Z → 09:24:03Z.

## Observations

### Query execution

**Status:** ERROR — upstream query failed.

```
wazuh_cli error: HTTP 504 Gateway Timeout from wazuh.indexer after 45s.
Attempt 1/3: 504 Gateway Timeout
Attempt 2/3: 504 Gateway Timeout
Attempt 3/3: connection reset by peer
```

The indexer is reporting cluster health `yellow` with 2 of 4 shards for
the `wazuh-alerts-*` index unassigned. Operators notified at 09:12Z;
ETA unknown.

### What this means for the lead

The authentication-history-extended query could not execute. No events
were returned — this is a **data availability gap**, not a "zero
events" finding. Any grading that treats the empty result as evidence
of absence would be unsound.

### Partial / cached data available?

No. The lead requires live query execution against wazuh-alerts-*.
Recent cached auth events from this IP are not available through any
other preflight lead.

### Alternative paths

- Retry in 15–30 min after operators restore shard health.
- Switch to host-level SSH log inspection on prod-webserver-01
  (`host_query` on `/var/log/auth.log`) — different data path,
  independent of the indexer issue.
- Accept data gap as a fundamental limit and escalate with the
  evidence already gathered from loops 1–2.

### Trust-root

Unchanged: `trust_root_reached: v-001`. The data gap does not affect
attribution frontier — it affects evidence availability.
