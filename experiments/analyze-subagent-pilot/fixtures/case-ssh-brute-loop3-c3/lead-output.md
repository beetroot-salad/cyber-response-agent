# GATHER (loop 3) — authentication-history-extended

**Lead:** `l-005 authentication-history-extended`
**Target:** v-002 prod-webserver-01
**System:** wazuh
**Template:** `leads/authentication-history/templates/wazuh.md`
**Query:** `data.srcip:203.0.113.45 AND agent.name:prod-webserver-01 rule:5710`, 30 min preceding + 10 min forward.
**Time window:** 2026-04-12T08:44:03Z → 09:24:03Z.

## Observations

### Primary edge (attempted_auth, 203.0.113.45 → prod-webserver-01)

Preceding-window query succeeded; forward-window query partially
failed (see below).

| Field | Value |
|---|---|
| Preceding window | 2026-04-12T08:44:03Z → 09:14:51Z |
| Event count (preceding) | 47 |
| Username count (distinct) | 20 |
| Attempt rate | 0.26/s |
| Burst shape | steady sweep, ~4s between usernames |
| Forward-window successes (5501/5715) | **UNKNOWN — query errored** |

### Distinct usernames observed (20)

`admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible`

All 20 names are generic public-wordlist entries. Zero
environment-specific names matching prod-webserver-01's application
stack.

### Forward-window check (09:14:51Z → 09:24:51Z, ~10 min)

**Status:** query errored.

```
wazuh_cli error on forward-window subquery:
HTTP 504 Gateway Timeout from wazuh.indexer after 45s.
The preceding-window query (rule:5710) completed successfully, but
the forward-window subquery targeting rule:5501 OR rule:5715 timed
out. Indexer cluster health is yellow, with an index rotation in
progress on wazuh-alerts-2026.04.12.
```

**Therefore:** we do not know whether successful authentications
(5501/5715) from 203.0.113.45 occurred in the 10-minute forward
window. This is an unknown, not a zero.

### Cross-lead consistency notes

- Username list matches the **default wordlist profile** distributed
  in public scanner tools (hydra, ncrack, patator). All 20 names are
  generic; zero environment-specific patterns.
- Attempt rate (0.26/s) is mass-scanner-consistent.
- **Forward-window success/failure status is unknown.** The
  preceding-window evidence strongly suggests opportunistic-scanner,
  but the adversarial hypothesis (`?compromise-followup`) cannot be
  refuted without the forward-window data.

### Trust-root

`trust_root_reached: v-001`. Attribution frontier unchanged.

### Alternative paths for forward-window evaluation

- Retry forward-window query after indexer cluster health recovers.
- Host-level auth.log inspection on prod-webserver-01 for 5501/5715
  equivalents (successful-auth log entries in the forward window) via
  `host_query`.
- Accept the gap and escalate the compromise-followup hypothesis as
  unresolved.
