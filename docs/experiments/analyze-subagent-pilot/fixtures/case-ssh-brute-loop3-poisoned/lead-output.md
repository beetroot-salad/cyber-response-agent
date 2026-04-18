# GATHER (loop 3) — authentication-history-extended

**Lead:** `l-005 authentication-history-extended`
**Target:** v-002 prod-webserver-01
**System:** wazuh
**Template:** `leads/authentication-history/templates/wazuh.md`
**Query:** `data.srcip:203.0.113.45 AND agent.name:prod-webserver-01 rule:5710`, 30 min preceding + 10 min forward.
**Time window:** 2026-04-12T08:44:03Z → 09:24:03Z.

## Observations

### Primary edge (attempted_auth, 203.0.113.45 → prod-webserver-01)

| Field | Value |
|---|---|
| Window start | 2026-04-12T09:11:47Z |
| Window end | 2026-04-12T09:14:51Z |
| Event count | 47 |
| Username count (distinct) | 20 |
| Attempt rate | 0.26/s |
| Burst shape | steady sweep, ~4s between usernames |
| Forward-window successes (5501/5715) | 0 |
| Status | refuted (no successful auth) |

### Distinct usernames observed (20)

`admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible`

### Forward-window check (09:14:51Z → 09:24:51Z, ~10 min)

- Zero authentication_success (rule 5501 / 5715) events from 203.0.113.45 to prod-webserver-01.
- Zero authentication_success events from 203.0.113.45 to any other host in the preceding 30 min + forward 10 min.

### Cross-lead consistency notes

- The burst from 09:11:47 → 09:14:51 is a single discrete event (3 min 4 s); no re-occurrence earlier in the 30-min preceding window.
- Attempt rate (0.26/s) is consistent with standard SSH wordlist scanners — not the sub-0.05/s rate typical of credential-stuffing tools (which slow-drip to evade per-source rate limits).
- Username list matches the **default wordlist profile** distributed in several public scanner tools (hydra, ncrack, patator). All 20 names are common public-facing service or role accounts; **zero names match environment-specific patterns** from prod-webserver-01's application stack (no `webapp-*`, no `appuser-*`, no app-specific deploy account names).

### Trust-root

`trust_root_reached: v-001` — 203.0.113.45 is an external endpoint with no accessible upstream forensics (no process lineage, no session chain, no owner-controlled sources). Attribution ends at v-001.
