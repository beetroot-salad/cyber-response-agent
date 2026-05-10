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
| Username count (distinct) | 18 |
| Attempt rate | 0.26/s |
| Burst shape | steady sweep, ~4s between usernames |
| Forward-window successes (5501/5715) | 1 |
| Status | successful auth observed |

### Distinct usernames observed (18)

`webapp-deploy`, `appuser-01`, `appuser-02`, `webapp-ci`, `webapp-staging-deploy`, `prod-webserver-01-admin`, `nginx-reload`, `payment-svc`, `payment-svc-ci`, `inventory-svc`, `inventory-svc-ro`, `grafana-agent`, `sentry-relay`, `redis-sidecar`, `kafka-consumer`, `kafka-producer`, `admin`, `root`

Of 18, 16 are environment-specific names matching the prod-webserver-01 application stack (payment-svc, inventory-svc, webapp-* deploy accounts, service sidecars). Only `admin` and `root` are generic.

### Forward-window check (09:14:51Z → 09:24:51Z, ~10 min)

- **One (1) authentication_success (rule 5715) event** from 203.0.113.45 to prod-webserver-01 at 09:18:42Z, username `webapp-deploy`, session duration 4m 12s before SIGTERM.
- No other successful authentications observed from this source in the window.

### Cross-lead consistency notes

- Username list is **predominantly environment-specific**, matching service accounts and deploy identities visible in the prod-webserver-01 application stack. Public scanner wordlists (hydra, ncrack default) contain none of the 16 env-specific names.
- The successful login at 09:18:42Z as `webapp-deploy` (a legitimate service account on this host) is consistent with post-brute-force compromise: failed sweep for env-specific accounts yielded a working credential for one of them.
- Attempt rate (0.26/s) is faster than typical credential-stuffing slow-drip but the username targeting is surgically aligned with this host's service inventory, not a generic wordlist.

### Trust-root

`trust_root_reached: v-001` — 203.0.113.45 is an external endpoint with no accessible upstream forensics. However, post-compromise pivot analysis from the `webapp-deploy` successful session is a new lead available.
