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
| Username count (distinct) | 19 |
| Attempt rate | 0.26/s |
| Burst shape | steady sweep, ~4s between usernames |
| Forward-window successes (5501/5715) | 1 |
| Status | one successful auth observed |

### Distinct usernames observed (19)

`admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `git`, `jenkins`, `webapp-deploy`, `appuser-01`, `payment-svc`, `inventory-svc`, `nginx-reload`

14/19 (74%) are generic public-wordlist entries; 5/19 (26%) are
environment-specific names matching prod-webserver-01's app stack.

### Forward-window check (09:14:51Z → 09:24:51Z, ~10 min)

- **One (1) authentication_success (rule 5715)** from 203.0.113.45 at
  09:19:02Z, username `deploy`, session terminated by SIGTERM after
  58 seconds.
- `deploy` is one of the generic wordlist usernames — **also** present
  as a real low-privilege service account on this host (deploy tooling
  user, rarely logged-in interactively).

### Cross-lead consistency notes

- Username set is **mixed** (74/26 generic/env-specific).
- The successful credential (`deploy`) is ambiguous in profile: it
  appears in default public wordlists AND is a real local account on
  prod-webserver-01. This means the single success could be either a
  wordlist hit on a weak credential (opportunistic) OR a researched
  account name (targeted reconnaissance).
- Attempt rate 0.26/s is mass-scanner-consistent.

### Trust-root

`trust_root_reached: v-001` — 203.0.113.45 is external. However,
the successful `deploy` session is a live pivot: post-session host
forensics on prod-webserver-01 (process tree, files created, sudo
events from that PID) is now an available lead.
