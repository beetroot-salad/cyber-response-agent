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
| Forward-window successes (5501/5715) | 0 |
| Status | no successful auth |

### Distinct usernames observed (19)

`admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `git`, `jenkins`, `webapp-deploy`, `appuser-01`, `payment-svc`, `inventory-svc`, `nginx-reload`

Of 19, **14 are generic public-wordlist names** (admin, root, ubuntu, pi, oracle, postgres, deploy, user, test, guest, operator, mysql, git, jenkins) and **5 are environment-specific names matching the prod-webserver-01 application stack** (webapp-deploy, appuser-01, payment-svc, inventory-svc, nginx-reload).

### Forward-window check (09:14:51Z → 09:24:51Z, ~10 min)

- Zero authentication_success (rule 5501 / 5715) events from 203.0.113.45 to prod-webserver-01.
- Zero authentication_success events from 203.0.113.45 to any other host in the preceding 30 min + forward 10 min.

### Cross-lead consistency notes

- The username set is **mixed**: roughly 74% generic wordlist + 26%
  environment-specific. This is inconsistent with a pure opportunistic
  scanner (which would carry ~100% generic names from a public
  wordlist) and also inconsistent with a pure targeted attacker (which
  would carry primarily env-specific names).
- Two possible explanations, not discriminated by this evidence:
  (a) an opportunistic scanner running a customized wordlist that has
  been seeded with env-specific names harvested from prior
  reconnaissance or public leak sources (hybrid tooling);
  (b) a targeted actor deliberately padding env-specific attempts with
  a generic-wordlist mask to reduce signal.
- Attempt rate (0.26/s) is consistent with either.

### Trust-root

`trust_root_reached: v-001` — 203.0.113.45 is an external endpoint
with no accessible upstream forensics. Attribution ends at v-001.
