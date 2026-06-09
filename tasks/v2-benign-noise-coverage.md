---
title: v2 playground — benign-noise generators for detection-rule FP coverage
status: doing
groups: playground-v2, noise, evaluation
---

**Motivation.** v2 playground currently has 5 detection rules and only one
explicit benign-noise generator (`typo-failed-login`). Attack runs from
`attacks/runner.py` fire alerts cleanly against an otherwise quiet detection
stream — there's no FP pressure on the agent. To validate the learning
workflow and stress-test FP precision we need legitimate activity that fires
the same detection rules.

**Approach.** Lead with "what activity occurs in modern environments → what
telemetry it generates → which rules it trips," not "rule → reverse-engineer
benign trigger." Adds 3 detection rules to fill coverage gaps (bulk SSH
success, internal port-scan burst, sudo-activity burst) and 9 baseline
catalog entries that map common authorized patterns to the resulting alerts.

**Cadence target.** 10:1 noise:attack dominance across the catalog. Per-action
`mean_s` chosen so each rule fires from noise multiple times per investigation
window; `shape:` picks the time-of-day envelope (config-mgmt + CI = workhours,
vuln scan = flat, oncall sudo = overnight-peak).

## Scope (this PR)

- [x] **Identity + host inventory.** 3 new realm users (`svc.config-mgmt`,
  `svc.deploy`, `svc.security`), 3 new host roles (`config-mgmt`, `ci-host`,
  `scanner-host`), 3 new hosts (`config-mgmt-1`, `ci-1`, `scanner-1`).
  Per-host `svc.config-mgmt` accounts on all 8 managed hosts; `svc.deploy`
  on web-*; trust_edges_out reflects each role's push surface.
- [x] **Compose wiring.** Three new host services (all use `target: plain`
  in `hosts/Dockerfile`), three new `agent_state_*` named volumes,
  `fleet-host-policies` ROLES list extended.
- [x] **Squid Dockerfile.** Three new entries in the htpasswd loop —
  maintains the cross-file invariant called out in CLAUDE.md.
- [x] **3 new detection rules.**
  - `v2-bulk-ssh-success` — threshold ≥5 sshd success per source.ip / 10min
  - `v2-internal-port-scan` — threshold ≥20 Falco suspicious-network-tool
    events per container / 10min
  - `v2-off-hours-sudo` — threshold ≥3 Falco "Sudo execution" events per
    host / 10min. The time-of-day distinction is enforced by the noise
    pattern's shape (`overnight-peak`), not the rule.
- [x] **Falco rule.** New `Sudo execution` rule in
  `falco/falco_rules.local.yaml` (matches `proc.exepath = /usr/bin/sudo`).
- [x] **9 noise patterns** in `hosts/base/baseline/catalog.yaml` with
  `triggers_rules:` + `category: noise` tagging:

  | id | mean_s | shape | fires |
  |---|---|---|---|
  | `config-mgmt-fleet-push` | 600 | workhours-utc | bulk-ssh-success, cross-tier-ssh-pivot |
  | `config-mgmt-key-rotate` | 3600 | workhours-utc | authorized_keys-modification |
  | `ci-deploy-push` | 1200 | workhours-utc | suspicious-network-tool, off-hours-sudo |
  | `vuln-scan-weekly` | 1800 | flat | internal-port-scan, suspicious-network-tool |
  | `monitoring-port-probe` | 300 | flat | suspicious-network-tool |
  | `oncall-offhours-sudo` | 1800 | overnight-peak | off-hours-sudo |
  | `fat-finger-then-success` | 2400 | workhours-us | success-after-failures, failed-auth-burst |
  | `stale-automation-token` | 7200 | flat | sshd-failed-auth-burst |
  | `dba-tunnel` | 2400 | workhours-us | cross-tier-ssh-pivot |

- [x] **Catalog schema update.** Header documents the new `triggers_rules:`
  + `category:` fields (informational; scheduler ignores them).

## Validation (post-merge to defender-v2-env)

- [ ] **Stack bring-up.** `docker --context soc-playground compose up -d
  --build config-mgmt-1 ci-1 scanner-1` — confirm all three enroll into
  Fleet (Kibana → Fleet → Agents shows them online).
- [ ] **Re-seed realm.** `docker volume rm soc-playground_keycloak_data &&
  compose up -d keycloak keycloak-init` to pick up the 3 new identities.
- [ ] **Install rules.** `python3 playground-v2/scripts/install_detection_rules.py`
  loads the 3 new rules into Kibana's detection engine.
- [ ] **Observe.** Tail `/var/log/baseline.log` on each new host for
  bound-action lines; tail `falco.alerts` data stream in Kibana for the
  new "Sudo execution" + suspicious-network-tool events; confirm the
  `.internal.alerts-security.alerts-default-*` index shows fires from
  every new rule within ~30min of bring-up.
- [ ] **Cadence sanity.** Over a 1-hour observation window, expect rough
  fire counts: bulk-ssh-success ~6, internal-port-scan ~2, off-hours-sudo
  spike at 22:00-06:00 UTC, sshd-failed-auth-burst rare.

## Cherry-pick

Per the worktree convention this work lands on `defender-v2-env`. Once
validation passes, cherry-pick to `main` as a separate step.

## Open questions / follow-ups

- **NOPASSWD for service accounts.** `seed-users.py` adds `sudo: true` users
  to the sudo group but doesn't set NOPASSWD; `sudo -n` in noise commands
  fires Falco on execve but the underlying command never executes. Adequate
  for telemetry generation; revisit if realism (actual service restarts,
  actual artifact writes) becomes required.
- **`cross-tier-ssh-pivot` event-1 coverage.** The pivot rule requires an
  sshd success on `dev-ws-*`/`office-ws-*` as its first event. Pre-this-PR
  no baseline action inbound-SSH'd to dev-ws or office-ws, so the rule
  effectively never fired. `config-mgmt-fleet-push` now hits dev-ws-1 +
  office-ws-1 + office-ws-2 every dispatch, supplying event-1 reliably.
- **Scanner-host nmap vs nc.** Chose `nc` loops over `nmap` to avoid
  inflating the base host image. The Falco suspicious-network-tool rule
  fires on either; the internal-port-scan threshold rule fires on burst
  count regardless of tool name.
