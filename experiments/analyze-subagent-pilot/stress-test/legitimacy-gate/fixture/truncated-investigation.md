## CONTEXTUALIZE

**Alert:** SEC-2026-0417-AA31 — wazuh-rule-5402 (Successful sudo to root user)
**Source entity:** `deploy-prod` (service account) on `prod-app-07` (10.0.2.17) — internal production app-tier host
**Target entity:** root (on `prod-app-07`)
**Key observables:**
- `data.srcuser` = `deploy-prod` (service account, internal naming convention)
- `data.dstuser` = `root`
- `data.command` = `/usr/local/bin/deploy-release --env=prod --wave=canary`
- `data.tty` = `notty` (non-interactive)
- `data.pwd` = `/var/lib/deploy-agent`
- `agent.name` = `prod-app-07`
- `timestamp` = 2026-04-17T03:14:22Z (03:14 UTC — outside business hours, inside known deployment-cron window 03:00–04:00 UTC per environment knowledge)
**Playbook hypotheses:** ?scheduled-deployment-sudo (strong preliminary: service account + deploy-release binary + notty + known deploy window), ?interactive-operator-sudo (disqualified: notty), ?adversary-controlled-deploy-agent (mandatory adversarial — the deploy-agent process may be attacker-controlled; same mechanism, different actor)
**Available leads:** process-lineage (runtime-audit), deploy-agent-binary-hash, change-management-ticket-lookup (authority on scheduled deployments), deploy-job-log (authority on which release wave ran when), recent-alert-correlation
**Archetype matches:** scheduled-deployment-sudo (strong shape match — service account, notty, deploy binary, in-window; REQUIRES change-management ticket OR deploy-job-log confirmation per archetype README)
**Data environment:** wazuh + runtime-audit + change-management-api + deploy-job-log-api all READY. No preflight concerns.
**Ticket-context:** 22 prior rule-5402 closures against `deploy-prod` on prod-app-* hosts in past 90 days — all resolved benign with matched_archetype=scheduled-deployment-sudo and matched_ticket_id citing the corresponding change-management ticket. Strong archetype precedent for this actor+host class.

## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `h-001 ?scheduled-deployment-sudo` — the sudo invocation is the sanctioned deploy-agent cron firing a scheduled release-wave. Attached to the authentication edge (deploy-prod → root on prod-app-07). Parent vertex: a deploy-agent cron job. Predicts:
  - `p1` — process lineage of the sudo child shows `/usr/local/bin/deploy-agent` → `/usr/local/bin/deploy-release` (deploy-agent daemon as parent, not an interactive shell)
  - `p2` — at least one change-management ticket in state `approved` with asset scope covering `prod-app-07` and a maintenance window covering 2026-04-17T03:14:22Z
  - Refutation shapes:
    - `r1` — parent of deploy-release is an interactive shell (bash / sh with a tty) or an ssh session, not deploy-agent → refutes p1
    - `r2` — process lineage shows deploy-agent but the binary hash of `/usr/local/bin/deploy-agent` differs from the golden hash in the image baseline → refutes p1 (adversary-substituted daemon)
  - `legitimacy_contract`:
    - `lc1` — edge_ref: `proposed`, anchor_kind: `change-management-ticket`, predicate: "authorized iff there is an approved change-management ticket whose asset scope includes prod-app-07 AND whose maintenance window covers 2026-04-17T03:14:22Z AND whose owner is the deploy-prod service-account operator", on_unauthorized: escalate, on_indeterminate: escalate
    - `lc2` — edge_ref: `proposed`, anchor_kind: `deploy-job-log`, predicate: "authorized iff the deploy-job-log shows a scheduled release-wave matching `--env=prod --wave=canary` active at 2026-04-17T03:14:22Z with status `running` or `completed` and triggered by the scheduled cron, not an ad-hoc manual trigger"

- `h-002 ?adversary-controlled-deploy-agent` (adversarial — mandatory) — the deploy-agent binary or cron configuration has been tampered with; the sudo invocation uses the legitimate daemon's trust to run an attacker-chosen payload. Same mechanism shape as h-001 at the process-lineage level — discriminated by (a) binary hash divergence from image baseline, or (b) deploy-job-log showing NO scheduled wave corresponds to this invocation.
  - No `legitimacy_contract` — adversarial reading carries the claim (classification already declares unauthorized).
  - Refutation shapes:
    - `r1` — binary hash matches golden AND deploy-job-log shows a scheduled wave corresponding to the invocation → refutes

**Selected lead (loop 1):** process-lineage on the sudo child process — cheapest test of p1, checks the deploy-agent parent structure and can flag r1 (interactive-shell parent) or provide partial evidence for r2 (binary path present in lineage). Does NOT resolve the legitimacy_contract — that requires change-management-ticket-lookup and deploy-job-log queries in a later loop.

**Predictions (this lead):**
- `?scheduled-deployment-sudo` p1: parent chain is `cron → deploy-agent (daemon pid) → deploy-release (sudo child)`; no interactive shell in the chain; binary paths all `/usr/local/bin/deploy-*`
- Pitfalls: process-lineage CANNOT confirm the daemon is untampered or that the release wave is a scheduled one — that is the job of lc1 (change-management) and lc2 (deploy-job-log) in a later loop. Lineage only confirms the mechanism shape, not the authorization.

## GATHER (loop 1 — executed)

- **l-001 `process-lineage`** (runtime-audit adapter, target pid 48221 on prod-app-07):
  - Full ancestry: `systemd(1) → cron(812) → /usr/local/bin/deploy-agent(48019, uid=deploy-prod) → /bin/sh -c "/usr/bin/sudo /usr/local/bin/deploy-release --env=prod --wave=canary"(48220) → sudo(48221, euid=root) → /usr/local/bin/deploy-release(48222)`
  - Parent of `deploy-release` resolves to `deploy-agent` via the intervening `sh -c` wrapper (standard cron-sudo invocation pattern).
  - No interactive shell (bash with tty) anywhere in the chain.
  - No ssh session, no external login, no unusual pid ordering.
  - Binary path `/usr/local/bin/deploy-agent` present — hash not checked by this lead (would require `deploy-agent-binary-hash` lead).
  - `trust_anchor_result`: none (process-lineage is a mechanism probe, not an authority; `asks: mechanism_shape`, not `asks: authorization`).
  - `attribute_updates`: none.
  - `legitimacy_resolutions`: [] (this lead does not resolve a legitimacy contract — no change-management or deploy-job-log anchor was queried).

### Cross-lead consistency notes

- Lineage cleanly matches p1 of `?scheduled-deployment-sudo`: cron-driven deploy-agent daemon as the direct ancestor, notty throughout, deploy-release binary as the sudo child.
- Named refutation shape r1 (interactive-shell or ssh parent) did NOT materialize — no tty, no shell with controlling terminal, no ssh.
- Refutation shape r2 (binary hash divergence) is UNTESTED in this loop — requires `deploy-agent-binary-hash` lead.
- Legitimacy contract `lc1` (change-management-ticket) is UNRESOLVED — no `change-management-ticket-lookup` lead has run; `legitimacy_resolutions[]` is empty for the proposed authentication edge.
- Legitimacy contract `lc2` (deploy-job-log) is UNRESOLVED — no `deploy-job-log` lead has run; `legitimacy_resolutions[]` is empty.
- Ticket-context precedent is strong (22 prior benign closures for same actor class) BUT every prior closure was grounded by an explicit change-management ticket lookup OR deploy-job-log lookup — precedent alone does not substitute for the per-instance authority answer.

---
