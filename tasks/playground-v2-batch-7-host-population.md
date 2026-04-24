---
title: Playground v2 batch 7 — role-clustered host population
status: done
groups: playground-v2
---

Batch 7 from PR #112's checklist: eight role-clustered host containers (web×2, db, jump-box, dev-ws, office-ws×2, canary), each enrolled via Fleet with role-appropriate integrations. Source of truth for attributes: `playground-v2/hosts/inventory.yaml`.

Split into sub-batches so each ships independently:

- [x] **7a** — inventory YAML + role-container skeletons (Ubuntu 22.04 + 24.04 mix, sshd, rsyslog, cron, seeded realm users with per-role shell/sudo, per-host overrides, web nginx + db postgres role services). All 8 services live in `playground-v2/compose.yml`; multi-stage `hosts/Dockerfile` shares a base layer across roles + OS variants.
- [x] **7b** — per-role Fleet policies + container-side elastic-agent enrollment. `fleet-host-policies` one-shot mints 6 role policies (web/db/jump-box/dev-ws/office-ws/canary) and writes an enrollment token per role to the shared `fleet_tokens` volume. Base Dockerfile installs elastic-agent from the same `STACK_VERSION` pin. `hosts/base/agent-enroll.sh` enrolls at entrypoint via `https://fleet-server:8220` with the self-signed CA from the `certs` volume; a per-host `agent_state_*` volume keeps `agent.id` stable across lever-down/up cycles.
- [x] **7c** — Shared Falco with modern-eBPF driver; JSON at `/var/log/falco/falco.json` on VPS. Per-host attribution via Falco's container plugin (`container.name` on every event). Fleet custom-logs integration attach left manual (Kibana UI or curl recipe in `playground-v2/CLAUDE.md`) because the `log` package version varies per Elastic release. auditd is deferred with rationale: per-container auditd in docker fights the kernel's single-listener, and Falco + rsyslog cover the same syscall / auth ground with less pain.

Exit criteria: 16 containers running on the VPS (7 pre-batch + Falco + 8 hosts), each host visible in Kibana → Fleet → Agents with a role-tagged policy, system data flowing to ES, Falco events queryable under `falco.alerts` dataset with per-host attribution via `container.name`. Lever-down / up survival to be verified on next deploy.

Deferred to later batches:
- Baseline activity generators (7→8)
- SSH key distribution (7→8)
- pgaudit + real DB schema (7→9)
- Automated attach of Falco custom-logs integration to `vps-host-policy` (follow-up; needs `log` package version lookup that's brittle to bake into a one-shot)
- Per-container auditd (deferred — Falco + rsyslog cover the same ground without fighting the kernel's single-listener audit socket)
