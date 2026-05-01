---
title: Validate Hetzner Elastic health + simulation richness via batch-10 attacks
status: doing
groups: playground-v2, eval
---

Goal: confirm the Hetzner Elastic stack is healthy and the batch-10 attack scenarios produce telemetry rich enough to drive the investigate loop. Signatures are a probe for that, not the deliverable.

Batch 10 ships 4 attack scenarios in `playground-v2/attacks/`. Each is supposed to produce telemetry in Elasticsearch via elastic-agent / Falco / Zeek / Keycloak. We don't yet know which actually do, with what field shapes, or which integrations are wired up.

## Phase 0 — Bring the Hetzner VPS up ✅

Stack is currently leveled-down (SSH to `soc-playground` refused, no live VPS). Before any probing:

- [x] `infra/bin/up.sh` to restore CCX33 from latest snapshot (~€74/mo while up — confirm with user before running).
- [x] `infra/bin/update-ssh-config.sh` to sync the IP.
- [x] `docker --context soc-playground compose -f playground-v2/compose.yml up -d` (with `V2_BASELINE_ENABLED=false` for a clean probe).
- [x] Sanity: `docker --context soc-playground ps` shows elasticsearch / kibana / fleet-server / keycloak / target hosts healthy.

## Phase 1 — Telemetry health probe (primary deliverable) ✅

Done — see `playground-v2/attacks/runs/phase1-notes.md` for the full per-scenario writeup. Verdict: v2 IS fit for end-to-end loop runs against batch-10 scenarios; three of four shapes are signature-ready and the fourth (cross-tier) is a duplicate of the first.

Five source-side fixes shipped during Phase 1 (all uncommitted under `playground-v2/`):

1. **sshd logging** — `hosts/Dockerfile` CMD changed from `sshd -D -e` to `sshd -D` so sshd's full `Failed password ...` lines reach `/var/log/auth.log` and the system integration's ECS pipeline parses them with `user.name` / `source.ip` / `event.outcome` populated.
2. **Falco upgrade + standard rule packs** — `FALCO_VERSION` 0.39.2 → 0.43.1, multi-stage build pulling `falco-sandbox-rules` + `falco-incubating-rules` + `container` plugin, container plugin loaded with the docker socket override. Adds `Adding ssh keys to authorized_keys`, `Decoding Payload in Container`, `Launch Ingress Remote File Copy Tools in Container`, etc.
3. **ES mapping conflict in `falco.yaml` `append_output`** — the phase-1 block injected `container.image` as a flat string while Falco's rule output emits the conflicting object path `container.image.repository`. ES rejected the combination with `illegal_argument_exception` and silently routed every Falco event to the failure store (`failure_store: 6298` of 7419), surfacing as a "filebeat stall". Dropped the conflicting field; forced `_rollover` so the new `.ds-…-000003` backing index has a fresh dynamic mapping.
4. **Falco noise — source side** (`compose.yml`): every host healthcheck swapped from `nc -z 127.0.0.1 22` to `pgrep -x sshd >/dev/null`. The dominant noise (99.1% of all events for the data stream's 6 days) was sshd's per-accept `dup2` triggered by 8 hosts × 6/min nc probes. Process check has the same intent without a socket. Web/db hosts get analogous `pgrep nginx` / `pgrep postgres`.
5. **Falco noise — filter side** (new `playground-v2/falco/falco_rules.local.yaml` → `/etc/falco/rules.d/zz_playground_overrides.yaml`): suppresses agent-internal probes (EC2 metadata + `/proc/<pid>/environ` from `elastic-otel-collector`), Keycloak's `/dev/tcp/127.0.0.1/9000` healthcheck, and curl DNS lookups for container healthchecks. Scoped via `proc.exepath` to system paths so attacker-dropped binaries can't inherit the suppression. Attack-relevant rules untouched.

Combined effect on Falco idle noise: **~251 events/min → ~0.4 events/min (~600× reduction).** `logs-falco.alerts-default` now ingests cleanly; only attack-relevant signal remains at idle.

## Phase 2 — Minimum-viable signatures, only after Phase 1 is green ✅

One thin signature per *distinct telemetry shape*:

| Telemetry shape | Signature | Covers scenarios |
|---|---|---|
| sshd via system integration | `elastic-ssh-invalid-user` | ssh-brute-force-canary |
| `falco.alerts` | `elastic-falco-shell-lineage` | living-off-the-land |

Defer:
- `elastic-falco-authorized-keys-write` — same index as shell-lineage, no new shape coverage.
- `elastic-cross-tier-ssh` — multi-index correlation; only attempt once single-index health is green.

Each signature: `context.md` + `playbook.md` + at least one archetype, plus `config/signatures/elastic-*/permissions.yaml`. Reuse archetype catalogs from the wazuh analogs (`wazuh-rule-5710`, `wazuh-rule-100001`) with field-shape adjustments.

**Shipped:**

- `elastic-ssh-invalid-user` — context.md + field-quirks.md + playbook.md + 4 archetypes (monitoring-probe, service-account-rotation, credential-stuffing, external-bruteforce) — story.md + trust-anchors.md per archetype, no precedent snapshots. Playbook authored via `/author` (Sonnet) with reconstruction/comprehension/coherence/replay probes; service-account regex anchored on actual playground identities (`svc.<role>` form per `keycloak/realm.yaml` + `hosts/inventory.yaml`).
- `elastic-falco-shell-lineage` — context.md + field-quirks.md + playbook.md, archetype directories TODO pending Phase-3 run grounding (per author-skill ground rule — no archetypes without a run_dir). Playbook table mirrors the wazuh-rule-100001 catalog (`container-init-script`, `app-spawned-shell`, `post-exploit-interactive`, `operator-runtime-debug`, `ci-pipeline-exec`) marked TODO.
- Both `config/signatures/elastic-*/permissions.yaml` ship in `recommend` mode only; mitigation actions deferred until precedent snapshots + auto-close judge calibration land.
- Pre-existing gap: 6 lead names referenced in playbooks (`source-classification`, `username-classification`, `shell-context`, `container-baseline`, `endpoint-context`, `identity-context`) have no dedicated `common-investigation/leads/{name}/` directories. Same gap exists in the wazuh analogs. Not introduced by this phase.
- All 53 KB schema + resolver tests pass; `resolve_imports.py` exits 0 for both signatures.

## Phase 3 — One live loop run per shipped signature

Exit criterion is **loop reached REPORT**, not disposition correctness. Capture the run dir; file any blocking loop/prompt bugs as separate task cards.

## Exit criteria

- Phase 1 notes committed for all 4 scenarios.
- At least 2 signatures shipped covering the 2 distinct telemetry shapes.
- At least 1 live run reaching REPORT against the Hetzner Elastic stack.

Out of scope: chaos (batch 11), fixture capture (10b — dropped), MinIO-backed data-access archetypes, the 2 deferred signatures.
