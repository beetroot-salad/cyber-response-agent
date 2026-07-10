---
id: cmdb.container-host-mapping
status: draft
---

## Goal

Map a container ID observed in syscall or runtime events (Falco, auditd, CRI logs)
back to the host it runs on. In single-shared-Falco or host-clustered deployments,
a container's Falco `container.id` may not carry the host name; this template
resolves which role host (web, db, jump-box, etc.) is the container's owner based
on the container ID and available metadata (role, image, listen ports).

## What to summarize

- host name the container runs on
- role the host plays (web, db, dev-ws, jump-box, etc.)
- owner of the host
- criticality of the host
- expected services / trust edges on the host
- whether the container's observed activity (command, network target) aligns with the host's expected behavior

## Query

**Procedure**: Query CMDB for all hosts, then correlate the container ID against
deployment metadata. In the v2 playground, container IDs correspond to role hosts;
cross-reference against `hosts/inventory.yaml` entries and role-host mappings from
recent baseline activity or Falco/Docker event logs.

```
# Step 1: Get container ID metadata from the deployment context
# (role host assignments are deterministic per role in the v2 playground)
container_id: ${container_id}

# Step 2: Query CMDB for all hosts
cmdb_cli.py list-hosts

# Step 3: Cross-reference: which host's container(s) have this ID?
# Heuristic: container ID truncation, role-cluster names (web-*, db-*, etc.),
# or direct Docker inspect (docker exec <host> docker inspect ${container_id} |
# jq .Config.Hostname) from a bastion.
```

## Common pitfalls

- **Container ID encoding varies by daemon.** Docker uses 12-char short ID in
  logs and CLI; full 64-char ID in APIs and systemd journal. The Falco event
  carries the 12-char form.
- **Shared Falco daemon across all containers.** If Falco runs on the VPS host
  (not per-container), every event's `container.id` is opaque until you map it
  against a container listing. The container plugin *does* supply `container.name`,
  but in early event streams it may be `<NA>` if the container was young at event time.
- **Role-host naming conventions.** In the v2 playground, hosts follow
  `{role}-{index}` (web-1, web-2, db-1, jump-box-1, dev-ws-1, office-ws-1,
  office-ws-2, canary-1). Container names often match or are derived from the
  host name; if `container.name` is missing, the container ID's hex digits may
  encode a UUID or hash of the Compose service name.

## Baseline

Not applicable — container-host mapping is source-of-truth, not time-dependent.
