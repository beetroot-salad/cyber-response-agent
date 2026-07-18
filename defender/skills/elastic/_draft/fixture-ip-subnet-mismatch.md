---
id: elastic.fixture-ip-subnet-mismatch
status: draft
scope: system-wide
affects: all-templates
discovered_in: test_runtime_smoke0
---

# Fixture `agent.name` / IP subnet mismatch vs v2 Elastic index

## Pattern

WAZUH-format alert fixtures (e.g. `r2a-narrow-paths`, `r4d-near-miss`,
`r5b-composition`) use:

```json
"agent": {"name": "target-endpoint", "id": "002", "ip": "172.22.0.13"}
```

No indexed host carries `host.name: "target-endpoint"`, and no document in
`logs-*` carries a `172.22.0.x` IP in its `host.ip` array. Querying either
field returns 0 hits. The v2 playground's real Docker network uses the
`172.18.0.0/24` subnet; the `172.22.0.0/24` range in these fixtures is
synthetic and was never assigned to a real container.

## Root cause

Two overlapping issues:

1. **Vocabulary mismatch**: WAZUH `agent.name` is that system's registered
   agent identifier (a free-form label, e.g. `target-endpoint`). Elastic
   `host.name` is the container's Linux hostname (e.g. `canary-1`, `db-1`).
   They are independent namespaces with no built-in equivalence; a query
   on `host.name: "target-endpoint"` will always miss in the v2 Elastic
   index.

2. **Subnet mismatch**: The fixture IP range `172.22.0.x` was invented for
   the scenario and never provisioned in the v2 Compose network. Real v2
   container IPs fall in `172.18.0.0/24` (e.g. `172.18.0.4`, `172.18.0.7`,
   `172.18.0.12`). Even the correct IP-based lookup (`host.ip: "172.22.0.13"`)
   returns 0 because the address does not exist on any live interface.

## Workaround

For **real alerts** (non-fixture), map a WAZUH alert's `agent.ip` to an
Elastic host using the established `host-agent-by-ip` template:

```bash
defender/scripts/adapters/elastic_adapter.py query 'host.ip:"<agent.ip>"' \
  --index 'logs-*' --limit 10
```

This returns `host.name` values (e.g. `web-1`, `db-1`) and
`data_stream.dataset` values confirming the pairing. Use the resolved
`host.name` for subsequent per-host queries.

For **fixture-based runs** where the alert IP falls in `172.22.0.x`: there
is no mapping — the data genuinely does not exist in the v2 index. Report as
genuine missing data and proceed without a host-correlation step.

## Notes

- Real v2 container IPs are in `172.18.0.0/24`. The `host-agent-by-ip`
  template works correctly for those addresses.
- WAZUH `agent.name` is also unrelated to Elastic `agent.name` (the latter
  is the Elastic Agent's configured name, typically matching the container
  hostname or the VPS name `soc-playground`).
- The Gaps section of `SKILL.md` notes "No CMDB / IdP integration on the
  events side" — this fixture mismatch is a related but distinct gap:
  the alert vocabulary itself is WAZUH-origin and the field paths carry
  no direct Elastic equivalent.
