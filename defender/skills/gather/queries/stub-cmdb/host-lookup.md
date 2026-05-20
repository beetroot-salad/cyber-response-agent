---
id: stub-cmdb.host-lookup
status: established
---

## Goal

Look up a host in the CMDB registry by IP or hostname. Used to determine
whether a host is documented infrastructure, its assigned role, owner team,
active status, and authorized network paths (inbound/outbound).

## What to characterize

- Whether the host is documented in CMDB (present/absent)
- Hostname and owning team (if documented)
- Role (monitoring, workload-host, bastion, etc.)
- Active status (active / decommissioned)
- Authorized inbound paths (which sources are permitted to connect)
- Authorized outbound paths (which targets this host may initiate to)

## Query

```bash
jq '.hosts[] | select(.ip == "${ip}" or .hostname == "${hostname}")' /workspace/playground/cmdb/hosts.json
```

Bind either `${ip}` (IPv4 or IPv6 literal) or `${hostname}` (FQDN or short name),
not both. If neither is provided, refuse the dispatch.

## Filter binding

- `ip` → IPv4 or IPv6 literal (e.g. `172.22.0.13`, `2001:db8::1`).
- `hostname` → hostname string (e.g. `target-endpoint`, `monitoring-host`).

### REFUSE: both ip and hostname bound

Bind exactly one of `${ip}` or `${hostname}`, not both. If the lead provides
both, use the IP as primary and report the hostname as a secondary lookup
for cross-reference.

## Common pitfalls

- **Absence is evidence.** A lookup miss on an IP that is actively sending
  traffic is a meaningful signal (undocumented, shadow, or possibly adversary-
  controlled). Do not conflate "not in CMDB" with "the lookup failed."
- **Authorized paths are host-scoped, not port-scoped.** A host is listed
  as authorized to connect to a target; it does not specify which ports or
  protocols. Pair with firewall / network-policy logs for port-level ACL
  confirmation (not available in this environment).
- **Status field only covers CMDB state.** `status: decommissioned` means
  the CMDB entry is marked as retired; it does not prove the physical host
  is offline. Pair with network reachability checks if needed.
