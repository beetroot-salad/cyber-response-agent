---
name: defender-stub-cmdb
description: Stub CMDB system reference — playground asset registry mapping IPs and hostnames to owner, role, and authorized inbound/outbound paths. Use to ground legitimacy questions about which hosts are documented infrastructure vs. unknown/undocumented sources.
---

A static registry standing in for what an organization's CMDB,
asset-management spreadsheet, or platform wiki holds about hosts.
Answers "who owns this IP," "what's its role," "what is it
authorized to talk to."

The file is split by audience. The **Visibility surface** section
informs PLAN routing and ANALYZE-time legitimacy grounding. The
**Execution** section is read by gather when it dispatches a query.

## Visibility surface

### What the registry holds

For each documented host:

- IP and hostname
- Owning team
- Role (`workload-host`, `monitoring`, `bastion`, …)
- Criticality tier
- Authorized inbound / outbound paths (which other hosts are
  permitted to initiate or receive traffic)
- Status (`active`, `decommissioned`)
- Reference to a longer narrative note in `README.md`

### Gaps

- **Sparse — not every IP active on the network is documented.** A
  lookup miss for an IP that is observably sending traffic is a
  meaningful signal (unprovisioned, shadow, or adversary-controlled
  internal host), not a system limitation. Treat absence as evidence.
- **No time dimension.** The registry is current-state only. It does
  not record when a host was provisioned, who edited the entry, or
  prior values of any field.
- **No port-level ACL.** Authorized paths are stated at host
  granularity ("`monitoring-host:22`"), not full 5-tuple firewall
  rules. For the latter, network-policy or firewall logs would be
  needed (not available in this environment).
- **No identity binding.** The CMDB documents hosts, not the
  accounts running on them. Cross-reference `stub-iam` for which
  account is authorized to use a given host-to-host path.

### Read guidance

- A documented host with `status: active` and a matching authorized
  path is dispositive evidence of legitimacy at the network layer —
  but still requires `stub-iam` to confirm the account in use is the
  authorized one for that path.
- A lookup miss does **not** by itself prove malice; pair with the
  observed behavior. The interesting pattern is "behavior consistent
  with adversarial activity **and** source IP undocumented" — the
  conjunction is much stronger than either alone.
- The narrative `README.md` body is freeform text. Read it directly
  with `Read` when the structured JSON answer is ambiguous or when
  the question needs context the JSON fields don't carry (e.g. "what
  is the *intent* of this host?").

### When to use

- **Use stub-cmdb for**: grounding "is this IP documented
  infrastructure," confirming authorized network paths, resolving
  hostnames to teams for routing escalations.
- **Do not use stub-cmdb for**: historical state, identity / account
  ownership (`stub-iam`), endpoint state (`host-query`), event
  evidence (`wazuh`).

## Execution

The registry lives at `/workspace/playground/cmdb/`:

- `hosts.json` — structured index (one object per documented host)
- `README.md` — narrative notes per host, grouped by `notes_ref`

Query directly with `jq` against the JSON, or `Read` the markdown
for narrative context. There is no adapter CLI — the data is small
enough that gather can run the lookup itself.

```bash
# look up a host by IP (returns null if undocumented)
jq '.hosts[] | select(.ip == "172.22.0.13")' /workspace/playground/cmdb/hosts.json

# look up by hostname
jq '.hosts[] | select(.hostname == "monitoring-host")' /workspace/playground/cmdb/hosts.json

# list all documented hosts (sanity check / discovery)
jq '.hosts[] | {ip, hostname, role, status}' /workspace/playground/cmdb/hosts.json
```

When grounding a legitimacy contract that references a host, prefer
a single `jq` to extract the relevant entry, then `Read` the
narrative section under the matching `notes_ref` heading in
`README.md` for the qualitative context. Quote the dispositive
field (e.g. `authorized_inbound`) directly in the gather summary.
