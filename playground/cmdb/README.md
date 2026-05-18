# Stub CMDB

Mock asset registry for the playground. Stand-in for what an organization's
CMDB (or asset-management spreadsheet, or Confluence page, or
`hosts.yaml`) typically holds: which hosts exist, who owns them, what
they're for, what they're authorized to talk to.

Structured index: `hosts.json`. Narrative notes per host below — these
are the kind of paragraph an analyst would find when they search the
internal wiki for a hostname or IP. CLI adapter:
`defender/scripts/tools/stub_cmdb.py`.

The registry intentionally **does not list every IP active on the
playground network**. A lookup miss is a meaningful signal (host is
undocumented / not provisioned through the normal path), not a system
limitation.

## target-endpoint (172.22.0.13)

Generic Linux workload host. Receives application traffic from the
internal load balancer on 443 and is reachable on SSH (22) from
`monitoring-host` (NRPE-style health checks) and the bastion
(`bastion-01`) for operator access. No other inbound paths are
authorized; direct SSH from any other internal IP is a policy
violation and should be treated as suspicious regardless of outcome.

## monitoring-host (172.22.0.20)

SRE-managed monitoring node. Polls `target-endpoint` over SSH for
service health using a dedicated, non-privileged account
(`nrpe-check`). Poll cadence is one attempt every 60 seconds; bursts
of failures from this host typically indicate a real outage on the
target side, not scanning behavior. The host does not run general
scanners (no nmap, no fail2ban probes, no credential sweeps).

If `monitoring-host` is the source of SSH auth failures using any
account name **other than** `nrpe-check`, that is a misconfiguration
or compromise indicator on `monitoring-host` itself — investigate the
monitoring agent, not the target.

## bastion-01 (172.22.0.5)

Operator jump host. All interactive SSH sessions into production
workload hosts originate from here. Login on `bastion-01` is via SSO
+ short-lived certificate; the audit log of operator sessions is the
authoritative record of "who did what" in production.
