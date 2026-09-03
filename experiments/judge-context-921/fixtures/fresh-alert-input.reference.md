# Reference — 20260830T100154Z-fresh-alert-input (written 2026-09-02, before any judge output)

Disposition reached: inconclusive (exhaustion-escalation). Behavioral case closed benign; authz contracts ac1 (change-mgmt) unauthorized and ac2 (iam) indeterminate forced escalation.

## R1 — lead-set gap: it never asked who ran the burst
All 26 queries; every Elastic query hits `logs-falco.alerts-*`. No query touches the SSH auth index (`logs-system.auth-*`), sshd events, or the process parent/tree for the sudo events. "Automated" is inferred from the sub-millisecond burst plus a baseline. The lesson `behavioral-anomaly-needs-affirmative-explanation` (loaded 10:02:46) says exactly that inference needs a process-audit or scheduler lead. The lesson `source-ip-check-auth-log-not-just-enrollment` (loaded 3×) prescribes the auth-index query. Sibling trials of the same alert that queried `logs-system.auth-*` found `Accepted` ssh for root from 147.235.199.7 at 09:54:41Z, ten seconds before the burst; trials that pulled the process parent found the container startup script (role-start.sh / host-entrypoint.sh).
A hit names the auth index / sshd / process parent as UNQUERIED (or names the lesson as loaded-and-not-applied). Bucket: lead-set.

## R2 — lead quality (wrong scope): right systems, wrong asset
l-002 queried CMDB for `soc-playground` (the Falco host.name = the Docker host). The inventory returned (gather_raw/l-002/1.json) lists `db-1`: role db, criticality prod, owner team.data, change_window "sat 04:00-06:00 UTC", service postgres:5432, users svc.monitoring / svc.backups / svc.config-mgmt (only the last has sudo). Loop 2 (l-006) identified container e5b0213bd690 as `db-1`. No lead re-queried CMDB, IAM, change-mgmt or tickets for `db-1`. The ceiling "soc-playground is unregistered in all available governance systems" is therefore false for the asset that ran the commands; the authz contracts were anchored on the wrong asset. Five sibling trials issued `cmdb get-host db-1`.
A hit says db-1 IS in the CMDB payload / the CMDB lookup was at the wrong scope / never reconciled after the container was named. Bucket: lead-quality.

## R3 — analyze discipline: claims cannot be traced to bytes
(a) The main agent only sees gather summaries; l-002's summary says "not registered" over a payload that contains db-1; l-005's summary says "roughly every 1–3 days" over payloads (gather_raw/l-005/0.json, /1.json) where postgres sudo activity ends 2026-08-22 and ALL other sudo (433/354/256-event command groups) ends 2026-08-17 — eight days of silence before a Sunday burst, never noted. (b) `:T resolutions` rows cite edges (e-002…e-007) that are the agent's paraphrase of the summary; no belief points at a payload row. (c) The four error rows (l-002/0, l-004/1, l-004/2, l-006/0) have EMPTY payload files; the "404 user root not found" that justified ac2=indeterminate exists only inside the l-004 summary. (d) Leaked tool-call markup (`</parameter></invoke>`) sits in the document body after loop 1.
A hit names at least one of: summary-vs-payload discrepancy (db-1 or the cadence gap), the pre-alert silence, empty error payloads, or resolutions citing paraphrase rather than payload. Bucket: analyze-discipline.

## Context, not a finding
Twenty-five finished trials of this alert on disk (all runs sharing the alert_id): benign 10, inconclusive 9, malicious 4, false-positive 1, unresolved 1. A judge reading one trajectory reads one draw.
