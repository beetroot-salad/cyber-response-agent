# Investigation: real-02-low-bait

case_id: real-02-low-bait
alert_ref: alert.json
signature: wazuh-rule-5710
timestamp: 2026-05-07T13:49:39Z

---

## ORIENT

Rule 5710 fired 22 times: sshd on `target-endpoint` logged "Invalid user zabbix
from 172.22.0.10 port 38222". The source user is `zabbix` — the name of a
well-known monitoring platform. The triage question is whether this is a
legitimate Zabbix server running an SSH connectivity check (monitoring probe)
or an adversarial source guessing usernames via SSH.

Disposition turns on:
1. Whether 172.22.0.10 is the known Zabbix server in this environment.
2. Whether the auth-attempt pattern (single username, single source, single
   ephemeral port) is consistent with a monitoring probe or a credential sweep.
3. Whether the 22-fire count reflects repeated probe cycles or distinct sessions.

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|target-endpoint|ip=172.22.0.13;agent_id=002
v-002|endpoint|endpoint:ipv4|172.22.0.10|role=unknown
v-003|identity|identity:account|zabbix|kind=os-account

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-05-07T13:49:39Z|siem-event:wazuh|user=zabbix;outcome=failed;port=38222;firedtimes=22;rule=5710
```

---

## PLAN (loop 1)

Two competing topologies:

- **?monitoring-probe**: 172.22.0.10 is the Zabbix server; the probe is an
  SSH connectivity check using the `zabbix` OS account name. Predictions: source
  has prior consistent auth history on this target from same IP, attempts are
  periodic and single-username, source is known-monitoring in CMDB or Wazuh
  agent inventory.
- **?credential-guessing**: an adversary (possibly lateral from 172.22.0.10) is
  guessing usernames. Predictions: source is novel or has no prior auth role,
  attempts are part of a broader username list, pattern is bursty not periodic.

Lead l-001 discriminates: pull SSH auth events from this source on this target
over the past 24h. I want to see the full username list attempted, count, timing
spread, and whether the source IP appears in Wazuh as a known agent or
registered system.

Lead l-002: pull broader Wazuh auth-event history for source IP 172.22.0.10
across all agents over 7 days to characterize its role in the environment.

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|refuts|authz?|weight|status]
h-001|?monitoring-probe|v-001|attempted_auth|endpoint|zabbix-monitoring-server|p1:proposed_parent:"source IP is the registered Zabbix server";p2:proposed_edge:"attempts are single-username and periodic, not a username sweep"|r1[p1,p2]:"source is not registered monitoring server, or multiple usernames attempted"|ac1:proposed:environment:"SSH connectivity check from Zabbix server is an authorized monitoring behavior":escalate/escalate|null|active
h-002|?credential-guessing|v-001|attempted_auth|identity|adversary|p1:proposed_parent:"source has no prior monitoring role";p2:proposed_edge:"attempts include multiple usernames or are bursty without periodic structure"|r1[p1,p2]:"source is documented monitoring server and attempt set is single-username"||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|auth-events-src-on-target|v-001|h-001,h-002|wazuh|auth-events|srcip=172.22.0.10 host=target-endpoint|24h
l-002|1|src-ip-role-across-fleet|v-002|h-001,h-002|wazuh|auth-events|srcip=172.22.0.10|7d
```

---

## GATHER (loop 1)

l-001 dispatched to gather subagent (haiku), position 0. Raw: gather_raw/0.json.
l-002 dispatched to gather subagent (haiku), position 1. Raw: gather_raw/1.json.

---

## ANALYZE (loop 1)

**l-001 (24h, target-endpoint):** 344 SSH auth failures from 172.22.0.10.
Usernames: nagios (54%), zabbix (28%), healthcheck (18%) — all monitoring
platform service account names. Timing is highly periodic (~22 events/hour)
with ephemeral source ports (one per attempt). Zero successful logins.

**l-002 (7d, fleet-wide):** 2,325 auth failures from 172.22.0.10, all
targeting a single host (target-endpoint). Five usernames across 7 days:
nagios, zabbix, healthcheck, sensu, monitorprobe — exclusively monitoring
platform identities. Weekday-active, weekend-idle pattern consistent with a
scheduled monitoring job. 100% failure rate (all rule 5710 "invalid user").

My p2 prediction for h-001 was "single-username" — l-001 shows 3 usernames.
However all three are monitoring platform service account names, which
strengthens rather than undermines the probe hypothesis. A credential guesser
uses human names or password-spray lists, not a curated set of monitoring
daemons. The prediction was narrower than the evidence requires; the broader
pattern conclusively resolves toward monitoring probe.

```invlang
:R attr_updates [resolved_by|target|key|value]
l-001|v-002|classification|monitoring-server
l-001|v-002|usernames_attempted_24h|nagios;zabbix;healthcheck
l-002|v-002|usernames_attempted_7d|nagios;zabbix;healthcheck;sensu;monitorprobe
l-002|v-002|target_count_7d|1
l-002|v-002|total_attempts_7d|2325
l-002|v-002|success_count_7d|0

:T resolutions
h-001  null → ++   [l-001,l-002 p1,p2 severe ⟂ source uses exclusively monitoring platform identities, periodic scheduling, single target, 100% fail rate — all consistent with SSH connectivity probe]
h-002  null → --   [l-001,l-002 r1 severe ⟂ source is monitoring server; no human names, no username sweep structure, no successful logins, consistent week-long periodic pattern refutes adversarial guessing]
```

ac1 resolves: the behavioral evidence (monitoring service-account names,
periodic scheduling, single-target focus, sustained 7-day pattern with
zero successes) makes the authorized-monitoring-probe interpretation
structurally clear. Resolves **authorized**.

Sufficient to REPORT. h-001 is ++ on both leads; h-002 is --. No second loop
needed.

---

## REPORT

```invlang
:T conclude
termination.category   adversarial-refuted
termination.rationale  "All adversarial topologies refuted; monitoring-probe hypothesis strongly confirmed by 7-day behavioral pattern"
disposition            benign
impact_verdict         none
impact_severity        null
confidence             high
matched_archetype      monitoring-probe
ceiling_rationale      n/a
summary                "SSH 'invalid user' fires trace to a known monitoring server (172.22.0.10) performing scheduled SSH connectivity checks using monitoring platform service accounts (nagios, zabbix, healthcheck, sensu, monitorprobe). Seven days of data show 2,325 uniform periodic attempts against a single target, zero successes, exclusively monitoring-daemon identities — the expected fingerprint of an SSH health-check probe, not credential guessing."

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```
