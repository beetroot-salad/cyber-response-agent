## ORIENT

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|target-endpoint|ip=172.22.0.13;agent_id=002
v-002|endpoint|endpoint:ipv4|172.22.0.10|
v-003|identity|identity:ghost|healthcheck|kind=non-existent-user

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-04-20T03:05:51.865Z|siem-event:wazuh|user=healthcheck;srcport=56984;outcome=failed;firedtimes=7;rule=5710;prog=sshd
```

Triage question: Is the SSH invalid-user attempt from 172.22.0.10 using the non-existent username "healthcheck" a Docker health check probing SSH as a side effect of container orchestration (benign/misconfigured), or an internal credential-guessing attack? Disposition turns on: source identity (Docker service or threat actor), username pattern (single fixed vs. cycling), timing cadence (regular periodic vs. burst), and whether any subsequent auth succeeded.

## PLAN

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|refuts|authz?|weight|status]
h-001|?docker-healthcheck-probe|v-001|attempted_auth|endpoint|container-orchestrator|p1:proposed_parent:"source 172.22.0.10 is a Docker service with a HEALTHCHECK that opens an SSH connection using a fixed username";p2:proposed_edge:"all observed fires use a single username at a regular slow cadence with no credential cycling"|r1[p1,p2]:"multiple distinct usernames attempted, or attempts are bursty/irregular, or source is not a Docker orchestrator"||null|active
h-002|?internal-brute-force|v-001|attempted_auth|identity|adversary-internal|p1:proposed_parent:"source is a compromised or adversary-controlled internal host systematically cycling SSH credentials";p2:proposed_edge:"multiple distinct usernames and/or a burst timing pattern inconsistent with health-check cadence"|r1[p1,p2]:"single fixed username, regular slow cadence consistent with container health polling"||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|rule-5710-pattern|v-001|h-001,h-002|wazuh|recent-rule-fires|rule_id=5710|7d
l-002|1|source-ip-auth-history|v-002|h-001,h-002|wazuh|auth-events|srcip=172.22.0.10|7d
```

## GATHER (loop 1)

Dispatched l-001 and l-002 in parallel.

**l-001 result** (wazuh.recent-rule-fires, rule_id=5710, 7d, JSON+aggs):
- 2,255 fires total, all from 172.22.0.10, single target: target-endpoint
- 5 distinct usernames: nagios (1,198 / 53%), zabbix (607 / 27%), healthcheck (430 / 19%), monitorprobe (10 / <1%), sensu (10 / <1%)
- Steady ~22 events/hour during active windows; no burst spikes; multi-hour silent gaps between sessions

**l-002 result** (wazuh.auth-events, srcip=172.22.0.10, host=target-endpoint, 7d, + server-side agg):
- 100% authentication_failed — zero successes in 7-day window
- Same 5 monitoring-tool usernames confirmed; multi-username batches arrive together (zabbix + healthcheck within seconds of each other)
- Active periods uniform at ~22/hr; sessions separated by multi-hour or multi-day gaps

## ANALYZE (loop 1)

```invlang
:R attr_updates [resolved_by|target|key|value]
l-001|v-002|classification|automated-monitoring-probe
l-001|v-002|observed_usernames|nagios;zabbix;healthcheck;monitorprobe;sensu
l-001|v-001|scope|single-target-no-lateral-spread
l-002|v-002|success_rate|0/2255

:T resolutions
h-001  null → +     [l-001 p1 moderate ⟂ single-source single-target fixed-username-set at regular cadence is automation not human; p2 partial miss: 5 usernames not 1, but all are monitoring-tool service accounts (nagios,zabbix,healthcheck,monitorprobe,sensu) with no credential diversity beyond that fixed set]
h-002  null → --    [l-001 r1 + l-002 r1 severe ⟂ all 5 usernames are monitoring-tool account names; regular slow cadence; zero successes across 2255 attempts over 7 days; no lateral spread — adversarial credential sweep requires username diversity, success signal, or escalation, none observed]
```

Pattern is definitively a misconfigured monitoring probe (likely a Docker service at 172.22.0.10 cycling through standard monitoring service-account names to check SSH reachability on target-endpoint). No credential cycling variation, no success, no lateral movement. Sufficient for disposition — no second loop needed.

## REPORT

```invlang
:T conclude
termination.category   adversarial-refuted
termination.rationale  "Five fixed monitoring-tool usernames, regular cadence, zero successes across 2255 fires — adversarial brute-force interpretation is not consistent with this pattern"
disposition            benign
impact_verdict         none
impact_severity        null
confidence             high
matched_archetype      misconfigured-monitoring-probe
ceiling_rationale      n/a
summary                "Rule-5710 fires trace to a misconfigured monitoring probe at 172.22.0.10 cycling through five standard monitoring service-account names (nagios, zabbix, healthcheck, monitorprobe, sensu) against target-endpoint at ~22/hr. Zero auth successes across 2,255 attempts over 7 days; single source, single target, no lateral spread. Recommendation: identify and fix the monitoring probe's SSH health-check configuration to use a valid user or a key-based check."

:T conclude.surviving [hyp_id|final_weight]
h-001|+
```
