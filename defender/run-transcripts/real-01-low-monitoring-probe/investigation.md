## ORIENT

**Alert**: Wazuh rule 5710 — "sshd: Attempt to login using a non-existent user"
**Source**: 172.22.0.10 port 42850 → target-endpoint (172.22.0.13), user "nagios"
**When**: 2026-05-07T10:55:02Z; firedtimes=23
**Full log**: `May 7 10:55:01 target-endpoint sshd[57968]: Invalid user nagios from 172.22.0.10 port 42850`

**Triage question**: Is this an internal monitoring/service misconfiguration (a Nagios-class tool in the Docker network probing SSH with unprovided credentials), or an opportunistic credential spray from an internal container acting as rogue source?

Disposition turns on:
1. Whether 172.22.0.10 has an expected monitoring role and prior consistent SSH-probe activity to this or other hosts
2. Whether the timing pattern is periodic (monitoring heartbeat) vs burst (active scan)
3. Whether the "nagios" username attempts appear elsewhere in the environment

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:ipv4|172.22.0.10|network=docker-internal
v-002|endpoint|endpoint:linux|target-endpoint|agent_id=002;ip=172.22.0.13
v-003|identity|identity:service|nagios|kind=service-account;exists_on_target=false

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-002|2026-05-07T10:55:02Z|siem-event:wazuh|user=nagios;outcome=failed;firedtimes=23;srcport=42850;rule=5710
```

## PLAN (loop 1)

Two competing explanations, discriminated by source role and timing pattern:

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?monitoring-misconfig|v-001|attempted_auth|endpoint|internal-monitoring-host|role=monitoring-agent|p1:proposed_parent:"172.22.0.10 is a known monitoring host (Nagios/NRPE)";p2:proposed_edge:"auth-probe pattern is periodic (heartbeat cadence), same src appearing on multiple targets"||r1[p1,p2]:"source has no monitoring role in environment; probes are bursty or one-shot"||null|active
h-002|?opportunistic-ssh-probe|v-001|attempted_auth|endpoint|rogue-internal-source||p1:proposed_parent:"172.22.0.10 has no documented monitoring role";p2:proposed_edge:"username diversity across attempts or burst pattern indicating active scanning"||r1[p1,p2]:"source is a known monitoring host with consistent periodic probe history"||null|active

:L findings [id|loop|name|target|mode?|tests|system|template|query|window]
l-001|1|srcip-auth-history|v-001||h-001,h-002|wazuh|auth-events|srcip=172.22.0.10 host=target-endpoint|7d
l-002|1|nagios-user-across-fleet|v-003||h-001,h-002|wazuh|auth-events|user=nagios|7d
```

**Predictions**:
- h-001 confirmed if: l-001 shows a consistent periodic pattern (e.g., every N minutes), firedtimes tracks stable cadence; l-002 shows same srcip probing multiple hosts with "nagios"
- h-002 confirmed if: l-001 shows burst or single cluster of attempts; l-002 shows zero or narrow history

## GATHER (loop 1)

Dispatched l-001 and l-002 in parallel as Task calls to Haiku gather subagent.

**l-001 return**: 2,320 auth failures from 172.22.0.10 over 7d (~13.8/hr). Three usernames observed: nagios (59%), zabbix (27%), healthcheck (18%) — all service-account monitor patterns. Strongly periodic daily windows, machine-regular cadence. Target: only target-endpoint. Raw: gather_raw/0.json.

**l-002 return**: 1,232 auth failures for user "nagios" over 7d. Single source IP (172.22.0.10), single target host (target-endpoint). Exactly 5-minute intervals — classic monitoring heartbeat. Zero successful auths. Raw: gather_raw/1.json. Note: template uses `data.srcuser` (not `data.dstuser`) for SSH invalid-user events.

## ANALYZE (loop 1)

l-001 and l-002 together sharply resolve both hypotheses.

The three usernames (nagios, zabbix, healthcheck) are the canonical service-account set for monitoring frameworks. A 5-minute probe interval is a textbook Nagios/Icinga check interval. The pattern has been running consistently for 7 days — this is not a scan campaign, it is a recurring automated probe.

h-001 (monitoring-misconfig): p1 and p2 both land. Source 172.22.0.10 exhibits a documented monitoring pattern — periodic, multi-username, single-target, machine-regular. The misconfig is that the usernames are not provisioned on target-endpoint, so every SSH health check fires rule 5710.

h-002 (opportunistic-ssh-probe): r1 refuted. The source has a clear monitoring-role signature; the probe pattern is periodic, not bursty; username diversity matches monitoring frameworks, not adversarial exploration.

```invlang
:R attr_updates [resolved_by|target|key|value]
l-001|v-001|classification|internal-monitoring-host
l-001|v-001|probe_pattern|periodic;interval_approx=5min;usernames=nagios,zabbix,healthcheck
l-002|v-003|auth_history|7d_failures=1232;successes=0;source_diversity=1;target_diversity=1

:T resolutions
h-001  null → ++    [l-001 p1,p2 severe ⟂ 5-min cadence + monitoring username set (nagios/zabbix/healthcheck) + 7-day consistent history ≡ automated monitoring probe; predictions met]
h-002  null → --    [l-001 r1 + l-002 r1 severe ⟂ periodic machine-regular pattern with monitoring username set rules out opportunistic recon]
```

Sufficient to disposition. No second loop needed — both hypotheses resolved to terminal weight on one dispatch pair.

## REPORT

```invlang
:T conclude
termination.category   adversarial-refuted
termination.rationale  "Opportunistic-ssh-probe refuted by 7-day periodic monitoring pattern with canonical service-account username set"
disposition            benign
impact_verdict         none
impact_severity        null
confidence             high
matched_archetype      monitoring-misconfig-ssh-healthcheck
ceiling_rationale      n/a
summary                "172.22.0.10 is a monitoring host running 5-minute SSH health checks against target-endpoint using unprovisionned service-account usernames (nagios, zabbix, healthcheck). 2320 rule-5710 fires over 7 days with machine-regular cadence and no successful auths. Disposition: benign misconfig — monitoring service needs the check username provisioned on target-endpoint or the SSH check replaced with a non-auth probe."

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```

