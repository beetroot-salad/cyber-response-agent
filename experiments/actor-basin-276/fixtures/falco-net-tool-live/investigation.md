## ORIENT

Falco rule `Launch Suspicious Network Tool in Container` fired at 2026-06-14T19:10:26Z on host `soc-playground`. Container `7e76d1cea7c4` ran `nc -z -w1 jump-box-1 22` — a zero-I/O SSH port probe with 1-second timeout — under uid 1001, parent process bash. Container name and image are `<NA>` (Falco enrichment gap). EXE_LOWER_LAYER flag confirms nc binary is from the base image, not written post-boot. loginuid=-1 / tty=0 indicates non-interactive automated context but does not identify the exec origin (container entrypoint vs docker exec vs cron — all produce this profile per lesson `falco-loginuid-tty-non-interactive-not-docker-exec`).

Triage question: Is this `nc` invocation authorized automation (readiness probe, health-check, CI/CD wait-for-it script) or attacker reconnaissance probing SSH reachability to `jump-box-1` prior to lateral movement?

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/??|7e76d1cea7c4|kind=container;knowledge=partial
v-002|compute|container-host/internal/known-corp|soc-playground|kind=physical;os=linux
v-003|process|bash|bash[pid=??]|user=uid:1001;loginuid=-1;tty=0
v-004|process|nc|nc[pid=??]|image=/usr/bin/nc.openbsd;cmdline="nc -z -w1 jump-box-1 22";flags=EXE_LOWER_LAYER;user=uid:1001
v-005|socket|tcp-endpoint|jump-box-1:22|protocol=ssh;port=22

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|contained_in|v-001|v-002||inferred-structural|
e-002|runs_on|v-003|v-001||inferred-structural|
e-003|spawned|v-003|v-004|2026-06-14T19:10:26.005695Z|siem-event:falco|evt_type=execve
e-004|connected_to|v-004|v-005|2026-06-14T19:10:26.005695Z|siem-event:falco|
```

## PLAN (loop 1)

Lessons applied: `container-identity-gap-not-terminal` (must resolve container via docker platform lead, not infer from context fields), `container-id-anchor-before-uid-lookup` (anchor uid resolution to container_id 7e76d1cea7c4), `falco-loginuid-tty-non-interactive-not-docker-exec` (loginuid=-1/tty=0 means non-interactive only; cannot infer exec origin), `falco-terminal-phase-no-upstream-chain` (must check co-occurring Falco events from adjacent attack phases in same container window).

`nc -z -w1` is a canonical wait-for-service pattern but is also used in attacker recon. Disposition turns on four parallel questions:
1. **Container identity** — what image and entrypoint does 7e76d1cea7c4 run? Resolves `??` class on v-001.
2. **Falco container timeline** — co-occurring collection/persistence/exfiltration events in the same ±15m window?
3. **Uid 1001 authorization** — who is uid 1001 in this container and is that account authorized to run network tools? (Anchored to container_id per lesson.)
4. **Network tool cadence baseline** — has this container previously launched nc or other network tools?

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?container-native-nc-ssh-check|v-003|spawned|process|unclassified-process||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"service entrypoint or init script spawned bash: nc probe recurs in historical Falco cadence; no co-occurring collection/persistence events"
p2|proposed_parent|"container image entrypoint is a service with SSH readiness dependency on jump-box-1"

:H h-001.refuts [id|refutes|claim]
r1|p1|"co-occurring Falco collection/persistence events (write-below-etc, read-sensitive-file, write-below-tmp) in the same ±15m window"
r2|p1,p2|"nc launch is novel — first time seen for this container or image in the 7-day baseline"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-003|iam-policy|"uid 1001 authorized to execute network tools in this container"|escalate|escalate
ac2|e-004|endpoint-policy|"this container authorized to probe jump-box-1:22 via outbound TCP"|escalate|escalate

:L findings [id|loop|name|target|tests|system|window]
l-001|1|container-identity-resolution|v-001|h-001|host-state|n/a
l-002|1|falco-container-timeline|v-001|h-001|elastic|±15m of 2026-06-14T19:10:26Z
l-003|1|uid-identity-authorization|v-001|h-001|identity|n/a
l-004|1|network-tool-cadence-baseline|v-001|h-001|elastic|7d preceding 2026-06-14T19:10:26Z
```

## ANALYZE (loop 1)

l-001 (container-identity-resolution): thin return — gather subagent did not execute any CLI queries. Container class on v-001 remains `??/??/??`. Gap: cannot resolve image or entrypoint without the host-state CLI executing.

l-002 (falco-container-timeline): thin return — gather subagent did not execute any CLI queries. Co-occurring collection/persistence events remain untested. Per lesson `falco-terminal-phase-no-upstream-chain`, this is a required check before disposition.

l-003 (uid-identity-authorization): thin return — gather subagent did not execute any CLI queries. Authz contracts ac1 and ac2 remain indeterminate.

l-004 (network-tool-cadence-baseline): real queries executed (elastic.launch-network-tool-container + elastic.falco-suspicious-network-rule). Strong signal:
- 9,189 nc executions in 7-day baseline for container 7e76d1cea7c4. Pattern: `nc -z -w1 <target> <port>`, parent=bash, uid 1001/1002 — entirely zero-I/O port-check probes.
- The specific `nc -z -w1 jump-box-1 22` SSH probe appears 6 times in the 40 minutes preceding the alert (18:29:35, 18:39:55, 18:47:57, 18:48:26, 18:57:44, 19:06:17) with ~8-10 minute inter-probe intervals — a highly regular automated cadence.
- Fleet-wide: 314 "Launch Suspicious Network Tool in Container" events in the 1-hour pre-alert window across 11 containers (ed96a85a7480, ffbff1299702, c58bf05facac, and others) showing identical `nc -z -w1 <host> <port>` pattern across multiple service ports (22, 80, 443, 5432, 8080).
- Container 7e76d1cea7c4 accounts for 140/314 (44.6%) of fleet activity — it is the highest-volume prober.
- This is the FIRST Falco alert for this container despite 9,189 prior nc executions — strong indicator the alert rule was newly deployed, not that the behavior is new.
- h-001 refutation r2 ("nc launch is novel") is strongly refuted — pattern predates the alert window by at least 7 days.

```invlang
:V l-004.observations.vertices [id|type|class|ident|attrs?]
v-006|compute|container-host/internal/known-corp|soc-playground-fleet|kind=physical;note=fleet-aggregate-11-containers

:E l-004.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-005|spawned|v-003|v-004|2026-06-14T18:29:35.523Z|siem-event:falco|prior_probe=1;pattern="nc -z -w1 jump-box-1 22"
e-006|spawned|v-003|v-004|2026-06-14T19:06:17.012Z|siem-event:falco|prior_probe=6;pattern="nc -z -w1 jump-box-1 22"

:T resolutions
h-001  null → +    [l-004 p1 partial ⟂ e-005,e-006 :: 6 prior SSH probes in ±40m; 9189 baseline nc events confirms recurrent automated cadence — r2 novelty claim severely refuted; r1 (co-occurring collection/persistence) untested pending l-006]
```

l-001/l-002/l-003 returned no query data — re-dispatching as l-005/l-006 with tighter constraints.

## PLAN (loop 2)

l-004 behavioral data strongly supports h-001 but two gaps block disposition:
1. `??/??/??` on v-001 — container class unresolved; validator blocks benign until closed.
2. Falco co-occurrence (r1 untested) — per lesson `falco-terminal-phase-no-upstream-chain`, must check for collection/persistence/exfiltration events in same window before closing.

Authz contracts ac1 (iam-policy) and ac2 (endpoint-policy) remain indeterminate; identity/policy leads will retry.

```invlang
:L findings [id|loop|name|target|tests|system|window]
l-005|2|container-identity-resolution-retry|v-001|h-001|host-state|n/a
l-006|2|falco-container-timeline-retry|v-001|h-001|elastic|±15m of 2026-06-14T19:10:26Z
```

## ANALYZE (loop 2)

l-005 (container-identity-resolution-retry): real queries executed (container-inspect + passwd + proc-tree on scanner-1). Definitive result:
- Container id 7e76d1cea7c4 = **scanner-1**, image **soc-playground/host-plain:24.04**
- Entrypoint: `/usr/bin/tini -- /usr/local/bin/host-entrypoint.sh /usr/sbin/sshd -D` — tini as init, startup script, sshd as primary service
- uid 1001 = **svc.monitoring** (`/usr/sbin/nologin` shell — non-login service account)
- Active processes include: sshd, syslog, **cron**, elastic-agent. Cron running in container directly explains the ~8-10 min periodic nc cadence.
- Container is currently running.

l-006 (falco-container-timeline-retry): real query executed (Falco events ±15m window). Definitive result:
- 90 Falco events for 7e76d1cea7c4 in the 30-minute window (18:55Z–19:25Z).
- Exactly **one** distinct rule fired: "Launch Suspicious Network Tool in Container" — no write-below-etc, read-sensitive-file-untrusted, write-below-tmp, cron-write, or exfiltration events whatsoever.
- Scan scope: 8 playground hosts (canary-1, db-1, dev-ws-1, jump-box-1, office-ws-1, office-ws-2, web-1, web-2) × 5 ports (22, 80, 443, 5432, 8080) — full service availability check across the environment tier.
- 80 events under uid 1002, 10 under uid 1001 — two service accounts performing the same scan (uid 1002 name unresolved but consistent pattern).
- No exec events beyond nc, no process spawning, no privilege escalation in window.
- r1 (co-occurring collection/persistence events) is **strongly refuted** — the window contains purely nc port-check executions.

```invlang
:V l-005.observations.vertices [id|type|class|ident|attrs?]
v-007|identity|service-account/known-corp|svc.monitoring|uid=1001;shell=/usr/sbin/nologin;container=scanner-1

:E l-005.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-007|runs_on|v-007|v-001||authoritative-source|src=host-state.container-identity-and-uid
e-008|authenticated_as|v-003|v-007||authoritative-source|src=host-state.container-identity-and-uid

:R attr_updates [resolved_by|target|key|value]
l-005|v-001|class|monitoring/internal/known-corp
l-005|v-001|attrs.name|scanner-1
l-005|v-001|attrs.image|soc-playground/host-plain:24.04
l-005|v-001|attrs.entrypoint|/usr/bin/tini -- /usr/local/bin/host-entrypoint.sh /usr/sbin/sshd -D
l-005|v-003|attrs.user|svc.monitoring

:T resolutions
h-001  +  → ++   [l-005,l-006 p1,p2 severe ⟂ e-005,e-006,e-007,e-008 :: scanner-1/svc.monitoring confirms monitoring container and service-account origin; cron in container explains periodic cadence; l-006 r1 severely refuted — 90 events window contains only nc port-checks, zero collection/persistence/exfiltration signals]
```

h-001 is now at `++`. The remaining blocker for benign disposition is authz contract ac1 (iam-policy: is svc.monitoring IAM-authorized to run network tools). l-005 establishes the identity but the identity registry hasn't confirmed authorization scope.

## PLAN (loop 3)

Single remaining gap: ac1 (iam-policy on e-003 — uid 1001 / svc.monitoring authorized to execute network tools in this container). Container class resolved; r1 and r2 both refuted; behavioral case is ++. Identity registry lookup needed to formally close the authz contract.

```invlang
:L findings [id|loop|name|target|tests|system|window]
l-007|3|svc-monitoring-authorization|v-007|h-001|identity|n/a
```

## ANALYZE (loop 3)

l-007 (svc-monitoring-authorization): real queries executed. svc.monitoring is a provisioned service account:
- Email: svc-monitoring@soc-playground.local; `realm_role=service-account`
- Explicitly authorized on scanner-1 via **override** entry (deliberate provisioning, not default role inheritance)
- Authorized on exactly 11 hosts: canary-1, ci-1, config-mgmt-1, db-1, dev-ws-1, jump-box-1, office-ws-1, office-ws-2, scanner-1, web-1, web-2 — the 8-host scan scope (canary-1 through web-2) corresponds precisely to the authorized non-scanner hosts; ci-1 and config-mgmt-1 are in scope but probed on different port profiles
- No sudo, no interactive shell (`/usr/sbin/nologin`) — read-only/observation account consistent with monitoring purpose
- Account is enabled and fully documented

ac1 and ac2 are now closeable: svc.monitoring's provisioning and host-authorization scope confirm both the identity authorization (ac1) and the endpoint-reach authorization (ac2) for the jump-box-1:22 probe.

```invlang
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-007|e-003|ac1|authorized|iam-policy|"svc.monitoring provisioned in identity registry (realm_role=service-account); explicitly authorized on scanner-1 via override; monitoring account name + 11-host scope confirms provisioned monitoring purpose"
l-007|e-004|ac2|authorized|endpoint-policy|"svc.monitoring IAM-authorized on jump-box-1 (one of 11 documented hosts); nc -z -w1 jump-box-1 22 probe recurred 6 times in prior 40min and 9189 times over 7d with no policy block; access scope aligns with authorized endpoint reach"

:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      monitoring-container-health-check
summary                "scanner-1 (soc-playground/host-plain:24.04) runs IAM-authorized nc-z-w1 readiness probes across 8 playground hosts via cron-driven svc.monitoring service account on ~8-10min cadence; 9189-event 7d baseline, fleet-wide pattern across 11 containers, zero co-occurring collection/persistence/exfiltration signals; Falco rule newly deployed and catching known-good monitoring automation."
```
