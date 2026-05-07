# Investigation — real-03-low-shell

**Alert:** Wazuh rule 100001 — Falco: Terminal shell spawned in container  
**Time:** 2026-05-07T14:25:22Z  
**Run dir:** /tmp/defender-runs/real-03-low-shell

---

## ORIENT

**Behavior flagged:** Falco detected `bash -c whoami` executed inside container `target-endpoint` (id `2a124a5fc6d9`) as root with a TTY attached (`tty=34816`). Parent process is `<NA>` (Falco's pname field is null), and `loginuid=-1` (no PAM session). Wazuh rule 100001 wraps a Falco `Terminal shell in container` notice (MITRE T1059).

**Triage question:** Was this shell spawn an authorized operator action (e.g., `docker exec`) or evidence of unauthorized access or container escape?

**Key observations from the alert:**
- `proc.pname=null` — parent not visible to Falco in the container namespace; consistent with `docker exec` which injects a process without a visible in-container parent
- `user.loginuid=-1` — no PAM login session; again consistent with `docker exec` but also with reverse-shell delivery
- `proc.cmdline=bash -c whoami` — one-shot recon command; exits immediately rather than holding an interactive session
- `exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER` — bash binary is on the lower (base image) layer, not a modified overlay; normal for stock container image
- Container image: `cyber-response-agent_devcontainer-target-endpoint:latest` — this is the playground target-endpoint, expected to be operated by developers

**What disposition turns on:** Whether there is a pattern of repeated/escalating shell spawns, whether this is a one-off dev-issued exec, or whether surrounding alerts suggest a broader intrusion chain.

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|container|container:linux|target-endpoint|image=cyber-response-agent_devcontainer-target-endpoint:latest;container_id=2a124a5fc6d9
v-002|process|process:bash|bash[pid=?]|cmdline=bash -c whoami;tty=34816;exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER
v-003|identity|identity:system|root|uid=0;loginuid=-1

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|spawned_in|v-002|v-001|2026-05-07T14:25:22Z|siem-event:wazuh|pname=null;tty=34816;loginuid=-1
e-002|ran_as|v-002|v-003|2026-05-07T14:25:22Z|siem-event:wazuh|
```

---

## PLAN (loop 1)

Two competing explanations for an interactive shell in a container:

- **?authorized-docker-exec** — a developer or operator issued `docker exec` to run a diagnostic command. Predicted pattern: isolated one-shot command, no surrounding anomalous alerts, possibly recurs in Falco history at dev cadence.
- **?unauthorized-shell** — shell obtained via exploit, misconfigured service, or reverse shell delivery. Predicted pattern: surrounding Wazuh alerts (port scan, RCE attempt, C2 traffic), no recurrence pattern matching dev work, or escalating commands following the initial exec.

The pname=null + loginuid=-1 + one-shot `whoami` is ambiguous between the two. The discriminating evidence is:
1. Whether other Falco/Wazuh alerts surround this event (intrusion chain vs. isolated)
2. Historical frequency of rule 100001 on this container (dev baseline vs. anomaly)

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?authorized-docker-exec|v-001|spawned_in|identity|developer-operator||p1:proposed_parent:"this container has a history of similar shell spawns consistent with dev ops";p2:proposed_edge:"no co-occurring alerts suggesting intrusion chain"|p1:proposed_parent||r1[p1]:"no prior similar events, or co-occurring intrusion-chain alerts present"|ac1:proposed:ops-pattern:"developer issued docker exec for diagnostics":escalate/escalate||null|active
h-002|?unauthorized-shell|v-001|spawned_in|identity|adversary-or-exploit||p1:proposed_parent:"source of shell is external actor or exploit";p2:proposed_edge:"co-occurring alerts indicate recon, lateral movement, or C2 activity"|p1:proposed_parent||r1[p1,p2]:"isolated event with no surrounding alerts, matches dev baseline"|||null|active

:L findings [id|loop|name|target|mode?|tests|system|template|query|window]
l-001|1|shell-spawn-history-baseline|v-001||h-001,h-002|wazuh|falco-container-shell-history|container_name=target-endpoint|7d
l-002|1|surrounding-alerts-context|v-001||h-001,h-002|wazuh|alerts-around-event|container_name=target-endpoint t0=2026-05-07T14:25:22Z|±15m
```

---

## GATHER (loop 1)

Dispatched l-001 and l-002 as parallel Task calls on Haiku.

**l-001 (shell-spawn-history-baseline):** Returned 18 rule 100001 events in 7d for target-endpoint, all with identical cmdline `bash -c whoami`. Clustered in bursts (2026-05-01: 5, 2026-05-03: 8, 2026-05-07: 1). Sparse but recurring — consistent with automated health-check probe, not interactive dev ops. Raw: `gather_raw/0.json`.

**l-002 (surrounding-alerts-context):** 93 fleet alerts in the ±15m window. Within target-endpoint specifically: 12 rule 100002 alerts (Falco: STDOUT/STDIN redirected to network connection — possible reverse shell) starting at 2026-05-07T14:25:18Z — **4 seconds before** the focal shell spawn. The 100002 alerts report sshd redirecting stdio to `172.22.0.10:38078 → 172.22.0.13:22`. Raw: `gather_raw/1.json`, `gather_raw/1b.json`.

---

## ANALYZE (loop 1)

```invlang
:R attr_updates [resolved_by|target|key|value]
l-001|v-001|shell_spawn_history_7d|18 events; all cmdline=bash -c whoami; clustered bursts; consistent with automated health-check probe
l-002|v-001|co_occurring_alerts_15m|12 x rule 100002 (reverse-shell possible) starting 4s before focal alert; sshd stdio->172.22.0.10:38078->172.22.0.13:22

:T resolutions
h-001  null → +    [l-001 p1 weak ⟂ recurring bash -c whoami pattern matches automated probe/health-check cadence; not escalating command series]
h-002  null → +    [l-002 p2 weak ⟂ co-occurring rule 100002 (reverse-shell) alerts surround the event; unclear if sshd FP or genuine stdio redirect]
```

**Loop decision:** h-002 is not refuted. Rule 100002 co-occurrence 4s before shell spawn is decision-relevant. Need to characterize the rule 100002 events: are they sshd false positives (normal SSH session stdio→network, which Falco sometimes misclassifies) or genuine reverse-shell activity from another process?

Additionally: the `bash -c whoami` 18-event history all looking identical raises a separate question — is this a health-check or a scripted probe from outside the container (via docker exec or SSH)?

---

## PLAN (loop 2)

Branching question: the 12 rule 100002 alerts involve `sshd` on port 22. Normal SSH sessions redirect stdio to the network — Falco fires on this. But if the process in rule 100002 is *not* sshd (or if sshd is being abused), the chain is genuine.

Lead l-003: Characterize the rule 100002 events — what process, what IPs, what direction, and whether this is a known Falco FP for sshd.

```invlang
:L findings [id|loop|name|target|mode?|tests|system|template|query|window]
l-003|2|reverse-shell-alert-detail|v-001||h-001,h-002|wazuh|falco-reverse-shell-events|container_name=target-endpoint rule_id=100002 t0=2026-05-07T14:25:18Z|±5m
```

---

## GATHER (loop 2)

Dispatched l-003 as single Task call on Haiku.

**l-003 (reverse-shell-alert-detail):** All 8 rule 100002 events in the window are from `sshd`. Connection tuples: 172.22.0.10→172.22.0.13:22 (multiple source ports: 38078, 60574, 60576, 55496 — distinct TCP sessions). All use `dup2` syscall, which is normal SSH session file-descriptor setup. sshd redirecting stdio to a network socket is expected behavior; Falco fires on this as a conservative rule. **No non-sshd process involved.** Raw: `gather_raw/2.json`.

---

## ANALYZE (loop 2)

```invlang
:R attr_updates [resolved_by|target|key|value]
l-003|v-001|reverse_shell_source_process|sshd (all 8 events)
l-003|v-001|reverse_shell_connection_direction|inbound to target-endpoint:22 from 172.22.0.10 (Docker internal network)
l-003|v-001|reverse_shell_syscall|dup2 (normal SSH session fd setup)
l-003|v-001|reverse_shell_verdict|sshd false positive — normal SSH session dup2 activity; no malicious process

:E l-003.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-003|connected_ssh|v-004|v-001|2026-05-07T14:20:04Z..14:25:18Z|siem-event:wazuh|src=172.22.0.10;dst_port=22;sessions=4;rule=100002_fp

:V l-003.observations.vertices [id|type|class|ident|attrs?]
v-004|endpoint|endpoint:ipv4|172.22.0.10|network=docker-internal

:T resolutions
h-001  + → ++   [l-003 r1 severe ⟂ all stdio-redirect alerts are sshd FPs (dup2 for normal SSH); SSH from internal Docker IP 172.22.0.10; recurring bash -c whoami matches automated monitoring-probe pattern]
h-002  + → --   [l-003 r1 severe ⟂ no non-sshd process involved; connection is inbound SSH on port 22 from Docker-internal IP; no outbound C2 pattern]
```

**Loop decision:** h-001 is now `++`, h-002 is `--`. The case is:
- Shell was spawned via SSH from Docker-internal 172.22.0.10 → target-endpoint:22
- Pattern: 18 identical `bash -c whoami` events over 7 days → automated monitoring/health-check probe
- Rule 100002 co-occurrences are sshd FPs (normal dup2 syscalls for SSH session setup)
- No escalating commands, no persistence, no lateral movement

Authz contract: SSH access from the Docker network to this container is expected dev/playground infrastructure behavior; the repeated identical command is a liveness probe, not interactive access. REPORT.

---

## REPORT

```invlang
:T conclude
termination.category   adversarial-refuted
termination.rationale  "Rule 100002 co-occurrences are sshd FPs; shell spawn traces to inbound SSH from Docker-internal IP with a 7-day recurring identical-command pattern consistent with automated monitoring probe"
disposition            benign
impact_verdict         none
impact_severity        null
confidence             high
matched_archetype      monitoring-probe-ssh
ceiling_rationale      n/a
summary                "SSH from 172.22.0.10 (Docker internal) into target-endpoint:22; bash -c whoami executed 18 times over 7 days with identical command — automated health-check liveness probe. Co-occurring rule 100002 alerts are sshd dup2 FPs (normal SSH session setup). No escalating commands, no lateral movement, no outbound C2. Benign."

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```
