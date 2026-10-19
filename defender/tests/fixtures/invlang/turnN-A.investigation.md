## ORIENT

Falco rule `v2-falco-authorized-keys-modification` fired on host `soc-playground` at 2026-07-28T16:16:53Z — a write to a user's `~/.ssh/authorized_keys` inside a container. This is a persistence-class signal: an attacker adding their SSH key gets persistent backdoor access. The triage question is **who initiated the write and whether the change is part of an approved key-rotation or admin activity**.

Key facts from the alert:
- Host `soc-playground` is a Docker host (public IP 178.104.17.107, Docker bridge IPs 172.17.0.1/172.18.0.1), `containerized: false` — Falco monitors container workloads running on it.
- Alert description says the write occurred "inside a container" — per Falco's eBPF container monitoring surface.
- No user name, process name, container name, or file path in the alert payload — all must be retrieved from the raw Falco event in Elastic.
- Ancestor event `AZ-pf1zgSr4B7DH3Zx68` in `.ds-logs-falco.alerts-default-2026.06.29-000007` is the underlying Falco hit.

What disposition turns on:
1. **Process identity** — what process wrote to authorized_keys (admin tool vs. unexpected binary)
2. **User identity** — who ran the process (authorized admin vs. root/unknown)
3. **Change authorization** — is there an approved CR covering this host at this time?
4. **Co-occurring events** — are there adjacent attack-phase Falco events (sensitive-file reads, cron writes, network tools) in the same container/time window?

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|container-host/??/known-corp|soc-playground|os=linux;ip=178.104.17.107;docker_bridge=172.17.0.1,172.18.0.1
v-002|file|ssh-credential|authorized_keys|path=??
v-003|process|??|??[pid=??]|image=??;cmdline=??;user=??

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|modified|v-003|v-002|2026-07-28T16:16:53Z|siem-event:siem|falco_rule="Adding ssh keys to authorized_keys";container_name=??
```

## PLAN

The process that wrote to authorized_keys is unknown (v-003 class=??). The first lead is mechanical — retrieve the full Falco event from Elastic to get process name, cmdline, user, container name, and parent process. In parallel, check CMDB for the host's role/criticality, change-mgmt for an approved CR, and Elastic for co-occurring Falco events in the same time window.

Per the lesson `falco-terminal-phase-no-upstream-chain`: the authorized_keys write could be the end of an attack chain; co-occurring Falco rules from adjacent phases (cron/scheduler writes, sensitive-file reads, tmp writes) in the same container window must be checked.

One hypothesis carries the observed topology (a process modified the file). Two authz contracts encode the legitimacy question — change-mgmt and identity. If the Falco event reveals an unexpected process or the authz contracts resolve unauthorized, the co-occurring events lead provides corroborating evidence for escalation.

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?authorized-keys-write-process|v-002|modified|process|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"Falco event shows a recognized admin/automation process (bash, ansible, ssh-keygen) as the writer"
p2|proposed_parent|"Falco event shows a known admin user running the process"
p3|proposed_edge|"Change-mgmt returns an active CR covering soc-playground at alert time"
p4|proposed_edge|"No co-occurring Falco events from adjacent attack phases in the same container window"

:H h-001.refuts [id|refutes|claim]
r1|p1,p2|"Falco event shows unexpected process or unknown user"
r2|p3,p4|"No active CR and co-occurring attack-phase Falco events present"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|change-mgmt|"approved change ticket exists for SSH key addition on soc-playground at alert time"|escalate|escalate
ac2|e-001|iam-policy|"user running the process is permitted to modify SSH authorized_keys on this host"|escalate|escalate

:L findings [id|loop|name|target|tests|system|window]
l-001|1|falco-event-details|v-003|h-001|elastic|±5m
l-002|1|cmdb-host-lookup|v-001||cmdb|n/a
l-003|1|change-mgmt-active-cr|v-001|h-001.ac1|change-mgmt|n/a
l-004|1|co-occurring-falco-events|v-001|h-001|elastic|±10m
```

### GATHER (loop 1)

Dispatching four parallel leads: Falco event details, CMDB lookup, change-mgmt check, and co-occurring Falco events.
```invlang
:V l-001.observations.vertices [id|type|class|ident|attrs?]
v-004|compute|??/??/??|1df4bcd65ee4|container.id=1df4bcd65ee4;kind=container
v-005|identity|user/anonymous|root|uid=0;loginuid=-1

:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|runs_on|v-003|v-004||siem-event:siem|
e-003|authenticated_as|v-003|v-005||siem-event:siem|uid=0;loginuid=-1

:E l-004.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-004|connected_to|v-004|??|2026-07-28T16:06:55Z|siem-event:siem|falco_rule="Launch Suspicious Network Tool in Container";proc=nc;count=27
e-005|connected_to|v-004|??|2026-07-28T16:06:55Z|siem-event:siem|falco_rule="Launch Ingress Remote File Copy Tools in Container";count=21
e-006|connected_to|v-004|??|2026-07-28T16:06:55Z|siem-event:siem|falco_rule="Redirect STDOUT/STDIN to Network Connection in Container";count=60

:R attr_updates [resolved_by|target|key|value]
l-001|v-003|class|bash
l-001|v-003|ident|bash[pid=??]
l-001|v-003|attrs.image|/usr/bin/bash
l-001|v-003|attrs.cmdline|"bash -lc mkdir -p /root/.ssh && chmod 700 /root/.ssh; ts=$(date +%s); echo ssh-rsa AAAAB3NzaC1yc2EAAAAD_fake_key_0_${ts}_attacker attacker@elsewhere >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; ls -la /root/.ssh/authorized_keys"
l-001|v-003|attrs.user|root
l-001|v-003|attrs.anomaly|loginuid=-1;key_comment="attacker@elsewhere";key_material_contains="fake_key"
l-001|v-002|attrs.path|/root/.ssh/authorized_keys
l-001|v-002|ident|/root/.ssh/authorized_keys
l-002|v-001|attrs.knowledge|partial
l-002|v-001|attrs.cmdb_status|not_registered

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-003|e-001|ac1|unauthorized|change-mgmt|"zero active CRs covering soc-playground at 2026-07-28T16:16:53Z — change-mgmt returned empty array"
l-001|e-001|ac2|unauthorized|iam-policy|"writer is root with loginuid=-1 (no tracked login session); SSH key comment is attacker@elsewhere; host soc-playground absent from CMDB inventory (l-002) — no legitimate identity established"

:T resolutions
h-001  null → ++    [l-001 r1 severe ⟂ e-001 :: bash running as root with loginuid=-1 appended key containing 'fake_key' and comment 'attacker@elsewhere' to /root/.ssh/authorized_keys — not a recognized admin process or known admin user]
h-001  ++ → ++      [l-003 r2 severe ⟂ e-001 :: no active CR covering soc-playground at alert time; ac1 unauthorized]
h-001  ++ → ++      [l-004 r2 severe ⟂ e-004,e-005,e-006 :: co-occurring attack-phase Falco events in same container 1df4bcd65ee4: 27 network tool launches (nc), 21 remote file copy tools (curl), 60 STDIN/STDOUT-to-network redirects — full attack chain alongside authorized_keys write]
```

## ANALYZE (loop 1)

All four leads returned. The evidence is conclusive:

**Process identity (l-001):** The writer was `bash` running as `root` (UID 0, loginuid=-1). The command line creates `/root/.ssh/`, then appends an SSH public key whose material literally contains `fake_key` and whose comment is `attacker@elsewhere` to `/root/.ssh/authorized_keys`. This is not a key-rotation operation — no legitimate admin names a key "attacker@elsewhere" or uses placeholder material labeled "fake_key". The `loginuid=-1` means the process was not launched from a tracked login session — no authenticated user identity is associated with this write.

**Host context (l-002):** `soc-playground` is not registered in the CMDB inventory. It is the Docker host VPS running the v2 playground containers, not one of the 11 managed role hosts. CMDB cannot vouch for it.

**Change authorization (l-003):** Zero active change requests covering `soc-playground` at alert time. The authorized_keys modification was not part of any approved change.

**Co-occurring events (l-004):** Container `1df4bcd65ee4` — the same container where the authorized_keys write occurred — also saw:
- 27 "Launch Suspicious Network Tool in Container" events (proc=nc)
- 21 "Launch Ingress Remote File Copy Tools in Container" events (proc=curl)
- 60 "Redirect STDOUT/STDIN to Network Connection in Container" events

This is a full attack chain: remote file copy tools bringing in payloads, network tools establishing connections, STDIN/STDOUT redirection for remote control, and finally SSH key injection for persistence. The authorized_keys write is the persistence step at the end of this chain.

Both authz contracts resolve **unauthorized** — no CR, no legitimate identity. Per `on_unauth: escalate`, this forces escalation regardless of behavioral grading. The behavioral grading independently confirms: the key content is overtly adversarial, the session has no tracked login identity, and the co-occurring events form a complete attack chain in the same container.
```invlang
:T conclude
termination.category   adversarial-confirmed
disposition            malicious
impact_verdict         persistence-backdoor
confidence             high
matched_archetype      ssh-key-injection-persistence
summary                "bash running as root (loginuid=-1) appended an SSH key with comment 'attacker@elsewhere' and material containing 'fake_key' to /root/.ssh/authorized_keys in container 1df4bcd65ee4 on soc-playground. No change request covered the modification. Co-occurring Falco events in the same container and time window — 27 network tool launches (nc), 21 remote file copy tools (curl), 60 STDIN/STDOUT-to-network redirects — form a complete attack chain culminating in SSH key persistence."
```

## REPORT

The Falco `authorized_keys` modification alert on `soc-playground` is a confirmed persistence attack. A `bash` process running as `root` with no tracked login session (`loginuid=-1`) appended an SSH public key whose key material contains the string `fake_key` and whose comment is `attacker@elsewhere` to `/root/.ssh/authorized_keys` inside container `1df4bcd65ee4`. The key content is overtly adversarial — no legitimate administrator names a key "attacker@elsewhere" or uses placeholder material. No approved change request covers this host at the alert time, and the host is not registered in the CMDB inventory. Critically, the same container in the same ±10 minute window produced 27 "Launch Suspicious Network Tool" events (nc), 21 "Launch Ingress Remote File Copy Tools" events (curl), and 60 "Redirect STDOUT/STDIN to Network Connection" events — a full attack chain from initial access through remote file copy, network tool deployment, and finally SSH key injection for persistence. Both authz contracts (change-mgmt and iam-policy) resolve unauthorized. This is a high-confidence malicious finding requiring immediate escalation.
