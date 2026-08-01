## Account: Adversary reconnaissance from compromised dev-ws-1 targeting prod jump-box-1

At approximately 16:33Z on 2026-07-27, an adversary operating from IP **79.177.137.245** established root SSH access to the soc-playground Docker host. This IP carries no benign classification in threat intelligence — it is an unknown, unseeded indicator with zero reputation data. Within two minutes of the dev-ws-1 container's initialization, the adversary executed three actions captured by Falco:

**Anti-forensics (16:33:57Z):** `agent-enroll.sh` triggered the "Clear Log Activities" Falco rule. The adversary cleared container enrollment logs to eliminate forensic evidence of initial access, masquerading as a routine agent enrollment step.

**Persistence (16:35:02Z):** A bash process appended an SSH public key to `~/.ssh/authorized_keys`, keyed as `svc.config-mgmt@rotation`. This granted the adversary persistent root SSH access via publickey authentication. The `svc.config-mgmt` comment is deliberate masquerading — the key was added by a bash process inside the container, not by a configuration management service operating from a known infrastructure IP.

**Implant deployment:** The adversary deployed `python3 /opt/soc-playground/baseline/scheduler.py` as a persistent orchestrator. The process (PID 77) runs as a direct child of **sshd** (PID 7), not as a child of the container init system (tini, PID 1). A legitimate scheduled baseline task would be launched by cron, systemd, or the container entrypoint — not spawned from an SSH session. This process-tree position confirms the scheduler was launched via an interactive or automated SSH login from 79.177.137.245, not as part of the container's designed startup. The path name `/opt/soc-playground/baseline/scheduler.py` is masquerading (MITRE T1036), chosen to blend into the SOC playground environment.

The implant's primary mission is lateral movement reconnaissance. It continuously probes **jump-box-1** — a **prod** bastion owned by team.sre — using `nc -z -w1 jump-box-1 22` (106 events over ~14 hours). It also runs local SSH probes (`nc -z 127.0.0.1 22`, 100 events) to verify local SSH service availability. These are not health checks; they are sustained adversary reconnaissance mapping the connectivity path from a compromised dev workstation toward a production jump box, the gateway to web-1, web-2, and db-1.

The SSH login pattern confirms adversary automation. 79.177.137.245 is the **sole** SSH source IP to soc-playground in the entire 24-hour window (1,660 accepted logins, all root, all publickey, zero failures). There is no legitimate admin SSH traffic — the entire SSH activity IS the adversary's access maintenance. The variable volume (28–1,049 logins/hour) reflects automated session cycling, not human administrative work.

The Falco alert at 06:24:43Z fired on one iteration of the ongoing nc probe. The 141 SSH logins in the preceding 10 minutes (06:14:43–06:24:41Z) represent the adversary's session maintenance immediately before this probe cycle. The 2-second gap between the last SSH login (06:24:41Z) and the nc execve (06:24:43Z) reflects the implant establishing a fresh session and then executing its reconnaissance routine. The `dpkg --print-foreign-architectures` event at 06:25:04Z is consistent with the adversary querying system architecture for potential tool deployment.

### Addressing awkward observations

**CMDB authorizes dev-ws-1 → jump-box-1:** CMDB documents intended trust policy between roles, not the legitimacy of the actor currently operating inside the container. The adversary is exploiting a pre-authorized network path from a compromised host. An authorized path does not authenticate the actor using it.

**nc probes are habitual (106 over 14h):** Habitual frequency does not establish legitimacy. The probes are habitual because the adversary's implant runs them on a fixed schedule. The entire 14-hour history is the adversary's campaign duration, not a pre-existing operational baseline predating the compromise.

**SSH volume is "within baseline":** The baseline itself is adversary activity. 79.177.137.245 is the only source IP — there is no separate legitimate baseline to compare against. A pattern consisting entirely of an unclassified, unknown IP is not evidence of benign behavior.

**No collection/persistence Falco events in ±15m window:** The persistence (SSH key addition) and anti-forensics (log clearing) occurred at 16:33–16:35Z on July 27, 14 hours before the alert window. The ±15m window captures the adversary's steady-state operational phase, not the initial compromise. The "Adding ssh keys to authorized_keys" and "Clear Log Activities" events appear in the 24h historical Falco data (l-008), confirming the persistence and anti-forensics phases occurred earlier.

**Container image is `soc-playground/host-plain:24.04`:** A plain host image in a playground is an ideal initial target — it provides SSH, bash, and standard networking utilities without application-specific hardening, making it trivial to repurpose once access is obtained.

```yaml
claims:
  - entity: 79.177.137.245
    field: threat_intel_verdict
    asserted_value: unknown (not classified as benign or known-infrastructure)
    would_show_in: l-007
  - entity: 79.177.137.245
    field: sole_ssh_source_to_soc_playground
    asserted_value: true (no other source IPs in 24h Accepted SSH events)
    would_show_in: l-010
  - entity: scheduler.py (PID 77 in dev-ws-1)
    field: parent_process
    asserted_value: sshd (PID 7), not tini/init (PID 1)
    would_show_in: l-011
  - entity: dev-ws-1
    field: ssh_key_added_to_authorized_keys
    asserted_value: true (bash appended key to authorized_keys at 2026-07-27T16:35:02Z)
    would_show_in: l-008
  - entity: jump-box-1
    field: role_and_criticality
    asserted_value: jump-box / prod
    would_show_in: l-006
  - entity: nc process in dev-ws-1
    field: cmdline
    asserted_value: "nc -z -w1 jump-box-1 22"
    would_show_in: l-001
```