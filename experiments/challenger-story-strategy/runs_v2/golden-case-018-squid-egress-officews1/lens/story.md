## Account: Adversary reconnaissance from compromised dev-ws-1 targeting prod jump-box-1

At 16:33:57Z on 2026-07-27, an adversary operating from IP **79.177.137.245** compromised the **dev-ws-1** container (ID `ffbff1299702`, image `soc-playground/host-plain:24.04`) on the soc-playground Docker host. This IP carries no benign classification in threat intelligence — the SOC environment's threat-intel service (172.18.0.3:8080) returned an `unknown` verdict with zero reputation data, no tags, and no sources. The compromise unfolded in three phases captured by Falco's 24-hour historical data:

**Anti-forensics (16:33:57Z):** `agent-enroll.sh` triggered the "Clear Log Activities" Falco rule. The adversary cleared container enrollment logs to eliminate forensic evidence of initial access, masquerading as a routine agent enrollment step.

**Implant deployment (16:34:56Z):** The adversary deployed `python3 /opt/soc-playground/baseline/scheduler.py` as a persistent orchestrator, which immediately began lateral-movement reconnaissance with its first `nc -z -w1 jump-box-1 22` probe. The path name `/opt/soc-playground/baseline/scheduler.py` is masquerading (MITRE T1036), chosen to blend into the SOC playground environment as a legitimate baseline automation component.

**Persistence (16:35:02Z):** A bash process appended an SSH public key to `~/.ssh/authorized_keys`, keyed as `svc.config-mgmt@rotation`. The key string `ssh-rsa AAAAB3rotated$(date +%s) svc.config-mgmt@rotation` contains an unevaluated `$(date +%s)` command substitution — the adversary's key-generation script had a shell quoting error that prevented timestamp expansion, leaving the raw substitution in the key comment. The `svc.config-mgmt` comment borrows the name of a real, highly-privileged service account that exists on both dev-ws-1 and jump-box-1 with `sudo: true` and is managed by the legitimate `config-mgmt-1` host. The masquerade is effective precisely because it impersonates an existing trusted service: the key was added by a bash process inside the container, not by `config-mgmt-1` performing a routine rotation. The first SSH login from 79.177.137.245 using this planted key occurred at 16:40:32Z — seven minutes after the key was added, confirming the key was planted by the adversary and then used for ongoing access.

The implant's primary mission is lateral movement reconnaissance. It continuously probes **jump-box-1** — a **prod** bastion owned by team.sre and the gateway to web-1, web-2, and db-1 — using `nc -z -w1 jump-box-1 22` (106 events over ~14 hours, from 16:34:56Z July 27 through 06:24:44Z July 28). It also runs local probes: `nc -z 127.0.0.1 22` (100 events) to verify local SSH service availability, and `curl -sf -o /dev/null http://127.0.0.1/` (100 events) to verify local HTTP readiness. These local curl checks produce no HTTP traffic visible to Zeek because they target loopback, which does not traverse the network tap. They are not health checks in the benign operational sense — they are the implant's own service-availability verification, executed on a fixed schedule alongside the lateral probes. The co-occurrence of SSH-port probes, HTTP-port probes, and lateral-target probes over 14 hours reflects a single automated routine, not independent administrative tasks.

The scheduler's process architecture reveals adversary design. PID 77 (`python3 /opt/soc-playground/baseline/scheduler.py`) runs as a direct child of **sshd** (PID 7), not as a child of the container init system (tini, PID 1) or of the cron daemon (PID 68, which is present and actively running cron.daily jobs). The scheduler invokes nc via a bash subprocess — producing the chain sshd → python3 → bash → nc, of which Falco captures the final link (bash → nc). The bash and nc processes are transient (nc has a 1-second timeout per `-w1`), so they do not appear in process snapshots taken minutes after execution.

### Container restart and persistence across reboots

The container was restarted at approximately 06:09Z on July 28 — roughly 15 minutes before the alert. The ps snapshot captured at 06:30Z shows tini (PID 1) with ~21 minutes elapsed, sshd (PID 7) with ~21 minutes, and scheduler.py (PID 77) with ~21 minutes, all starting within a 3-second window. A second ps snapshot at 06:38Z confirms the same timeline (~29 minutes elapsed). The Falco 24-hour historical data captures the full campaign: events from the container's July 27 incarnation (nc probes from 16:34:56Z, persistence at 16:35:02Z, anti-forensics at 16:33:57Z) and events from its July 28 post-restart incarnation.

The near-identical start times of sshd and scheduler.py at container boot are not evidence of benign startup design — they are evidence of adversary persistence that survives restarts. The adversary's automation from 79.177.137.245 fires an SSH login the instant sshd becomes available: the first accepted SSH login in the 06:00 hour bucket is at 06:09:08Z, exactly when sshd starts, and scheduler.py begins one second later at 06:09:09Z. A legitimate scheduled baseline task would be launched by cron (which is present and functioning) or the container entrypoint (tini) — not spawned from an SSH session established within one second of the daemon's availability. The adversary chose to parent the implant under sshd rather than cron specifically to maintain control via interactive SSH sessions, allowing reconfiguration without modifying cron tables.

### SSH automation pattern

79.177.137.245 is the **sole** SSH source IP to soc-playground in the entire 24-hour window (1,660 accepted logins, all from a single user, zero other source IPs). There is no legitimate admin SSH traffic — the entire SSH activity is the adversary's access maintenance. The variable volume (16–1,049 logins/hour) reflects automated session cycling, not human administrative work.

The SSH activity is not continuous across 24 hours. After the initial July 27 activity (28 logins at 16:00, 328 at 17:00, 35 at 18:00, 16 at 19:00, 1,049 at 20:00), there is a ~9-hour gap (20:57:30Z July 27 → 06:09:08Z July 28) with no accepted logins. The adversary's automation paused overnight or maintained persistent sessions without re-authentication, then resumed immediately upon the container's restart at 06:09Z July 28 (204 logins in the 06:00 hour bucket). The burst of 204 logins between 06:09:08Z and 06:25:10Z includes the 141 accepted logins in the 10-minute alert window (06:14:43–06:24:41Z, confirmed by the ±10m auth log query) — the adversary's session maintenance immediately before the probe cycle that triggered the Falco alert.

### Alert-time events

The Falco alert at 06:24:43Z fired on one iteration of the ongoing `nc -z -w1 jump-box-1 22` probe. Zeek confirms a matching TCP connection at 06:24:43.574Z from 172.18.0.25 (dev-ws-1) to 172.18.0.14 (jump-box-1) on port 22, with no SSH protocol negotiation (204 bytes out, 207 bytes in) — a zero-I/O port probe, not an established SSH session. The 2-second gap between the last SSH login (06:24:41Z) and the nc execve (06:24:43Z) reflects the implant establishing a fresh session and then executing its reconnaissance routine via bash.

The `dpkg --print-foreign-architectures` event at 06:25:04Z has parent process `apt-config`, indicating the adversary (or the implant) initiated an `apt` command (e.g., `apt install` or `apt update`) which internally invoked `apt-config` and `dpkg` to query system architecture for potential tool deployment.

### Addressing awkward observations

**CMDB authorizes dev-ws-1 → jump-box-1:** CMDB documents intended trust policy between roles, not the legitimacy of the actor currently operating inside the container. The adversary is exploiting a pre-authorized network path from a compromised host. An authorized path does not authenticate the actor using it.

**nc probes are habitual (106 over 14h):** Habitual frequency does not establish legitimacy. The probes are habitual because the adversary's implant runs them on a fixed schedule. The entire 14-hour history is the adversary's campaign duration, not a pre-existing operational baseline predating the compromise.

**SSH volume is "within baseline":** The baseline itself is adversary activity. 79.177.137.245 is the only source IP — there is no separate legitimate baseline to compare against. A pattern consisting entirely of an unclassified, unknown IP with no reputation data is not evidence of benign behavior.

**No collection/persistence Falco events in ±15m window:** The persistence (SSH key addition) and anti-forensics (log clearing) occurred at 16:33–16:35Z on July 27. The ±15m window captures the adversary's steady-state operational phase, not the initial compromise. The "Adding ssh keys to authorized_keys" and "Clear Log Activities" events appear in the 24h historical Falco data (l-008), confirming the persistence and anti-forensics phases occurred earlier.

**Container image is `soc-playground/host-plain:24.04`:** A plain host image in a playground is an ideal initial target — it provides SSH, bash, and standard networking utilities without application-specific hardening, making it trivial to repurpose once access is obtained.

**jump-box-1's own null-protocol connections to 172.18.0.9:** Zeek shows jump-box-1 initiating null-protocol TCP connections to 172.18.0.9:22. These are legitimate administrative checks performed by the jump box itself — a bastion routinely verifying connectivity to hosts it manages — and are separate from the dev-ws-1 implant's reconnaissance. They do not involve dev-ws-1 as either source or destination.

**Falco container enrichment gaps:** The Falco alert event shows `container.name: "<NA>"`, `container.image.repository: null`, `user.name: "<NA>"`, and `user.loginuid: -1`. The dev-ws-1 name and image attribution come from Docker runtime metadata (l-002), not Falco's container enrichment. The root/publickey SSH attribution comes from the SSH auth logs (l-004), not from this Falco execve event. Falco commonly does not resolve user context for containerized syscall events.

```yaml
claims:
  - entity: 79.177.137.245
    field: threat_intel_verdict
    asserted_value: unknown (verdict=unknown, score=0, no sources, no tags)
    would_show_in: l-007
  - entity: 79.177.137.245
    field: sole_ssh_source_to_soc_playground
    asserted_value: true (no other source IPs in 24h Accepted SSH events)
    would_show_in: l-010
  - entity: 79.177.137.245
    field: total_accepted_ssh_logins_24h
    asserted_value: "1660"
    would_show_in: l-010
  - entity: scheduler.py (PID 77 in dev-ws-1)
    field: parent_process
    asserted_value: sshd (PID 7), not tini/init (PID 1)
    would_show_in: l-002
  - entity: scheduler.py (PID 77 in dev-ws-1)
    field: cmdline
    asserted_value: "python3 /opt/soc-playground/baseline/scheduler.py"
    would_show_in: l-011
  - entity: dev-ws-1
    field: ssh_key_added_to_authorized_keys
    asserted_value: true (bash appended key with comment svc.config-mgmt@rotation at 2026-07-27T16:35:02Z)
    would_show_in: l-008
  - entity: dev-ws-1
    field: container_name_and_image
    asserted_value: name=dev-ws-1, image=soc-playground/host-plain:24.04
    would_show_in: l-002
  - entity: jump-box-1
    field: role_and_criticality
    asserted_value: jump-box / prod, owner=team.sre
    would_show_in: l-006
  - entity: nc process in dev-ws-1
    field: cmdline
    asserted_value: "nc -z -w1 jump-box-1 22"
    would_show_in: l-001
  - entity: nc probes from dev-ws-1 to jump-box-1
    field: count_and_duration
    asserted_value: "106 events from 2026-07-27T16:34:56Z through 2026-07-28T06:24:44Z"
    would_show_in: l-008
  - entity: Zeek connection dev-ws-1 to jump-box-1
    field: connection_at_alert_time
    asserted_value: TCP null-protocol connection at 2026-07-28T06:24:43.574Z from 172.18.0.25 to 172.18.0.14 port 22
    would_show_in: l-005
  - entity: Falco alert event
    field: alert_time
    asserted_value: 2026-07-28T06:24:43Z
    would_show_in: l-001
  - entity: SSH auth logins in ±10m alert window
    field: accepted_count
    asserted_value: "141 (all root, all publickey, zero failures, source 79.177.137.245)"
    would_show_in: l-004
```