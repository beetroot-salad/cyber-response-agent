## Account: Adversary reconnaissance from compromised dev-ws-1, staging lateral movement through jump-box-1

At approximately 16:33 UTC on 2026-07-27, an adversary compromised the container identified as `dev-ws-1` (container ID `ffbff1299702`) on the `soc-playground` Docker host. The `dev-ws-1` designation comes from the container name and CMDB role (role=`dev-ws`, criticality=`dev`, owner=`team.dev`), not from the base image — which is a generic `host-plain:24.04` template reused across multiple playground roles. Three Falco events fired within the same second at 16:33:57 — "Clear Log Activities" from `agent-enroll.sh`, "Write below etc" from `elastic-agent`, and "Unexpected UDP Traffic" from `sshd -D` — marking the initial intrusion: log clearing (anti-forensics), system configuration modification, and SSH daemon startup. No Falco events of any kind exist for this container before 16:33:57 in the 24-hour collection window, indicating the container (or Falco collection on it) began at approximately this time.

At 16:35:02 UTC, the adversary added an SSH public key to `root`'s `authorized_keys` via a bash command disguised as a config-management key rotation. The key string `AAAAB3rotated$(date +%s)` does not begin with `AAAAB3NzaC1yc2E` — the mandatory prefix of a valid OpenSSH RSA public key — indicating a forged key inserted under a `svc.config-mgmt@rotation` guise for persistent root access. The `svc.config-mgmt` account is a real, sudo-enabled service account on `jump-box-1` (the very bastion being probed), which strengthens the disguise: the adversary is impersonating a legitimate management identity that genuinely administers the target.

One minute earlier, at 16:34:56 UTC, the first reconnaissance probes had already begun: `nc -z -w1 jump-box-1 22` and `nc -z 127.0.0.1 22`, launched under `bash` and `runuser` respectively. The jump-box-1 probe tests whether the production bastion's SSH port is reachable from the compromised container; the localhost probe confirms the adversary's SSH backdoor is listening. The scheduler uses `runuser` for the local backdoor check (testing under a different user context) and `bash` for the remote jump-box probe.

At 16:40:32 UTC — five minutes after the SSH key was planted — the first login from `79.177.137.245` arrived. This IP is the sole SSH source for the entire `soc-playground` host across 24 hours (1,660 accepted logins, all root, all publickey). Threat intelligence returns `unknown` for this IP: no benign classification, no corporate ownership, no prior reputation. The burst pattern (28 → 328 → 35 → 16 → 1049 → 204 per hour, with multi-hour gaps) is consistent with automated C2 check-ins and interactive session establishment, not with steady-state infrastructure monitoring.

The adversary modified or replaced `/opt/soc-playground/baseline/scheduler.py` — a Python process running as root (PID 77), child of `sshd` — to orchestrate continuous SSH port probes against `jump-box-1`. The scheduler spawns `bash`, which runs `nc -z -w1 jump-box-1 22` approximately every 8 minutes. The probe processes run as uid 1009, not uid 0 — the root-owned scheduler drops to a non-root service account for child process execution, consistent with the `runuser` wrapper seen in the localhost probes. Over 14 hours, 106 probes targeted `jump-box-1:22` and 100 targeted `127.0.0.1:22`. Zeek confirms these are zero-I/O TCP probes (204 bytes out, 207 bytes in, no SSH protocol) — pure port discovery, not legitimate SSH sessions. The target is significant: `jump-box-1` is a production bastion (role=`jump-box`, criticality=`prod`) whose `trust_edges_out` include `web-1`, `web-2`, `db-1`, and `dev-ws-1` — the latter creating a bidirectional dev-to-bastion relationship. The adversary exploits the `dev-ws-1` → `jump-box-1` direction; the reverse edge remains available for a later stage. The CMDB also lists additional reachable hosts in the playground network (`canary-1`, `office-ws-1`, `office-ws-2`) that the adversary has not yet been observed probing — the reconnaissance scope may be broader than the current observations capture.

A point-in-time process snapshot at 06:38:19 UTC shows `scheduler.py` (PID 77) with no child processes. This is expected: `nc -z -w1` completes in under one second and fires roughly every 8 minutes, so a single `ps` capture between probe cycles would miss the ephemeral `bash`/`nc` children.

The container restarted at approximately 06:09 UTC on 2026-07-28. The SSH daemon resumed as `sshd -D -R` (re-exec mode after restart, distinct from the initial `sshd -D` at 16:33:57). The compromised scheduler resumed probing within 2 minutes (first probe at 06:11:42 UTC), demonstrating that the adversary's modifications persist across restarts — either through a persistent volume or image-level compromise. SSH logins from `79.177.137.245` resumed at 06:09:08 UTC, with 204 accepted logins over 16 minutes, the last at 06:25:10 UTC — one second before the alert fired at 06:25:11 UTC. The nc probe at 06:24:43 UTC occurred during this active login burst, 27 seconds before the final login. The adversary was actively connected and orchestrating activity throughout the alert window.

Zeek also recorded `jump-box-1` (`172.18.0.14`) making two full SSH connections to `172.18.0.9:22` at 06:18:50 and 06:19:52, with ~9,000–10,000 bytes exchanged and `network.protocol: ssh`. The identity of `172.18.0.9` is not resolved by any available lead. If this is an unauthorized destination, it suggests the adversary may have already compromised `jump-box-1` and is conducting further lateral movement through the bastion; if it is a legitimate management target, it is expected bastion administration. Either way, the observation does not alter the core account: the adversary on `dev-ws-1` is probing the bastion as a staging target.

The co-occurring `curl -sf -o /dev/null http://127.0.0.1/` events (7 in the alert window, 100 in 24h, first_seen 16:34:56 — the same second as the first nc probe) are local health checks that appeared from the moment the container started. No Falco events exist before 16:33:57, so all scheduler activity — curl included — is post-startup; "preserved" means present from container creation, not pre-existing a defender-recognized baseline. No Zeek HTTP records exist for `172.18.0.25` (dev-ws-1) because the curl targets loopback — consistent with a local service-availability check, not exfiltration. The single `dpkg --print-foreign-architectures` event at 06:25:04 is apt's routine architecture query (confirmed by `cron.daily/apt-compat` in the process tree) and does not contradict the adversary narrative.

### Accommodating awkward observations

**nc probes are habitual (206 events over 14 hours).** Habitual does not mean benign. An adversary who has compromised the scheduler produces habitual patterns by design — continuous low-frequency probes blend into any baseline a defender might build. The 14-hour span marks the duration of adversary presence, not evidence of legitimacy. The first probes appear at 16:34:56, one minute after the log-clearing and `/etc` write events at 16:33:57, establishing the temporal boundary of the intrusion.

**CMDB shows dev-ws-1 has a trust edge to jump-box-1.** A CMDB trust edge describes network reachability, not intent. The adversary is abusing an existing dev-to-prod trust relationship — a classic lateral movement technique. The trust edge is bidirectional (jump-box-1 also lists dev-ws-1 in its trust_edges_out), but the adversary exploits only the dev→bastion direction for this phase.

**scheduler.py path contains "baseline".** A filename is not evidence of legitimacy. An adversary with root access can name a malicious script anything; choosing an innocuous name is basic operational security. The data shows the process exists and spawns `bash → nc`; it does not show the script's contents or that they match the original container image.

**48 "Contact cloud metadata service from container" events from elastic-otel-co.** These are present in the ±15m alert window but are generated by `elastic-otel-co`, a child of `elastic-agent` — Elastic's OpenTelemetry collector performing routine telemetry collection. They are not adversary IMDS credential theft.

**18 "Redirect STDOUT/STDIN to Network Connection in Container" events from sshd, plus 197 "Unexpected UDP Traffic" events from `sshd -D -R` across the full 14-hour window.** These are the operational footprint of the running SSH backdoor — the daemon accepting connections, relaying I/O for interactive sessions, and generating UDP traffic as part of its normal operation. Falco's sshd rules fire for ongoing session activity, not solely on login, so events continuing to 06:28:57 — past the final login at 06:25:10 — are expected artifacts of sessions that remained open. The initial "Unexpected UDP Traffic" event at 16:33:57 from `sshd -D` marked the daemon's first startup; the subsequent 197 events under `sshd -D -R` reflect continuous operation after the restart.

**No collection/persistence Falco events in the ±15m alert window.** The adversary established persistence 14 hours earlier (16:33–16:35 on 07-27). The alert window captures the ongoing reconnaissance and lateral-movement-preparation phase, not initial access. The absence of new persistence events is expected — the adversary already has what they need.

**Threat intel returns "unknown" for 79.177.137.245.** "Unknown" is not "benign." No source classifies this IP as corporate infrastructure, admin VPN, or known automation. A previously unseen IP being the sole root SSH source for an entire host — with no other IP ever logging in — is consistent with attacker infrastructure, not with established operational tooling that would have a documented identity.

**SSH volume: 204 logins in 16 minutes (06:09:08–06:25:10).** Of these, 141 fell within a 10-minute sub-window (06:14:43–06:24:41) captured by the narrower ±10m auth-log query. The 24h burst pattern (28–1049 per hour) is itself the adversary's activity pattern, not a pre-existing legitimate baseline. The data shows zero SSH logins from any IP other than `79.177.137.245` — there is no independent legitimate baseline to compare against. The variability reflects interactive adversary sessions and automated tooling bursts, not a monitoring agent with fixed cadence.

**The "Adding ssh keys" event used `$(date +%s)` in the key string.** The Falco-captured cmdline shows `echo "ssh-rsa AAAAB3rotated$(date +%s) svc.config-mgmt@rotation"`. Whether or not the shell expanded the timestamp before writing, the prefix `AAAAB3rotated` is not a valid base64-encoded SSH key header (legitimate RSA keys begin `AAAAB3NzaC1yc2E`). This is a forged key disguised with a rotation naming convention.

```yaml
requires:
  - assertion: 79.177.137.245 is not classified as a known-benign or corporate IP in any reputation source
    settled_by: l-007
    if_false: If any source classified this IP as legitimate corporate infrastructure, the SSH logins would be attributable to authorized administration and the account would collapse
  - assertion: Container ID ffbff1299702 is the container the account calls dev-ws-1
    settled_by: unsettled
    if_false: The account describes the wrong container; all process, network, and CMDB claims are misattributed
  - assertion: scheduler.py (PID 77) is the parent process that spawns bash, which runs nc — the full process tree at 06:24:43 shows this chain
    settled_by: unsettled
    if_false: The orchestrator of the nc probes is not scheduler.py; the account's claim that a compromised scheduler automates reconnaissance is wrong
  - assertion: /opt/soc-playground/baseline/scheduler.py has been modified from its original container-image version by the adversary to launch nc probes, and the host-plain:24.04 image does not ship with this probe behavior by default
    settled_by: unsettled
    if_false: The scheduler is a legitimate baseline component that has always run these probes, the nc activity is authorized monitoring, and the reconnaissance narrative collapses
  - assertion: The 48 "Contact cloud metadata service from container" events from elastic-otel-co are benign Elastic-agent telemetry, not adversary IMDS credential collection
    settled_by: unsettled
    if_false: The adversary is also stealing cloud credentials via the metadata endpoint, expanding the scope beyond what the account describes
  - assertion: SSH logins in the alert window came from 79.177.137.245 — the Falco sshd process events do not themselves contain source-IP data
    settled_by: unsettled
    if_false: The Falco sshd process events may correspond to logins from a different source IP, breaking the correlation between external SSH entry and nc probe activity
  - assertion: 79.177.137.245 is attacker-controlled infrastructure, not a legitimate admin/automation IP belonging to the organization
    settled_by: unsettled
    if_false: The 1,660 root SSH logins from this IP are legitimate administrative access, the initial-access and C2 narrative collapses, and the remaining observations reduce to a dev container running authorized connectivity checks
  - assertion: 79.177.137.245 is the sole SSH source for the soc-playground host across the entire 24-hour period
    settled_by: unsettled
    if_false: Other IPs logged in to soc-playground during the 24h window, providing an independent legitimate baseline that undermines the claim that all SSH activity is adversary-originated
  - assertion: 172.18.0.9 is an unauthorized lateral movement destination from jump-box-1, not a known authorized management target
    settled_by: unsettled
    if_false: jump-box-1's SSH connections to 172.18.0.9 are legitimate bastion administration, and the observation does not indicate further adversary lateral movement through the bastion
  - assertion: dev-ws-1 is the only container (or the relevant container) on the soc-playground Docker host
    settled_by: unsettled
    if_false: Other containers on soc-playground may be the actual source of the observed activity, and the account's attribution to dev-ws-1 is unconfirmed
  - assertion: The absence of Falco events before 16:33:57 means the container was created at approximately 16:33, not that Falco collection started later
    settled_by: unsettled
    if_false: A pre-intrusion baseline of nc and curl activity may exist that was not captured, undermining the claim that these behaviors are adversary-introduced
  - assertion: The curl -sf -o /dev/null http://127.0.0.1/ events actually executed on dev-ws-1
    settled_by: unsettled
    if_false: The curl events may not have run on dev-ws-1 at all; the account's claim that they are local health checks preserved by the adversary is unsupported
  - assertion: All 1,660 accepted SSH logins used the root account
    settled_by: unsettled
    if_false: If logins used non-root accounts, the adversary's privilege profile and the authorized_keys-to-root persistence mechanism may not apply to all sessions
  - assertion: All accepted SSH logins used publickey authentication
    settled_by: unsettled
    if_false: If some logins used password or keyboard-interactive auth, the forged-key persistence mechanism is not the sole access method
  - assertion: 141 of the 204 post-restart logins fell within the first 10 minutes of the 16-minute burst
    settled_by: unsettled
    if_false: The "141 in 10 minutes" figure is not a real 10-minute subset; the specific count and timing claim is inaccurate
```