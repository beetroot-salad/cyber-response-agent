## Account: Adversary reconnaissance from compromised dev-ws-1, staging lateral movement through jump-box-1

At approximately 16:33 UTC on 2026-07-27, an adversary compromised the `dev-ws-1` container on the `soc-playground` Docker host. Three Falco events fired within the same second — "Clear Log Activities" from `agent-enroll.sh`, "Write below etc" from `elastic-agent`, and "Unexpected UDP Traffic" from `sshd -D` — marking the initial intrusion: log clearing (anti-forensics), system configuration modification, and SSH daemon restart.

At 16:35:02 UTC, the adversary added an SSH public key to `root`'s `authorized_keys` via a bash command disguised as a config-management key rotation. The key string `AAAAB3rotated$(date +%s)` does not begin with `AAAAB3NzaC1yc2E` — the mandatory prefix of a valid OpenSSH RSA public key — indicating a forged key inserted under a `svc.config-mgmt@rotation` guise for persistent root access.

One minute earlier, at 16:34:56 UTC, the first reconnaissance probes had already begun: `nc -z -w1 jump-box-1 22` and `nc -z 127.0.0.1 22`, launched under `bash`. The jump-box-1 probe tests whether the production bastion's SSH port is reachable from the compromised dev container; the localhost probe confirms the adversary's SSH backdoor is listening.

At 16:40:32 UTC — five minutes after the SSH key was planted — the first login from `79.177.137.245` arrived. This IP is the sole SSH source for the entire `soc-playground` host across 24 hours (1,660 accepted logins, all root, all publickey). Threat intelligence returns `unknown` for this IP: no benign classification, no corporate ownership, no prior reputation. The burst pattern (28 → 328 → 35 → 16 → 1049 per hour, with multi-hour gaps) is consistent with automated C2 check-ins and interactive session establishment, not with steady-state infrastructure monitoring.

The adversary modified or replaced `/opt/soc-playground/baseline/scheduler.py` — a Python process running as root (PID 77), child of `sshd` — to orchestrate continuous SSH port probes against `jump-box-1`. The scheduler spawns `bash`, which runs `nc -z -w1 jump-box-1 22` approximately every 8 minutes. Over 14 hours, 106 probes targeted `jump-box-1:22` and 100 targeted `127.0.0.1:22`. Zeek confirms these are zero-I/O TCP probes (204 bytes out, 207 bytes in, no SSH protocol) — pure port discovery, not legitimate SSH sessions. The target is significant: `jump-box-1` is a production bastion whose `trust_edges_out` include `web-1`, `web-2`, and `db-1`. The adversary is mapping the lateral movement path from a dev workstation through the jump box into production infrastructure.

The container restarted at approximately 06:09 UTC on 2026-07-28. The compromised scheduler resumed probing within 2 minutes (first probe at 06:11:42 UTC), demonstrating that the adversary's modifications persist across restarts — either through a persistent volume or image-level compromise. SSH logins from `79.177.137.245` resumed at 06:09:08 UTC, with 204 logins in 16 minutes, the last at 06:24:41 UTC — 2 seconds before the `nc` probe that triggered the alert at 06:24:43 UTC. The tight timing between the final SSH login and the probe indicates the adversary was actively connected and orchestrating activity at the moment the alert fired.

The co-occurring `curl -sf -o /dev/null http://127.0.0.1/` events (7 in the alert window, 100 in 24h) are local health checks the adversary preserved from the original scheduler to maintain the container's baseline appearance. No Zeek HTTP records exist for `172.18.0.25` (dev-ws-1) because the curl targets loopback — consistent with a local service-availability check, not exfiltration. The single `dpkg --print-foreign-architectures` event at 06:25:04 is apt's routine architecture query and does not contradict the adversary narrative.

### Accommodating awkward observations

**nc probes are habitual (206 events over 14 hours).** Habitual does not mean benign. An adversary who has compromised the scheduler produces habitual patterns by design — continuous low-frequency probes blend into any baseline a defender might build. The 14-hour span marks the duration of adversary presence, not evidence of legitimacy. The first probes appear at 16:34:56, one minute after the log-clearing and `/etc` write events at 16:33:57, establishing the temporal boundary of the intrusion.

**CMDB shows dev-ws-1 has a trust edge to jump-box-1.** A CMDB trust edge describes network reachability, not intent. The adversary is abusing an existing dev-to-prod trust relationship — a classic lateral movement technique. The trust edge makes the probe technically permitted by network policy but does not authenticate the actor behind it or validate the purpose.

**scheduler.py path contains "baseline".** A filename is not evidence of legitimacy. An adversary with root access can name a malicious script anything; choosing an innocuous name is basic operational security. The data shows the process exists and spawns `bash → nc`; it does not show the script's contents or that they match the original container image.

**No collection/persistence Falco events in the ±15m alert window.** The adversary established persistence 14 hours earlier (16:33–16:35 on 07-27). The alert window captures the ongoing reconnaissance and lateral-movement-preparation phase, not initial access. The absence of new persistence events is expected — the adversary already has what they need.

**Threat intel returns "unknown" for 79.177.137.245.** "Unknown" is not "benign." No source classifies this IP as corporate infrastructure, admin VPN, or known automation. A previously unseen IP being the sole root SSH source for an entire host — with no other IP ever logging in — is consistent with attacker infrastructure, not with established operational tooling that would have a documented identity.

**SSH volume (141 in 10 minutes) is within the 24h burst pattern.** The 24h burst pattern is itself the adversary's activity pattern, not a pre-existing legitimate baseline. The data shows zero SSH logins from any IP other than `79.177.137.245` — there is no independent legitimate baseline to compare against. The variability (28–1049 per hour) reflects interactive adversary sessions and automated tooling bursts, not a monitoring agent with fixed cadence.

**The "Adding ssh keys" event used `$(date +%s)` in the key string.** The Falco-captured cmdline shows `echo "ssh-rsa AAAAB3rotated$(date +%s) svc.config-mgmt@rotation"`. Whether or not the shell expanded the timestamp before writing, the prefix `AAAAB3rotated` is not a valid base64-encoded SSH key header (legitimate RSA keys begin `AAAAB3NzaC1yc2E`). This is a forged key disguised with a rotation naming convention.

```yaml
requires:
  - assertion: 79.177.137.245 is attacker-controlled infrastructure, not a legitimate admin/automation IP belonging to the organization
    settled_by: unsettled
    if_false: The 1,660 root SSH logins from this IP are legitimate administrative access, the initial-access and C2 narrative collapses, and the remaining observations reduce to a dev container running authorized connectivity checks
  - assertion: /opt/soc-playground/baseline/scheduler.py has been modified from its original container-image version by the adversary to launch nc probes against jump-box-1
    settled_by: unsettled
    if_false: The scheduler is a legitimate baseline component that has always run these probes, the nc activity is authorized monitoring, and the reconnaissance narrative collapses
  - assertion: 79.177.137.245 is not classified as a known-benign or corporate IP in any reputation source
    settled_by: l-007
    if_false: If any source classified this IP as legitimate corporate infrastructure, the SSH logins would be attributable to authorized administration and the account would collapse
```