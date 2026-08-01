## l-001
## 1. Contradictions

None. No value in this payload is directly incompatible with the account.

## 2. Strain

- **`"container.name":"<NA>"`** — The account identifies the container as `dev-ws-1`, but this Falco event cannot resolve a container name (only `container.id` = `ffbff1299702`). To accommodate cleanly, the account would have to say the name `dev-ws-1` is resolved from the container ID via Docker API or CMDB, not from this Falco record.

- **`"user.uid":1009`** — The account describes the scheduler as "a Python process running as root (PID 77)" that spawns `bash → nc`. The `nc` process here runs as uid 1009, not uid 0. To accommodate cleanly, the account would need to explain why a root-owned scheduler spawns child processes as a non-root user (e.g., user-namespace remapping, a `setuid`/`su` in the chain, or a service-account transition), or clarify that it only claims the *scheduler* is root, not the probe processes it spawns.

## 3. Unsettled

- **Container ID `ffbff1299702` is the container the account calls `dev-ws-1`.** This payload provides the ID but not the name; a reader would have to check Docker/CMDB to confirm the mapping.

- **The parent chain above `bash` includes `scheduler.py` (PID 77) as a child of `sshd`.** This payload shows only `proc.pname` = `bash`; it does not show the grandparent or the scheduler process itself. A reader would have to check the full process tree at 06:24:43Z.

## 4. Support

- **`"proc.cmdline":"nc -z -w1 jump-box-1 22"`** — Exactly matches the account's claim of `nc -z -w1 jump-box-1 22` probes against the production bastion's SSH port.

- **`"proc.pname":"bash"`** — Confirms the account's claim that "the scheduler spawns bash, which runs nc."

- **`"proc.name":"nc"`** / **`"proc.exepath":"/usr/bin/nc.openbsd"`** — Confirms the network tool is `nc` as the account states.

- **Event time `"2026-07-28T06:24:43.571890378Z"`** — Matches the account's "the nc probe that triggered the alert at 06:24:43 UTC."

- **`"host":{"name":"soc-playground"}`** — Confirms the `soc-playground` Docker host named in the account.

- **Rule `"Launch Suspicious Network Tool in Container"`** with MITRE tag `T1059` — Consistent with the account's framing of adversary tool execution inside the compromised container.

## l-002
## 1. Contradictions

None. The payload is compatible with the account.

## 2. Strain

- **Image name `soc-playground/host-plain:24.04`.** The account repeatedly characterizes `dev-ws-1` as a "dev workstation" / "dev container," implying a purpose-built role. The image is a generic `host-plain` template — nothing in the image name ties it to a developer workstation role. To accommodate cleanly, the account would need to say the "dev workstation" designation comes from the container name and network placement, not the base image, which is a plain host template reused across multiple roles.

- **`hosts_present` includes `canary-1`, `office-ws-1`, `office-ws-2`.** The account's lateral-movement narrative maps a path through `jump-box-1` to `web-1`, `web-2`, and `db-1` but never mentions canaries or office workstations. Their presence is not contradictory, but the account would need to explain why the adversary ignored (or has not yet probed) these other reachable hosts, or acknowledge that the reconnaissance scope may be broader than described.

## 3. Unsettled

- **`/opt/soc-playground/baseline/scheduler.py` in the `host-plain:24.04` image launches `nc` probes by default, without adversary modification.** The ps output confirms the process exists (PID 77, PPID 7, root) but shows only the command line, not the script's contents or the image's original version. A reader would have to extract and diff `scheduler.py` against the base image to determine whether the `nc` probes are adversary-added or were always present.

- **The `host-plain:24.04` image ships with `scheduler.py` at that path.** If the original image does not contain this file, its presence is itself evidence of compromise; if it does, the account's "adversary modified or replaced" claim needs content-level proof. The payload does not settle this either way.

## 4. Support

- **Container identity:** `"name": "dev-ws-1"`, `"image": "soc-playground/host-plain:24.04"` confirms the account's identification of the compromised container as `dev-ws-1` on the `soc-playground` host.

- **Scheduler process lineage:** ps output shows `PID 77 PPID 7 USER root ... python3 /opt/soc-playground/baseline/scheduler.py` — exactly as the account states: "a Python process running as root (PID 77), child of `sshd`" (PID 7 is `sshd: /usr/sbin/sshd -D`).

- **sshd -D running:** PID 7, child of tini/PID 1, confirms the account's reference to the SSH daemon restart and `sshd -D` as one of the three initial Falco events.

- **elastic-agent present:** PID 75, `/usr/share/elastic-agent/bin/elastic-agent`, confirms the account's reference to the "Write below etc" `elastic-agent` Falco event at initial intrusion.

- **Hosts present include jump-box-1, web-1, web-2, db-1:** Confirms the account's claim that `jump-box-1`'s `trust_edges_out` include `web-1`, `web-2`, and `db-1`, and that these production hosts exist in the playground.

- **Restart timing:** ELAPSED `20:58` for PID 77 at capture time `06:30:06Z` places the process start at approximately `06:09:08Z` — matching the account's claim that "SSH logins from `79.177.137.245` resumed at 06:09:08 UTC" and "the compromised scheduler resumed probing within 2 minutes."

- **apt daily cron context:** ps output shows `/etc/cron.daily/apt-compat` running under cron (PIDs 858–868), supporting the account's dismissal of the `dpkg --print-foreign-architectures` event as "apt's routine architecture query."

## l-003
## 1. Contradictions

None. No value in this payload is strictly incompatible with the account.

## 2. Strain

1. **`nc -z 127.0.0.1 22` has parent `"runuser"`, not `"bash"`.** The account states "The scheduler spawns `bash`, which runs `nc`" as the general mechanism. The jump-box-1 probes do show parent `bash`, but the localhost probes show parent `runuser`. To accommodate cleanly, the account would need to explain that the scheduler uses `runuser` for the local backdoor check (perhaps to test under a different user context) while using `bash` for the remote jump-box probe.

2. **48 `"Contact cloud metadata service from container"` events from `elastic-otel-co` are present but unmentioned.** The account asserts "No collection/persistence Falco events in the ±15m alert window." Cloud-metadata-service contact is a credential-access-relevant event class. To accommodate cleanly, the account would need to acknowledge these 48 events and explain they are benign Elastic-agent telemetry (`elastic-otel-co` spawned by `elastic-agent`), not adversary IMDS credential theft.

3. **18 `"Redirect STDOUT/STDIN to Network Connection in Container"` events from `sshd` are present but unmentioned.** These span 06:10:17.897Z–06:28:57.314Z. To accommodate cleanly, the account would note these are expected artifacts of the interactive SSH sessions it describes and are consistent with the adversary being actively connected.

4. **sshd Falco events continue to `"2026-07-28T06:28:57.314Z"`, ~4 minutes after the account's claimed last SSH login at 06:24:41.** To accommodate cleanly, the account would need to state that the Falco sshd rules (Redirect STDOUT/STDIN, Unexpected UDP Traffic) fire for ongoing session activity, not solely on login, so post-login events from an active session are expected.

5. **sshd cmdline is `"sshd -D -R"`, not `"sshd -D"` as referenced in the initial-intrusion description.** To accommodate cleanly, the account would note the `-R` flag indicates re-exec mode after the container restart at ~06:09, consistent with the restart-and-resume narrative.

## 3. Unsettled

1. **A reader would have to check** whether the 48 `"Contact cloud metadata service from container"` events from `elastic-otel-co` are legitimate Elastic-agent telemetry or adversary credential collection via the cloud metadata endpoint.

2. **A reader would have to check** whether `/opt/soc-playground/baseline/scheduler.py` has been modified from its original container-image version — this payload shows `nc` events with parent `bash`/`runuser` but does not show the scheduler's file contents or a diff against the image baseline.

3. **A reader would have to check** whether SSH logins in this window came from `79.177.137.245` — this payload contains Falco sshd process events but no SSH authentication source-IP data.

## 4. Support

1. **`"first_seen": "2026-07-28T06:11:42.935Z"` for `nc -z -w1 jump-box-1 22`** — directly supports "resumed probing within 2 minutes" after the ~06:09 restart.

2. **`"events": 7` for `curl -sf -o /dev/null http://127.0.0.1/`** — directly supports "7 in the alert window."

3. **`"events": 1` for `dpkg --print-foreign-architectures` at `"2026-07-28T06:25:04.244Z"`** — directly supports "The single `dpkg --print-foreign-architectures` event at 06:25:04."

4. **`"parent": "bash"` for `nc -z -w1 jump-box-1 22`** — supports "The scheduler spawns `bash`, which runs `nc -z -w1 jump-box-1 22`."

5. **`"last_seen": "2026-07-28T06:24:44.233Z"` for `nc -z -w1 jump-box-1 22`** — supports the tight timing between the final probe and the alert at 06:24:43.

6. **Presence of `nc -z 127.0.0.1 22` events (7)** — supports the localhost backdoor-listening probe claim.

7. **sshd process events spanning the full window** — supports ongoing SSH activity during the alert period, consistent with the interactive-session narrative.

## l-004
**1. Contradictions**
None. The payload is fully compatible with the account.

**2. Strain**
None. The account easily accommodates this data without awkward adjustments.

**3. Unsettled**
- *Assertion to check:* 79.177.137.245 is attacker-controlled infrastructure rather than a legitimate admin/automation IP belonging to the organization. The payload confirms the IP is responsible for all observed SSH logins in this window but provides no reputation or threat intelligence context to classify its intent.
- *Assertion to check:* 79.177.137.245 is the sole SSH source for the `soc-playground` host across the entire 24-hour period. The payload only shows this 10-minute window.

**4. Support**
- The payload shows `141` accepted logins from `79.177.137.245` as `root` via `publickey` with `0` failed attempts, directly supporting the account's mention of "141 in 10 minutes" and reinforcing the narrative of uninterrupted, successful adversary access.
- The `last_seen` timestamp of `2026-07-28T06:24:41.566Z` positively supports the account's specific claim that the final SSH login occurred at `06:24:41 UTC` — exactly 2 seconds before the alert-triggering `nc` probe at `06:24:43 UTC`.
- The source IP `79.177.137.245` matches the account's identified attacker IP.
- The absence of any sudo activity (0 attempts) in the second query supports the account's claim that the adversary is operating directly as `root` (having added a key to root's `authorized_keys`), meaning privilege escalation via sudo is unnecessary.

## l-005
### 1. Contradictions
None. The account's claims about the specific `nc` probe at 06:24:43 are perfectly compatible with the payload. The payload shows `172.18.0.25` (dev-ws-1) connecting to `172.18.0.14` (jump-box-1) on port 22 at `06:24:43.574Z` with `"network.protocol": null`, `"bytes_out": 204`, and `"bytes_in": 207`, exactly as the account describes.

### 2. Strain
The payload shows `jump-box-1` (`172.18.0.14`) making successful, full SSH connections (`"network.protocol": "ssh"`, ~9,000–10,000 bytes exchanged) to `172.18.0.9` on port 22 at 06:18:50 and 06:19:52. The account focuses entirely on *inbound* probes from `dev-ws-1` to `jump-box-1` and omits any mention of `jump-box-1` making outbound SSH connections to other internal hosts. To accommodate this cleanly, the account would have to address whether `172.18.0.9` is an expected destination for the bastion (e.g., legitimate administration) or evidence that the adversary has already compromised `jump-box-1` and is continuing lateral movement.

### 3. Unsettled
The payload does not show what `172.18.0.9` is. A reader would have to go and check: **"Is `172.18.0.9` a known, authorized management target for `jump-box-1`, or is it an unauthorized lateral movement destination?"** 

### 4. Support
- The account requires that the `nc` probes from `dev-ws-1` to `jump-box-1` are zero-I/O TCP probes (204 bytes out, 207 bytes in, no SSH protocol). The payload provides direct support: `{"bytes_out": 204, "bytes_in": 207, "source.ip": "172.18.0.25", "destination.ip": "172.18.0.14", "destination.port": 22, "network.protocol": null}`.
- The account requires that `jump-box-1` is a production bastion. The payload's CMDB record supports this: `{"name": "jump-box-1", "role": "jump-box", "criticality": "prod"}`.
- The account requires that no Zeek HTTP records exist for `172.18.0.25` (dev-ws-1). The payload supports this, as the only Zeek connections involving `172.18.0.25` in this window are the TCP port 22 probes to `172.18.0.14`.

## l-006
## 1. Contradictions

None. Every concrete claim the account makes about `jump-box-1`'s CMDB attributes is present in the payload.

## 2. Strain

- **`jump-box-1` has `dev-ws-1` in its `trust_edges_out`, which the account omits.** The account lists only `"web-1", "web-2", and db-1"` as the bastion's outgoing edges, framing the path as dev → jump-box → production. The data shows `"trust_edges_out": ["web-1", "web-2", "db-1", "dev-ws-1"]` — a fourth edge back to the compromised host. To accommodate this cleanly, the account would have to say that the `dev-ws-1` → `jump-box-1` relationship is bidirectional at the CMDB level (dev workstations can reach the bastion and the bastion can reach them), and that the adversary's probe direction (dev → jump-box) exploits only one direction, leaving the reverse edge unused or relevant for a later stage.

- **`svc.config-mgmt` has `sudo: true` on `jump-box-1`.** The account's forged-key narrative uses the `svc.config-mgmt@rotation` guise as cover, but the payload shows `svc.config-mgmt` is a real, sudo-enabled service account on the very bastion being probed. To accommodate cleanly, the account would need to explain whether the adversary is impersonating an account that genuinely manages `jump-box-1` (which strengthens the disguise) or whether the presence of this account on the target is coincidental.

## 3. Unsettled

- **Container ID `ffbff1299702` maps to `dev-ws-1` (or to the role `dev-ws`).** The question asked the lookup tool to resolve this container ID's expected role, but the payload contains no reference to `ffbff1299702` anywhere. A reader would have to check a separate container-registry or runtime mapping to confirm that `ffbff1299702` is indeed `dev-ws-1` and not some other container on the `soc-playground` host.

- **`dev-ws-1` is the only container (or host) running on the `soc-playground` Docker host.** The CMDB lists `dev-ws-1` as a host with role `dev-ws`, criticality `dev`, owner `team.dev`, but nothing in this payload ties it to the Docker host named `soc-playground` or confirms it is the container the account claims was compromised.

## 4. Support

- **`jump-box-1` is a production bastion.** The payload returns `"role": "jump-box"`, `"criticality": "prod"`, `"owner": "team.sre"` — directly supporting the account's characterization of it as "a production bastion."

- **`jump-box-1`'s `trust_edges_out` include `web-1`, `web-2`, and `db-1`.** The payload returns `"trust_edges_out": ["web-1", "web-2", "db-1", "dev-ws-1"]`, confirming the three production targets the account names for the lateral-movement path.

- **`dev-ws-1` has a CMDB trust edge to `jump-box-1`.** The payload shows `dev-ws-1`'s `"trust_edges_out": ["jump-box-1"]`, directly supporting the account's "Accommodating awkward observations" claim that "CMDB shows dev-ws-1 has a trust edge to jump-box-1."

- **`dev-ws-1` is a dev-tier host.** The payload returns `"criticality": "dev"`, `"owner": "team.dev"`, `"role": "dev-ws"`, supporting the account's framing of the compromise originating on a development workstation.

## l-007
1. **Contradictions**
   None.

2. **Strain**
   None. The payload's verdict of `"unknown"` aligns perfectly with the account's claim that there is "no benign classification, no corporate ownership, no prior reputation."

3. **Unsettled**
   The account explicitly requires but this payload does not show: "79.177.137.245 is attacker-controlled infrastructure, not a legitimate admin/automation IP belonging to the organization." (The payload only shows the IP is not classified by any reputation source, not that it is definitively malicious.)

4. **Support**
   - The account requires the threat intelligence verdict to be unknown, which is supported by `"verdict": "unknown"`.
   - The account requires that the IP has no benign classification or prior reputation, which is supported by `"sources": []`, `"tags": []`, and `"score": 0`.

## l-008
## 1. Contradictions

None. The payload does not contain any value that is strictly incompatible with the account. Every specific figure the account cites — event counts, timestamps, command lines, rule names — is present and matches.

## 2. Strain

**The "curl preserved from the original scheduler" claim.** The account says curl events are "local health checks the adversary preserved from the original scheduler to maintain the container's baseline appearance." The data shows curl's `first_seen` is `"2026-07-27T16:34:56.167Z"` — the same second as the first nc probe and two seconds after the intrusion events at 16:33:57. There are zero Falco events of any kind before 16:33:57 in the 24-hour window. To accommodate cleanly, the account would have to say the container was freshly started at approximately 16:33–16:34 (or Falco collection began then), so that all scheduler activity — curl included — is post-startup, and "preserved" means "present from container creation" rather than "pre-existing a baseline that defenders would recognize."

**197 `Unexpected UDP Traffic` events from `sshd -D -R` and 378 `Redirect STDOUT/STDIN to Network Connection in Container` events from `sshd`.** The account frames "Unexpected UDP Traffic" as one of three single-shot intrusion markers (`"sshd -D"`, 1 event at 16:33:57). The data confirms that single event, but also shows a large ongoing body of sshd network activity under a different cmdline (`"sshd -D -R"`, 197 events) and 378 stdout/stdin-redirect events from `sshd`, both spanning the full 14-hour window. To accommodate cleanly, the account would need to acknowledge these as the operational footprint of the running SSH backdoor (the daemon accepting connections and relaying I/O), not merely a one-time restart signal at initial access.

## 3. Unsettled

**"No Falco events exist for container `ffbff1299702` before `2026-07-27T16:33:57Z`, confirming the container (or Falco collection on it) did not exist or was not active prior to the intrusion."** A reader would have to check whether the container was created at ~16:33 or whether Falco simply wasn't shipping events earlier — this determines whether there is any pre-intrusion baseline at all, which directly bears on the account's claim that nc probes and curl were added versus pre-existing.

## 4. Support

- **106 `nc -z -w1 jump-box-1 22` events**, `first_seen` `"2026-07-27T16:34:56.158Z"` — matches the account's count and first-probe timing exactly.
- **100 `nc -z 127.0.0.1 22` events**, `first_seen` `"2026-07-27T16:34:56.167Z"` — matches the account's count and timing.
- **Three initial intrusion events at 16:33:57**: `Clear Log Activities` (`agent-enroll.sh`, 16:33:57.329Z), `Write below etc` (`elastic-agent`, 16:33:57.415Z), `Unexpected UDP Traffic` (`sshd -D`, 16:33:57.329Z) — all present within the same second as claimed.
- **SSH key insertion at 16:35:02**: `"Adding ssh keys to authorized_keys"`, `bash`, cmdline containing `AAAAB3rotated$(date +%s)`, `first_seen` `"2026-07-27T16:35:02.721Z"` — matches exactly.
- **100 curl events**: `"curl -sf -o /dev/null http://127.0.0.1/"`, 100 events — matches the account's "100 in 24h."
- **`dpkg --print-foreign-architectures`** at `"2026-07-28T06:25:04.244Z"` — matches the account's single-event description.
- **Habitual nc pattern**: 206 total nc events (`106` + `100`) spanning ~14 hours (16:34:56 → 06:24:44) — directly supports the account's "206 events over 14 hours" and the habitual-probing characterization.

## l-009
1. **Contradictions**
   - None. The payload contains no data that is incompatible with the account.

2. **Strain**
   - None. The account accommodates the returned data cleanly.

3. **Unsettled**
   - The payload does not show whether the `curl -sf -o /dev/null http://127.0.0.1/` events actually executed on `dev-ws-1`, because Zeek does not capture loopback traffic. A reader would have to check process execution logs (e.g., Falco, sysmon, or auditd) to confirm that the local health-check curl commands actually occurred on `dev-ws-1` during this window.

4. **Support**
   - `"row_count": 0, "values": []` for the query filtering by `source.ip == "172.18.0.25"` positively supports the account's explicit assertion: "No Zeek HTTP records exist for `172.18.0.25` (dev-ws-1)".

## l-010
## 1. Contradictions

- **Last SSH login timestamp.** The account states "the last at **06:24:41 UTC**" and ties it to an alert at "06:24:43 UTC." The payload shows `"last_seen": "2026-07-28T06:25:10.151Z"` — 29 seconds later than the account claims. The query window upper bound (`2026-07-28T06:25:11.465Z`) further implies the alert is at ~06:25:11, not 06:24:43. The account's "2 seconds before the nc probe" tight-timing argument is incompatible with the data's last_seen.

## 2. Strain

- **"141 logins in 10 minutes" vs. 204 in 16 minutes.** The account's awkward-observations section references "SSH volume (141 in 10 minutes)," while this payload shows 204 accepted logins from 06:09:08 to 06:25:10 (~16 minutes). The account can accommodate this only by asserting that 141 is a 10-minute subset within the 16-minute window. To settle it cleanly, the account would need a finer-grained query (per-minute or per-10-minute bucketing) showing that 141 of the 204 logins fell in the first 10 minutes.

## 3. Unsettled

- **The single SSH user is `root`.** The data shows `distinct_users: 1` in every bucket but does not expose the username. A reader would have to check that `user.name == "root"` for all 1,660 accepted logins.
- **All logins use `publickey` authentication.** The query filters on `message LIKE "*Accepted*"` and `event.outcome == "success"` but does not surface the authentication method. A reader would have to check that every accepted login used publickey (not password, keyboard-interactive, etc.).
- **"141 logins in 10 minutes."** The payload does not break the 06:00 bucket into 10-minute intervals, so this specific count is neither confirmed nor denied.

## 4. Support

- **79.177.137.245 is the sole SSH source.** l-010/1 and l-010/2 return `row_count: 0` for any `source.ip != "79.177.137.245"`. Directly supports "This IP is the sole SSH source for the entire soc-playground host."
- **Total of 1,660 accepted logins.** 28 + 328 + 35 + 16 + 1049 + 204 = 1,660. Supports "1,660 accepted logins."
- **First login at 16:40:32.** `"first_seen": "2026-07-27T16:40:32.341Z"` in the 16:00 bucket supports "the first login from 79.177.137.245 arrived" at that time.
- **Burst pattern (28 → 328 → 35 → 16 → 1049).** The hourly accepted counts match exactly, in that order.
- **Multi-hour gaps.** No buckets exist between 20:00 (last_seen 20:57:30) and 06:00 (first_seen 06:09:08) — a ~9-hour gap, plus smaller gaps between the 18:00 and 19:00 buckets. Supports "multi-hour gaps."
- **Post-restart resumption at 06:09:08 with 204 logins.** `"first_seen": "2026-07-28T06:09:08.864Z"` and `accepted: 204` in the 06:00 bucket support "SSH logins from 79.177.137.245 resumed at 06:09:08 UTC, with 204 logins in 16 minutes."

## l-011
## 1. Contradictions

None. The payload is compatible with the account.

## 2. Strain

- **No `bash` or `nc` child visible under PID 77.** The account states the scheduler "spawns `bash`, which runs `nc -z -w1 jump-box-1 22`." The `ps --forest` output shows `python3 /opt/soc-playground/baseline/scheduler.py` (PID 77) with **no children listed**. This is accommodatable only if `bash`/`nc` are ephemeral — the `nc -z -w1` probe completes in under one second and fires roughly every 8 minutes, so a single point-in-time `ps` snapshot would almost certainly miss them. The account would need to say exactly this: the capture happened between probe cycles, and the ephemeral children are not visible at 06:38:19.

## 3. Unsettled

- **"`scheduler.py` (PID 77) actually launches `bash → nc` as child processes."** The process tree proves the scheduler exists, runs as root under sshd, and has been alive since the container restart — but it shows no child, so the account's claim that PID 77 is the probe orchestrator is not confirmed by this payload alone. A reader would need to check Falco exec events or the script's contents to see whether PID 77 spawned `bash`/`nc`.

## 4. Support

- **"`scheduler.py` is a Python process running as root (PID 77), child of `sshd`."** Directly confirmed: PID 77, PPID 7 (`sshd: /usr/sbin/sshd -D [listener]`), USER `root`, CMD `python3 /opt/soc-playground/baseline/scheduler.py`.
- **"The container restarted at approximately 06:09 UTC on 2026-07-28."** Confirmed by ELAPSED `29:13` for PID 1 at capture time 06:38:19 → start ≈ 06:09:06 UTC.
- **"The compromised scheduler resumed probing within 2 minutes" / "resumed after restart."** Supported indirectly: PID 77 ELAPSED is `29:10` (started ≈ 06:09:09 UTC), meaning the scheduler was running well before the claimed first probe at 06:11:42 UTC.
- **"`sshd -D` is running as the container's foreground process."** Confirmed: PID 7 is `sshd: /usr/sbin/sshd -D [listener]`, launched via `tini` → `host-entrypoint.sh`.