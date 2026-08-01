## l-001
## 1. Contradictions

None. No field in this payload directly refutes the account.

## 2. Strain

- **`proc.pname: "bash"`** — The account frames nc as executed by the scheduler.py implant (PID 77, child of sshd). The Falco event shows nc's *immediate* parent is `bash`, not `python3`/`scheduler.py`. To accommodate cleanly, the account would need to state that scheduler.py invokes nc via a bash subprocess (e.g., `os.system` or `subprocess` with `shell=True`), producing the chain sshd → python3 → bash → nc, of which Falco captures only the last link.

- **`container.name: "<NA>"`** — The account consistently refers to the container as "dev-ws-1," but Falco records no container name (only `container.id: ffbff1299702`). To accommodate cleanly, the account would need to say the dev-ws-1 name is mapped from the container ID via a separate data source (e.g., Docker runtime metadata), not from Falco.

- **`container.image.repository: null`** — The account asserts the image is `soc-playground/host-plain:24.04`. Falco shows null for the image repository. To accommodate cleanly, the account would need to say image attribution comes from a different source than this Falco event, and that Falco's container enrichment did not populate image fields.

- **`user.name: "<NA>"`, `user.loginuid: -1`** — The account describes root SSH access from 79.177.137.245, but this event carries no user or login-uid attribution. To accommodate cleanly, the account would need to say Falco did not resolve the user context for this execve (common in containerized syscall events) and that the root/publickey attribution is established from SSH auth logs (l-010), not from this Falco alert.

## 3. Support

- **`proc.cmdline: "nc -z -w1 jump-box-1 22"`** — Exactly the string the account asserts for the reconnaissance probe, including the target host (`jump-box-1`) and port (22).

- **`evt.time: 2026-07-28T06:24:43.571890378Z`** — Matches the account's stated alert time of 06:24:43Z.

- **`rule: "Launch Suspicious Network Tool in Container"`** — Matches the rule name referenced in the account and question.

- **`proc.name: "nc"`, `proc.exepath: "/usr/bin/nc.openbsd"`** — Confirms the network tool is nc, as the account requires.

- **`host.hostname: "soc-playground"`** — Matches the account's identification of the Docker host.

- **`container.id: "ffbff1299702"`** with `host.containerized: false` — Consistent with the account's description of a Docker host running containers, where Falco captures host-level syscall events with container IDs but limited container enrichment.

## l-002
## 1. Contradictions

**Container and scheduler.py start time incompatible with claimed 16:33Z compromise.**
The `ps_output` (l-002/2.json) was captured at `2026-07-28T06:30:06Z`. PID 1 (tini) shows `ELAPSED` of `21:00`; PID 77 (scheduler.py) shows `ELAPSED` of `20:58`. This places the container's start at approximately 09:30Z on July 27 and scheduler.py's start at approximately 09:32Z — roughly 7 hours **before** the account's claimed initial-access time of "approximately 16:33Z on 2026-07-27." The account explicitly states the adversary acted "within two minutes of the dev-ws-1 container's initialization," which would require container init at ~16:31Z. The elapsed-time data says otherwise.

## 2. Strain

**scheduler.py started within 2 seconds of sshd, yet the account claims it was deployed via a post-compromise SSH login.**
PID 7 (sshd) has `ELAPSED` `20:58`; PID 77 (scheduler.py) also has `ELAPSED` `20:58`. The two started within seconds of each other and within seconds of container boot. The account argues the process-tree parentage (child of sshd, not tini) "confirms the scheduler was launched via an interactive or automated SSH login… not as part of the container's designed startup." The parent-process observation is real, but the near-identical elapsed times make a "deployed 14 hours after boot" narrative very difficult to sustain. To accommodate this cleanly, the account would have to say that an automated SSH login from 79.177.137.245 fired within seconds of sshd becoming available at container boot — effectively at 09:32Z, not 16:33Z — which would require revising the entire compromise timeline and the stated Falco timestamps.

**cron is present and running, complicating the "not launched by cron" argument.**
PID 68 (`/usr/sbin/cron -P`) is a child of tini (PID 1) with `ELAPSED` `20:58`, and it has active children (PIDs 858–868, including `run-parts /etc/cron.daily`). The account asserts "A legitimate scheduled baseline task would be launched by cron, systemd, or the container entrypoint — not spawned from an SSH session." cron's presence and activity show that the expected scheduling infrastructure exists and functions. The account can still argue scheduler.py was *not* launched by cron (its parent is indeed sshd, not cron), but it must now explain why an adversary would bypass a working cron daemon to instead parent the implant under sshd — and why that sshd-parented process started at boot time rather than post-compromise.

## 3. Support

**Container name and image exactly match.**
l-002/0.json returns `"name": "dev-ws-1"` and `"image": "soc-playground/host-plain:24.04"`. The account identifies the compromised container as dev-ws-1 and specifically discusses the image `soc-playground/host-plain:24.04` in its "Addressing awkward observations" section. This is a positive match.

**scheduler.py parent process is sshd (PID 7), not tini (PID 1).**
The `ps_output` shows PID 77 with `PPID` 7, where PID 7 is `sshd: /usr/sbin/sshd -D [listener]`. PID 1 is `tini`. This directly supports the account's claim: "The process (PID 77) runs as a direct child of sshd (PID 7), not as a child of the container init system (tini, PID 1)."

**scheduler.py command line matches.**
The `ps_output` shows `python3 /opt/soc-playground/baseline/scheduler.py` for PID 77, matching the account's description of the implant path and invocation.

**jump-box-1 is present in the playground.**
l-002/1.json lists `"jump-box-1"` in `hosts_present`, consistent with the account's central claim that the implant probes jump-box-1 as a lateral-movement target within the same Docker environment.

## l-003
### 1. Contradictions
None. The payload is compatible with the account. The account explicitly anticipates the absence of persistence/collection events (e.g., authorized_keys modifications) in the ±15m window, and the payload indeed contains no such events.

### 2. Strain
- **`dpkg --print-foreign-architectures` parent process:** The account characterizes this event as "the adversary querying system architecture for potential tool deployment," implying a direct manual or scripted query by the implant. However, the payload shows the parent process is `apt-config`, indicating this command was likely invoked automatically as part of an `apt`/`apt-get` package management routine, rather than being run directly by the adversary's implant. To accommodate this cleanly, the account would have to say the adversary initiated an `apt` command (e.g., `apt install` or `apt update`) which internally triggered `apt-config` and `dpkg`.
- **Unexplained `curl` activity:** The payload shows 7 events for `curl -sf -o /dev/null http://127.0.0.1/` (parent: `bash`) occurring in the same timeframe as the `nc` probes. The account does not mention this `curl` command. To accommodate it cleanly, the account would have to explain this as another local connectivity check performed by the implant alongside the local `nc` probes. 

### 3. Support
- **`nc -z -w1 jump-box-1 22`:** The payload positively requires the presence of this exact command line for lateral movement reconnaissance, and it is present (5 events, parent `bash`, occurring up to 06:24:44Z).
- **`nc -z 127.0.0.1 22`:** The account claims local SSH probes are occurring, and the payload supports this exactly (7 events, parent `runuser`).
- **`dpkg --print-foreign-architectures`:** The account claims this event occurred at 06:25:04Z, and the payload supports this exactly (1 event at 06:25:04.244Z).
- **Absence of persistence/anti-forensics events:** The account claims that Falco events for SSH key additions and log clearing would not appear in this ±15m window because they occurred 14 hours prior. The payload supports this, as there are no rule fires for "Adding ssh keys to authorized_keys" or "Clear Log Activities" in the returned data.

## l-004
1. **Contradictions**
- None. The payload is fully compatible with the account.

2. **Strain**
- None. The account accommodates the data cleanly. The absence of sudo activity (l-004/1.json and l-004/2.json returning zero rows) is perfectly consistent with the account's assertion that the adversary is operating directly as root via SSH, rather than using sudo for privilege escalation or session management.

3. **Support**
- The account claims "141 SSH logins in the preceding 10 minutes (06:14:43–06:24:41Z)". The payload directly supports this with `"accepted": 141`, `"first_seen": "2026-07-28T06:14:43.678Z"`, and `"last_seen": "2026-07-28T06:24:41.566Z"`.
- The account claims the logins are "all root, all publickey, zero failures". The payload supports this with `"user.name": "root"`, `"auth_method": "publickey"`, and `"failed": 0`.
- The account claims "79.177.137.245 is the sole SSH source IP". The payload supports this for this 10-minute window by returning exactly one row with `"source.ip": "79.177.137.245"`.

## l-005
### 1. Contradictions
None. 

### 2. Strain
**Jump-box-1 initiating `nc`-style probes:** The Zeek data includes `null` protocol connections on port 22 originating from jump-box-1 (`172.18.0.14`) to another internal host (`172.18.0.9`). For example:
`{"conns": 1, "bytes_out": 204, "bytes_in": 206, "first_seen": "2026-07-28T06:15:12.388Z", "last_seen": "2026-07-28T06:15:12.388Z", "source.ip": "172.18.0.14", "destination.ip": "172.18.0.9", "source.port": 47840, "network.protocol": null, "network.transport": "tcp"}`
The account claims the `nc -z` probes are exclusively the dev-ws-1 implant targeting jump-box-1. To accommodate this cleanly, the account would have to explain that jump-box-1's `null` protocol connections to `172.18.0.9` are legitimate administrative checks or a separate benign behavior, rather than part of the dev-ws-1 implant's reconnaissance.

**Masquerade vs. Local Service Account:** l-005/1.json and l-005/3.json show that `svc.config-mgmt` is a legitimate user with `sudo: true` on both jump-box-1 and dev-ws-1:
`{"username": "svc.config-mgmt", "shell": "/bin/bash", "sudo": true}`
The account frames the `svc.config-mgmt@rotation` SSH key comment as "deliberate masquerading" to look like a config management service operating from a known infrastructure IP. To accommodate this cleanly, the account would clarify that the adversary is blending in by utilizing the name of an existing, highly-privileged local service account rather than inventing a masquerade out of whole cloth.

### 3. Support
**Execution and success of the nc probe at alert time:** The Zeek logs contain a connection at exactly `06:24:43.574Z` from `172.18.0.25` to jump-box-1 (`172.18.0.14`) on port 22 with no application protocol (`null`), which directly supports the account's claim that the Falco alert at `06:24:43Z` fired on an `nc -z -w1 jump-box-1 22` probe and that it resulted in an actual TCP connection:
`{"conns": 1, "bytes_out": 204, "bytes_in": 207, "first_seen": "2026-07-28T06:24:43.574Z", "last_seen": "2026-07-28T06:24:43.574Z", "source.ip": "172.18.0.25", "destination.ip": "172.18.0.14", "source.port": 53898, "network.protocol": null, "network.transport": "tcp"}`

**Role and criticality of jump-box-1:** The CMDB data confirms the account's exact description of the target bastion:
`{"name": "jump-box-1", "role": "jump-box", "criticality": "prod", "owner": "team.sre", ...}`

## l-006
### 1. Contradictions
None. This payload does not directly contradict any explicit claim in the account.

### 2. Strain
- **Account claim:** The SSH key keyed as `svc.config-mgmt@rotation` is "deliberate masquerading" added by a bash process, "not by a configuration management service operating from a known infrastructure IP."
- **Strain:** The CMDB data shows a legitimate host named `config-mgmt-1` with `"trust_edges_out": ["web-1", "web-2", "db-1", "jump-box-1", "dev-ws-1", "office-ws-1", "office-ws-2", "canary-1"]`. Furthermore, both `dev-ws-1` and `jump-box-1` list `svc.config-mgmt` as a user with `"sudo": true`. This establishes that a configuration management service operating from known infrastructure *does* legitimately manage these hosts.
- **To accommodate cleanly:** The account must explain why the key addition seen in the container is definitively the adversary's bash process and not a routine key rotation executed by the legitimate `config-mgmt-1` host. It should clarify that the masquerade is effective precisely because `svc.config-mgmt` is a real, privileged service, rather than asserting that no such configuration management service from known infrastructure exists.

### 3. Support
- **Quote:** `"jump-box-1", "role": "jump-box", "criticality": "prod"`
  **Supports:** The account's explicit assertion that `jump-box-1` is a prod jump-box.
- **Quote:** `"jump-box-1", ... "owner": "team.sre"`
  **Supports:** The account's claim that the bastion is owned by team.sre.
- **Quote:** `"dev-ws-1", ... "trust_edges_out": ["jump-box-1"]`
  **Supports:** The account's acknowledgment that "CMDB authorizes dev-ws-1 → jump-box-1".
- **Quote:** `"jump-box-1", ... "trust_edges_out": ["web-1", "web-2", "db-1", "dev-ws-1"]`
  **Supports:** The account's characterization of `jump-box-1` as "the gateway to web-1, web-2, and db-1."
- **Quote:** `"dev-ws-1", "role": "dev-ws", "criticality": "dev"`
  **Supports:** The account's framing of the compromised host as a dev workstation.

## l-007
1. **Contradictions**
   - None.

2. **Strain**
   - None. The payload cleanly aligns with the account's description of the IP's threat-intel status.

3. **Support**
   - The account requires the IP `79.177.137.245` to have an "unknown" threat-intel verdict and zero reputation data. The payload supports this directly: `"verdict": "unknown"`, `"score": 0`, `"sources": []`, `"tags": []`, and `"first_seen": null`, `"last_seen": null`.

## l-008
### 1. Contradictions
None. The payload does not contain data that is strictly incompatible with the account. 

### 2. Strain
- **The 100 `curl -sf -o /dev/null http://127.0.0.1/` events:** In l-008/1, there are exactly 100 `curl` events to localhost HTTP over the exact same timeframe as the 100 `nc -z 127.0.0.1 22` events. The account claims the local `nc` probes are adversary actions verifying local SSH service availability and explicitly states "These are not health checks." The account would have to explain why the adversary is simultaneously making 100 HTTP requests to localhost over 14 hours, which strongly resembles an automated readiness/health check probe for both SSH and HTTP endpoints. 
- **Sequence of initial compromise actions:** The account lists the initial actions in the order of Anti-forensics, Persistence, and Implant deployment. However, the first `nc` probe (implant activity) occurs at 16:34:56Z, which is *before* the SSH key persistence event at 16:35:02Z. To accommodate this cleanly, the account would have to reorder its narrative to acknowledge that the implant was deployed and began lateral movement reconnaissance before the SSH persistence key was appended to `authorized_keys`.
- **The SSH key string:** The account asserts a bash process appended an SSH public key keyed as `svc.config-mgmt@rotation`. The data shows the key string is literally `ssh-rsa AAAAB3rotated$(date +%s) svc.config-mgmt@rotation`, meaning the `$(date +%s)` command substitution appears to not have evaluated (or was logged raw). The account would have to explain why the adversary's key generation failed to evaluate the timestamp, or why a masquerading script would contain this specific malformed syntax.

### 3. Support
- **`nc -z -w1 jump-box-1 22` volume and duration:** The account claims 106 events over ~14 hours. l-008/0 and l-008/2 positively confirm 106 events from 16:34:56Z to 06:24:44Z.
- **`nc -z 127.0.0.1 22` volume:** The account claims 100 events. l-008/0 and l-008/3 positively confirm 100 events.
- **SSH key addition:** The account claims a bash process appended a key keyed as `svc.config-mgmt@rotation` at 16:35:02Z. l-008/1 confirms the "Adding ssh keys to authorized_keys" rule fired at 16:35:02Z via `bash`, with the comment `svc.config-mgmt@rotation` in the command line.
- **Anti-forensics log clearing:** The account claims `agent-enroll.sh` triggered "Clear Log Activities" at 16:33:57Z. l-008/1 confirms this exact rule, process, and timestamp.
- **`dpkg` architecture query:** The account claims a `dpkg --print-foreign-architectures` event occurred at 06:25:04Z. l-008/1 confirms this exact event and timestamp.

## l-009
### 1. Contradictions
There are no direct contradictions between the account and the returned data. The account makes no claims regarding HTTP traffic originating from `dev-ws-1` (172.18.0.25), so the `0` HTTP requests from that IP in the ±15m window do not conflict with the narrative.

### 2. Strain
The question's premise—investigating "what the curl events were fetching"—implies that curl executions were observed (likely by Falco or another endpoint sensor) on `dev-ws-1`. However, `l-009/0.json` shows absolutely zero HTTP requests from `dev-ws-1` (172.18.0.25) in the window. The account completely ignores any curl activity, focusing only on `nc`, `sshd`, `bash`, and `dpkg`. To accommodate this cleanly, the account would have to explain why curl was executed (if it was) but failed to produce HTTP traffic (e.g., it failed to connect, targeted a non-HTTP port, or fetched from a local file path), or explicitly state that curl was not part of the adversary's steady-state operational phase. 

Additionally, the account states that `79.177.137.245` is an "unseeded indicator with zero reputation data." The Zeek logs show an HTTP request to a local `threat-intel` service (`172.18.0.3:8080/lookup/79.177.137.245`) returning a `200 OK` with 128 bytes. While this doesn't contradict the "unknown" verdict, the account implies the IP was essentially a blank slate; the presence of an active threat-intel lookup infrastructure means the IP was actively queried by the SOC environment, which the account would need to acknowledge as the mechanism by which the "unknown" verdict was established.

### 3. Support
- **Adversary IP focus:** The HTTP log from `172.18.0.7` querying `/lookup/79.177.137.245` confirms that the IP `79.177.137.245` is the central indicator of interest in this incident, directly supporting the account's focus on this IP.
- **Threat Intel Verdict:** The existence of a threat intel lookup supports the account's claim that the IP was subjected to threat intelligence evaluation (and likely returned an "unknown" verdict, given the account's claim that it carries no benign classification).
- **Activity Profile:** The total lack of HTTP traffic from `dev-ws-1` (172.18.0.25) in the ±15m window positively supports the account's assertion that the adversary's steady-state operational phase consists of SSH session maintenance, `nc` probing, and local system enumeration (`dpkg`), rather than HTTP/web-based command-and-control or tool downloading in this timeframe.

## l-010
## 1. Contradictions

- **"28–1,049 logins/hour"** — The data contains a bucket with `accepted: 16` (bucket `2026-07-27T19:00:00.000Z`). The account's stated minimum of 28 is incompatible with this 16-login hour.

## 2. Strain

- **Root SSH access "at approximately 16:33Z" vs. first accepted SSH log at 16:40:32Z.** The earliest row in the data is `first_seen: "2026-07-27T16:40:32.341Z"`. To accommodate cleanly, the account would say the 16:33Z compromise was via container initialization (Falco-captured actions), not an SSH auth event, and the first *login via the planted key* occurred at 16:40Z.

- **~9-hour gap in SSH activity (20:57:30Z → 06:09:08Z).** The account frames the SSH pattern as continuous "automated session cycling" and "session maintenance," but the data shows no accepted logins across roughly 21:00–06:00. To accommodate cleanly, the account would say the automation paused overnight or maintained persistent sessions without re-authentication during that window.

- **"141 SSH logins in the preceding 10 minutes (06:14:43–06:24:41Z)."** The data only provides hourly buckets; the `2026-07-28T06:00:00.000Z` bucket shows 204 accepted from 06:09:08 to 06:25:10. To accommodate cleanly, the account would acknowledge that 141 is a sub-bucket estimate not directly verifiable from this aggregation, and that 204 total over ~16 minutes is consistent with but not proof of 141 in any specific 10-minute slice.

- **"all root, all publickey, zero failures."** This query returns only `event.outcome == "success"` / `Accepted` events with `distinct_users: 1` per bucket. To accommodate cleanly, the account would note that single-user is confirmed, but that root identity, publickey method, and zero failures require log fields not surfaced by this query.

## 3. Support

- **79.177.137.245 as the sole SSH source IP** — l-010/1 and l-010/2 both return `row_count: 0` for any `source.ip != "79.177.137.245"`, directly confirming the account's claim.

- **1,660 accepted logins** — The per-bucket totals sum exactly to 1,660 (28 + 328 + 35 + 16 + 1049 + 204), matching the account's stated total.

- **1,049 logins/hour upper bound** — The bucket `2026-07-27T20:00:00.000Z` shows `accepted: 1049`, matching the account's stated maximum.

- **Single user across all buckets** — `distinct_users: 1` in every row, consistent with the account's "all root" (single-user) characterization.

- **Variable volume** — The per-hour counts (28, 328, 35, 16, 1049, 204) confirm highly variable login volume, consistent with the account's "automated session cycling, not human administrative work" claim.

## l-011
## 1. Contradictions

- **Container age vs. claimed 14-hour campaign:** The `ps` output shows `tini` (PID 1) with `ELAPSED 29:13`, captured at `2026-07-28T06:38:19Z`. This places container start at approximately 06:09Z on **July 28** — roughly 15 minutes before the alert, not 14 hours. The account's claim that anti-forensics (`16:33:57Z`) and persistence (`16:35:02Z`) occurred on **July 27** in this container is incompatible with a process tree whose oldest process has been alive only ~29 minutes.

- **No bash process and no nc process present:** The question asks to "find the bash process that spawned nc and determine its full command line, user, and parent process." The `ps_output` contains neither a `bash` process nor an `nc` process. Only `python3 /opt/soc-playground/baseline/scheduler.py` (PID 77) appears as the relevant non-system process.

## 2. Strain

- **scheduler.py started within seconds of container boot:** PID 77 shows `ELAPSED 29:10` vs. `tini` at `29:13` and `sshd` at `29:11` — a 3-second spread. The account claims the adversary deployed the implant *after* establishing SSH access post-compromise, implying it was injected into a already-running container. The near-identical elapsed times make it look like the scheduler launched as part of container startup, not as a post-boot adversary action. To accommodate this cleanly, the account would need to say the container was freshly (re)started at ~06:09Z on July 28 with the scheduler already embedded — which then undercuts the narrative that the implant was deployed via an interactive SSH session during the July 27 compromise window.

- **Parent is sshd but could be startup-configured, not session-spawned:** The account asserts that being a child of `sshd` (PID 7) "confirms the scheduler was launched via an interactive or automated SSH login." The data confirms the parent-child relationship, but sshd as parent does not uniquely imply an SSH *session* — sshd could be configured to exec a process at startup. To accommodate this cleanly, the account would need to argue that no sshd startup configuration for scheduler.py exists (which this payload does not show either way).

## 3. Support

- **scheduler.py parent is sshd (PID 7), not tini (PID 1):** The `ps_output` row `"77 7 root Sl 29:10 \_ python3 /opt/soc-playground/baseline/scheduler.py"` directly confirms the account's claim that PID 77's parent is PID 7 (sshd), not PID 1 (tini).

- **Full command line matches:** The `ps_output` shows `python3 /opt/soc-playground/baseline/scheduler.py`, matching the account's asserted path exactly.

- **Running as root:** The `USER` field for PID 77 is `root`, consistent with the account's claim of root-level adversary access.