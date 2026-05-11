# Batch 04 — judge-alignment samples

Three samples grounded in common Linux SIEM/EDR evidence classes
(auth events, recent rule fires, DNS history, file-integrity changes,
container runtime alerts, sudo commands, and agent alerts). Refutations
and gaps live in cross-lead joins or in missing host-execution visibility,
not in adapter-specific query quirks.

---

## Sample 10 — survived (sudo escalation, lead set saturates wazuh surface)

**Expected outcome:** `survived`

**Rationale:** Defender ran every host-side SIEM lead that could plausibly
touch the alert (sudo history, auth events around the sudo, file-integrity
activity in the affected window, recent rule fires for elevation patterns).
Every result is consistent with the actor's "routine admin maintenance"
framing. The discriminating evidence — what commands the sudo'd shell
actually ran after the recorded `sudo -i` — sits in auditd / process-exec
telemetry. Story survives across a competent investigation that lacks that
execution-level view.

### alert.json (trimmed)

```json
{
  "agent": {"name": "db-02", "ip": "172.22.0.18"},
  "data": {
    "srcuser": "jcho",
    "dstuser": "root",
    "command": "/bin/bash",
    "tty": "pts/3"
  },
  "rule": {"id": "5402", "level": 3, "description": "Successful sudo to ROOT executed."}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.sudo-commands
  goal: 30d sudo history for jcho on db-02
  result: 142 sudo events. ~5/week, all from pts/* sessions during business
    hours, dstuser=root. Command distribution: /bin/bash (44%), systemctl
    restart postgresql (18%), tail /var/log/postgresql/*.log (16%),
    /usr/local/bin/db-maintenance.sh (12%), remainder ad-hoc psql / ls.
    The triggering event sits inside this 30d distribution.

Lead 1: wazuh.auth-events
  goal: 24h SSH auth context for jcho on db-02
  result: 1 successful login at 09:14:02Z from 198.18.4.211 (office NAT,
    jcho's typical egress). No failures from this user in window. Session
    matches the pts/3 of the sudo event.

Lead 2: wazuh.file-integrity-changes
  goal: FIM changes on db-02 in ±2h around the sudo
  result: 0 monitored paths changed. /etc, /usr/local/bin, /root, and the
    postgres data dirs all unchanged.

Lead 3: wazuh.recent-rule-fires
  goal: 7d scope of privilege-escalation/persistence rules on db-02
  (rules: 5402, 2902, 5104, 100001 family)
  result: 38 rule-5402 fires (all jcho or postgres-svc, all business hours),
    0 rule-2902 (sudoers modified), 0 rule-5104 (new user), 0 falco-family
    fires.

## PHASE: ANALYZE
?routine-admin ++ (sudo pattern, login context, no FIM, no elevation/persistence
  rules firing)
?compromised-account-using-jcho-pattern + (cannot rule out — every wazuh
  signal is consistent with jcho's baseline, but baseline-matching is what a
  competent attacker would target). Discriminating evidence: what the
  resulting root shell *did*. Out of wazuh surface.
Picture: insufficient on wazuh-only surface. Disposition: inconclusive,
escalate for auditd / endpoint-exec review.
```

### actor_story.md

```
## Attack story
jcho's SSH key was stolen by an operator with hands-on access to her laptop.
The operator authenticates as jcho during her normal working hours from the
office NAT (using a SOCKS proxy through her own machine, so the source IP
matches), opens a pts session, runs `sudo -i` to root (jcho legitimately uses
sudo many times per week, so the pattern is preserved), and then performs
slow data staging into postgres dumps that are uploaded over an existing
backup channel — leaving no FIM trace and no new processes that any
existing wazuh rule fires on.

## Goal
Live entirely inside jcho's baseline so host-side SIEM leads return
consistent-with-baseline answers.

## Bypass
Mimic timing, source IP, sudo cadence, and command shape. Avoid file writes
that FIM monitors. Use only the postgres user's normal toolchain. The
investigation will exhaust coarse host-side telemetry without hitting
the discriminating signal (the actual command stream inside the root
shell).
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {srcuser: jcho, dstuser: root, command: /bin/bash, count: many_in_30d, hours: business}
- lead_position: 1
  events:
    - {srcuser: jcho, srcip: 198.18.4.0/24, action: "Accepted publickey", time: 09:14:02Z}
- lead_position: 2
  events: []   # no FIM writes by design
- lead_position: 3
  events:
    - {rule: 5402, count: ~30-40_in_7d}
    # no 2902 / 5104 / falco fires projected
```

**Expected findings:**

- **`observability`** gap: the investigation covers the sudo invocation
  and surrounding rule/FIM/auth context, but not per-process command
  execution inside the resulting root shell. Auditd / EDR / shell-history
  forwarding would be needed to ground "what did the root shell do" —
  precisely the load-bearing claim the actor's story targets.
- **`analyze-discipline`** on lead 0 (`wazuh.sudo-commands`): the template
  returned a 30-day baseline that made the alert look normal, but ANALYZE did
  not treat baseline-match as benign proof. The root discipline is that
  baseline-match is consistent-with-baseline, not consistent-with-benign, and
  the difference matters when the threat model includes credential theft.

---

## Sample 11 — caught (DNS, single-host scope refutes SaaS-SDK framing)

**Expected outcome:** `caught`

**Rationale:** Actor frames rule-100110 fires as routine SaaS telemetry —
the product hashes account IDs into subdomains under a vendor parent, so
high-entropy subdomains are expected. The framing implies the *parent domain*
appears across the fleet (every customer's host using the SaaS hits it). The
defender's recent-rule-fires lead by parent domain shows fires from this one
host only, while a baseline lead shows the host is otherwise quiet on this
parent. Single-host concentration is incompatible with shared SaaS adoption
and is the load-bearing refutation.

### alert.json (trimmed)

```json
{
  "agent": {"name": "marketing-laptop-07", "ip": "10.40.7.22"},
  "data": {
    "srcip": "10.40.7.22",
    "dns_domain": "a4f1c829ee21.mtrx.telemetry-cloud.io",
    "dns_query_type": "A"
  },
  "rule": {"id": "100110", "level": 8, "description": "DNS query to high-entropy subdomain"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.dns-query-history
  goal: 7d queries for parent telemetry-cloud.io across the fleet
  result: 1,182 events, all from marketing-laptop-07. 612 distinct subdomains
    under telemetry-cloud.io. No other host has resolved this parent in 7d.

Lead 1: wazuh.recent-rule-fires
  goal: 30d fleet-wide rule-100110 fires by parent telemetry-cloud.io
  result: 47 fires, all from marketing-laptop-07.

Lead 2: wazuh.dns-query-history
  goal: 7d top-100 parent domains resolved by marketing-laptop-07
  result: standard fleet baseline (windows update, browser CDNs, m365,
    company SaaS endpoints). telemetry-cloud.io appears at rank 4 — high
    volume relative to this host's other traffic; rank 0 for fleet share.

Lead 3: wazuh.agent-alerts-in-window
  goal: 24h alerts on marketing-laptop-07 around alert time
  result: 5 rule-100110 fires (same parent), 1 rule-32152 fire (process
    spawn from a downloads folder by a user not in the IT group), 2 hours
    earlier.

## PHASE: ANALYZE
?saas-sdk-on-this-host -- (no other host on the fleet uses this SaaS in 7d;
  a real product would have more than one customer endpoint)
?personal-sdk -- (volume is high enough that a casual personal app would
  show similar traffic on at least one other marketing host)
?implant-on-this-host ++ (single-host concentration + co-occurring
  unprivileged process spawn + high subdomain entropy + fresh parent domain
  combine into the canonical hashed-subdomain C2 fingerprint)
```

### actor_story.md

```
## Attack story
marketing-laptop-07 has the company's managed marketing analytics SaaS
installed. The product is deployed to the marketing laptop fleet and hashes
account identifiers into DNS subdomains under telemetry-cloud.io. The
high-entropy subdomains are routine telemetry; the volume reflects an active
workday.

## Goal
Frame the DNS pattern as a managed vendor SDK whose presence the defender
cannot disprove.

## Bypass
The defender cannot verify the SaaS product's identity from DNS alone. A 7d
query history should show many distinct subdomains under the parent across
marketing hosts, consistent with hashed-id telemetry. Without an asset
inventory or SBOM the defender has no direct way to rule out the SDK.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {parent: telemetry-cloud.io, count: ~1000_per_active_customer, hosts: "many across fleet"}
- lead_position: 1
  events:
    - {rule: 100110, parent: telemetry-cloud.io, hosts: "many across fleet"}
- lead_position: 2
  events:
    - {parent: telemetry-cloud.io, rank_on_host: "top-5-on-active-customers"}
- lead_position: 3
  events:
    - {rule: 100110, count: ~5}
    # no concurrent unrelated process-spawn alert expected
```

**Expected findings:**

- **`detection-confirmed`** on leads 0 + 1 joined (`wazuh.dns-query-history`
  + `wazuh.recent-rule-fires`). Both leads independently restrict
  telemetry-cloud.io activity to a single host across a 7–30d window. The
  oracle projected fleet-wide presence — the SaaS framing structurally
  requires it. Single-host concentration is the load-bearing refutation
  and is robust to the actor's "vendor SDK" cover.
- **`detection-confirmed`** on lead 3 (`wazuh.agent-alerts-in-window`).
  The co-occurring rule-32152 fire (unprivileged process spawn from
  Downloads two hours before the DNS burst) gives the responder a
  pivot — the implant carrier candidate — that none of the DNS-only leads
  could surface. Worth preserving as a discipline: pulling a 24h alert
  window on the originating host catches carrier-of-carrier signal even
  when the focal signature is DNS.
---

## Sample 12 — caught (FIM cron drop, refuted by joining FIM with the alerts window)

**Expected outcome:** `caught`

**Rationale:** Actor claims a package install dropped the new file under
`/etc/cron.d/`. Defender's FIM lead shows the cron file's body — a one-liner
invoking `/tmp/.cache/run`. Two adjacent leads close the case: a
recent-rule-fires lookup finds no package-manager-related rule fires in the
24h before the FIM event, and an agent-alerts-in-window lookup finds a
concurrent rule-100001 (Falco shell-in-container) fire from the same host in
the same minute. FIM-only or recent-rule-fires-only would not be decisive;
the join is.

### alert.json (trimmed)

```json
{
  "agent": {"name": "build-runner-04", "ip": "10.60.1.44"},
  "data": {
    "syscheck": {
      "path": "/etc/cron.d/system-cache",
      "mode": "realtime",
      "size_after": "78",
      "uname_after": "root", "gname_after": "root",
      "perm_after": "rw-r--r--"
    }
  },
  "rule": {"id": "554", "level": 7, "description": "File added to the system."}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.file-integrity-changes
  goal: enumerate content + recent neighbors of /etc/cron.d/system-cache
  result: file body (78 bytes): `*/15 * * * * root /tmp/.cache/run >/dev/null 2>&1`
    Recent /etc/cron.d/ changes: this is the only new file in 30 days.
    No companion /etc/cron.d/* deletions.

Lead 1: wazuh.recent-rule-fires
  goal: 24h preceding fires on build-runner-04 for package-manager and shell
  (rules: 2902, 2904, 2932, 51002, 100001, 100002)
  result: 0 rule-2902/2904/2932 (no apt/yum/dpkg-typed fires). 1 rule-100001
    fire 47 seconds before the FIM event (Falco terminal shell in
    container=build-runner). 1 rule-100002 fire 12 seconds before the FIM
    event (stdout/stdin redirected to network, fd.rip=185.220.101.45).

Lead 2: wazuh.agent-alerts-in-window
  goal: full alert stream for build-runner-04, ±5min around FIM event
  result: 9 alerts. The rule-100001 + rule-100002 pair above; a rule-100110
    high-entropy DNS query 12 minutes earlier; 6 routine fires (rsyslog,
    auditd housekeeping). No rule-2902/2904 anywhere in window.

## PHASE: ANALYZE
?package-install -- (no apt/yum/dpkg rule fires within the 24h window; cron
  drops from package installs typically co-occur with rule-2902 or
  rule-2904)
?legitimate-orchestrator-push -- (would be installed under
  /etc/cron.d/<package-name>, not "system-cache"; orchestrator pushes also
  do not co-occur with falco shell-in-container fires)
?host-side-implant ++ (the rule-100001/100002 pair seconds before the FIM
  write, plus the high-entropy DNS 12 minutes earlier, plus the cron entry
  pointing into /tmp/.cache/, are the canonical "shell → network-redirect
  → persistence" sequence)
```

### actor_story.md

```
## Attack story
A routine package install on build-runner-04 dropped a cron file under
/etc/cron.d/ to schedule a cleanup job. The path under /tmp/.cache/ is a
working directory used by the package's runtime. The 554 rule fired because
file-add monitoring is noisy.

## Goal
Frame the cron drop as part of an authorized package install.

## Bypass
Most defenders only look at FIM in isolation. The cron file is small,
root-owned, mode 0644 — visually indistinguishable from a packaged drop.
The investigation will not have a good way to verify whether a package
install actually occurred.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - path: /etc/cron.d/system-cache
      body: "*/15 * * * * root /tmp/.cache/run >/dev/null 2>&1"
- lead_position: 1
  events:
    # Oracle projects what a real package install would produce
    - {rule: 2902, agent: build-runner-04, count: 1, time: "T-<small>"}
    # No falco shell / network-redirect fires projected
- lead_position: 2
  events:
    - {rule: 2902, count: 1}
    - {rule: 554, count: 1}
```

**Expected findings:**

- **`detection-confirmed`** on lead 1 + lead 2 joined. The load-bearing
  refutation is the *absence* of package-manager rule fires combined with
  the *presence* of a falco shell-in-container + network-redirect pair
  seconds before the FIM event. Neither lead is decisive alone — no
  package-manager fires could mean a quiet install method; falco fires
  alone do not name the persistence mechanism. The temporal join
  (shell-redirect → 47s gap → FIM write of a cron entry pointing into
  /tmp/.cache) is the signal.
