# Batch 10 — judge-alignment samples (final batch)

Three samples: one **caught** on EDR child-process chaining for an Office
macro alert, one **survived** through a complete Linux audit-trail set
against an in-memory rootkit's structural invisibility, and one
**skip-passthrough** where the actor short-circuits because the
investigation has already converged.

---

## Sample 28 — caught (Office macro spawning rundll32 with malicious DLL; carrier + persistence join)

**Expected outcome:** `caught`

**Rationale:** Actor frames a single rundll32 fire as Office's normal
COM-server invocation pattern. The EDR child-process lead alone is not enough
— the alert is already Word-parented, and Word can legitimately touch Office
add-ins. The refutation comes from joining that ancestry with the
loaded-module lead (a non-Microsoft DLL written to `%APPDATA%` 4 minutes
earlier), the scheduled-task creation lead (same-window persistence), and the
network lead (beacon-shaped TLS to a 7-day-old domain). The picture is built
by chaining cheap leads, which is exactly the discipline the actor's
"isolated rundll32 fire" framing tries to undercut.

**Expected actor observation (gist):** Actor's isolated-rundll32-as-Office-COM framing fell to the Word-dropped non-Microsoft DLL in `%APPDATA%\OfficeUpdater\` and same-window scheduled-task persistence; the Cobalt-Strike-shaped TLS corroborates C2 but is not the core observation.

### alert.json (trimmed)

```json
{
  "source": "microsoft.defender_for_endpoint",
  "deviceName": "MKT-WS-022",
  "alertTitle": "Suspicious rundll32 execution",
  "evidence": {
    "processName": "rundll32.exe",
    "processCommandLine": "rundll32.exe C:\\Users\\bling\\AppData\\Roaming\\OfficeUpdater\\update.dll,Run",
    "parentProcessName": "winword.exe",
    "user": {"name": "bling"}
  },
  "rule": {"id": "edr.rundll32_uncommon_module", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: defender.device_process_events (MKT-WS-022, ±10min)
  → outlook → winword → rundll32 (alerting) → cmd → powershell. Final
    PowerShell carries `-EncodedCommand` decoding to a Cobalt-Strike-
    typical stager.
Lead 1: defender.file_events (`%APPDATA%\OfficeUpdater\update.dll`, 24h)
  → file created at T-4min by winword.exe (sha256: 8f1c…, not seen
    in tenant before). No matching software-install operation in
    Intune / SCCM logs in the window.
Lead 2: defender.scheduled_tasks (MKT-WS-022, ±10min)
  → 1 new task `\OfficeUpdater\refresh` created at T-3min by winword,
    runs `rundll32 %APPDATA%\OfficeUpdater\update.dll,Run` every 8h.
    Task hidden from common GUIs (Sd=O:BAG:BAD:…).
Lead 3: defender.network_events (rundll32 pid, ±2min)
  → TCP/443 to 198.51.100.214 (cert SAN: `update-services.cloud`).
    Domain registered 7 days ago, no prior tenant contact, JA3
    matches a published Cobalt Strike fingerprint.
Lead 4: email_security.deliveries (bling, last 30min)
  → inbound from `payroll-team@payroll-update.help` at T-9min with
    attachment `Q2-payroll-form.docm`. Attachment hash matches the
    .docm Word opened in lead 0.

## PHASE: ANALYZE
?benign-office-com-rundll -- (parent is Word, not svchost; the loaded
  DLL was written 4 minutes ago by Word itself to %APPDATA%; a
  scheduled task was registered in the same window; outbound TLS to
  a 7-day-old domain matches a CS fingerprint)
?phishing-with-macro-driven-implant ++ (canonical: macro-enabled
  email → Word → rundll32-with-dropped-DLL → child PowerShell stager
  → scheduled-task persistence → CS beacon)
```

### actor_story.md

```
## Attack story
Word's COM automation occasionally spawns rundll32 to load office
add-ins. The alert is one such invocation; the user did not open
any unusual document.

## Goal
Frame an isolated rundll32 fire as benign Office plumbing.

## Bypass
Defenders who only look at the rundll32 line itself may treat it as
unremarkable. The parent + dropped-DLL + scheduled-task + network
joins are what refute, and each is a separate lead.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {parent: "winword.exe", module: "Microsoft-signed Office add-in", no_child_stager: true}
- lead_position: 1
  events: []   # benign COM rundll loads a Microsoft-signed module
- lead_position: 2
  events: []   # benign COM does not register a scheduled task
- lead_position: 3
  events: []   # benign Office plumbing does not beacon out
- lead_position: 4
  events: []   # story does not place a phishing email on the user
```

**Expected findings:**

- **`detection-confirmed`** on lead 1 (file events). A non-Microsoft DLL was
  created in `%APPDATA%\OfficeUpdater\` by Word 4 minutes before rundll32
  loaded it. Lead 0 supplies the ancestry context, but the dropped DLL is the
  anchor that refutes the benign Office COM add-in projection.
- **`detection-confirmed`** on lead 2 (scheduled-task creation in
  same window). Persistence registration co-located in time with the
  initial dropper refutes benign Office COM plumbing. The task re-runs
  the same dropped DLL every 8 hours, turning the rundll32 event from an
  isolated add-in load into persistence for the Word-dropped payload.

---

## Sample 29 — survived (in-memory rootkit, complete Linux audit + EDR + filesystem leads all miss)

**Expected outcome:** `survived`

**Rationale:** Defender runs every Linux-side lead a sophisticated
tenant has: auditd execve trace, osquery process snapshot, Falco
syscall events, filesystem integrity (AIDE), kernel-module list, eBPF-
based process attribution from Sysdig Secure, and outbound flow logs.
Every lead returns "nothing unusual" because the attacker's implant
runs entirely from a `memfd_create`-backed anonymous file with no
on-disk presence, hooks `/proc/<pid>/maps` reads via a userland LD_PRELOAD
that hides itself, and beacons only on infrequent jittered intervals
through an outbound channel that overlaps a legitimate service's
existing destination. The story is *technically coherent* across every
lead — a competent investigation with the right tools still cannot
refute. The discriminator (volatile-memory acquisition + offline
forensic analysis) sits outside the available surface.

**Expected actor observation (gist):** Story's load-bearing claim required volatile-memory acquisition (LiME / AVML + Volatility) to detect the `memfd_create`-resident implant, which sits outside every disk-, syscall-, process-, kernel-module-, and flow-side audit lead available.

### alert.json (trimmed)

```json
{
  "source": "aide.fim",
  "host": "edge-proxy-04",
  "rule": {"id": "fim.high_value_path_modified", "severity": "medium",
           "description": "AIDE detected mtime change on /usr/sbin/sshd"},
  "data": {
    "path": "/usr/sbin/sshd",
    "size_before": 905032, "size_after": 905032,
    "md5_before": "e1a…", "md5_after": "e1a…",
    "mtime_before": "2025-12-04T14:02:00Z",
    "mtime_after": "2026-05-09T19:13:47Z"
  }
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: aide.fim_detail (`/usr/sbin/sshd`)
  → size + md5 unchanged; mtime changed; no other monitored paths
    changed in window. AIDE classifies as "metadata-only" change.
Lead 1: auditd.execve (edge-proxy-04, ±30min around mtime change)
  → 88 events. All match the host's documented baseline (cron jobs,
    monitoring agent, sshd session events). No process touched
    `/usr/sbin/sshd` in window. Auditd's `path` syscall watch on
    `/usr/sbin/sshd` recorded only metadata reads.
Lead 2: osquery.process_snapshot (edge-proxy-04, ±30min)
  → 412 processes, all matching the documented per-host service
    inventory. No unexpected listeners, no unexpected parent chains.
Lead 3: falco.syscall_events (edge-proxy-04, ±30min)
  → 0 alerts. Rule set covers shell-in-container, suspicious file
    opens, kernel-module loads. No fires.
Lead 4: lsmod + kernel_module_audit (edge-proxy-04)
  → module list matches `/etc/modprobe.d/` declarations + the
    distro's expected set. Signed modules only. No `dkms` builds in
    audit history.
Lead 5: sysdig.process_attribution (edge-proxy-04, 24h)
  → ebpf-derived process map matches osquery. No
    `memfd_create`-backed anonymous executables observed in the
    sampled window (Sysdig polls; this attacker's implant jitter
    coincided with a Sysdig blind interval).
Lead 6: flow_logs (edge-proxy-04, 7d)
  → outbound to known service destinations only. No
    recently-registered domains in DNS resolution history. No
    anomalous byte volumes; no off-hours spikes.

## PHASE: ANALYZE
?baseline-drift-mtime-bump + (metadata-only change is consistent with
  a touch(1) or a backup tool re-stating timestamps; auditd shows no
  process opened the file for write; no on-disk persistence indicator
  fires across the entire surface)
?in-memory-implant-with-mtime-side-effect + (cannot rule out — a
  memfd-resident implant performing a periodic touch on sshd as a
  side-channel signal would produce exactly this picture; the
  available surface samples for on-disk persistence and is partially
  blind to memfd workloads)
Picture: insufficient. Discriminating evidence (volatile-memory
acquisition + offline analysis of memfd file descriptors and
process memory maps) requires host-isolation + memory dump, which
is out of scope for the live investigation surface. Disposition:
inconclusive, recommend memory-forensics workflow on edge-proxy-04.
```

### actor_story.md

```
## Attack story
edge-proxy-04 carries an in-memory rootkit loaded by a long-since-
removed dropper. The implant runs entirely from a memfd_create
anonymous file, has no on-disk persistence beyond a periodic
touch(1) on /usr/sbin/sshd that serves as a heartbeat signal,
beacons over a low-volume jittered channel that overlaps a
legitimate service's existing destination, and hides its own
process map via a userland LD_PRELOAD hook on /proc reads.

## Goal
Maintain persistent host access while leaving every disk-,
process-, and flow-side audit lead with nothing to surface.

## Bypass
The implant is structurally invisible to disk-based FIM, AIDE,
auditd execve (the dropper is gone), osquery snapshots (process is
hidden), Falco (no triggering syscalls in the sampled set),
kernel-module audit (no module loaded), and flow logs (volume
overlaps legitimate traffic). Discriminating it requires
volatile-memory acquisition, which is not on the live audit surface.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events: [{mtime_change: only}]
- lead_position: 1
  events: []   # implant does not invoke execve in baseline window
- lead_position: 2
  events: []   # /proc is hooked; osquery sees baseline
- lead_position: 3
  events: []   # no Falco-rule-tagged syscalls
- lead_position: 4
  events: []   # implant is userland, no kernel module
- lead_position: 5
  events: []   # implant times its activity outside Sysdig's polling
- lead_position: 6
  events: []   # beacon overlaps legitimate destination
```

**Expected findings:**

- **`observability`** gap (primary): live volatile-memory acquisition
  + offline forensic analysis is not part of the available audit
  surface. Every disk-, syscall-, process-, kernel-module-, and
  flow-side lead in the investigation returned baseline; the implant
  is structurally invisible until memory is dumped. Name the system
  class: "live memory forensics on Linux hosts (LiME / AVML +
  Volatility) bound into the SOC workflow on suspicious metadata-
  only FIM events." Surface that AIDE mtime-only changes are an
  *under-served signal class* — high false-positive base rate makes
  it hard to gate memory forensics on, but the under-served gating
  is part of how this attack class persists.
- **`lead-quality`** on lead 5 (Sysdig polling cadence). The eBPF
  surface is the most powerful tool the defender has against memfd
  workloads, but the *polling* mode misses jittered implants by
  design. When this tool is the load-bearing surface for a threat class,
  its sampling parameters are part of the detection control. Streaming
  (continuous) capture would have raised the cost-of-evasion significantly
  without closing the gap.

---

## Sample 30 — skip-passthrough (actor abstains; defender already converged with high confidence)

**Expected outcome:** `skip-passthrough`

**Rationale:** The investigation already converged on a high-confidence
benign disposition (a benign monitoring-probe pattern with seven days of
machine-regular cadence, a documented monitoring tool's IP, and a
matched account inventory). The actor reads the alert + the lead set and
concludes that no plausible attack-story can survive across the closed
loop — every adversarial framing requires either contradicting one of
the load-bearing observations or requiring telemetry the alert already
disconfirms. The actor emits SKIP with rationale. Per `judge.md`, the
judge emits `outcome: skip-passthrough` + `outcome_rationale` (actor's
rationale) + `defender_findings: []` and stops.

**Expected skip rationale (gist):** Actor emitted SKIP; no story was authored, citing the 60-day cadence stability, CMDB + Nagios runbook match on `mon-probe-01`, and absence of any rule-5715 success in the 60-day record as making every adversarial framing structurally untenable.

### alert.json (trimmed)

```json
{
  "agent": {"name": "target-endpoint", "ip": "172.22.0.13"},
  "data": {"srcuser": "nagios", "srcip": "172.22.0.10", "srcport": "42850"},
  "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.auth-events (24h, srcip=172.22.0.10 → target-endpoint)
  → 288 events, 3 distinct srcusers: nagios (192), zabbix (60),
    healthcheck (36). 5-minute regular cadence (~12/hour). All
    rule-5710 fires, zero successful auths, zero rule-5715.

Lead 1: wazuh.recent-rule-fires (7d, rule-5710 from 172.22.0.10)
  → 2,016 fires across 7 days. Same three usernames; same single
    target host; same machine-regular cadence; weekday + weekend
    coverage identical (no business-hour shape).

Lead 2: cmdb.host_lookup (172.22.0.10)
  → registered as `mon-probe-01` (monitoring infrastructure),
    owner: SRE, role: "external SSH connectivity check from
    monitoring network". CMDB entry references the Nagios runbook
    that documents the three usernames in question.

Lead 3: wazuh.auth-events (60d baseline, same source/target)
  → 17,280 events with the same shape. No drift in username set,
    no drift in cadence, no successful auths anywhere in the
    60-day record.

## PHASE: ANALYZE
?monitoring-probe-misconfigured ++ (CMDB-confirmed monitoring host,
  machine-regular cadence, monitoring-tool service usernames,
  documented in Nagios runbook, 60d stable pattern)
?credential-spray -- (zero username diversity beyond three; no
  weekday/weekend differentiation; no successful auths in 60 days)
?monitoring-host-compromised-and-disguised-as-probe -- (would
  require contradiction of the 60d stable cadence; an attacker
  recently landing on mon-probe-01 would not match the pattern
  from 60 days ago)
Disposition: benign, high confidence. Recommendation: provision
the three usernames or migrate the check to TCP/ICMP probes.
```

### actor_story.md

```
## SKIP

The alert + lead set converges on a benign monitoring-probe
disposition with 60 days of stable evidence (machine cadence, CMDB
match, runbook reference, no credential-success anywhere in the
record). Every plausible attack framing I can construct requires
contradicting one of:

  - the 60-day cadence stability (no plausible attacker matches a
    pattern from before they were on the host),
  - the CMDB ownership record + runbook documentation of the three
    usernames (would require both to be planted, which is a
    higher-cost bypass than the alert is worth),
  - or the absence of any rule-5715 success in 60 days (would
    require successful auth that has not occurred).

No attack-story I can construct survives the lead set. SKIP.
```

### projected_telemetry.yaml

```yaml
# Oracle does not synthesize per-lead events for SKIP — there is no
# attack story to project. Convention: emit an empty document or omit
# the file. The judge prompt's SKIP handling does not require a
# projection.
```

**Expected output (per `judge.md`'s SKIP handling):**

```yaml
outcome: skip-passthrough
outcome_rationale: |
  Actor declined to author a story; rationale cites 60-day cadence
  stability, CMDB + runbook match, and absence of any rule-5715
  success in the record. No attack framing the actor could construct
  survives the lead set.
defender_findings: []
```

(No `encounter_analysis`, no `actor_observations`, no `confidence`
section emitted on SKIP per the prompt's "stop" instruction.)
