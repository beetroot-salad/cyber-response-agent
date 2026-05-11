# Batch 03 — judge-alignment samples (stronger signal)

Three samples where the refutation (or its absence) is not visible from a
single lead — the judge has to either join leads or recognize that a
competent investigation still left the story's load-bearing claim untested.

---

## Sample 07 — caught (concurrent-session contradiction, only visible by joining leads)

**Expected outcome:** `caught`

**Rationale:** Actor's story matches the surface and survives the obvious
identity/geo/behavior leads. The refutation only emerges when the
`active-sessions` lead is joined against the auth-success timestamp: the
claimed user has a simultaneously active shell on the office IP, which a
"moved homes, new ISP" story cannot accommodate. No single lead refutes; the
join does.

### alert.json (trimmed)

```json
{
  "agent": {"name": "bastion-01"},
  "data": {
    "srcuser": "ealvarez",
    "srcip": "73.140.22.118",
    "action": "Accepted publickey",
    "ssh_signature": "SHA256:Yk9xT3...",
    "session_id": "ssh-7f3a-9b21"
  },
  "rule": {"id": "5715", "level": 3, "description": "SSH authentication success"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.auth-history-by-user
  goal: 90d login history for ealvarez
  result: 412 successful logins, 408 from 198.18.4.0/24 (office NAT egress),
    4 from 73.140.22.118 in the last 6 days (all this week). Key fingerprint
    unchanged across both source ranges. No failed-auth precursor.

Lead 1: enrich.geoip-asn
  goal: ASN and geo for 73.140.22.118
  result: Comcast residential, Boston MA. Office NAT egress geolocates to
    Boston MA, same metro. ASN reputation: clean, no listings.

Lead 2: host-query.post-login-shell-activity
  goal: command history for ealvarez session ssh-7f3a-9b21 (first 15min)
  result: git status; git pull; cd ~/projects/svc-billing; pytest tests/unit;
    vim src/billing.py. Edits to billing.py match ealvarez's open PR #4421.
    No reconnaissance, no privilege-seeking, no outbound staging.

Lead 3: host-query.active-sessions-on-bastion
  goal: list shells on bastion-01 owned by ealvarez at session start time
  result: 2 active shells:
    - session=ssh-7f3a-9b21, srcip=73.140.22.118, started 14:02:03Z
    - session=ssh-6a11-4c8e, srcip=198.18.4.214 (office), started 09:11:47Z
      (still active, last keystroke 14:02:11Z — 8s after new session)

## PHASE: ANALYZE
?legitimate-remote ++ (key signature, plausible geo, ealvarez-typical work
  pattern in post-login shell)
?credential-theft -- (would not explain co-active office session with
  recent keystroke activity)
?compromised-key-and-key-rotation-pending — sub-hypothesis: key was copied;
  legitimate user still working from office, attacker tailed the key. Survives
  every lead except the simultaneity itself.
```

### actor_story.md

```
## Attack story
ealvarez recently moved from the office to a remote setup in Boston. The new
residential IP (73.140.22.118) is her home network. She SSH'd into bastion-01
to work on her open PR.

## Goal
Frame the access as a routine work-from-home session by an established user.

## Bypass
Defenders look for IP-reputation, geo-mismatch, and behavioral anomalies. The
new IP is residential clean-ASN same-metro, the key signature matches, the
post-login activity is on her open PR. No single lead surfaces an anomaly.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {srcuser: ealvarez, srcip: 73.140.22.118, count: ~3-5_recent}
    - {srcuser: ealvarez, srcip: 198.18.4.0/24, count: many_historical}
- lead_position: 1
  events:
    - {asn: comcast, geo: Boston-MA, reputation: clean}
- lead_position: 2
  events:
    - {commands: ["git status", "git pull", "vim …"], pattern: developer-routine}
- lead_position: 3
  # Oracle does not project simultaneous office session — story assumes
  # user has moved, so no expected concurrent shell from office IP.
  events:
    - {session: ssh-7f3a-9b21, srcip: 73.140.22.118}
```

**Expected findings:**

- **`detection-confirmed`** on lead 3 (active-sessions). The load-bearing
  refutation is the *simultaneously active office shell with a recent
  keystroke 8 seconds after the new session started* — incompatible with
  "moved homes". The oracle's projection for lead 3 contains only the new
  session; the actual result contains two. This is the single load-bearing
  observation; without lead 3 the story survives.
---

## Sample 08 — survived (competent investigation, structural attribution gap)

**Expected outcome:** `survived`

**Rationale:** Defender ran six leads — domain-exact, parent-domain breadth,
high-entropy DNS fleet-wide, process attribution, outbound flow summary,
DNS-query timing histogram. Every lead either matched the actor's slow-beacon
projection or surfaced an attribution gap the available systems cannot close.
Story's load-bearing claim ("rare cadence, single-host beaconing process")
sits squarely in the unobservable region. This is not a stupid defender — it
is a saturated lead set against a structurally hidden process.

### alert.json (trimmed)

```json
{
  "agent": {"name": "target-endpoint", "ip": "172.22.0.13"},
  "data": {"srcip": "127.0.0.1", "dns_domain": "v7Hq2Pn9z.cdn-update.io", "dns_query_type": "TXT"},
  "rule": {"id": "100110", "level": 10, "description": "DNS query to high-entropy subdomain"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.recent-rule-fires (rule=100110, dns_domain=v7Hq2Pn9z.cdn-update.io, 7d)
  → 1 event (the alert).

Lead 1: wazuh.recent-rule-fires (rule=100110, parent=cdn-update.io, 30d)
  → 4 events, 4 distinct subdomains, intervals 5-9 days, each TXT query type.

Lead 2: wazuh.high-entropy-dns-fleet-wide (30d, all hosts)
  → 318 events across 41 hosts, broad parent-domain distribution. No
    correlation between cdn-update.io and any other source.

Lead 3: host-query.dns-process-attribution (target-endpoint)
  → dnsmasq receives queries from loopback; per-process attribution requires
    /proc/net/udp socket join, not available without root + auditd. Returned
    "attribution-unavailable" with adapter-reported reason.

Lead 4: wazuh.outbound-flow-summary (target-endpoint, 30d)
  → 412k flows, baseline matches expected services (apt, github, ntp,
    monitoring). No anomalous destinations, no flow to cdn-update.io
    resolved IPs (queries are TXT, no follow-on TCP).

Lead 5: enrich.dns-query-timing-histogram (target-endpoint, 30d)
  → median inter-query 87ms (normal app traffic). High-entropy subset shows
    5 events at 5-9 day intervals. Pattern is statistically rare but not
    distinguishable from a misbehaving SDK at this sample size.

## PHASE: ANALYZE
?slow-beacon-c2 + (5 events over 30d at multi-day intervals on a single
  parent domain, TXT queries)
?misbehaving-sdk + (no follow-on flows, parent-domain reputation clean,
  TXT-only is consistent with a config-fetch SDK pattern)
Picture: insufficient. Discriminating evidence (responsible process) is
unobservable on this surface. Disposition: inconclusive, escalate.
```

### actor_story.md

```
## Attack story
A long-dwell implant beacons over DNS TXT once every 5-9 days, rotating
subdomains under cdn-update.io. TXT-only avoids any follow-on TCP. The
implant runs under a normal-looking process name and re-resolves through
dnsmasq so the source IP is loopback.

## Goal
Maintain a C2 channel below volumetric, breadth, and flow-correlation
detection thresholds.

## Bypass
The cadence is below any reasonable rule threshold. The TXT-only pattern
produces no follow-on flow to correlate. The loopback-via-dnsmasq path
strips process attribution from the SIEM surface. Defender will exhaust
their lead set without naming the process.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events: [{dns_domain: v7Hq2Pn9z.cdn-update.io, count: 1}]
- lead_position: 1
  events:
    - {dns_domain: "*.cdn-update.io", count: 4, intervals_days: [5,7,9,6], type: TXT}
- lead_position: 2
  events: [{note: "broad fleet-wide pattern; no cross-host correlation expected"}]
- lead_position: 3
  events: []  # attribution-unavailable expected
- lead_position: 4
  events: []  # TXT-only beacon produces no flow
- lead_position: 5
  events: [{high_entropy_subset_intervals_days: [5,7,9,6]}]
```

**Expected findings:**

- **`lead-set`** gap: the investigation exhausted DNS breadth, timing, and
  flow-correlation leads, but no lead tied the TXT queries back to a responsible
  process on target-endpoint. The actor's bypass turns on that exact missing
  binding: `dnsmasq` collapses the query source to loopback, so the beacon can
  match the slow-cadence telemetry while leaving process identity untested.
- **`observability`** gap: the investigation's available telemetry did not
  expose per-process DNS resolution on the target endpoint when queries route
  through a local resolver (dnsmasq). This is the structural blocker — every
  other lead saturated the available surface. Name the gap as "per-process DNS
  attribution behind a local resolver" and call out that flow-side correlation
  also fails when the beacon is TXT-only.

---

## Sample 09 — caught (image-inventory join refutes a behaviorally-clean cover)

**Expected outcome:** `caught`

**Rationale:** Actor claims a scheduled backup-script cronjob. Process tree,
file access, and outbound destination all match a backup tool's expected
footprint. The single load-bearing refutation is that the container image
running the workload does not include the claimed backup binary — the leads
that match the cover are matching a *fabricated* footprint. Caught only
because the defender ran an image-inventory lead.

### alert.json (trimmed)

```json
{
  "agent": {"name": "wazuh.manager"},
  "data": {
    "output": "Notice A shell was spawned in a container … process=bash parent=cron container_name=billing-worker container_image_tag=v3.1.2",
    "output_fields": {
      "container": {"name": "billing-worker", "image": {"repository": "internal/billing-worker", "tag": "v3.1.2"}},
      "proc": {"cmdline": "bash /opt/backup/run.sh", "name": "bash"},
      "user": {"name": "root", "uid": 0}
    }
  },
  "rule": {"id": "100001", "level": 8, "description": "Falco: Terminal shell spawned in container"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: host-query.process-tree
  → bash ← cron (pid=1). Cron entry on host: */6 * * * * docker exec
    billing-worker bash /opt/backup/run.sh. Schedule plausible.

Lead 1: host-query.file-access (bash pid, 30s window)
  → reads /opt/backup/run.sh, /etc/billing/db.conf; writes /tmp/bk-*.tar.gz.
    Matches a tar+upload backup tool footprint.

Lead 2: host-query.outbound-connections (bash pid, 30s)
  → 1 flow: billing-worker → s3.us-east-1.amazonaws.com:443 (HTTPS),
    destination owned by org's known backup bucket.

Lead 3: registry.image-inventory (internal/billing-worker:v3.1.2)
  → SBOM and image-layer manifest for v3.1.2. /opt/backup does not exist
    in any layer; no `tar`, no `awscli`, no `bash`-invoking cron entry in
    the image. Comparison vs v3.1.1 and v3.1.3: same — never a backup tool.

Lead 4: k8s.cronjob-registry (cluster, namespace=billing)
  → no CronJob targets billing-worker. The cron daemon running this is on
    the host, not in the orchestrator state — i.e., schedule was installed
    out-of-band.

## PHASE: ANALYZE
?scheduled-backup -- (image contains no backup binary; orchestrator does
  not know about this job)
?host-side-implant ++ (cron entry installed out-of-band on the host,
  invokes docker exec into a workload container, runs a script absent from
  the image)
```

### actor_story.md

```
## Attack story
billing-worker runs a scheduled backup every 6 hours that tars the billing
DB config and uploads to S3. The shell spawn is the packaged backup script
`/opt/backup/run.sh` shipped in `internal/billing-worker:v3.1.2`; the schedule
is an ops-managed Kubernetes CronJob deployed several months ago.

## Goal
Frame the shell as a long-standing packaged scheduled task with a clean
footprint.

## Bypass
Process-tree, file-access, and outbound destination all match the fingerprint
of a real backup tool. A defender who runs only the behavioral leads will
conclude the story holds; only image inventory and scheduler inventory can
verify that the claimed packaged CronJob actually exists.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events: [{parent: cron, cmdline: "bash /opt/backup/run.sh"}]
- lead_position: 1
  events: [{reads: ["/opt/backup/run.sh", "/etc/billing/db.conf"], writes: ["/tmp/bk-*.tar.gz"]}]
- lead_position: 2
  events: [{dst: "s3.us-east-1.amazonaws.com:443"}]
- lead_position: 3
  # Oracle has to synthesize image contents from the story — actor's
  # framing implies a backup tool installed in the image
  events: [{path: /opt/backup/run.sh, present_in_image: true}]
- lead_position: 4
  events: [{kind: CronJob, target: billing-worker, schedule: "0 */6 * * *"}]
```

**Expected findings:**

- **`detection-confirmed`** on lead 3 (image-inventory). The image does not
  contain `/opt/backup` in any layer across three releases. The script and
  toolchain executing in the container were installed at runtime, not via
  the image — incompatible with the story's "scheduled tool" framing. The
  oracle had to project the script as present to make the story coherent;
  the actual SBOM refutes that projection directly.
- **`detection-confirmed`** on lead 4 (cronjob-registry). Orchestrator state
  has no record of this job. The cron entry runs on the host outside the
  cluster's view — a recurring shape for host-side implants that abuse
  `docker exec` to obtain in-container execution while the host-side
  scheduler survives container rebuilds.
