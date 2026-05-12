# Batch 01 — judge-alignment samples

Three samples spanning **caught / survived / incoherent**. Each sample bundles
the four artifacts the judge sees and an expected outcome with a one-line
rationale. Designed to be unambiguous so disagreement on these is signal that
the judge prompt drifts on easy cases.

---

## Sample 01 — caught (SSH brute force, actor invents monitoring cover)

**Expected outcome:** `caught`

**Rationale:** Actor claims a single-username monitoring probe; oracle projects
nagios-only failures; defender lead actually returned 11 distinct dictionary
usernames against multiple targets. Direct refutation.

**Expected actor observation (gist):** Actor's single-username Nagios monitoring-probe framing crumbled against the 11-username dictionary spanning OS service accounts (root, admin, oracle, postgres, …) swept across three hosts that lead 0 surfaced.

**Expected findings:**

- **`detection-confirmed`** on lead 0 (auth-events). The 24h auth-events pull
  caught the story by returning an 11-username dictionary (root, admin,
  oracle, postgres, …) where the oracle projected nagios-only events. The
  username diversity itself is the discriminator: a monitoring framework
  sweeps a fixed account, not a list spanning OS service accounts. Cite
  investigation's "11 distinct srcusers" and the actor's "uses the username
  nagios" claim.
- **`detection-confirmed`** on lead 1 (recent-rule-fires). Multi-target scope
  (target-endpoint + app-01 + db-02) refutes the story's per-target check
  framing; a Nagios check is configured per-target with per-target account
  conventions, not a single dictionary swept against three unrelated hosts.
  Cite "18,440 fires … three targets" vs actor's "single source/target pair".
### alert.json (trimmed)

```json
{
  "agent": {"name": "target-endpoint", "ip": "172.22.0.13"},
  "data": {"srcuser": "root", "srcip": "203.0.113.42", "srcport": "55102"},
  "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user"},
  "predecoder": {"program_name": "sshd", "timestamp": "May  9 03:12:14"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.auth-events
  goal: characterize 24h SSH auth failures from 203.0.113.42 to target-endpoint
  result: 4,812 events. 11 distinct srcusers: root (1411), admin (982), oracle
    (744), postgres (612), ubuntu (501), test (321), git (118), jenkins (62),
    deploy (37), www-data (18), centos (6). Sub-second inter-arrival, source
    port monotonically increasing. Zero successful auths.

Lead 1: wazuh.recent-rule-fires
  goal: 7d scope of rule-5710 from 203.0.113.42 across all agents
  result: 18,440 fires. Three targets: target-endpoint (4,812), app-01 (7,221),
    db-02 (6,407). Same username dictionary across all three.

## PHASE: ANALYZE
?credential-spray ++ (broad username dict, multi-target, fast cadence)
?monitoring-probe -- (zero overlap with monitoring tool service-account names)
```

### actor_story.md

```
## Attack story
203.0.113.42 is a managed Nagios check host. The "root" attempt seen in the
alert is one tick of a 5-minute SSH connectivity check that uses the username
"nagios" for service identification; alert noise sometimes mislabels the user
field. No real credential testing occurs.

## Goal
Hide the fact that 203.0.113.42 is a rented VPS conducting opportunistic
credential spray.

## Bypass
The username field in the alert is unreliable. Most monitoring frameworks
sweep a single service account on a fixed interval, and a 24h pull on this
single source/target pair will show a narrow nagios-only pattern indistinguishable
from baseline monitoring traffic.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {srcip: 203.0.113.42, srcuser: nagios, hostname: target-endpoint, count: ~288}
- lead_position: 1
  events:
    - {srcip: 203.0.113.42, srcuser: nagios, hostname: target-endpoint, count: ~2000}
```

---

## Sample 02 — survived (DNS DGA, single-event alert, narrow lead set)

**Expected outcome:** `survived`

**Rationale:** Defender only ran a domain-exact lookup, returning the single
triggering query. Actor's slow-beacon story projects exactly that — one query
per 24h. No lead in the run touches the story's load-bearing claim (any other
beacon channels, process attribution). Projection matches actual.

**Expected actor observation (gist):** Actor's slow-beacon C2 story relied on the parent domain `beacon.example.org` never being enumerated for sibling high-entropy subdomains; the defender's domain-exact lookup tested only the alert's own subdomain.

**Expected findings:**

- **`lead-set`** gap: no lead used `wazuh.dns-query-history` to enumerate
  other high-entropy subdomains under `beacon.example.org` or the parent
  domain itself. A 7-day parent-domain pull would have surfaced
  whether the triggering subdomain is one of many siblings (consistent with
  DGA-style rotation, refuting the "one-off typo" alternative). The
  domain-exact lookup is too narrow — it tests the alert it already has,
  not the story's beacon-rotation claim.
- **`observability`** gap: process attribution for the query is impossible
  from the available SIEM surface alone — `srcip: 127.0.0.1` routes through
  `dnsmasq`, and the investigation has no host-side DNS attribution. The
  actor's process-level "long-dwell implant" claim remains untested even
  though parent-domain DNS history could still test the rotation claim.

### alert.json (trimmed)

```json
{
  "agent": {"name": "target-endpoint", "ip": "172.22.0.13"},
  "data": {"srcip": "127.0.0.1", "dns_domain": "q8Hk3pZv2.beacon.example.org", "dns_query_type": "A"},
  "rule": {"id": "100110", "level": 10, "description": "DNS query to high-entropy subdomain"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.recent-rule-fires
  goal: scope rule-100110 fires for dns_domain q8Hk3pZv2.beacon.example.org in 24h
  result: 1 event. The triggering query at 2026-05-09T11:14:02Z. No other fires
    in window.

## PHASE: ANALYZE
?dga-c2 + (entropy and parent domain unusual)
?one-off-typo + (single event, no recurrence)
Picture: cannot discriminate between rare beacon and one-off. Disposition:
inconclusive. Termination: exhaustion (no further leads attempted on process
attribution since srcip=127.0.0.1 routes through dnsmasq).
```

### actor_story.md

```
## Attack story
A long-dwell implant on target-endpoint beacons over DNS with one query per
24-30h to avoid volumetric detection. Each beacon uses a fresh subdomain
under beacon.example.org; the parent domain rotates every ~14 days.

## Goal
Maintain C2 with a query rate that blends into baseline DNS noise.

## Bypass
A narrow 24h domain-exact lookup will return only the single triggering query.
The defender lacks process-attribution telemetry (no EDR / no host-side DNS
attribution), so they cannot tie the query to the implant process.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {dns_domain: q8Hk3pZv2.beacon.example.org, srcip: 127.0.0.1, count: 1, time: 2026-05-09T11:14:02Z}
```

---

## Sample 03 — incoherent (actor misreads invalid-user alert as root success)

**Expected outcome:** `incoherent`

**Rationale:** Rule 5710 fires on **invalid user** — authentication failure —
and the alert's `srcuser` is `fakeadmin`. The actor explicitly treats that
focal alert as the successful root SSH login. The contradiction is present on
the alert surface before considering any lead result, so lead coverage is
irrelevant.

**Expected actor observation (gist):** Story read a rule-5710 invalid-user failure (`srcuser: fakeadmin`) as the attacker's successful root SSH login, contradicting the alert's failure-class signature directly.

**Expected findings:** `defender_findings: []` (per judge.md, incoherent → empty
list). Surface the alert/story contradiction in `actor_observations` instead:

- **`misprediction`**: actor read the focal `rule 5710` alert (`Attempt to
  login using a non-existent user`, `srcuser: fakeadmin`) as if it were a
  successful root login. Rule 5710 is a failure-class signature by definition
  — successful logins fire rule-5715 / `Accepted publickey`, which the
  investigation explicitly confirmed absent. The story should have been
  constrained to failed-auth framings (credential spray, dictionary attack,
  account probing).

### alert.json (trimmed)

```json
{
  "agent": {"name": "target-endpoint", "ip": "172.22.0.13"},
  "data": {"srcuser": "fakeadmin", "srcip": "198.51.100.7"},
  "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER
Lead 0: wazuh.auth-events
  goal: 24h auth events for 198.51.100.7 → target-endpoint
  result: 4 events, all rule-5710 fires, usernames: fakeadmin, testadmin,
    administrator, admin. Zero successful logins (no rule-5715 / no
    "Accepted password"/"Accepted publickey").

## PHASE: ANALYZE
?credential-spray + (4 distinct invalid usernames, external IP)
Picture: probable low-volume spray, no auth success.
Disposition: inconclusive (low signal, source IP attribution unresolved).
```

### actor_story.md

```
## Attack story
The focal alert is the attacker's successful SSH authentication to
target-endpoint as root from 198.51.100.7. After that root login, the attacker
executed reconnaissance commands (whoami, id, /etc/passwd read) and staged a
payload in /tmp.

## Goal
Establish initial access and persistence.

## Bypass
The defender misclassified the focal root success as a failed-login event and
then focused only on failed-login leads, missing the successful authentication
and subsequent shell activity entirely.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {srcip: 198.51.100.7, srcuser: root, hostname: target-endpoint, action: "Accepted publickey"}
    - {srcip: 198.51.100.7, srcuser: root, command: "whoami"}
```
