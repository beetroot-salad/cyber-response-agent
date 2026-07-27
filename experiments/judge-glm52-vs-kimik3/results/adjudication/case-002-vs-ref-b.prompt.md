You are adjudicating two independent judgements of the same security investigation. Both judges saw exactly the evidence reproduced below and were asked the same question under the same rubric.

The judge's role in this system: it is the ground truth for a learning loop. Its `outcome` drives false-negative / false-positive accounting, and its `defender_findings` become the lessons a downstream agent trains on. So a verdict that is confidently wrong, or that cites evidence which does not support it, actively poisons training labels. Fluency is worth nothing here; grounding is worth everything.

Judge them on, in descending order of weight:

1. **Grounding** — is every load-bearing claim traceable to the evidence shown? Quote any citation that does not support the claim it is attached to, or any assertion about the telemetry that the evidence does not contain. A fabricated or misattributed citation is the single most serious defect available here.
2. **Correctness of the outcome** — given this evidence, is the outcome right? Say what you think the correct outcome is and why, BEFORE weighing which judge agrees with you.
3. **Findings quality** — are the findings real, specific defects in the investigation, anchored to the right lead? Or are they generic process observations that would apply to any investigation?
4. **Calibration** — does the confidence match the evidence? Over-calling an ambiguous case and under-calling a clear one are both failures.

Do not reward length, structure, or confident tone. If both are weak, say so. If they reach the same outcome by different reasoning, judge the reasoning. It is a legitimate result that the two are indistinguishable in quality — say that rather than manufacturing a winner.

End your response with exactly one line:

VERDICT: A | B | TIE — <one clause naming the deciding difference>


# Direction

benign

The benign direction hunts a FALSE POSITIVE: the actor proposes a routine-activity story consistent with the same alert, and the outcome is `refuted` if the defender's evidence rules that story out, `survived` if the escalation may have been an over-call.

# Alert

```json
{
  "alert_id": "336c0454371987cf43e1eb54a9634956eca3bc15ec99830c8c0a4ffc3fa9f79e",
  "alert_timestamp": "2026-07-27T16:44:58.498Z",
  "rule": {
    "id": "v2-sshd-failed-auth-burst",
    "name": "v2 sshd failed-auth burst",
    "type": "threshold",
    "severity": "medium",
    "risk_score": 47,
    "tags": [
      "v2",
      "auth",
      "ssh",
      "brute-force"
    ],
    "description": "Five or more sshd authentication failures on a single host within 5 minutes. The threshold groups by host.name; pivot on source.ip / user.name to determine whether failures came from one source or many.",
    "language": "lucene",
    "query": "process.name:sshd AND event.outcome:failure"
  },
  "reason": "event on canary-1 created medium alert v2 sshd failed-auth burst.",
  "host": {
    "name": "canary-1"
  },
  "user": {},
  "ancestor_events": [
    {
      "id": "883de532-1b6a-5cbc-9756-5b4fa2cbcc2b",
      "type": "event",
      "index": "logs-system.auth-*",
      "depth": 0
    }
  ],
  "signal_index": ".internal.alerts-security.alerts-default-000003"
}

```

# The defender's report

---
case_id: fresh-01
disposition: inconclusive
confidence: high
---

Office workstation `office-ws-1` (172.18.0.16, owner dev.dana) conducted 96 SSH brute-force authentication attempts against `root` on canary-1 (a sandbox canary host owned by team.sre) over a 3-minute window starting 16:44:43Z on 2026-07-27, split evenly between password and other auth methods. CMDB lookup (l-004) confirmed the source is a developer workstation in the preprod zone — not a scanner or monitoring system — with no declared trust relationship to canary-1. The same IP concurrently appeared in nginx access logs on production web servers web-1 and web-2 (l-004), indicating broader probing of production infrastructure. Change-management query (l-005) returned zero change tickets for canary-1 — no authorized pen test or security testing covers this activity. Both authz contracts (approved-source-list, change-mgmt) return `unauthorized`, forcing escalation. The misconfigured-monitoring hypothesis (h-002) is strongly refuted; the brute-force hypothesis (h-001) is strongly supported. Disposition is `inconclusive` because the mechanism behind the workstation's behavior cannot be confirmed from available telemetry — the workstation may be compromised by an external attacker conducting lateral movement, or an insider may be running unauthorized security tools. Either way, the unauthorized brute-force from a workstation against a canary and production web servers requires immediate escalation to investigate `office-ws-1`.


# The defender's investigation log

## ORIENT

Alert `v2-sshd-failed-auth-burst` fired on host `canary-1` at 2026-07-27T16:44:58Z. The rule is a threshold detector: 5+ sshd authentication failures on a single host within 5 minutes, grouped by `host.name`. The alert payload does not include the underlying events — source IPs, targeted usernames, and exact timestamps are unknown. The alert description explicitly says to pivot on `source.ip` / `user.name` to distinguish single-source brute-force from multi-source credential spraying.

Triage question: What produced the burst of sshd failures on canary-1 — a genuine brute-force or credential-spray attack, or a benign misconfiguration (monitoring scanner, health check, stale key negotiation)?

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/known-corp|canary-1|os=linux
v-002|compute|??/??/??|??|knowledge=partial

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-07-27T16:44:58Z|siem-event:siem|outcome=failed;count>=5;window=5m
```

v-001 (canary-1) is a known-corp host but its role/zone are unknown — it could be internet-facing (making brute-force likely) or internal (making misconfiguration more plausible). v-002 is the source of the auth attempts — entirely unknown from the alert payload. Both open slots gate disposition.

## PLAN (loop 1)

Three independent leads resolve the first-order questions:

1. **l-001 (elastic):** Query the actual sshd failed-auth events on canary-1 around the alert timestamp. This is the primary discriminator: source IP cardinality (1 vs many), username cardinality (1 vs many), exact count, and timestamps. This lead closes the `??` on v-002.

2. **l-002 (elastic):** Query for any sshd *successful* auth events on canary-1 in a wider window (±30m around the alert). Per the `v2-sshd-success-after-failures` lesson family, a successful `Accepted` event after failures is a first-order IOC — the difference between "noisy failed scan" and "attacker got in."

3. **l-003 (cmdb):** Look up canary-1 in CMDB to establish its role, zone, and exposure. This closes the `??` on v-001 — is it internet-facing (bastion, web-server) or internal? The host's exposure profile changes the prior probability of brute-force vs misconfiguration.

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?external-brute-force|v-001|attempted_auth|compute|ip-only/internet/novel||null|active
h-002|?misconfigured-monitoring|v-001|attempted_auth|compute|monitoring/internal/known-corp||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"failures come from a single source IP not in CMDB"
p2|proposed_parent|"targeted usernames are real accounts or common defaults (root, admin)"
p3|proposed_edge|"a successful Accepted event follows the failure burst"

:H h-001.refuts [id|refutes|claim]
r1|p1|"source IP resolves to a known monitoring/scanner system in CMDB"
r2|p2,p3|"no successful auth events; usernames are random or non-existent accounts"

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"failures come from a known monitoring/scanner IP in CMDB"
p2|proposed_parent|"failures are periodic/cadenced, consistent with a health-check pattern"
p3|proposed_edge|"no successful Accepted event follows; failures are password/key-negotiation noise"

:H h-002.refuts [id|refutes|claim]
r1|p1,p2|"source IP is external/novel, not in any asset registry"
r2|p3|"a successful Accepted event follows the failures"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|sshd-failed-auth-events|v-002|h-001,h-002|elastic|±10m of alert
l-002|1|sshd-successful-auth-check|v-001|h-001,h-002|elastic|±30m of alert
l-003|1|cmdb-host-lookup|v-001|h-001,h-002|cmdb|n/a
```

Hypothesis shape note: both hypotheses share `rel=attempted_auth` and `parent_type=compute`, but differ on `parent_class` (`ip-only/internet/novel` vs `monitoring/internal/known-corp`) — topologically distinct on the class axis. The `?name`s are minted fresh; corpus has 0 cases for this signature.

## GATHER (loop 1)

Dispatched l-001 (elastic — failed-auth events), l-002 (elastic — successful auth check), l-003 (cmdb — host lookup) in parallel. l-001 returned abnormally (tool retries exhausted); l-002 captured the key stats; l-003 returned CMDB context.

## ANALYZE (loop 1)

l-002 returned far more than expected — it included both accepted and failed events:
- **96 failed events** from single source `172.18.0.16` as `root`, split 48 password / 48 other, spanning 16:44:43→16:47:50 (~3 min)
- **4 accepted events** from `172.18.0.23` as `svc.config-mgmt`, password auth, first at 16:40:22, last at 17:09:19
- Some accepted events bracket the failure burst (before and after)

l-003 (CMDB) established canary-1 context:
- Role: `canary`, zone: `sandbox`, owner: `team.sre`, OS: Ubuntu 22.04
- NOT internet-facing — sandbox criticality, canary role implies decoy/test asset
- Declared accounts: `svc.monitoring` (nologin), `svc.config-mgmt` (bash, sudo)
- Root is NOT a declared local account

```invlang
:V l-002.observations.vertices [id|type|class|ident|attrs?]
v-003|compute|ip-only/??/??|172.18.0.16|knowledge=partial
v-004|compute|ip-only/??/known-corp|172.18.0.23|knowledge=partial

:E l-002.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|attempted_auth|v-003|v-001|2026-07-27T16:44:43Z|siem-event:siem|outcome=failed;count=96;user=root;methods=password,other;duration=~3m
e-003|attempted_auth|v-004|v-001|2026-07-27T16:40:22Z|siem-event:siem|outcome=success;count=4;user=svc.config-mgmt;method=password

:V l-003.observations.vertices [id|type|class|ident|attrs?]
v-005|identity|service-account/known-corp|svc.config-mgmt|shell=bash;sudo=true
v-006|identity|service-account/known-corp|svc.monitoring|shell=nologin;sudo=false

:R attr_updates [resolved_by|target|key|value]
l-003|v-001|class|canary/sandbox/known-corp
l-002|v-002|attrs.source_ip|172.18.0.16
l-002|v-002|attrs.target_user|root
l-002|v-002|attrs.count|96
l-002|v-002|attrs.methods|password,other
```

Assessment so far:
- Single-source brute-force against root on a canary host — 96 attempts in 3 min
- The successful auths are from a different IP (172.18.0.23) as svc.config-mgmt — likely legitimate config management, not related to the brute-force
- canary-1 is a sandbox canary (honeypot-class asset) — failed auth against canaries can be expected detection signal
- The brute-force source 172.18.0.16 is an internal IP — need to identify it
- Root is not a declared account — the attacker is targeting a non-existent/locked account

```invlang
:T resolutions
h-001  null → +    [l-002 p1,p2 mild ⟂ e-002 :: single source 172.18.0.16 targeting root, 96 failures is brute-force pattern]
h-002  null → +    [l-003 p3 mild ⟂ e-002 :: canary host in sandbox zone could attract scanning; source IP not yet confirmed as monitoring]
```

Both hypotheses remain active — the discriminating question is the identity of 172.18.0.16. Loop 2 will resolve this.

```invlang
:T close
loop  1
```

## PLAN (loop 2)

The frontier is: what is 172.18.0.16? If it's a known scanner/monitoring host, h-002 (misconfigured-monitoring) wins. If it's unknown/novel, h-001 (external-brute-force, reinterpreted as internal-lateral) wins. Three independent leads:

- **l-004 (cmdb):** Look up 172.18.0.16 in CMDB — is it a registered host? What role? This directly closes the `??` on v-003.
- **l-005 (change-mgmt):** Check for any change ticket or authorized security testing covering canary-1 around 2026-07-27. Canary hosts are often targets of authorized pen tests or security scans.
- **l-006 (host-state):** Check root account status on canary-1 — is root locked/disabled? If root is locked, the brute-force is futile and the noise level against a canary suggests detection signal, not a real threat.

```invlang
:L findings [id|loop|name|target|tests|system|window]
l-004|2|cmdb-source-ip-lookup|v-003|h-001,h-002|cmdb|n/a
l-005|2|change-mgmt-pentest-check|v-001|h-001,h-002|change-mgmt|±1d of alert
l-006|2|host-state-root-account-status|v-001|h-001,h-002|host-state|n/a
```

Predictions:
- h-001 predicts: 172.18.0.16 is NOT in CMDB (or is a novel/unregistered host), no change ticket covers this activity
- h-002 predicts: 172.18.0.16 IS in CMDB as a scanner/monitoring host, and/or a change ticket authorizes security testing on canary-1

## GATHER (loop 2)

Dispatched l-004 (cmdb — source IP lookup), l-005 (change-mgmt — pen test check), l-006 (host-state — root account status) in parallel. l-004 and l-005 returned; l-006 hit request limit (incomplete).

## ANALYZE (loop 2)

l-004 resolved 172.18.0.16 as `office-ws-1` — a developer workstation:
- Role: `office-ws`, zone: `preprod`, owner: `dev.dana`
- NO trust relationship with canary-1 (`trust_edges_out: []` for both)
- The same IP appeared in nginx access logs on production web servers web-1 and web-2 at 16:44-16:46 UTC — concurrent with the brute-force
- Also appeared in Zeek flows (connection, ssl, ssh, http) — broader network activity

l-005 returned zero change tickets for canary-1 — no authorized testing, no pen test, no change window covering this activity.

l-006 failed (request limit) — root account status and sshd PermitRootLogin config unknown. This is a gap but does not change disposition: the unauthorized brute-force from a workstation with no trust relationship is the signal, regardless of whether root is locked.

```invlang
:V l-004.observations.vertices [id|type|class|ident|attrs?]
v-003|compute|workstation/preprod/known-corp|office-ws-1|owner=dev.dana;ip=172.18.0.16
v-007|compute|web-server/prod/known-corp|web-1|role=web;criticality=prod
v-008|compute|web-server/prod/known-corp|web-2|role=web;criticality=prod

:E l-004.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-004|connected_to|v-003|v-007|2026-07-27T16:44:00Z|siem-event:siem|via=nginx.access;count=3
e-005|connected_to|v-003|v-008|2026-07-27T16:44:00Z|siem-event:siem|via=nginx.access;count=3

:R attr_updates [resolved_by|target|key|value]
l-004|v-003|class|workstation/preprod/known-corp
l-004|v-003|attrs.hostname|office-ws-1
l-004|v-003|attrs.owner|dev.dana
l-003|v-004|class|ip-only/??/known-corp

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-004,l-005|e-002|ac1|unauthorized|approved-source-list|"172.18.0.16 is office-ws-1 (dev workstation), not a scanner; no trust_edges_out to canary-1 in CMDB"
l-005|e-002|ac2|unauthorized|change-mgmt|"zero change tickets for canary-1 in change-mgmt system; no authorized testing window"
```

Adding authz contracts to h-001 (the surviving hypothesis):

```invlang
:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-002|approved-source-list|"source IP 172.18.0.16 is on an approved scanner/monitoring list for canary-1"|escalate|escalate
ac2|e-002|change-mgmt|"approved change ticket or pen test authorization exists for SSH testing on canary-1"|escalate|escalate
```

Both authz contracts return `unauthorized` — the source is a developer workstation with no trust relationship to canary-1, and no change ticket covers this activity. Per disposition gating, `unauthorized` on any live-weight hypothesis's contract forces escalation regardless of behavioral grading.

```invlang
:T resolutions
h-001  + → ++    [l-004 p1 confirmed ⟂ e-002 :: source is office-ws-1 (dev workstation), not a scanner; no trust relationship to canary-1; also probing production web servers concurrently]
h-002  + → --    [l-004 r1 severe ⟂ e-002 :: source IP resolves to office-ws-1, a developer workstation — NOT a monitoring/scanner system; l-005 r2 severe ⟂ e-002 :: zero change tickets, no authorized testing]
```

h-002 (misconfigured-monitoring) is strongly refuted: the source is a developer workstation, not a scanner, and no authorization exists. h-001 (brute-force) is strongly supported: single source (office-ws-1) conducting 96 SSH brute-force attempts against root on canary-1, concurrently probing production web servers, with no trust relationship or change ticket.

The remaining uncertainty is mechanism: is office-ws-1 compromised by an external attacker, or is dev.dana running unauthorized tools? Either way, the behavior is unauthorized and malicious in pattern. The authz contracts both return `unauthorized`, forcing escalation regardless.

```invlang
:T conclude
termination.category   adversarial-confirmed
disposition            inconclusive
confidence             high
impact_verdict         none
matched_archetype      internal-brute-force-from-workstation
summary                "Office workstation office-ws-1 (172.18.0.16, owner dev.dana) conducted 96 SSH brute-force attempts against root on canary-1 (sandbox canary) in 3 minutes, concurrently probing production web servers web-1 and web-2. Source is a developer workstation with no trust relationship to canary-1 and zero change tickets authorizing testing. Authz contracts return unauthorized. Escalation required — cannot confirm whether workstation is compromised or insider is running unauthorized tools; security team must investigate office-ws-1."
```


# The actor's story

1. **Routine-activity story.** Host `canary-1` is a canary / deception host — its name and purpose are explicit in the deployment: it exists to be found and probed, and every SSH authentication attempt against it is a detection event, not a production login path. The burst of sshd authentication failures that tripped this alert came from a source classified as `known-corp`, i.e., an internal corporate identity, not an external or unknown origin. The routine operation is the fleet-wide internal security / compliance scan: a corporate-owned scanning tool sweeps every reachable SSH endpoint in the environment — production hosts, jump boxes, and canaries alike — attempting authentication with its scanner credentials as part of a scheduled vulnerability or posture assessment. The canary, having no legitimate user accounts, rejects every attempt, producing five or more sshd `failure` events within the 5-minute threshold window. The alert fires because the rule groups by `host.name` and counts raw failure events; it does not distinguish a deception host from a production host, and it does not distinguish an internal scanner from an external brute-forcer. The canary did exactly what it was deployed to do: it recorded the probe. The scanner did exactly what it was scheduled to do: it tried every SSH endpoint including the canary.

2. **Benign grounding.**

   - **Purpose & impact:** `canary-1` is a deception host by name and function; its entire purpose is to attract and log unauthorized access attempts. SSH auth failures on it are detection telemetry, not a disruption to any production service. The impact is bounded to log generation — no data is accessed, no service is degraded, no state changes on the canary beyond its event log. The scanner's impact is likewise read-only reconnaissance: it attempts authentication and records the result; it does not provision, modify, or exfiltrate.

   - **Authorization:** The source is classified `known-corp` — a known corporate identity in the environment's entity catalog, not an unknown or external source. A corporate-owned security scanner is an authorized participant in the environment's posture-assessment process. The SSH attempts originate from inside the trusted network boundary from an identity the deployment already recognizes.

   - **Integrity:** The alerted events are authentication *failures* — `event.outcome:failure`. No session was established, no shell was opened, no command was executed. The scanner attempted and was rejected by sshd on every try. The canary's integrity is intact; it logged the attempts and denied access, which is its designed behavior.

   - **Policy / change compliance:** The canary host is deployed precisely to capture this class of signal; SSH-probe detection on a deception host is the standing detection policy working as designed, not a policy violation. The scanner sweeping internal hosts including canaries is the routine posture-assessment cadence — a scheduled, recurring corporate security operation rather than an ad-hoc or out-of-band action. The alert is a side effect of two authorized processes intersecting: the scanner doing its sweep and the canary doing its job.

# The oracle's projected telemetry

(A signed diff over the routine baseline: what the story would have added to or removed from each lead's query results. `events: []` means the story writes no delta to that lead at all; `- <standard environment noise>` means it lights that envelope but only with events shape-identical to the baseline, so the lead cannot distinguish it.)

```yaml
projections:
- lead_id: l-003
  events: []
- lead_id: l-002
  events: []
- lead_id: l-001
  events:
  - <standard environment noise>
- lead_id: l-004
  events: []
- lead_id: l-005
  events: []
- lead_id: l-006
  events: []
```

# Judge A

I attempted to read the per-lead comparison files and payloads through every available path and the sealed query sandbox, but the run-dir artifacts are not readable in this session (the sandbox reports no attached container, and no comparison/payload path resolves under the declared read roots). I therefore score this encounter on the authoritative records I do have — the alert, the report, the synthesis, and the coverage_manifest (which records every executed query, its parameters, and its payload status/digest, including error text) — and I flag inside the affected findings where the per-lead projection-vs-actual check could not be re-run against the raw payloads.

outcome: refuted
defender_findings:
  - type: disposition-confirmed
    subject_anchor: l-004
    subject_topic: source-identity grounding via CMDB plus log pivot
    finding: |
      The routine story load-bore on the source being a "known-corp" corporate scanner identity. The defender grounded the source instead of assuming it: the direct CMDB IP lookup returned 404, and instead of stopping there the defender pivoted to a log-based IP-to-host search that resolved 172.18.0.16 to office-ws-1, a developer workstation owned by dev.dana in the preprod zone, whose CMDB record shows no trust edges to canary-1. That identity grounding is exactly what refused the scanner cover — a registered posture-assessment scanner would surface as a scanner/monitoring role, not as a dev workstation. Preserve and generalize: before accepting any scanner/monitoring framing on auth-failure bursts, resolve the source to a CMDB identity and check declared trust edges to the target. One residual ambiguity worth naming: an ad-hoc scan run by the workstation's owner is not fully excluded by this evidence, which is why `inconclusive` (not `malicious`) was the right ceiling — but neither reading is the actor's "scheduled corporate scanner" story.
    citations:
      - source: coverage_manifest
        quote: |
          payload_digest: 'exit=1; HTTP 404 from http://cmdb:8080/hosts/172.18.0.16: host 172.18.0.16 not found'
      - source: report
        quote: |
          CMDB lookup (l-004) confirmed the source is a developer workstation in the preprod zone — not a scanner or monitoring system — with no declared trust relationship to canary-1.
      - source: synthesis
        quote: |
          [l-004] h-002: +->--  (severity=severe)  source IP resolves to office-ws-1, a developer workstation — NOT a monitoring/scanner system
  - type: disposition-confirmed
    subject_anchor: l-005
    subject_topic: authorized-testing window check
    finding: |
      The second leg of the routine story was "a scheduled, recurring corporate security operation." The defender tested it against the authoritative system: change-mgmt queries for canary-1 across every status (active at alert time, in_progress, planned, approved) all returned empty. That grounds "no authorized pen test or vulnerability scan covers canary-1" as a collected fact rather than an assumption, and it is what forced the ac2 contract to `unauthorized`. The capability to preserve: on any authorized-testing cover story, exhaust the change-mgmt status space (not just active-at-time) before weighing the claim.
    citations:
      - source: coverage_manifest
        quote: |
          - query_id: change-mgmt.active-changes
            verb: active-changes
            params:
              host: canary-1
              at: '2026-07-27T16:44:58Z'
            payload_status: empty
      - source: synthesis
        quote: |
          verdict: unauthorized
          anchor_kind: change-mgmt
          reasoning: '"zero change tickets for canary-1 in change-mgmt system; no authorized
            testing window"'
  - type: lead-quality
    subject_anchor: l-006
    subject_topic: guessed-filename FIM spray
    finding: |
      l-006 burned roughly sixty fim-checksum queries on guessed sshd_config.d filenames (00-root.conf through 99-permitrootlogin.conf and beyond), every one erroring with "does not exist." Guessing configuration filenames one at a time is not investigation: a directory listing of sshd_config.d, or reading sshd_config's Include directives, would have answered the PermitRootLogin question in one or two queries. The lead contributed nothing to the disposition while dominating the query budget. The discipline gap: enumerate what exists before checksumming what you hope exists.
    citations:
      - source: coverage_manifest
        quote: |
          payload_digest: 'exit=1; docker exec on canary-1 (rc=1): sha256sum: /etc/ssh/sshd_config.d: Is a directory'
environment_observations:
  - subject: canary-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: host
      - type: process
        class: sshd
    relevance_criteria: sshd failed-auth alert on canary-1 or any deception-host target
    fact: |
      canary-1 is a deception / canary host registered in the CMDB, owned by team.sre, sitting in the sandbox zone. It has no production login path; SSH authentication attempts against it are detection telemetry by design. The threshold rule v2-sshd-failed-auth-burst groups by host.name and counts raw failures, so it does not distinguish a canary from a production host — any sustained failure burst on canary-1 will fire it.

      Grounded by the CMDB host record for canary-1 (retrieved successfully during this investigation) and by the alert surface itself. A routine explanation for activity targeting canary-1 must still ground the *source's* authorization — the host being a canary explains why the alert fires, not who is allowed to probe it.
    citations:
      - source: report
        quote: |
          96 SSH brute-force authentication attempts against `root` on canary-1 (a sandbox canary host owned by team.sre)
      - source: coverage_manifest
        quote: |
          - query_id: cmdb.host-trust-edges
            verb: get-host
            params:
              host: canary-1
            payload_status: ok
  - subject: office-ws-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: host
    relevance_criteria: any story sourcing internal probing or scanning from 172.18.0.16 / office-ws-1
    fact: |
      office-ws-1 (172.18.0.16) is a developer workstation owned by dev.dana, registered in the CMDB in the preprod zone. It is not a scanner, monitoring, or security-tooling system, and its CMDB record declares no trust edges to canary-1. During this investigation the same source IP appeared concurrently in nginx access logs on production web servers web-1 and web-2.

      A routine-explanation that casts this host as a corporate scanner contradicts its CMDB-registered role; any authorized-scan story sourced from office-ws-1 would need an approved change record, and change-mgmt held none for canary-1 at any status on 2026-07-27.
    citations:
      - source: synthesis
        quote: |
          reasoning: '"172.18.0.16 is office-ws-1 (dev workstation), not a scanner; no trust_edges_out
            to canary-1 in CMDB"'
  - subject: cmdb
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: host
    relevance_criteria: any investigation or story that needs to resolve an internal source IP to a host identity
    fact: |
      The CMDB host index is keyed by hostname, not by IP: a direct lookup of 172.18.0.16 returned HTTP 404 "host not found" even though the host is registered as office-ws-1 and retrievable by name. Resolving an IP to a CMDB identity requires a two-step pivot — first find the hostname (e.g. via a log search for the IP across datasets), then query the CMDB by hostname.

      A bare CMDB 404 on an IP is therefore not evidence that a source is unregistered or external; it is an artifact of the lookup key. Grounded by this investigation's l-004 query sequence.
    citations:
      - source: coverage_manifest
        quote: |
          - query_id: cmdb.hostname-by-ip
            verb: get-host
            params:
              host: 172.18.0.16
            payload_status: error
            payload_digest: 'exit=1; HTTP 404 from http://cmdb:8080/hosts/172.18.0.16: host 172.18.0.16 not found'

# Judge B

The closed-ticket lookup failed due to infrastructure issues, but since `cited_policy_read` is empty, no policy was cited and the policy-confirm walk doesn't apply. I have enough to produce my output.

Based on my lead-by-lead analysis: no lead's actual result refutes the routine scanner projection. l-001's actuals (96 failures from one source, root-targeted, multi-method) match the scanner signature exactly. l-004's CMDB data (developer workstation) is consistent with a scanner tool running from a workstation. l-005's zero change tickets is consistent with a program-level standing authorization. The defender escalated on interpretations that don't distinguish scanner traffic from attacker traffic, and never queried the system that would ground a standing scanner authorization.

outcome: survived
defender_findings:
  - type: lead-set
    subject_anchor: no-lead-exists
    subject_topic: scanner authorization grounding
    finding: |
      No lead queried the system that would authorize a standing security scanner. The defender's two authz contracts checked the wrong dimensions: the `approved-source-list` contract was evaluated via CMDB host role (a scanner tool running from a developer workstation shows as a developer workstation in CMDB, not as a scanner), and the `change-mgmt` contract was scoped to per-host change tickets on canary-1 (a recurring scheduled scan is authorized at the program level, not per-target). The missing lead is a query to a scanner registration, security operations schedule, or tool inventory — the authoritative systems that would confirm or deny a standing corporate scanning authorization. Without that lead the defender escalated on the absence of evidence in the wrong systems rather than the presence of a refutation in the right one.
    citations:
      - source: synthesis
        quote: |
          resolved_by_lead: l-004,l-005
          edge: e-002
          fulfills_contract: ac1
          verdict: unauthorized
          anchor_kind: approved-source-list
          reasoning: '"172.18.0.16 is office-ws-1 (dev workstation), not a scanner;
            no trust_edges_out to canary-1 in CMDB"'
      - source: synthesis
        quote: |
          resolved_by_lead: l-005
          edge: e-002
          fulfills_contract: ac2
          verdict: unauthorized
          anchor_kind: change-mgmt
          reasoning: '"zero change tickets for canary-1 in change-mgmt system; no
            authorized testing window"'
  - type: analyze-discipline
    subject_anchor: l-004
    subject_topic: CMDB host role conflated with process identity
    finding: |
      The defender moved h-002 (misconfigured-monitoring) from + to -- based on the CMDB showing the source as a developer workstation, concluding it is "NOT a monitoring/scanner system." But CMDB records the host's designated role, not the software currently running on it — a scanning tool executing from a developer workstation produces exactly this CMDB result. The defender also found the same IP in nginx access logs on web-1 and web-2 and read this as "broader probing of production infrastructure" rather than a vulnerability scanner checking multiple protocols and hosts. Both readings are consistent with the actuals; the defender chose the malicious interpretation without a lead that distinguished scanner traffic from attacker reconnaissance. The routine ground — that a known corporate identity was running a scanning tool — was rationalized away by conflating host role with process identity.
    citations:
      - source: synthesis
        quote: |
          [l-004] h-002: +->--  (severity=severe)  source IP resolves to office-ws-1,
          a developer workstation — NOT a monitoring/scanner system; l-005 r2 severe
          ⟂ e-002 :: zero change tickets, no authorized testing
      - source: report
        quote: |
          The same IP concurrently appeared in nginx access logs on production web
          servers web-1 and web-2 (l-004), indicating broader probing of production
          infrastructure.
environment_observations:
  - subject: canary-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: host
      - type: process
        class: sshd
    relevance_criteria: alert fires on a canary or deception host where SSH auth failures are detection telemetry not production login attempts
    fact: |
      Host `canary-1` is a sandbox canary or deception host. CMDB (l-003) places it in the sandbox zone with SRE ownership. Its name and zone are consistent with a deception deployment: it exists to attract and log unauthorized access attempts. The host has no fail2ban installed (l-006: /etc/fail2ban does not exist on canary-1), which is expected for a canary — automated brute-force protection would suppress the detection telemetry the canary is meant to collect. The alert rule `v2-sshd-failed-auth-burst` fires on it because it groups by host.name and counts raw sshd failure events without distinguishing canaries from production hosts. SSH auth failures on canary-1 are detection events, not disruptions to any production service.
    citations:
      - source: coverage_manifest
        quote: |
          lead_id: l-003
          goal: Look up canary-1 in CMDB to establish its role, network zone,
          exposure (internet-facing vs internal), OS, and any associated services
          or ownership information.
      - source: coverage_manifest
        quote: |
          query_id: host-state.fail2ban-dir-checksum
          params:
            host: canary-1
            path: /etc/fail2ban
          payload_status: error
          payload_digest: 'exit=1; ''/etc/fail2ban'' does not exist on canary-1'
  - subject: office-ws-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: host
    relevance_criteria: source IP 172.18.0.16 maps to a developer workstation in preprod zone that is a known corporate identity
    fact: |
      IP 172.18.0.16 resolves to host `office-ws-1`, a developer workstation in the preprod zone owned by `dev.dana` (l-004: elastic IP-to-host search, then cmdb.host-trust-edges for office-ws-1). The same IP appeared concurrently in nginx access logs on production web servers web-1 and web-2 during the alert window. The host has no declared trust_edges_out to canary-1 in CMDB. It is a registered corporate host — a known internal identity, not an external or unknown source. A scanning or security tool running from this workstation would produce exactly this CMDB profile: the host role reflects the assigned owner, not the software executing on it.
    citations:
      - source: coverage_manifest
        quote: |
          query_id: elastic.ip-to-host-search
          verb: esql
          params:
            query: "FROM logs-*\n| WHERE @timestamp >= \"2026-07-27T16:00:00Z\" AND
              @timestamp < \"2026-07-27T17:00:00Z\"\n        AND (source.ip == \"172.18.0.16\"
              OR client.ip == \"172.18.0.16\" OR host.ip == \"172.18.0.16\")"
          payload_status: ok
      - source: report
        quote: |
          CMDB lookup (l-004) confirmed the source is a developer workstation in the
          preprod zone — not a scanner or monitoring system — with no declared trust
          relationship to canary-1.