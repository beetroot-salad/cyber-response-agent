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

adversarial

The adversarial direction hunts a FALSE NEGATIVE: the actor proposes an attack story consistent with the same alert, and the outcome is `caught` if the defender's investigation would have surfaced it, `survived` if it would have slipped through.

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

**0. Selected techniques**

| MITRE ID | Note |
|---|---|
| T1566.001 | Spearphishing attachment delivers initial payload to an internal workstation |
| T1552.004 | SSH private keys harvested from the compromised workstation's `~/.ssh/` |
| T1563.001 | Stolen keys used to attempt SSH lateral movement to canary-1, producing the failed-auth burst |

**1. Attack story**

An external actor sends a spearphishing email with a macro-laced document to a user on the internal workstation at 172.18.0.16 (T1566.001). The user opens the attachment during normal working hours; the macro executes a lightweight payload that establishes a reverse shell over HTTPS (T1071.001) to the actor's C2, blending with routine outbound web traffic from a workstation that browses the internet throughout the day.

Once on 172.18.0.16, the actor enumerates the compromised user's home directory and locates SSH private keys in `~/.ssh/` — keys the legitimate user stores unencrypted for convenience and uses to access canary-1 as part of routine operations (T1552.004). The actor also finds the user's SSH config and `known_hosts`, confirming canary-1 as a regularly accessed target.

The actor then attempts to SSH to canary-1 using the harvested keys (T1563.001). Several keys are present in the directory: some are for other hosts in the environment (web-1, web-2), one is an older expired key, and one is the current key for canary-1 but is passphrase-protected. The actor tries each key in sequence, generating multiple publickey authentication failures against canary-1. The actor also attempts password authentication for the same user account, guessing a few common passwords, adding password-method failures to the burst. In total, five or more failures accumulate within the alert window, triggering the sshd failed-auth burst alert.

One of the harvested keys eventually authenticates successfully to canary-1 — the one whose passphrase the actor brute-forces offline in the seconds between the first failed attempt and the final successful one. The single accepted event amid the failures produces a pattern that matches a legitimate user struggling with credentials before finally connecting.

**2. Bypass**

The operation's cover rests on the source identity and the auth-failure pattern. The failed SSH attempts originate from 172.18.0.16, an internal workstation with an established SSH trust relationship to canary-1 — the kind of host whose legitimate user routinely connects to canary-1 during working hours. Failed authentications from an internal, trusted source IP to a host the user normally accesses are indistinguishable from a user mistyping a passphrase, dealing with a rotated key, or falling back from publickey to password after a key issue. The failure count — low single digits over a five-minute window — matches a human-paced retry pattern, not a machine-paced brute-force tool that would produce hundreds of attempts per minute across many usernames.

The auth-method mix (publickey failures followed by password attempts) mirrors the exact sequence a real user produces when their SSH agent offers the wrong key first, then they manually type a password. The user.name across all attempts is the same single account — the compromised user's own account on canary-1 — not a scatter of usernames characteristic of credential stuffing. The timing falls squarely within business hours on a weekday, when the legitimate user on 172.18.0.16 would plausibly be working and connecting to canary-1. The eventual single success after the string of failures completes the benign silhouette: a user who had trouble authenticating and then got in.

No configuration change on canary-1 explains the failures — the sshd config, PAM stack, and fail2ban rules are unmodified — which is consistent with the failures being client-side (wrong key, wrong passphrase) rather than server-side. The actor introduced no new host, no new account, and no novel destination; every entity in the operation (the workstation, the target, the user account, the SSH keys) already existed in the environment's normal trust fabric.

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
  events:
  - <standard environment noise>
- lead_id: l-005
  events: []
- lead_id: l-006
  events: []
```

# Judge A

All payloads checked. The picture is clear: the story's load-bearing claims are refuted by the actuals on multiple leads.

**Internal walk.** Story claims: publickey failures from harvested keys + a few password guesses for the *compromised user's own account*, "low single digits," and one eventual success — all from a workstation with an "established SSH trust relationship" to canary-1. Actuals (full payloads): l-001 — 96 failures, 100% `root`, methods `password`/`pam_unix other`, **zero publickey events**, machine-paced (~1 per 2s) over 3 minutes. l-002 — zero Accepted from 172.18.0.16 in ±30 min (only ambient `svc.config-mgmt`@172.18.0.23 password successes). l-004 — CMDB shows office-ws-1 has no trust edges to canary-1; l-005 — zero change tickets. Every load-bearing cover premise (trust relationship, own-account username, publickey method, human pace, eventual success) is contradicted by telemetry the defender actually gathered, and the defender's authz reasoning correctly returned `unauthorized` and escalated. The oracle under-projected (noise/empty projections where the story explicitly claims a success event and publickey failures), but the `caught` parenthetical test — "if the attack had happened, the lead would have surfaced events that conflict with what the lead actually returned" — is met on l-001, l-002, and l-004. Verdict: **caught**.

outcome: caught
defender_findings:
  - type: lead-set
    subject_anchor: no-lead-exists
    subject_topic: source-host compromise telemetry
    finding: |
      The disposition stalled at inconclusive for exactly one reason: no lead ever measured the source workstation. Every host-state query in the investigation targets canary-1; office-ws-1's process execution, network egress, and file telemetry were never queried, so the phishing/C2/lateral-tool question (compromised host vs insider running tools) was untestable. The report admits this — "the mechanism behind the workstation's behavior cannot be confirmed from available telemetry." For internal-source brute-force encounters, source-side host telemetry is the disambiguating surface; without it the disposition ceiling is always inconclusive.
    citations:
      - source: report
        quote: |
          Disposition is `inconclusive` because the mechanism behind the workstation's behavior cannot be confirmed from available telemetry — the workstation may be compromised by an external attacker conducting lateral movement, or an insider may be running unauthorized security tools.
      - source: coverage_manifest
        quote: |
          - query_id: host-state.sshd-config-checksum
            verb: fim-checksum
            params:
              host: canary-1
  - type: detection-confirmed
    subject_anchor: l-004
    subject_topic: CMDB trust-edge grounding defeats internal-source blending
    finding: |
      The story's entire bypass rested on the source being "an internal workstation with an established SSH trust relationship to canary-1." l-004's CMDB host-trust-edges lookup collapsed that premise directly — office-ws-1 has no trust_edges_out to canary-1 — and l-005's change-mgmt query returned zero tickets, so both authz contracts resolved unauthorized and escalation was forced. Source-identity grounding against CMDB trust edges plus change-management authorization is the load-bearing capability for this story class: it converts "internal source IP" from cover into evidence.
    citations:
      - source: synthesis
        quote: |
          reasoning: '"172.18.0.16 is office-ws-1 (dev workstation), not a scanner; no trust_edges_out
            to canary-1 in CMDB"'
      - source: actor
        quote: |
          The failed SSH attempts originate from 172.18.0.16, an internal workstation with an established SSH trust relationship to canary-1
  - type: lead-quality
    subject_anchor: l-006
    subject_topic: config-discovery by filename guessing
    finding: |
      l-006 degenerated into brute-force filename guessing: roughly 100 fim-checksum probes against plausible /etc/ssh/sshd_config.d/*.conf names, every one erroring "does not exist," after the directory-level probe failed with "Is a directory." The lead never enumerated the directory and never answered its own headline question (PermitRootLogin value; whether root auth is throttled) — it returned checksums, not config content. When a config path is a directory or a probe 404s, the lead needs an enumerate-then-read strategy, not an expanding list of guessed filenames; the query budget burned here produced zero signal.
    citations:
      - source: coverage_manifest
        quote: |
          - query_id: host-state.sshd-config-d-checksum
            payload_digest: 'exit=1; docker exec on canary-1 (rc=1): sha256sum: /etc/ssh/sshd_config.d: Is a directory'
          - query_id: host-state.sshd-config-d-99-permitrootlogin-conf-checksum-50
            payload_digest: 'exit=1; ''/etc/ssh/sshd_config.d/99-permitrootlogin.conf'' does not exist on canary-1'
actor_observations:
  - type: misprediction
    subject_anchor: cover
    subject_topic: fabricated trust relationship to canary-1
    observation: |
      The cover's central premise — that 172.18.0.16 is "an internal workstation with an established SSH trust relationship to canary-1" whose user "routinely connects to canary-1 during working hours" with keys "used to access canary-1 as part of routine operations" — was invented, not verified. CMDB shows office-ws-1 has no trust edges to canary-1, and the auth logs show zero successful authentications from 172.18.0.16 in the ±30-minute window. A blend that depends on a trust fabric the environment doesn't have is refuted by a single CMDB lookup; the defender keyed on exactly this.
    citations:
      - source: actor
        quote: |
          keys the legitimate user stores unencrypted for convenience and uses to access canary-1 as part of routine operations (T1552.004)
      - source: synthesis
        quote: |
          source is office-ws-1 (dev workstation), not a scanner; no trust relationship to canary-1
  - type: misprediction
    subject_anchor: cover
    subject_topic: benign silhouette required events the telemetry lacks
    observation: |
      The bypass narrative describes a different attack than the telemetry shows: the story claims "low single digits over a five-minute window," "the same single account — the compromised user's own account," publickey failures from harvested keys, and "one of the harvested keys eventually authenticates successfully." The actuals are 96 machine-paced attempts (~1 per 2 seconds) against root only, zero publickey events in the full 96-event payload, and zero successes from 172.18.0.16. The "eventual single success" that was supposed to complete the benign silhouette never occurred — and the story even leans on an implausible mechanism ("the one whose passphrase the actor brute-forces offline in the seconds between the first failed attempt and the final successful one"). A failures-then-success silhouette only blends if the success event and the own-account username actually exist.
    citations:
      - source: actor
        quote: |
          The failure count — low single digits over a five-minute window — matches a human-paced retry pattern
      - source: comparison
        quote: |
          {"accepted": 0, "failed": 48, "first_seen": "2026-07-27T16:44:43.000Z", "last_seen": "2026-07-27T16:47:49.000Z", "auth_method": "other", "source.ip": "172.18.0.16", "user.name": "root"}
  - type: framing-choice
    subject_anchor: target-selection
    subject_topic: ignored the environment's real SSH trust edge
    observation: |
      The environment contains a genuine, observable SSH trust relationship to canary-1 — svc.config-mgmt at 172.18.0.23 authenticated successfully four times by password within the alert window itself — and the actor passed over it in favor of a workstation with no trust edges at all. A story that had compromised or impersonated the config-management identity would have matched a real authorized-source pattern and forced the defender to discriminate on cadence and account rather than on a trust edge that simply doesn't exist. Investing the bypass in source identity while choosing a source with no identity to blend into wasted the story's strongest dimension.
    citations:
      - source: comparison
        quote: |
          {"accepted": 4, "failed": 0, "first_seen": "2026-07-27T16:40:22.000Z", "last_seen": "2026-07-27T17:09:19.000Z", "auth_method": "password", "source.ip": "172.18.0.23", "user.name": "svc.config-mgmt"}
environment_observations:
  - subject: canary-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: host
    relevance_criteria: SSH auth activity on canary-1 — identifying which source/account legitimately authenticates
    fact: |
      canary-1's routine successful SSH access comes from the service account svc.config-mgmt at 172.18.0.23 using password authentication; it logged 4 Accepted events spanning 16:40–17:09Z on 2026-07-27, bracketing the alert window. No other source produced a successful authentication to canary-1 in that window, and canary-1 is a sandbox-zone host owned by team.sre.
    citations:
      - source: comparison
        quote: |
          {"accepted": 4, "failed": 0, "first_seen": "2026-07-27T16:40:22.000Z", "last_seen": "2026-07-27T17:09:19.000Z", "auth_method": "password", "source.ip": "172.18.0.23", "user.name": "svc.config-mgmt"}
  - subject: office-ws-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    relevance_criteria: 172.18.0.16 appears as a source of auth or scanning activity — its registered role and trust edges
    fact: |
      office-ws-1 (172.18.0.16, owner dev.dana) is a developer workstation in the preprod zone. The CMDB does not resolve it by raw IP (hostname-by-ip returns 404); it is identified by searching log indices for the address and then looking up the hostname. It has no trust_edges_out to canary-1 in the CMDB, and it was concurrently present in nginx access logs on production web servers web-1 and web-2 during the same window as the SSH burst.
    citations:
      - source: synthesis
        quote: |
          reasoning: '"172.18.0.16 is office-ws-1 (dev workstation), not a scanner; no trust_edges_out
            to canary-1 in CMDB"'
      - source: coverage_manifest
        quote: |
          payload_digest: 'exit=1; HTTP 404 from http://cmdb:8080/hosts/172.18.0.16: host 172.18.0.16 not found'
  - subject: canary-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: host
    relevance_criteria: sshd brute-force against canary-1 — whether lockout or throttling will interrupt a burst
    fact: |
      canary-1 has no fail2ban installation — /etc/fail2ban and its jail files do not exist — so failed SSH attempts are not throttled or banned; a 96-attempt burst ran unimpeded for over three minutes. Its sshd configuration also uses none of the conventional /etc/ssh/sshd_config.d drop-in filenames (the directory exists, but every standard conf filename probed was absent).
    citations:
      - source: coverage_manifest
        quote: |
          - query_id: host-state.fail2ban-dir-checksum
            payload_digest: exit=1; '/etc/fail2ban' does not exist on canary-1

# Judge B

Now I have all the data I need. Let me synthesize the analysis.

**Key findings from the actuals:**

**l-002 (successful auth check):** The payload shows 3 rows. From 172.18.0.16 (the attacker's IP): `accepted: 0, failed: 96` (48 "other" + 48 "password"), all targeting `root`. The only accepted events are 4 from 172.18.0.23 (svc.config-mgmt). **Zero successful auth from the attacker's IP** — directly refuting the story's claim of "One of the harvested keys eventually authenticates successfully to canary-1."

**l-001 (failed auth events):** 96 total failures, all from 172.18.0.16, all targeting `root`, at ~2-second intervals over 3 minutes (16:44:43–16:47:50). Contradicts the story's "low single digits" and "human-paced retry pattern" claims.

**l-004 (CMDB lookup):** office-ws-1 has `trust_edges_out: []` — no trust relationship to canary-1 or any host. Contradicts the story's "established SSH trust relationship" claim.

**l-006 (host state):** canary-1's passwd file shows accounts: root, sre.alice, sre.ben, sre.chen, svc.monitoring, svc.config-mgmt. **No dev.dana account exists on canary-1** — refuting the story's "compromised user's own account on canary-1" mechanism. Also, fail2ban is not installed (`/etc/fail2ban` does not exist), contradicting the story's "fail2ban rules are unmodified."

outcome: caught
defender_findings:
  - type: lead-quality
    subject_anchor: l-002
    subject_topic: absence of successful auth not weaponized as refutation signal
    finding: |
      The defender queried l-002 for sshd accepted events on canary-1 in a ±30 min window and the actuals returned zero accepted events from 172.18.0.16 (the attacker's source IP) — only 4 accepted from 172.18.0.23 (svc.config-mgmt). The story's bypass explicitly claims "the eventual single success after the string of failures completes the benign silhouette," but the defender's l-002 resolution only noted "single source 172.18.0.16 targeting root, 96 failures is brute-force pattern" without flagging the absence of a successful auth. The absence of an accepted event from the alert source IP is the single most discriminating observation against any "user struggled then connected" narrative; the defender had the data but did not use it to refute that class of cover story.
    citations:
      - source: comparison
        quote: |
          [3] reasoning: single source 172.18.0.16 targeting root, 96 failures is brute-force pattern
      - source: comparison
        quote: |
          [1] Oracle projection — (empty projection — the story does not touch this lead)
  - type: analyze-discipline
    subject_anchor: l-006
    subject_topic: directory-guessing query proliferation
    finding: |
      The defender ran approximately 50+ FIM checksum queries against /etc/ssh/sshd_config.d/ with guessed filenames (50-canary.conf, 99-permitrootlogin.conf, etc.), all returning "does not exist." The very first sshd_config.d query failed with "Is a directory," which should have prompted a directory listing rather than dozens of filename guesses. The same pattern repeated for /etc/fail2ban paths. This consumed investigation budget without producing signal; a single directory-listing call would have established that no drop-in config files or fail2ban installation exist on canary-1.
    citations:
      - source: coverage_manifest
        quote: |
          host-state.sshd-config-d-checksum  verb=fim-checksum  params={"host": "canary-1", "path": "/etc/ssh/sshd_config.d"}  status=error — exit=1; docker exec on canary-1 (rc=1): sha256sum: /etc/ssh/sshd_config.d: Is a directory
  - type: detection-confirmed
    subject_anchor: l-004
    subject_topic: CMDB trust-edge lookup broke the trusted-source cover
    finding: |
      The defender's l-004 CMDB lookup of office-ws-1 (172.18.0.16) revealed trust_edges_out: [] — no declared trust relationship to canary-1 or any host — and confirmed the source as a developer workstation (owner dev.dana), not a scanner or monitoring system. The concurrent ESQL ip-to-host search also surfaced 3 nginx.access events each on production web-1 and web-2 from the same IP, indicating broader probing. This lead was the discriminating step that broke the "misconfigured monitoring" hypothesis and established the activity as unauthorized, directly contradicting the story's claim of "an internal workstation with an established SSH trust relationship to canary-1."
    citations:
      - source: comparison
        quote: |
          [3] reasoning: source is office-ws-1 (dev workstation), not a scanner; no trust relationship to canary-1; also probing production web servers concurrently
      - source: comparison
        quote: |
          [3] reasoning: 'source IP resolves to office-ws-1, a developer workstation — NOT a monitoring/scanner system; l-005 r2 severe ⟂ e-002 :: zero change tickets, no authorized testing'
actor_observations:
  - type: misprediction
    subject_anchor: cover
    subject_topic: trust relationship and user account assumed but absent
    observation: |
      The story's bypass rests on "an internal workstation with an established SSH trust relationship to canary-1 — the kind of host whose legitimate user routinely connects to canary-1." But the CMDB actuals show office-ws-1 has trust_edges_out: [] — no trust edge to canary-1 or any host. Furthermore, canary-1's passwd file lists only root, sre.alice, sre.ben, sre.chen, svc.monitoring, and svc.config-mgmt — dev.dana has no account on canary-1 at all. The story's entire mechanism ("keys the legitimate user stores unencrypted for convenience and uses to access canary-1 as part of routine operations") is broken because the compromised user has no account on the target. A future story should verify that the claimed trust relationship and user account actually exist in the target environment's CMDB and passwd before building a blending narrative around them.
    citations:
      - source: actor
        quote: |
          The failed SSH attempts originate from 172.18.0.16, an internal workstation with an established SSH trust relationship to canary-1 — the kind of host whose legitimate user routinely connects to canary-1 during working hours.
      - source: actor
        quote: |
          keys the legitimate user stores unencrypted for convenience and uses to access canary-1 as part of routine operations
  - type: framing-choice
    subject_anchor: cover
    subject_topic: volume and target account are the discriminating dimensions
    observation: |
      The story invests heavily in the "human-paced retry" framing — "low single digits over a five-minute window — matches a human-paced retry pattern, not a machine-paced brute-force tool" and "the compromised user's own account on canary-1 — not a scatter of usernames." But the actuals show 96 failures targeting root at ~2-second intervals over 3 minutes. The volume (96, not "low single digits") and the target account (root, not the compromised user's own account) are the dimensions that make this unmistakably machine-paced brute-force, not the auth-method mix or cadence the story optimized. The actor invested in the wrong bypass dimension: cadence and method-mix blending matter less than raw count and target-account choice.
    citations:
      - source: actor
        quote: |
          The failure count — low single digits over a five-minute window — matches a human-paced retry pattern, not a machine-paced brute-force tool that would produce hundreds of attempts per minute across many usernames.
      - source: actor
        quote: |
          The user.name across all attempts is the same single account — the compromised user's own account on canary-1 — not a scatter of usernames characteristic of credential stuffing.
  - type: misprediction
    subject_anchor: persistence
    subject_topic: claimed successful auth never occurred
    observation: |
      The story claims "One of the harvested keys eventually authenticates successfully to canary-1 — the one whose passphrase the actor brute-forces offline" and frames this as completing "the benign silhouette: a user who had trouble authenticating and then got in." But l-002's actuals show zero accepted SSH events from 172.18.0.16 in the ±30 minute window around the alert. The successful auth the story depends on for its cover narrative did not occur. A future story claiming eventual success should ensure the success event is actually present in the target's auth logs, since its absence is a clean refutation of the "struggled then connected" silhouette.
    citations:
      - source: actor
        quote: |
          One of the harvested keys eventually authenticates successfully to canary-1 — the one whose passphrase the actor brute-forces offline in the seconds between the first failed attempt and the final successful one.
environment_observations:
  - subject: office-ws-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: office-ws
    relevance_criteria: a future actor checking whether office-ws-1 has a trust relationship to canary-1 before building a blending narrative
    fact: |
      office-ws-1 (172.18.0.16, owner dev.dana, role office-ws, criticality preprod) has trust_edges_out: [] in CMDB — no declared outbound trust relationship to canary-1 or any other host. The workstation's CMDB users are dev.dana (bash, sudo), svc.monitoring (nologin, no sudo), and svc.config-mgmt (bash, sudo). This means SSH activity from office-ws-1 to canary-1 is not covered by any documented trust relationship and would register as unauthorized in an approved-source-list authorization check.
    citations:
      - source: comparison
        quote: |
          [3] reasoning: 'source IP resolves to office-ws-1, a developer workstation — NOT a monitoring/scanner system'
  - subject: canary-1
    alert_rule_ids: [v2-sshd-failed-auth-burst]
    entities:
      - type: compute
        class: canary
    relevance_criteria: a future actor assuming dev.dana has an account on canary-1 or that fail2ban is installed
    fact: |
      canary-1 (owner team.sre, role canary, criticality sandbox) has passwd accounts: root, sre.alice, sre.ben, sre.chen, svc.monitoring (nologin), svc.config-mgmt (bash, sudo). There is no dev.dana account. Fail2ban is not installed — /etc/fail2ban does not exist on the host. The sshd_config drop-in directory /etc/ssh/sshd_config.d/ exists but contains no .conf files. Root has a login shell (/bin/bash) and is a valid SSH auth target.
    citations:
      - source: comparison
        quote: |
          host-state.fail2ban-dir-checksum  verb=fim-checksum  params={"host": "canary-1", "path": "/etc/fail2ban"}  status=error — exit=1; '/etc/fail2ban' does not exist on canary-1