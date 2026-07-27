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
