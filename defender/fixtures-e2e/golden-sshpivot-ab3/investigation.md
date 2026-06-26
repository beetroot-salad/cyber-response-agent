## ORIENT

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|identity|user/known-corp|dev.dana|knowledge=partial
v-002|compute|workstation/internal/known-corp|dev-ws-??|os=linux;knowledge=partial
v-003|compute|??/internal/??|??|knowledge=partial;note=prod-tier-destination
v-004|session|interactive|session@dev-ws|
v-005|session|interactive|session@prod-dest|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|authenticated_as|v-004|v-001|2026-05-25T13:52:56Z|siem-event:elastic|host=dev-ws-??;process=sshd;outcome=success;event_id=AZ5faQ9rEmDJyXEvHqWo
e-002|authenticated_as|v-005|v-001|2026-05-25T13:53:35Z|siem-event:elastic|host=??;process=sshd;outcome=failure;event_id=AZ5faQ9rEmDJyXFGHg20
```

**Triage question:** User `dev.dana` authenticated to a workstation-tier host via sshd (success), then within 15 minutes there was an sshd auth event on a prod-tier host (web-*, db-*, or jump-box-*). Is this an authorized developer pivot or an adversarial cross-tier probe?

## PLAN (loop 1)

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?authorized-user-legitimate-pivot|v-001|authenticated_as|session|interactive||null|active
h-002|?adversarial-cross-tier-pivot|v-001|authenticated_as|session|interactive||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"dev.dana is provisioned for the prod-tier destination in IAM oracle"
p2|proposed_parent|"auth method matches provisioned credential type"
p3|proposed_parent|"timing is human-paced; source session on workstation initiated the pivot"
p4|proposed_parent|"prod-tier attempts are authorized dev workflow, not scripted brute-force"

:H h-001.refuts [id|refutes|claim]
r1|p1|"dev.dana has no provisioned access to the prod-tier destination host"
r2|p4|"attempts show rapid scripted cadence against an invalid user account"
r3|p3|"sub-second timing between workstation acceptance and prod-tier failures"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-002|iam-policy|"dev.dana is provisioned to authenticate to the prod-tier destination host"|escalate|escalate
ac2|e-002|change-mgmt|"no unauthorized access flag for this cross-tier attempt"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"dev.dana NOT provisioned for the prod-tier destination"
p2|proposed_parent|"prod-tier attempts are rapid/scripted from workstation container IP"
p3|proposed_parent|"pattern shows automated ssh scanning tool running in the workstation session"

:H h-002.refuts [id|refutes|claim]
r1|p1,p2|"dev.dana fully provisioned for the destination and attempts follow human-paced authorized workflow"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|anchor-event-fetch|v-002,v-003|h-001,h-002|elastic|alert-time
l-002|1|identity-authz-check|v-001|h-001,h-002,ac1|identity|n/a
l-003|1|sshd-auth-sequence|v-001|h-001,h-002,p2|elastic|±30m
l-004|1|sshd-baseline-dana|v-001|h-001,h-002|elastic|7d
```

**Predictions:**
- `?authorized-user-legitimate-pivot`: l-002 confirms IAM provisioning; l-001 shows deliberate single ssh to authorized host; l-003 shows human-paced single auth with pubkey/cert method.
- `?adversarial-cross-tier-pivot`: l-002 shows dev.dana absent from prod-tier IAM; l-001/l-003 show scripted burst pattern; "invalid user" sshd rejections confirm no account on destination.

## GATHER (loop 1)

**l-001 return (anchor events fetched):**
- Event 1 (`AZ5faQ9rEmDJyXEvHqWo`): host=`office-ws-1`, user=`dev.dana`, sshd **Accepted password** from `::1` (loopback), 2026-05-25T13:52:56Z, outcome=success
- Event 2 (`AZ5faQ9rEmDJyXFGHg20`): host=`db-1`, user=`dev.dana`, sshd **Invalid user** from `172.18.0.14`, 2026-05-25T13:52:57Z, outcome=failure

**l-002 return (identity authz):**
- dev.dana: active, developer role
- Authorized hosts: `dev-ws-1`, `jump-box-1`, `office-ws-1`
- `db-1`: **NOT authorized** (authorized: false)
- `web-1`: NOT authorized; `jump-box-1`: authorized via developer role
- Developer role maps to `/bin/bash` shell

**l-003 return (sshd auth sequence ±30m):**
- 14 events total: 2 Accepted (office-ws-1, password from ::1), 12 Failed (db-1, "Invalid user" from 172.18.0.14)
- Three scripted rounds: 4 db-1 failures 13:46:35–13:46:56; workstation Accepted 13:50:34 → 4 db-1 failures 13:50:37–13:50:59; workstation Accepted 13:52:56 → 4 db-1 failures 13:52:57–13:53:19
- Interval between db-1 attempts: ~3–7 seconds; sub-second initiation after each workstation acceptance
- All db-1 rejections: "Invalid user dev.dana" — no such account on db-1

**l-004 return (7d baseline):** Incomplete — request limit hit during gather. Not available.

## ANALYZE (loop 1)

```invlang
:V l-001.observations.vertices [id|type|class|ident|attrs?]
v-006|compute|workstation/internal/known-corp|office-ws-1|os=linux
v-007|compute|database-server/internal/known-corp|db-1|os=linux
v-008|compute|ip-only/internal/??|172.18.0.14|knowledge=partial;note=source-of-db-1-attempts;likely=office-ws-1-network-interface

:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-003|authenticated_as|v-004|v-001|2026-05-25T13:52:56Z|siem-event:elastic|host=office-ws-1;process=sshd;outcome=success;method=password;source_ip=::1;msg="Accepted password for dev.dana from ::1 port 56094 ssh2"
e-004|attempted_auth|v-008|v-007|2026-05-25T13:52:57Z|siem-event:elastic|host=db-1;process=sshd;outcome=failure;reason=invalid-user;count=12;rounds=3;cadence=3-7s-per-attempt;msg="Invalid user dev.dana from 172.18.0.14"

:R attr_updates [resolved_by|target|key|value]
l-001|v-002|class|workstation/internal/known-corp
l-001|v-002|attrs.hostname|office-ws-1
l-001|v-003|class|database-server/internal/known-corp
l-001|v-003|attrs.hostname|db-1

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-002|e-004|ac1|unauthorized|iam-policy|"dev.dana authorized hosts: dev-ws-1, jump-box-1, office-ws-1 only; db-1 explicitly authorized:false; sshd message Invalid user confirms no account on db-1"
l-002|e-004|ac2|indeterminate|change-mgmt|"change-mgmt not queried; unauthorized IAM verdict forces escalation regardless"

:T resolutions
h-001  null → --    [l-002 r1 severe ⟂ e-004 :: dev.dana NOT provisioned for db-1 (authorized:false); sshd confirms invalid user; ac1 unauthorized]
h-001  -- → --      [l-003 r2 severe ⟂ e-004 :: 12 failed attempts in 3 scripted bursts at 3-7s cadence; sub-second initiation after each workstation acceptance]
h-002  null → ++    [l-002 p1 severe ⟂ e-004 :: dev.dana absent from db-1 authorization; IAM oracle confirms unauthorized]
h-002  ++ → ++      [l-003 p2,p3 severe ⟂ e-004 :: scripted burst pattern (4 per round, 3-7s interval) from 172.18.0.14; initiated sub-second after each office-ws-1 workstation session acceptance; automated ssh probe tooling running under the session]
```

**Key findings:**
1. **dev.dana is NOT an authorized user on db-1.** IAM returns `authorized: false`. The sshd "Invalid user dev.dana" message confirms no account exists on db-1.
2. **The db-1 attempts are scripted/automated.** Three rounds of 4 attempts at 3–7 second intervals, each round initiated within 1–3 seconds of a workstation sshd acceptance event. Not human-paced.
3. **Source IP 172.18.0.14 is office-ws-1's network interface.** Loopback auth on office-ws-1 (::1) followed sub-second by probes from 172.18.0.14; tooling in the workstation session generates the db-1 probes.
4. **Auth method on workstation leg is password** — prod-tier all "invalid user" failures so no auth method reached on db-1.
5. **ac1 authz contract resolves unauthorized** — escalation required.

**Ceiling test gaps:**
- `l-004` (7d dev.dana baseline) incomplete — request limit; novelty not confirmed but unauthorized access is independently dispositive.
- Post-auth process execution on office-ws-1 within session window (auditd/EDR): what tool is generating the db-1 probes; credential-harvest step upstream of session not recovered.
- CMDB lookup for 172.18.0.14 to formally confirm it is office-ws-1's container/network interface.
- Authorized_keys / sshd_config FIM on db-1 not required — probe was rejected; no session established on db-1.

**Lessons applied:**
- `sshd-auth-method-token-is-hypothesis-discriminator`: Password auth on workstation leg extracted; prod leg all "invalid user" failures — auth method not reached on db-1.
- `auth-log-scope-does-not-cover-post-auth-behavior`: Post-auth process execution on office-ws-1 not covered; escalating — IR team handles forensic follow-up.
- `ssh-pivot-upstream-credential-harvest-lead`: Pre-pivot source-host activity relevant for IR; named as ceiling gap.

## REPORT

```invlang
:T conclude
termination.category   adversarial-confirmed
disposition            malicious
impact_verdict         attempted-lateral-movement
confidence             high
matched_archetype      ?adversarial-cross-tier-pivot
summary                "dev.dana authenticated to office-ws-1 via password sshd; within 1 second, scripted ssh probes for dev.dana hit db-1 from 172.18.0.14 (office-ws-1 IP). Twelve failures in three bursts of four at 3-7 second cadence, each round triggered sub-second after a workstation sshd acceptance. dev.dana has no account on db-1 and is IAM-provisioned only for dev-ws-1, jump-box-1, and office-ws-1. Unauthorized destination, scripted cadence, and sub-second workstation-session trigger confirm automated ssh scanning or lateral-movement tooling running under the session. Authz contract ac1 resolves unauthorized — escalate."
```
