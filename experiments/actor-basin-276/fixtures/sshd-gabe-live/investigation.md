## ORIENT

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|jump-box-1|os=linux;ip=172.18.0.18
v-002|identity|user/??|dev.gabe|
v-003|compute|ip-only/??/??|172.18.0.25|knowledge=partial

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-003|v-001|2026-06-15T07:44:59Z|siem-event:elastic|outcome=failed;count=3;user_asserted=dev.gabe
e-002|attempted_auth|v-003|v-001|2026-06-15T07:45:34Z|siem-event:elastic|outcome=success;user=dev.gabe
```

Triage question: Rule `v2-sshd-success-after-failures` fired on `jump-box-1` (172.18.0.18): ≥3 sshd failures followed by success within 10 minutes, from 172.18.0.25, for user `dev.gabe`. Disposition turns on: (a) whether 172.18.0.25 is a documented, authorized source; (b) whether dev.gabe is provisioned and authorized for jump-box-1; (c) what auth method sshd accepted — password signals credential brute-force per lesson `sshd-auth-method-token-is-hypothesis-discriminator`; and (d) what executed on jump-box-1 during/after the session per lessons `auth-log-scope-does-not-cover-post-auth-behavior` and `post-auth-lead-targets-landing-host-not-source`.

## GATHER (loop 1)

Dispatched l-001 through l-005 concurrently: l-001 (elastic, sshd auth sequence), l-002 (elastic, sshd 7d baseline), l-003 (cmdb, source IP lookup), l-004 (identity, dev.gabe authorization), l-005 (elastic, post-auth session activity).

## PLAN (loop 1)

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?authorized-dev-gabe-session|v-001|attempted_auth|identity|user/known-corp||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"CMDB records 172.18.0.25 as a known-corp device; dev.gabe is provisioned and authorized for jump-box-1"
p2|proposed_edge|"auth method is publickey or cert (not password); 3-failure count is consistent with user retry or automation retry, not credential spray"

:H h-001.refuts [id|refutes|claim]
r1|p1|"172.18.0.25 absent from CMDB or classified novel/external; or dev.gabe not provisioned for jump-box-1"
r2|p2|"auth method is password — password auth following a failure run is the credential brute-force fingerprint; or cadence is rapid-fire spray rather than human/automation retry"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-002|approved-source-list|"172.18.0.25 documented as authorized source for jump-box-1 access or as dev.gabe registered device"|escalate|escalate
ac2|e-002|iam-policy|"dev.gabe provisioned and authorized to access jump-box-1"|escalate|escalate

:L findings [id|loop|name|target|mode?|tests|system|window]
l-001|1|sshd-auth-sequence|v-001||h-001|elastic|2026-06-15T07:35:34Z/2026-06-15T07:55:34Z
l-002|1|sshd-auth-baseline|v-001||h-001|elastic|7d
l-003|1|cmdb-source-ip-lookup|v-003||h-001|cmdb|n/a
l-004|1|identity-dev-gabe-authz|v-002||h-001|identity|n/a
l-005|1|post-auth-session-activity|v-001||h-001|elastic|2026-06-15T07:45:34Z/2026-06-15T08:45:34Z
```

## ANALYZE (loop 1)

```invlang
:V l-001.observations.vertices [id|type|class|ident|attrs?]
v-004|session|interactive|ssh-dev.gabe-07:44:32Z|open_time=2026-06-15T07:44:32Z;auth_method=password;source_port=58066

:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-003|runs_on|v-004|v-001||inferred-structural|
e-004|authenticated_as|v-004|v-002||inferred-structural|

:V l-005.observations.vertices [id|type|class|ident|attrs?]
v-005|socket|unclassified-socket|172.18.0.7:22|protocol=ssh;port=22;knowledge=partial
v-006|socket|unclassified-socket|172.18.0.12:22|protocol=ssh;port=22;knowledge=partial

:E l-005.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-005|connected_to|v-001|v-005|2026-06-15T07:51:46Z|siem-event:elastic|direction=outbound;timing_aligns=sre.alice-runuser
e-006|connected_to|v-001|v-006|2026-06-15T07:53:13Z|siem-event:elastic|direction=outbound;timing_aligns=sre.chen-runuser

:R attr_updates [resolved_by|target|key|value]
l-001|e-001|attrs.first_failure_ts|2026-06-15T07:44:22Z
l-001|e-001|attrs.last_failure_ts|2026-06-15T07:44:31Z
l-001|e-001|attrs.inter_attempt_intervals_s|"0.68–2.58"
l-001|e-002|attrs.auth_method|password
l-001|e-002|attrs.exact_time|2026-06-15T07:44:32Z
l-001|e-002|attrs.source_port|58066
l-002|v-003|attrs.baseline_events_7d|796
l-002|v-003|attrs.distinct_auth_users_7d|"svc.config-mgmt,dev.dana,dev.ethan,dev.fatima,dev.gabe,dev.hira"
l-002|v-003|attrs.auth_method_7d|password-only
l-002|v-003|attrs.prior_failure_success_patterns|"dev.dana/dev.ethan 2026-06-14; dev.fatima 2026-06-14 and 2026-06-15 — all 3-failure then immediate success from same source"
l-002|v-002|attrs.prior_successful_auths_7d|11
l-003|v-003|class|ip-only/internal/novel
l-003|v-003|attrs.cmdb_status|not-registered
l-003|v-001|attrs.cmdb_trust_edges_out|"web-1,web-2,db-1,dev-ws-1"
l-004|v-002|class|user/known-corp
l-005|v-001|attrs.dev_gabe_session_close_observed|false

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-004|e-002|ac2|authorized|iam-policy|"dev.gabe active, developer role, jump-box-1 in authorized host list, /bin/bash shell"

:T resolutions
h-001  null → +    [l-001,l-002 r2,p2 moderate ⟂ e-002 :: l-001: password auth contradicts p2 publickey/cert prediction; l-002 normalizes — password-only established method from 172.18.0.25 for all 7 users over 7d; 3-failure cadence exact-matches dev.dana/ethan/fatima prior sessions from same source on 2026-06-14/15]
h-001  +    → ++   [l-004 p1 severe ⟂ e-002 :: dev.gabe active, authorized for jump-box-1 via developer role; ac2 resolved authorized]
h-001  ++   → +    [l-003 r1 moderate ⟂ e-002 :: 172.18.0.25 absent from CMDB; ac1 pending loop-2 resolution; l-005 no Falco auth-key alerts, no privilege escalation, dev.gabe session-close not observed in 1h window]
```

## PLAN (loop 2)

ac1 unresolved: 172.18.0.25 absent from CMDB but operationally established (796 baseline events, 6+ corp users over 7d). Need to resolve host identity. Per lesson `post-auth-lead-targets-landing-host-not-source`, also check current authorized_keys state on jump-box-1 for persistence artifacts not captured by the Falco event stream.

```invlang
:L findings [id|loop|name|target|mode?|tests|system|window]
l-006|2|elastic-ip-to-host-v003|v-003||h-001|elastic|n/a
l-007|2|authorized-keys-jump-box-1|v-001||h-001|host-state|n/a
```

## GATHER (loop 2)

Dispatched l-006 (elastic, IP-to-host for 172.18.0.25) and l-007 (host-state, authorized-keys on jump-box-1) concurrently.

## ANALYZE (loop 2)

```invlang
:R attr_updates [resolved_by|target|key|value]
l-006|v-003|class|workstation/internal/known-corp
l-006|v-003|attrs.hostname|dev-ws-1
l-006|v-003|attrs.elastic_agent_id|512ff451-c344-41e9-8c0f-9fc7ac20055f
l-007|v-001|attrs.authorized_keys_dev_gabe|empty
l-007|v-001|attrs.persistence_artifacts|none

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-006|e-002|ac1|authorized|approved-source-list|"172.18.0.25 = dev-ws-1 confirmed via Elastic agent metadata; dev-ws-1 present in jump-box-1 CMDB trust_edges_out; known-corp developer workstation with active Elastic agent enrollment; prior CMDB IP lookup gap — hostname registered, IP not indexed"

:T resolutions
h-001  +    → ++   [l-006,l-007 p1 severe ⟂ e-002 :: 172.18.0.25 = dev-ws-1 (CMDB-registered corp workstation in jump-box-1 trust_edges_out); ac1 resolved authorized; dev.gabe authorized_keys empty; no persistence artifacts on jump-box-1]

:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             medium
matched_archetype      authorized-developer-ssh
summary                "3-failure-then-success sshd pattern from authorized developer dev.gabe on corporate workstation dev-ws-1 (172.18.0.25); pattern is baseline-normal for this source (exact match for dev.dana/ethan/fatima on 2026-06-14/15); both authz contracts authorized; no post-auth artifacts."
```
