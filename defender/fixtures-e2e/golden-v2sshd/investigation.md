## ORIENT

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|workstation/internal/??|office-ws-1|ip=172.18.0.14;os=ubuntu-22.04
v-002|identity|user/??|dev.dana|
v-003|compute|ip-only/internal/known-corp|::1|knowledge=partial

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-003|v-001|2026-05-25T15:27:22.928Z|siem-event:elastic|outcome=success;user=dev.dana;auth_method=unknown
```

Alert `v2-sshd-success-after-failures` on `office-ws-1` (172.18.0.14): EQL sequence matched ≥3 sshd `event.outcome=failure` events followed by 1 `event.outcome=success` within 10 minutes, keyed by `host.name`. Success event: user `dev.dana`, source `::1` (IPv6 loopback — definitionally the same physical machine as `office-ws-1`).

**Critical structure note:** The EQL rule keys by `host.name` only — it does NOT join on `source.ip` or `user.name`. The 4 ancestor event IDs in the alert (3 failures + 1 success) may have different source IPs and may have targeted different usernames. The failure source IPs are unknown from the alert fields alone.

**Triage question:** Did the failure events also originate from `::1` (a local process on `office-ws-1` hammering its own SSH daemon, failing before succeeding), or from a different source IP (external/other internal), making the EQL correlation a spurious join of unrelated failure noise with a coincidental loopback success?

## PLAN (loop 1)

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?scanner-or-noise-probe|v-001|attempted_auth|compute|ip-only/internet/novel||null|active
h-002|?local-process-ssh-to-localhost|v-001|attempted_auth|process|unclassified-process||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"failure events originate from a non-loopback source IP (external or other internal, not ::1)"
p2|proposed_edge|"no failures from ::1 in the ±10m window — loopback success is an unrelated coincidental event"
p3|proposed_edge|"inter-event timing has a gap between last failure and success, consistent with independent unrelated sources"

:H h-001.refuts [id|refutes|claim]
r1|p1,p2|"failure events also originate from ::1 — same source as success, ruling out a cross-source spurious EQL join"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"dev.dana is an active provisioned user authorized to access office-ws-1"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"all failure events also originate from ::1 — same loopback source as the success"
p2|proposed_parent|"inter-failure timing is sub-10s, consistent with automated SSH retry from a local process"
p3|proposed_parent|"auth method on success is password, consistent with local credential-testing against sshd"

:H h-002.refuts [id|refutes|claim]
r1|p1,p2|"failure events originate from a non-loopback address — cross-source EQL correlation, not a local retry loop"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|sshd-auth-sequence-office-ws-1|v-001|h-001,h-002|elastic|±10m
l-002|1|identity-profile-dev-dana|v-002|h-001|identity|n/a
l-003|1|cmdb-lookup-office-ws-1|v-001|h-001,h-002|cmdb|n/a
```

**Lead discrimination:** l-001 is the primary discriminating lead — source IPs of failure events vs `::1` resolve h-001 vs h-002 directly. Auth method on the sshd Accepted message (per `sshd-auth-method-token-is-hypothesis-discriminator`) is a first-order discriminator. l-002 and l-003 are parallel registry checks: l-002 closes h-001's authz contract ac1; l-003 resolves v-001's provenance.

**Lesson applications noted:**
- `sshd-auth-method-token-is-hypothesis-discriminator`: extract auth-method token from sshd Accepted message in l-001; password vs pubkey is a first-order discriminator for credential-testing vs key-based automation.
- `behavioral-anomaly-needs-affirmative-explanation`: if l-001 shows loopback-source failures with automated cadence, a process-audit lead on office-ws-1 is required in loop 2 before attributing to a specific benign mechanism.
- `auth-log-scope-does-not-cover-post-auth-behavior`: auth-log leads cannot confirm post-auth behavioral cleanliness; if H2 survives loop 1, a process-execution lead on office-ws-1 is needed in loop 2.
- `post-auth-lead-targets-landing-host-not-source`: in the loopback case, source and landing host are the same (office-ws-1); any post-auth artifact lead targets office-ws-1 itself.

## GATHER (loop 1)

Dispatching l-001, l-002, l-003 in parallel.

## ANALYZE (loop 1)

l-001: All 3 failure events sourced from `::1` (loopback), same as success. Total span 2 seconds (15:22:40–15:22:42), sub-second cadence. Password auth on success. All 4 events targeted `dev.dana`. H1 (external scanner) directly refuted. H2 (local process SSH to localhost) confirmed on all 3 predictions.

l-002: dev.dana is an active developer, explicitly authorized on office-ws-1 with sudo, via per-host override (expected for developer workstations). No anomalous flags. ac1 fulfilled: authorized.

l-003: office-ws-1 is known-corp workstation, owned by dev.dana, preprod criticality. No services configured (service: null). Zero outbound trust edges. Authorized SSH users: dev.dana, svc.monitoring, svc.config-mgmt. The absence of any documented automation or outbound trust edges means the 2-second automated loopback-SSH pattern has no affirmative baseline explanation — per `behavioral-anomaly-needs-affirmative-explanation`, a process-audit lead is required before attribution.

```invlang
:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|attempted_auth|v-003|v-001|2026-05-25T15:22:40Z|siem-event:elastic|outcome=failure;user=dev.dana;count=3;span_secs=2;auth_method=password

:R attr_updates [resolved_by|target|key|value]
l-001|e-001|attrs.auth_method|password
l-002|v-002|class|user/known-corp
l-002|v-002|attrs.status|active
l-002|v-002|attrs.role|developer
l-003|v-001|class|workstation/internal/known-corp
l-003|v-001|attrs.owner|dev.dana
l-003|v-001|attrs.services_documented|none

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-002|e-001|ac1|authorized|iam-policy|"dev.dana active developer, explicitly authorized with sudo on office-ws-1 via identity registry"

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac2|e-001|approved-source-list|"a documented authorized process or cron job on office-ws-1 is expected to SSH to localhost with password auth for dev.dana"|escalate|escalate

:T resolutions
h-001  null → --    [l-001 r1 severe ⟂ e-002 :: all 3 failure events from ::1 (loopback) not external — h-001 p1,p2 both false]
h-002  null → ++    [l-001 p1,p2,p3 ⟂ e-002 :: all events from ::1; 2s total span; password auth — local process SSH retry pattern confirmed on all predictions]

:T close
loop  1
```

## PLAN (loop 2)

H2 (?local-process-ssh-to-localhost) is confirmed as the mechanism: a process on office-ws-1 SSH'd to its own sshd with password auth, failing 3 times before succeeding — all within 2 seconds. CMDB shows no documented services or outbound automation on this host. The authz contract ac2 requires confirming whether an authorized process produced this pattern.

Two parallel leads:

```invlang
:L findings [id|loop|name|target|tests|system|window]
l-004|2|process-exec-office-ws-1-ssh-window|v-001|h-002|elastic|15:20-15:25Z
l-005|2|authorized-keys-office-ws-1|v-001|h-002|host-state|current
```

**Lead discrimination:**
- l-004: if a known authorized binary (svc.config-mgmt agent, documented script) appears in the process tree initiating the SSH → supports ac2 authorized; if an anomalous process (bash, python, unknown binary, interactive shell) appears → ac2 unauthorized, escalate. If no process-exec telemetry is available, this becomes a ceiling_test gap (per `behavioral-anomaly-needs-affirmative-explanation`).
- l-005: current state of authorized_keys on office-ws-1. Any key added after 15:22:42Z would indicate persistence installation via the successful session (per `post-auth-lead-targets-landing-host-not-source`). Absence of new keys supports a non-persistence scenario.

## GATHER (loop 2)

Dispatching l-004 and l-005 in parallel.

## ANALYZE (loop 2)

l-004 (process execution): Telemetry ceiling. Elastic/Falco does not provide full process-execution ancestry for non-containerized hosts in this environment. `defender-elastic esql` subcommand unsupported; KQL-based Falco queries returned no process events in the window. **ceiling_test: process identity of the SSH initiator on office-ws-1 is unresolvable — would require auditd/execve logs (not collected) or a Falco rule targeting SSH client launches (not deployed for this host).**

l-005 (authorized-keys): No persistence artifacts. dev.dana's `authorized_keys` is **empty** (0 SSH public keys configured). Root, svc.monitoring, and sre accounts also empty. svc.config-mgmt has 15 RSA rotation keys consistent with documented key-rotation infrastructure. No new keys post-session. sshd_config unchanged (SHA-256 verified).

Additional inference: dev.dana has no SSH public keys on office-ws-1 — password auth is the only available method for this user to SSH. The loopback SSH's use of password auth is not anomalous relative to dev.dana's account configuration; it was the only option.

ac2 is `indeterminate` (process identity unresolvable at telemetry ceiling). Per `auth-log-scope-does-not-cover-post-auth-behavior`, a successful SSH session whose process is unattributable requires at least one of: process-execution (l-004 ceiling), outbound-network, or file-integrity (l-005 clean). Outbound-network via Zeek is the remaining discriminating check.

```invlang
:R attr_updates [resolved_by|target|key|value]
l-005|v-002|attrs.authorized_keys|empty
l-005|v-001|attrs.sshd_config_hash|76300f84e5d20a7850560de3ba4ec7bcd96d6ce797a1bf229cf71159b52a140f

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-004|e-001|ac2|indeterminate|approved-source-list|"process-exec telemetry unavailable: auditd not collected; Falco carries no full process ancestry on non-containerized hosts — initiating process on office-ws-1 cannot be identified from available data sources"

:T close
loop  2
```

## PLAN (loop 3)

One remaining post-auth check: outbound network connections from office-ws-1 after the successful session (15:22:42Z). This is the last available discriminating signal for post-auth behavioral cleanliness.

```invlang
:L findings [id|loop|name|target|tests|system|window]
l-006|3|zeek-outbound-office-ws-1-post-session|v-001|h-002|elastic|15:22-15:40Z
```

**Lead discrimination:** Anomalous outbound connections from 172.18.0.14 after 15:22:42Z (unexpected destinations, uncommon ports, large transfers) → post-auth malicious activity, escalate. Clean or normal workstation traffic → no post-auth malicious evidence; close as inconclusive (process identity at telemetry ceiling, all other indicators benign).

## GATHER (loop 3)

Dispatching l-006.

## ANALYZE (loop 3)

l-006 (Zeek outbound): Second telemetry ceiling. `defender-record-query` execution blocked by permission gate in this run environment. No Zeek network flow data retrieved for the post-session window. **ceiling_test: outbound network flow data for office-ws-1 (172.18.0.14) in window 15:22:42–15:40:00Z is inaccessible — Zeek query blocked by environment permission boundary.**

No new graph observations from loop 3.

**Cumulative picture for close:**
- H2 (`?local-process-ssh-to-localhost`) confirmed `++`: all events from `::1`, 2s automated cadence, password auth, authorized user
- H1 (`?scanner-or-noise-probe`) refuted `--`: no external source
- ac1 `authorized`: dev.dana active developer, sudo on office-ws-1, CMDB owner
- ac2 `indeterminate`: process identity unresolvable — two independent telemetry ceilings (l-004 process-exec, l-006 Zeek outbound)
- No persistence artifacts (l-005: authorized_keys empty, sshd_config unchanged)
- No affirmative automation baseline (CMDB: no services, no trust edges)
- Per `behavioral-anomaly-needs-affirmative-explanation`: authorization confirmed + telemetry ceiling = medium-confidence close. Per ac2 `on_indet=escalate`: process identity indeterminate forces escalation. Disposition: `inconclusive` at medium confidence.

```invlang
:T conclude
termination.category   data-ceiling
disposition            inconclusive
impact_verdict         none-detected
confidence             medium
matched_archetype      unattributed-loopback-ssh-retry
summary                "H2 confirmed: local process on office-ws-1 SSH'd to ::1 with password auth for authorized owner dev.dana in a 2s automated cadence; no persistence installed; process identity unresolvable (auditd not collected, Falco no ancestry, Zeek blocked by permission gate). CMDB documents no automation for this host. Escalating inconclusive at medium confidence: authorized user, no post-auth harm detected, but initiating process cannot be named."
```

## REPORT

Disposition: inconclusive / medium. See report.md.
