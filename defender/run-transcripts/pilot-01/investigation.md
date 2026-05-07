# Investigation — pilot-01

## ORIENT

**Alert:** `ssh-successful-login-from-new-source` on bastion-01.corp  
**Who:** jsmith (DevOps, infra-admins)  
**What:** Successful publickey auth from 10.42.7.183 — a corp-internal IP (Building 7, 4th floor wifi) never previously seen authenticating to this host  
**When:** 2026-05-05T03:47:12Z (Tuesday, off-hours)  
**Context signals:** Key fingerprint SHA256:a1b2c3... matches jsmith's known key (seen from 4 other corp IPs over 90d). 142 prior logins to this host over 180d, all from 10.42.5.0/24. INC-8821 ("rotated bastion sshd config") closed by jsmith at 03:31Z — 16 min before this login. No concurrent sessions from other IPs.

**Triage question:** Is this an authorized login by jsmith from an unfamiliar corp location (Building 7 wifi), or is the session unauthorized — e.g., SSH agent forwarding from a compromised corp host that gave the adversary jsmith's auth capability without possessing the private key?

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|bastion-01.corp|role=bastion
v-002|identity|identity:human|jsmith|team=DevOps;groups=infra-admins
v-003|endpoint|endpoint:ipv4|10.42.7.183|geoloc=corp-internal:building7-4f-wifi

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|authenticated_to|v-003|v-001|2026-05-05T03:47:12Z|siem-event:wazuh|user=jsmith;method=publickey;key_fp=SHA256:a1b2c3...;outcome=success
```

## PLAN (loop 1)

Key fork: the matching key fingerprint and corp-internal IP together support a benign location-change reading. But SSH agent forwarding (T1550.001) would produce the identical surface — same key (because the agent socket is forwarded, not the key exported), same corp-internal origin (because the forwarding host is corp-owned). The fork cannot be resolved from the alert field alone.

Two parallel leads that each discriminate on a different axis:

- **l-001** (device history): Does 10.42.7.183 carry prior jsmith auth events to other corp hosts? If yes → this IP is a known jsmith device on Building 7 wifi, strongly supporting the location-change reading. If no prior auth at all → the IP's identity is unanchored and agent-forwarding origin cannot be ruled out.
- **l-002** (lateral movement): Did bastion-01 originate any outbound SSH sessions after 03:47:12Z? Authorized admin follow-up on INC-8821 would not require bastion to reach further inward; unauthorized pivot use would.

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|refuts|authz?|weight|status]
h-001|?admin-session-building7-wifi|v-003|authenticated_to|identity|human-admin-device|p1:proposed_parent:"10.42.7.183 has prior jsmith auth events to other corp hosts (known device on wifi)";p2:proposed_edge:"no outbound pivot from bastion post-login"|r1[p1]:"10.42.7.183 has no prior jsmith auth history across corp";r2[p2]:"bastion originates outbound SSH sessions shortly after 03:47Z"|ac1:proposed:access-policy:"off-hours bastion login from new subnet permitted for infra-admins":escalate/escalate|null|active
h-002|?ssh-agent-forwarding-pivot|v-003|authenticated_to|endpoint|adversary-controlled-corp-host|p1:proposed_parent:"10.42.7.183 is a compromised host, not jsmith's personal device";p2:proposed_edge:"bastion session is used to reach internal targets post-login (pivot)"|r1[p1]:"10.42.7.183 has well-established jsmith auth history predating this event";r2[p2]:"no outbound auth from bastion follows the login"||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|source-ip-auth-history|v-003|h-001,h-002|wazuh|auth-events|srcip=10.42.7.183|90d
l-002|1|bastion-outbound-pivot-check|v-001|h-001,h-002|wazuh|auth-events|srcip=bastion-01.corp|2h
```

## GATHER (loop 1)

Dispatched l-001 and l-002 in parallel. Both returned dead ends: Wazuh CLI requires a configured indexer endpoint (`soc-agent/knowledge/environment/systems/wazuh/config.env` + credentials); the playground Docker stack is not running in this environment. Neither query executed; no `gather_raw/` files written.

## ANALYZE (loop 1)

Both leads are unrunnable dead ends — not null-result findings but missing infrastructure. The two discriminating measurements (device auth history for 10.42.7.183, bastion outbound pivot check) remain unanswered.

Reasoning from inline alert context only:

**Signals supporting h-001 (?admin-session-building7-wifi):**
- Key fingerprint SHA256:a1b2c3... matches keys seen from 4 other corp IPs over 90 days — this is not a new or unknown key for jsmith; key reuse across corp IPs is consistent with a single device roaming across networks.
- Source geolocates to corp-internal Building 7 4th floor wifi — same org, different physical location than usual subnet (10.42.5.0/24 → 10.42.7.0/24, likely wired vs. wifi).
- INC-8821 closed at 03:31Z ("rotated bastion sshd config") — 16 minutes before this login. The login is plausibly a post-change verification: connect to confirm the new config accepts jsmith's key.
- No concurrent sessions from other IPs — no signs of parallel attacker-controlled session.

**Why h-001 cannot close the investigation on its own:**
Agent forwarding (T1550.001) produces the identical surface on every one of the above signals. The key fingerprint matches because the agent is forwarded — not the private key exported. The corp-internal origin is explained if the forwarding host is any corp machine jsmith has an active `ssh-agent` socket on. The timing window (jsmith known active just minutes earlier) is favorable cover. Absence of concurrent sessions doesn't rule out a single adversary-controlled path through the forwarded socket. The inline alert context is entirely consistent with h-002.

**Belief state after loop 1:**
Neither hypothesis moved. h-001 has favorable inline signals but they are not falsifying for h-002. h-002 has no refuting evidence because l-001 and l-002 are blocked.

```invlang
:T resolutions
h-001  null → +    [inline alert context: matching key from multiple corp IPs, corp-internal geoloc, INC-8821 16min prior — consistent but non-exclusive; agent-forwarding produces identical surface]
h-002  null → null [l-001 dead-end: device identity for 10.42.7.183 unverifiable; l-002 dead-end: post-login pivot unchecked; no refuting evidence gathered]
```

No second loop warranted — the discriminating questions are blocked at the data layer, not answerable with a different lead design. Escalate with gaps named.

## REPORT

```invlang
:T conclude
termination.category   exhaustion-escalation
termination.rationale  "l-001 (device auth history for 10.42.7.183) and l-002 (bastion outbound pivot check) both blocked by missing Wazuh infrastructure; ?ssh-agent-forwarding-pivot cannot be driven to -- without them"
disposition            escalate
confidence             low
matched_archetype      ssh-new-source-ambiguous-origin
ceiling_rationale      "Agent forwarding produces identical surface to authorized location-change login; inline context is necessary but not sufficient to close"
summary                "SSH login to bastion-01 by jsmith from a new corp subnet (Building 7 wifi) minutes after closing a bastion config ticket. Key fingerprint matches known jsmith key and source is corp-internal — consistent with authorized location change. However, SSH agent forwarding (T1550.001) produces the identical surface without requiring key exfiltration. The two leads that would discriminate — cross-host auth history for 10.42.7.183 (l-001) and post-login outbound pivot check from bastion (l-002) — were blocked by unavailable Wazuh infrastructure. Escalate for manual review with the agent-forwarding path explicitly in scope."

:T conclude.surviving [hyp_id|final_weight]
h-001|+
h-002|null
```
