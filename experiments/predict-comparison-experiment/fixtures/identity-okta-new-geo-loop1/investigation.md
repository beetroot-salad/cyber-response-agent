## CONTEXTUALIZE

**Alert:** 1777231332.11 — Okta successful sign-in from country not seen in user's recent history
**Key observables:**
- actor: j.morales@example.com (Julia Morales) — User
- client.ip: 103.27.181.42
- geo: VN / Hanoi
- userAgent: CHROME on Mac OS X
- outcome: SUCCESS
- eventType: user.session.start
- session.id: 102t7fxXXXXyznI4sJ7oEVZ_g
- timestamp: 2026-04-26T05:42:12.118Z
**Playbook hypotheses:** ?credential-stuffing-success, ?legitimate-traveling-user, ?vpn-or-proxy-egress, ?session-hijack
**Available leads:** user-signin-history, ip-reputation, hr-travel-records, mfa-event-correlation, session-activity-after
**Archetype matches:**
- credential-stuffing-success — candidate — successful sign-in from a country never seen for this account is the classic "good password in a bad place" shape; if no MFA challenge fired, escalate.
- traveling-user — candidate — humans travel; geo-novelty alone is weak signal without context (HR travel records, prior trips to neighboring regions, calendar).
- vpn-egress — candidate — corp VPN egress nodes can present novel-looking IPs even for stationary users.
**Adversarial archetype:** credential-stuffing-success — worst-case is the password landed and an attacker now holds an active session.
**Data environment:** reachable: okta_api, hr_records, ip_reputation_api, playground_ticket; degraded: none

```yaml
prologue:
  vertices:
  - id: v-001
    type: identity
    classification: corp-user-account
    identifier: j.morales@example.com
    attributes:
      display_name: Julia Morales
  - id: v-002
    type: source_ip
    classification: external-ip
    identifier: 103.27.181.42
    attributes:
      country: VN
      city: Hanoi
  edges:
  - id: e-001
    relation: signed_in
    source_vertex: v-002
    target_vertex: v-001
    when:
      timestamp: '2026-04-26T05:42:12.118Z'
    attributes:
      outcome: SUCCESS
      session_id: 102t7fxXXXXyznI4sJ7oEVZ_g
      user_agent: 'CHROME/Mac OS X'
    authority:
      kind: siem-event
      source: Okta system log
```
