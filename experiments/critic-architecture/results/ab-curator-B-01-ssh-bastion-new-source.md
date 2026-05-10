# Arm B training: 01-ssh-bastion-new-source

### Single agent (triage + self-review + directive)

- cost: $0.1103
- tokens: in=2 out=2316 cache_read=11896 cache_create=18858

```
### TRIAGE

jsmith's publickey login to bastion-01 at 03:47 from a new subnet is suspicious — the ticket-based cover story is structurally consistent with post-exploitation pattern-washing, and the source location (Building 7 wifi at 03:47) is independently anomalous.

**Hypotheses considered:**

| Hypothesis | Lead |
|---|---|
| `?legitimate-maintenance` — jsmith moved to Building 7 to work late, verifying sshd rotation | Badge/physical-access log: did jsmith swipe into Building 7 tonight? |
| `?adversary-controlled-lateral-movement` — attacker extracted jsmith's key from one of 4 known hosts, now operating from Building 7 wifi | Check those 4 hosts for active sessions or new authorized_keys changes in past 24h |
| `?account-takeover-with-ticket-wash` — attacker closed INC-8821 to manufacture cover, key separately compromised | Review INC-8821 comment/edit history: source IP, timing cadence, whether changes match jsmith's normal session fingerprint |
| `?automated-post-rotation-validation` — sshd config rotation triggers an automated test script from a different runner subnet | Check INC-8821 automation context; was a CI/CD job spawned on ticket close? |
| `?vpn-or-proxy-shift` — jsmith changed network path (new VPN exit, different jump host) legitimately | Correlate jsmith's other authenticated actions tonight with same src IP |
| `?adversary-controlled-building-7-implant` — threat actor present on Building 7 wifi segment, not physically jsmith | DHCP lease for 10.42.7.183: what device class, first-seen, hostname? |

**Disposition:** `suspicious`

**Load-bearing assumption:** INC-8821 was created, worked, and closed by the real jsmith in a continuous legitimate session. If the ticket activity originated from a different IP or shows timing gaps inconsistent with jsmith's normal workflow, the cover story collapses and this becomes malicious.

---

### SELF-REVIEW

**1. Flip evidence.** The load-bearing assumption is ticket authenticity. A single concrete artifact flips the call: INC-8821's audit trail shows the ticket was edited or closed from an IP *other* than jsmith's normal 10.42.5.0/24 subnet, or the edit timestamp precedes the login by more than 30 minutes with no intermediate activity — indicating pre-positioned cover rather than active maintenance.

**2. Lead classification.**

| Lead | Classification |
|---|---|
| Badge log / Building 7 physical access | **load-bearing** — no swipe = strong escalation trigger |
| INC-8821 edit-history source IP | **load-bearing** — different IP breaks the cover story |
| 4 known hosts for active compromise | **load-bearing** — compromised host validates lateral movement |
| DHCP lease for 10.42.7.183 | **load-bearing** — unrecognized device class changes the picture |
| CI/CD automation context | corroborating |
| jsmith other actions from same IP tonight | corroborating |

Most leads are load-bearing — the triage is well-structured here.

**3. Counter-anchor.** I did not adequately consider `?key-replay-from-memory-resident-credential` — an attacker operating fully in-memory on a host jsmith previously authenticated to, forwarding the agent socket rather than extracting the key file. Agent-forwarding would produce the same fingerprint without key material ever leaving jsmith's machine, and would be invisible to the 4-host key-extraction check. This is a meaningful gap.

---

### DIRECTIVE

For alerts where a recent legitimate-looking ticket creates strong surface cover for an anomalous access, do not let the ticket absorb your skepticism — attack it as a separate artifact. Verify that the ticket activity and the alert event share a coherent session lineage (same source IP range, plausible timing, consistent privilege footprint). When the cover is ticket-based, the highest-yield lead is ticket edit provenance, not the access event itself. For key-authenticated logins specifically, complement static fingerprint matching with agent-forwarding detection: an attacker forwarding a live agent leaves no key on disk but produces an identical fingerprint — check for `SSH_AUTH_SOCK`-style session chaining on the intermediate hosts.
```
