# Arm B curated addendum library

### Curator

- cost: $0.1177
- tokens: in=2 out=2002 cache_read=11896 cache_create=21418

```
```
# Addendum library

1. For closed-firmware network device alerts, consult the vendor support KB before
   constructing an adversarial hypothesis tree; absence of a published CVE is weak
   evidence, not exculpatory — firmware-stability defects are systematically
   under-indexed in public advisories.

2. When a network device shows co-occurring protocol-layer and control-plane anomalies,
   require a single causal explanation before splitting into independent branches; also
   obtain the upstream operator's peer-side teardown reason codes — "no link flap" and
   "no self-originated session reset" are different claims.

3. On credentialed-action alerts from automation or CI/CD roles, attack the plan-to-
   reality gap: enumerate every executed action in the role session and diff against the
   approved artifact. Principal legitimacy (OIDC chain, PR approvals) establishes *who*
   ran, not *what* ran; audit change content (trust relationships, wildcard grants)
   independent of volume.

4. When a recent legitimate-looking ticket creates surface cover for an anomalous access
   event, verify that the ticket's source IP, timing, and privilege footprint share
   coherent session lineage with the alert — ticket edit provenance is the highest-yield
   lead, not the access event itself.

5. For key-authenticated access alerts, complement credential fingerprint matching with
   agent-forwarding detection on intermediate hosts; an attacker forwarding a live agent
   produces an identical fingerprint without key extraction.
```
```


## Raw inputs

[from single-agent on fixture 08-router-firmware-anomaly]
### TRIAGE

**Claim:** An edge router is exhibiting repeated BGP session resets co-occurring with an unexplained control-plane CPU spike; no benign operational trigger accounts for the observed pattern, making this a credible pre-compromise or active-exploit signal on a high-value asset.

**Hypotheses considered:**

| Hypothesis | Lead |
|---|---|
| `?firmware-bug-BGP-stability` — periodic crash in BGP state machine under specific peer config | Pull vendor TAM / support KB for 7.4.2 known issues; ask ISP for peer-side session teardown reason codes |
| `?hardware-fault-CPU` — failing component causing erratic CPU and session drops | Check OOB reachability continuity, request vendor chassis health log (memory ECC errors, thermal) |
| `?adversary-controlled-BGP-session-reset` — attacker sending malformed UPDATE/NOTIFICATION packets to force resets and probe CPU headroom | Inspect syslog for BGP NOTIFICATION reason codes and peer IP at each reset; correlate with any upstream ACL hit counters |
| `?adversary-controlled-control-plane-exploit` — active exploitation of an undisclosed firmware vuln giving RCE on control plane | Request vendor firmware integrity check; compare running config hash against last-known-good; check for unexpected management-plane connections |
| `?route-table-DDoS` — volumetric BGP UPDATE flood spiking CPU and destabilizing sessions | Check interface counters for UPDATE packet rate; ask ISP for peer-side UPDATE volume |
| `?legitimate-reconvergence-mislabeled` — partial reconvergence event not classified as "full" by vendor code | Compare BGP RIB size before/after each reset window via any available SNMP polling |

**Disposition: escalate**

**Load-bearing assumption:** There is no firmware bug or hardware fault in 7.4.2 that produces periodic BGP resets with a 14s CPU spike absent a config commit or reconvergence event — if such a defect exists and is confirmed, the call moves to suspicious/benign.

---

### SELF-REVIEW

**1. Load-bearing assumption under pressure.** The assumption is that the CPU spike has no benign explanation. The concrete flip: vendor support produces a field advisory (even undocumented) for 7.4.2 citing a BGP state-machine race under specific timer configurations that causes periodic session teardown with a 10–20s CPU burst. That single artifact — a vendor ticket number or firmware changelog entry — fully explains the cluster without adversarial involvement.

**2. Lead classification.**

| Lead | Classification |
|---|---|
| Vendor TAM / firmware bug search | **load-bearing** — could flip to benign |
| Chassis health / hardware fault | **load-bearing** — alternate non-adversarial explanation |
| BGP NOTIFICATION reason codes + peer IP | **load-bearing** — distinguishes inbound attack from self-originated reset |
| Firmware integrity / unexpected mgmt connections | **load-bearing** — confirms or denies active compromise |
| UPDATE packet rate / ISP peer volume | **load-bearing** — confirms or denies flood attack |
| BGP RIB size comparison | corroborating — only strengthens reconvergence hypothesis |

All five meaningful leads are load-bearing. No concern about a corroboration-heavy list here.

**3. Counter-anchor.** I did not weight the possibility that the ISP's NOC log has a visibility gap — specifically, a BGP peer process restart on their side that tears down the session cleanly (no link flap, no interface event) but still appears as a remote-initiated reset. That would be a fully benign external explanation I under-examined.

---

### DIRECTIVE

For alerts on closed-firmware network devices where syslog is the only telemetry surface, treat the absence of a vendor-published CVE as weak evidence — not exculpatory. The investigation sequence that matters is: (1) demand the exact peer-side teardown reason code from the upstream operator, because "no link flap" and "no session teardown from our side" are different claims; (2) treat any co-occurring control-plane CPU anomaly as a correlated event requiring a joint explanation, not two independent checks; (3) make the firmware vendor's TAM or support KB the first stop before building an adversarial hypothesis tree, because firmware-stability bugs are systematically under-indexed in public advisories.

---

[from single-agent on fixture 05-terraform-iam-mass-change]
### TRIAGE

**Claim:** This is a legitimate Terraform-apply run by the platform team that executed a pre-approved IAM change set; the alert fired on volume, not anomaly.

**Hypotheses considered:**

- `?legitimate-tf-apply` — PR plan artifact matches CloudTrail change-for-change; lead: diff CloudTrail events against the plan JSON line-by-line.
- `?plan-injection` — CI artifact was tampered after plan but before apply; lead: compare plan artifact SHA against the artifact stored in GitHub Actions run 7799123 at plan time.
- `?adversary-controlled-runner` — i-09abc was compromised and used the OIDC token to issue additional calls beyond the plan; lead: pull all CloudTrail events for this role session and check for any calls not in the plan diff.
- `?stolen-oidc-token` — token exfiltrated and replayed from a different execution context; lead: verify OIDC claims (repo, ref, run_id, aud) match GitHub's token verification endpoint and confirm no duplicate session from a different source IP or instance.
- `?supply-chain-compromise` — malicious Terraform provider or module injected extra resources at apply time; lead: check for any resource changes in state diff that do not appear in the plan diff.
- `?privilege-escalation-via-iam` — attacker used the apply to embed a backdoor role/policy; lead: review the 5 created policies and 9 UpdateAssumeRolePolicy changes for trust relationships pointing to external principals.

**Disposition:** `benign`

**Load-bearing assumption:** The Terraform plan artifact in the CI run was not tampered with between plan and apply — i.e., what the reviewers approved is exactly what ran.

---

### SELF-REVIEW

**1. Flip evidence for the load-bearing assumption:** A CloudTrail event for any IAM action not present in the plan artifact (even one extra `iam:PutRolePolicy`) would flip the call from benign to malicious. Concretely: a line in CloudTrail for this session's `userAgent` that has no counterpart in the plan JSON.

**2. Lead classification:**

- `?legitimate-tf-apply` — diff CloudTrail vs. plan: `load-bearing` (directly validates the core claim)
- `?plan-injection` — artifact SHA check: `load-bearing` (integrity of the approved scope)
- `?adversary-controlled-runner` — full session call enumeration: `load-bearing` (out-of-plan calls)
- `?stolen-oidc-token` — OIDC claims verification: `corroborating` (token metadata is already internally consistent; an attacker with runner access wouldn't need to steal the token)
- `?supply-chain-compromise` — state vs. plan diff: `load-bearing` (detects injected resources at apply time)
- `?privilege-escalation-via-iam` — trust policy review: `load-bearing` (benign volume ≠ benign content)

Most leads are load-bearing — coverage is adequate.

**3. Counter-anchor check:** I did not consider `?review-bypass` — the two approvers are colluding with the author, and the PR itself contains the malicious change legitimately approved. In that scenario all provenance checks pass and the attack surface is the human review layer, not the technical controls. This is low-probability but structurally invisible to automated analysis.

---

### DIRECTIVE

For high-volume IAM alerts triggered by CI/CD pipelines with strong provenance, the critical discipline is **plan-to-reality binding, not principal legitimacy**. The OIDC chain, PR approvals, and run metadata are relatively easy to forge or satisfy legitimately — they establish *who ran*, not *what ran*. Attack the gap between what was approved and what executed: enumerate every CloudTrail event in the role session and diff against the approved artifact. Then audit *content* of the changes (trust relationships, wildcard permissions, cross-account principals) independent of count. Volume-based signatures on CI roles almost always fire on legitimate deployments; the real signal lives in the delta.

---

[from single-agent on fixture 01-ssh-bastion-new-source]
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