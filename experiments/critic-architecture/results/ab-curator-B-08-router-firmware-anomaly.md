# Arm B training: 08-router-firmware-anomaly

### Single agent (triage + self-review + directive)

- cost: $0.1098
- tokens: in=2 out=2266 cache_read=11896 cache_create=18920

```
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
```
