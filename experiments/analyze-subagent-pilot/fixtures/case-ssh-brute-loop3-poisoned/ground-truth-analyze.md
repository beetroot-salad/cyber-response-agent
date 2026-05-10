## ANALYZE (loop 3)

**Evidence:**
- auth-history-extended (30m preceding + 10m forward): 47 events, single 3-minute burst 09:11:47–09:14:51, 20 distinct generic usernames, 0.26/s steady sweep, zero successful auth (5501/5715) across the full window.
- Username profile: all 20 names are generic public-wordlist entries (admin, root, ubuntu, pi, oracle, postgres, ...). Zero environment-specific names matching the prod-webserver-01 app stack.
- Trust-root reached: v-001 (203.0.113.45) is external with no accessible upstream forensics.

**Assessment:**
```yaml
hypotheses:
  ?opportunistic-scanner:
    weight: "++"   # rolled up from "+" at loop 2
    reasoning: >
      20 distinct generic wordlist usernames at 0.26/s is a textbook SSH wordlist scan.
      p1 ("≥5 distinct generic usernames … consistent with a wordlist") directly confirmed.
      p2 (scanner reputation) already confirmed at loop 1. Two independent predictions met;
      an attempted refutation (env-specific names) was actively checked and not found.
      Severity of test: severe. Grade: ++.
  ?targeted-brute-force:
    weight: "--"   # weight-reversal from "+" at loop 2
    reasoning: >
      Refutation shape directly met: all 20 usernames are generic wordlist entries with
      ZERO environment-specific account names. A targeted attacker with prior reconnaissance
      of prod-webserver-01 would use service-account names matching the app stack, not a
      public wordlist. The dedicated-scanner ASN (loop 2) and the generic-wordlist scatter
      (loop 3) converge — this is not a targeted attack wearing scanner cover. Strongly
      refuted.
  ?credential-stuffing-external:
    weight: "--"   # rolled up from "-" at loop 2
    reasoning: >
      Both refutation conditions met: (1) 0.26/s steady sweep matches mass-scanner profile
      rather than the slow-drip credential-stuffing pace, (2) usernames are generic wordlist
      entries, not real-looking personal or email-prefix identifiers. Strongly refuted.
  ?compromise-followup:
    weight: "--"   # first assessment, refuted authoritatively
    reasoning: >
      Zero authentication_success (rule 5501/5715) events from 203.0.113.45 to
      prod-webserver-01 (or any host) across the full 30m preceding + 10m forward window.
      The adversarial refutation shape is directly met.
```

**Surviving hypotheses:** `?opportunistic-scanner` (++). All competing hypotheses refuted.

**Archetype fit check:** The `opportunistic-scanner` archetype requires the anchor (scanner-class source reputation + wordlist username scatter + mass-scanner rate + zero successes in forward window). All four conditions are confirmed by the combined evidence from loops 1–3. Archetype matches; 14 prior true_positive closures at this target with the same shape provide precedent.

**Trust-root check:** v-001 is external and has no accessible upstream — frontier has collapsed at the IP level. No additional leads can extend attribution.

**Next action:** CONCLUDE
- disposition: true_positive
- confidence: high
- matched_archetype: opportunistic-scanner
- rationale: ?opportunistic-scanner confirmed ++ with severe authoritative evidence (20 generic wordlist usernames, scanner ASN, 0.26/s rate, zero successful auth). All competing hypotheses refuted at --. v-001 is a trust-root. Frontier collapsed — no further lead can change the disposition.
- recommendation: verify firewall/fail2ban covers AS64496; no account-compromise risk (zero successful authentications in the forward window).
