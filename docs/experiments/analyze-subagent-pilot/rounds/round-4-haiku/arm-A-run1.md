# ANALYZE (loop 3 — Arm A, run 1)

## Hypothesis Assessment

**`?opportunistic-scanner`** — `++` (was `+`)

The new evidence from authentication-history-extended provides direct confirmation of core predictions:
- **Username scatter check:** 20 distinct usernames observed, all matching default public wordlist profiles (admin, root, ubuntu, postgres, jenkins, tomcat, nagios, etc.). Zero environment-specific names (no `webapp-*`, `appuser-*`, or app-specific deploy accounts). ✓ Confirms ≥5 generic names.
- **Attempt rate:** 0.26/s is consistent with automated mass-scanner pace; directly contradicts human credential-stuffing pacing.
- **Attempted refutation (forward window):** No successful auth from 203.0.113.45 in the 10-min forward window. Refutation check for `?compromise-followup` passes.
- **Cross-correlation:** Reputation data (GreyNoise mass-ssh-scanner tag, dedicated scanner ASN) + DNS (no historical DNS presence, scanner-research hosting) + auth-history (wordlist profile, no env specificity, high rate) converge on opportunistic-scanner infrastructure.

Moved to `++` because the username-scatter refutation (all-generic vs env-specific) was the pre-committed anchor discriminator and it conclusively supports the hypothesis.

---

**`?targeted-brute-force`** — `--` (was `+`)

Explicit refutation by the auth-history evidence:
- **Core prediction failure:** Targeted attackers typically mix generic cover names with environment-specific reconnaissance (service account names matching the prod-webserver-01 stack: `webapp-deploy`, `appuser-01`, etc.). Zero env-specific names observed.
- **Pre-committed refutation shape:** "all usernames are generic wordlist entries with no environment-specific naming" → `--`. This condition is met.
- **Rate inconsistency with targeted model:** At 0.26/s, the burst is consistent with mass-scanner automation. Targeted attacks on a specific host typically sustain lower, more deliberate rates to avoid alerting.

Moved to `--` because the refutation condition (absence of env-specific names in a 20-name sample from a 47-attempt burst) directly contradicts the targeting hypothesis.

---

**`?credential-stuffing-external`** — `--` (was `-`)

Further refutation by auth-history:
- **Pre-committed refutation shape:** "attempt rate matches mass-scanner profile OR usernames are purely generic wordlist entries" → `--`. Both conditions apply.
- **Username profile mismatch:** Credential-stuffing relies on breach-list personal identifiers (email prefixes, real names) or known-compromise pairs. The observed list is purely generic service/role names (postgres, jenkins, tomcat, www-data, mysql, nagios, hadoop, ansible) — the opposite of breach-list replay.
- **Rate confirmation:** 0.26/s rate is mass-scanner-class, not the sub-0.05/s drip typical of credential-stuffing tools hiding in background noise.

Moved to `--` (from `-`) because the identity profile confirmation + rate evidence together provide a second independent refutation angle beyond the reputation data.

---

**`?compromise-followup`** — `--` (was live)

Refutation by forward-window check:
- **Core prediction:** Any successful auth (5501/5715) from 203.0.113.45 in the 10-min forward window.
- **Result:** Zero successful authentications from 203.0.113.45 to prod-webserver-01 AND zero to any other host in the preceding 30-min + forward 10-min window.
- **Refutation confidence:** Complete; no successful SSH auth from this source was recorded.

Moved to `--` because the mandatory forward-window check (the only way to confirm or refute this adversarial hypothesis in the absence of compromise) returned zero events.

---

## Summary

**Surviving hypotheses:** `?opportunistic-scanner` only (all others refuted with `--`).

**Confidence:** High. The opportunistic-scanner hypothesis is corroborated by:
1. Reputation data (GreyNoise scanner tags, dedicated ASN)
2. DNS infrastructure (scanner-research, no customer workloads)
3. Username profile (20 generic service/role names matching default wordlists)
4. Attempt rate (0.26/s, consistent with automation)
5. Forward-window check (no successful auth despite 47 attempts)

All three competing hypotheses are explicitly refuted by the auth-history evidence against their core predictions.

---

## Next Action

**CONCLUDE**

- **Disposition:** `true_positive` — confirmed opportunistic mass-SSH-scanner, no successful authentication, zero compromise risk.
- **Matched archetype:** `opportunistic-scanner` (aligns with 14 prior scanner-class closures against prod-webserver-01; strong precedent base).
- **Confidence:** High (all major hypotheses refuted except opportunistic; username scatter and rate provide direct confirmation).

---

## Self-report

### Context and Certainty

**Well-grounded:** The auth-history evidence (20 distinct usernames, 0.26/s rate, zero successful auth, no re-occurrence in 30-min window, no forward-window compromise) is sufficient and specific. The refutation shapes (env-specific names for targeted; breach-list names for credential-stuffing; zero successes for compromise-followup) are all met or decisively unmet.

**No gaps:** The lead selection (authentication-history-extended with 30-min preceding + 10-min forward) was precisely designed to discriminate these three competing hypotheses and check the adversarial hypothesis. All four hypotheses now have conclusive assessments.

### Anomalies or Inconsistencies Noticed

None. The investigation proceeded cleanly through three loops:
1. Loop 1: Reputation data shaped initial weights (opportunistic and targeted tied at `+`; credential-stuffing at `-`).
2. Loop 2: DNS and hosting-type data reinforced reputation without moving weights (scanner infrastructure confirmed, no residential signature).
3. Loop 3: Auth-history decisively refuted targeted and credential-stuffing hypotheses by their core predictions (env specificity, rate profile, username identity); confirmed opportunistic-scanner.

The pre-committed refutation shapes in the loop-3 HYPOTHESIZE block matched the evidence perfectly, avoiding post-hoc weight rationalization.

### Hypothesis Consistency

Prior investigation discipline was sound:
- Adversarial hypothesis (`?compromise-followup`) was maintained as live until the forward-window check ran — good practice.
- Refutation shapes were pre-committed at loop-3 HYPOTHESIZE (before GATHER), preventing post-hoc reasoning.
- The two `+` hypotheses at loop 2 were not collapsed prematurely; loop 3 evidence provided the discriminator both needed.

