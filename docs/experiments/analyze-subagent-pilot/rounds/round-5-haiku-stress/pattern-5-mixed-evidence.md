# ANALYZE (loop 3)

**Evidence:**
- authentication-history-extended (wazuh, 30 min preceding + 10 min forward, 203.0.113.45 → prod-webserver-01): 47 attempts across 19 distinct usernames, attempt rate 0.26/s, zero forward-window successes (5501/5715), no successful auth from this source to any host in the window.
- Username composition: 14/19 (74%) are generic public-wordlist entries (admin, root, ubuntu, pi, oracle, postgres, deploy, user, test, guest, operator, mysql, git, jenkins); 5/19 (26%) are environment-specific names matching the prod-webserver-01 application stack (webapp-deploy, appuser-01, payment-svc, inventory-svc, nginx-reload).

**Assessment:**

- `?opportunistic-scanner` (was `+`): `-` — The 26% environment-specific username presence contradicts the core prediction of a pure mass-scanner carrying only public-wordlist entries. An opportunistic scanner running an unmodified public wordlist should yield ≥95% generic names. This is a direct contradiction of the opportunistic hypothesis's discriminating refutation shape ("refutation if ≤2 names OR include env-specific names"). The hypothesis has not been ruled out entirely—it remains possible that the scanner was customized post-deployment or seeded with reconnaissance data—but the weakness is now substantive, not circumstantial.

- `?targeted-brute-force` (was `+`): `+` (unchanged) — The presence of 5/19 environment-specific names (26%) is consistent with a targeted attacker who researched the prod-webserver-01 application stack. However, the 74% padding with public-wordlist entries is unusual for a pure targeted breach. Targeted attackers typically avoid noise. The mixed signature could reflect deliberate masking to reduce signal, or could reflect a less-skilled attacker blending automated tooling with manual reconnaissance. Not elevated to `++` because the strategy is plausible but not confirmed.

- `?credential-stuffing-external` (was `-`): `-` (unchanged) — Neither the username profile (dominated by service account names and generic wordlist entries, not personal identifiers or email-prefix patterns) nor the attempt rate (0.26/s, consistent with mass-scanner, not human-paced) matches credential-stuffing predictions. The dedicated scanner ASN from loop 2 independently corroborates this refutation.

- `?compromise-followup` (was live): `--` — The forward-window check (10 min after the burst ended) returned zero successful authentications (5501/5715) from 203.0.113.45 to any host. The core prediction—"any successful auth from 203.0.113.45 in the forward window"—has been directly refuted. This hypothesis is eliminated.

**Surviving hypotheses:** `?opportunistic-scanner` (−), `?targeted-brute-force` (+), `?credential-stuffing-external` (−), `?compromise-followup` (−−, eliminated).

**Next action:** CONCLUDE — Evidence has eliminated three hypotheses and substantially weakened the fourth (opportunistic-scanner). The targeted-brute-force hypothesis remains consistent with the mixed username evidence and is supported by two anchors: (1) environment-specific names present in the attempt set, and (2) no successful breach (consistent with unmatched password guessing, even by a knowledgeable attacker). Confidence is moderate—the 74% generic-wordlist padding introduces ambiguity about intent. Matched archetype: `targeted-brute-force`. Grounding: the precedent of 14 prior SSH brute-force true_positive closures against prod-webserver-01 from external scanner ASNs in the past 90 days establishes strong archetype precedent, though the mixed username composition in this event is anomalous relative to past closures (which, as external scanners, would likely have carried higher generic-name concentration). Recommend escalating with the mixed username observation as a flag for analyst review: this attack pattern does not perfectly match the archetype closure history and warrants validation against the forward-window success/failure data.

---

## Self-report

**Context wished for:**
- Historical username-composition data for the 14 prior SSH brute-force closures against prod-webserver-01: if those were pure opportunistic scanners, we would expect ≥95% generic names. A second-order analysis comparing this event's 74% generic-name ratio against historical closures would resolve whether the mixed signature represents a genuine behavioral anomaly or a known variant.
- Reverse WHOIS or threat-actor-profile data on the dedicated scanner ASN (AS64496 Scanner-Hosting-Inc): is this ASN used by targeting infrastructure, or exclusively by commodity scanning operations? The loop-2 DNS evidence ("no customer workloads") is reassuring but incomplete.

**Claims uncertain:**
- The interpretation of "environment-specific names deliberately mixed with wordlist entries as masking" (targeted-brute-force hypothesis) vs. "a customized opportunistic scanner seeded with reconnaissance" (variant of opportunistic-scanner). Both are mechanically plausible given the mixed username composition. The 74/26 split alone does not discriminate between them without additional intent signals (e.g., are the env-specific names in any particular order? are they clustered temporally? are they retried more frequently than generic names?).
- Whether the lack of forward-window success (zero 5501/5715 events) should be weighted as strong evidence against compromise-followup, or simply as "no evidence of success *yet*" — a narrower forward window (10 min) might miss a delayed lateral movement or a second wave of attempts from the same source using a different service port.

**Anomalies or inconsistencies noticed:**
- Loop 1 assigned `?targeted-brute-force` a weight of `+` based solely on "malicious IP classification is consistent with targeted use," explicitly noting the dedicated scanner ASN weakens the signal. Loop 2 maintained `+` with identical reasoning ("dedicated scanner ASN slightly weakens targeted but does not refute it; deliberate cover remains possible"). This is reasonable caution, but the reasoning was not robust to the hypothesis refutation shape pre-committed in loop 3 ("refutation if all usernames are generic wordlist entries with no environment-specific naming"). The hypothesis held at `+` despite having a clear, measurable refutation threshold that was not actually tested until loop 3. This is a timing issue, not a grading error—the refutation was sound once evidence arrived—but it reflects incomplete hypothesis lifecycle documentation in the earlier loops.
- The assessment of `?opportunistic-scanner` → `-` in this block (loop 3) may be slightly harsh. The refutation shape stated "refutation if ... include env-specific names," and we have exactly that: 26% of the username set. However, the hypothesis is not `--` because the possibility of a customized scanner remains non-negligible. The weight `-` appropriately captures "consistent with refutation, but not a direct logical contradiction." This is sound.
