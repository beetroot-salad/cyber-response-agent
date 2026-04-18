# ANALYZE (loop 3) — authentication-history-extended

**Evidence:**
- authentication-history-extended (wazuh query on 203.0.113.45 → prod-webserver-01, rule 5710): 47 failed login attempts over 3 seconds using 18 distinct usernames. Window start 09:11:47Z, end 09:14:51Z. Attempt rate 0.26/s (consistent with automation but fast).
- **Username composition:** 16 of 18 are environment-specific service accounts matching prod-webserver-01 application stack (webapp-deploy, appuser-01, appuser-02, payment-svc, inventory-svc, kafka-producer, redis-sidecar, grafana-agent, nginx-reload, prod-webserver-01-admin, etc.). Only 2 are generic wordlist entries (admin, root).
- **Forward-window result:** one successful authentication (rule 5715) at 09:18:42Z from 203.0.113.45 as user `webapp-deploy`, session duration 4m 12s before SIGTERM. No other successful logins from this source.
- **Cross-lead consistency:** username list is not a public scanner wordlist (hydra, ncrack default). Service account names are application-stack specific, indicating prior reconnaissance or configuration knowledge.

**Assessment:**

- `?opportunistic-scanner`: `--` (was +) — core prediction was ≥5 distinct generic usernames at wordlist pace. Evidence directly contradicts: 16 of 18 usernames are environment-specific service accounts, not public wordlist entries. A mass-scanner sweeping via generic SSH wordlists would not produce this distribution. **Direct positive evidence of inconsistency.** Hypothesis refuted.

- `?targeted-brute-force`: `++` (was ++) — core predictions confirmed: (1) environment-specific usernames present (webapp-deploy, appuser-01, payment-svc, etc., matching this host's stack); (2) sustained volume consistent with directed activity (47 attempts in 3 seconds, focused on a single target); (3) successful compromise of a legitimate service account (`webapp-deploy`) immediately following the burst. Refutation check (attempted): would absence of env-specific usernames indicate opportunistic? Refutation failed — evidence shows precisely the env-specific pattern targeted attackers would produce. Sustained at `++`.

- `?credential-stuffing-external`: `-` (was -) — hypothesis predicts breach-list personal/email-prefix usernames and lower attempt rate. Evidence contradicts: usernames are application-stack service accounts (not personal identifiers), and attempt rate (0.26/s) is faster than typical credential-stuffing slow-drip. Weakly refuted; held at `-`.

- `?compromise-followup`: `++` (live → confirmed) — core prediction: any 5501/5715 from 203.0.113.45 in the forward window. **Direct positive evidence:** successful rule 5715 event at 09:18:42Z as `webapp-deploy`. Hypothesis confirmed. This is not an archetype hypothesis but a refutation check; included for completeness.

**Surviving hypotheses:** `?targeted-brute-force` (++), `?opportunistic-scanner` (--), `?credential-stuffing-external` (-), `?compromise-followup` (++).

**Routing decision: CONCLUDE**

Gate check:
- Exactly one hypothesis graded `++` (targeting archetype decision)? Yes — `?targeted-brute-force` at `++`. (`?compromise-followup` is also `++` but is a refutation check, not an archetype choice.)
- All `--` grades justified by direct positive evidence, not absence? Yes — `?opportunistic-scanner` contradicted by environment-specific username composition, confirmed by independent lead.
- Adversarial hypothesis refuted or retained live? Refuted on direct positive evidence — successful compromise confirmed by rule 5715.
- Discriminating follow-on lead available? No — authentication history has resolved all archetype discrimination and the forward-window check.

**Conclusion:**
- `matched_archetype`: `targeted-brute-force`
- `disposition`: true_positive + compromised (successful auth confirmed)
- `confidence`: high — evidence chain is complete and unambiguous.

---

## Self-report

**Context wished for:**
- Post-compromise forensics: The `webapp-deploy` session lasted 4m 12s before SIGTERM. What did the attacker do during this window? (This is outside loop 3 scope; would inform severity assessment but does not change archetype or disposition.)
- Reconnaissance precursors: Was there a preceding recon burst (HTTP scanning, port sweeps, config disclosure) from 203.0.113.45 or the same ASN? (Would strengthen the "prior reconnaissance" claim in the targeted-brute-force narrative.)

**Claims uncertain:**
- How the attacker obtained the environment-specific service account names (webapp-deploy, payment-svc, etc.) is not determined. Possibilities: prior public disclosure of the stack, reconnaissance from an earlier compromise, social engineering, or inference from the hostname pattern. The evidence supports targeted activity but not the reconnaissance source.

**Anomalies and inconsistencies noted:**
- Loop 2 graded `?targeted-brute-force` at `++` based on "dedicated scanner ASN is characteristic of purpose-built attack infrastructure for targeted campaigns." This reasoning conflates infrastructure ownership with attacker intent. A dedicated scanner ASN is ambiguous — it hosts many scanning clients, some malicious, some research. The upgrade to `++` at loop 2 was justified on the refutation logic ("refutation failed" if residential/VPN would be more consistent), but the bar for `++` requires confirming a *core prediction*, not merely ruling out alternatives. The evidence at loop 2 (dedicated scanner ASN, no DNS presence) was consistent but circumstantial; the `++` grade was premature by the stated semantics. Loop 3 evidence (environment-specific usernames) properly justifies `++` by confirming the core prediction of "targeted reconnaissance yielding env-specific names." The final conclusion is sound, but the rollup-path `++` (was +) at loop 2 may have been overweighted; the evidence chain would have been stronger stated as `+` → `++` (loop 2 → loop 3) rather than claiming `++` entered loop 3.
- Loop 1 graded `?credential-stuffing-external` at `-` on the basis of "dedicated scanner ASN is inconsistent with credential-stuffing infrastructure." This reasoning is sound for infrastructure profile, but loop 1 did not have username evidence yet. At loop 3, the `-` is now supported by direct username contradiction; the logic is cleaner.

**No blocking inconsistencies detected. Conclusion stands.**
