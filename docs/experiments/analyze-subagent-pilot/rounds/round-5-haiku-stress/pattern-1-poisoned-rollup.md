# ANALYZE (loop 3)

**Evidence:**
- authentication-history-extended: 203.0.113.45 → prod-webserver-01 over 2026-04-12T09:11:47Z → 09:14:51Z. 47 attempts, 20 distinct usernames, 0.26/s attempt rate.
- Username list: `admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible` — all public-facing role accounts, matches default public scanner wordlists.
- Zero environment-specific usernames (no webapp-*, appuser-*, app-specific deploy names).
- Forward-window check (09:14:51Z → 09:24:51Z): zero successful authentications (5501/5715) from 203.0.113.45 to any host.
- Burst shape: steady sweep at ~4s intervals between usernames, single discrete event (3m 4s total), no re-occurrence earlier in 30-min preceding window.
- Attempt rate 0.26/s is consistent with mass-scanner automation; inconsistent with credential-stuffing sub-0.05/s evasion pacing.

**Assessment:**

- `?opportunistic-scanner` (was `+`): **`++`** — username scatter (20 distinct public-wordlist role names, zero environment-specific patterns) confirms a core prediction of opportunistic-scanner behavior. The attempt rate (0.26/s), burst shape (steady sweep), and absence of re-occurrence all match mass-scanner characteristics. Refutation check: would targeted behavior look similar? No — targeted attackers would study the target environment and use application-aware account names (missing here). Refutation failed. This is a decisive confirmation.

- `?targeted-brute-force` (was `++`): **`--`** — the username list is purely generic wordlist entries with zero environment-specific patterns. A targeted attacker with prior reconnaissance would attempt to use environment-aware account names specific to prod-webserver-01's stack (e.g., app service accounts, deployment users). The complete absence of such names directly contradicts a core prediction of targeted-brute-force. This is a core refutation. Downgraded from `++` to `--`.

- `?credential-stuffing-external` (was `-`): **`--`** — attempt rate (0.26/s) is inconsistent with credential-stuffing infrastructure, which profiles as sub-0.05/s to evade rate limiting. Additionally, usernames are generic common-service names (admin, root, postgres), not the real-looking personal identifiers or email-prefix patterns predicted by credential-stuffing. Remains `--`.

- `?compromise-followup` (adversarial, was live): **`--`** — forward-window check shows zero successful authentications from 203.0.113.45 to prod-webserver-01 and zero to any other host across the entire 40-min window. Core refutation condition met: no evidence of successful login following or during the burst. Refutation complete.

**Surviving hypotheses:** `?opportunistic-scanner` (++).

**Confidence:** High. All hypotheses except opportunistic-scanner have been directly refuted via pre-committed refutation shapes (username scatter for targeted, attempt rate + wordlist profile for credential-stuffing, forward-window success check for compromise-followup). The opportunistic-scanner matches all observable evidence and passes the attempted refutation (would environment-specific names be present? no). Archetype precedent supports this disposition (14 prior true_positive closures against prod-webserver-01 from external scanner ASNs in past 90 days).

**Recommended action:** CONCLUDE with disposition `true_positive`, matched_archetype `opportunistic-scanner`, confidence `high`.

---

## Self-report

### Context wished for
- None identified at this decision point. The lead output provides complete username enumeration, sufficient forward-window coverage (10 min post-burst), explicit attempt-rate measurement, and cross-consistency confirmation (wordlist profile matches known scanner distributions).

### Claims uncertain
- None. The refutation discipline is satisfied: each downgraded hypothesis (targeted-brute-force, credential-stuffing-external, compromise-followup) has been directly contradicted by explicit evidence (zero environment-specific names, attempt rate incompatible with credential-stuffing pacing, zero successful auth).

### Anomalies or inconsistencies noticed
- **Loop 2 grading anomaly:** The prior loop upgraded `?targeted-brute-force` from `+` to `++` based on the reasoning that "sophisticated targeted adversaries prefer scanner ASNs to blend with noise." This claim lacks empirical grounding. The prompt template specifies `++` requires confirmation of *both* a core prediction AND a failed attempted refutation. The DNS evidence (no public service presence, scanner-class hosting) did not confirm a prediction specific to targeted-brute-force (which would be env-specific usernames); it was circumstantial on IP sourcing. The `++` assignment appears to have pre-judged the outcome without committing to explicit refutation criteria in advance. Loop 3 confirms the error: the username scatter immediately revokes the `++` via direct contradiction of the core targeting-specific prediction.

- **Refutation-discipline correction:** The prior `?targeted-brute-force: ++` should have been held at `+` pending auth-history username scatter. The upgrade used reasoning about attacker infrastructure preferences rather than evidence discriminating target-aware behavior, which is load-bearing for this hypothesis. This is not a substantive investigation error (the conclusion is correct), but a grading inconsistency under the stated semantics: `++` requires an *attempted* refutation to have failed, not a forward-reasoning speculation about attacker tradecraft.

