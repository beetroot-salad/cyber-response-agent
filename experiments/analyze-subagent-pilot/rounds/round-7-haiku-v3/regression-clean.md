# ANALYZE (loop 3, final)

**Evidence:**
- authentication-history-extended (wazuh): 20 distinct usernames observed across 47 attempts in 3m 4s burst at 0.26/s. Usernames: `admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible`. All match public wordlist defaults; zero environment-specific names (no `webapp-*`, `appuser-*`, or app-stack-specific accounts).
- Forward-window check (10 min after burst): zero successful logins (5501/5715) from 203.0.113.45 to any host.

**Assessment:**

- `?opportunistic-scanner`: `++` (was `+`) — username scatter confirms ≥5 distinct generic names on wordlist pace (0.26/s matches standard SSH scanner rate), reputation corroborated (GreyNoise mass-scanner tag), and attempted refutation (env-specific names absent) failed. Core prediction fully confirmed.

- `?targeted-brute-force`: `--` (was `+`) — core prediction requires environment-specific usernames (webapp-*, appuser-*, or deployment service accounts matching prod-webserver-01 stack). Zero env-specific names observed; all 20 are generic wordlist entries. Direct contradiction of core prediction.

- `?credential-stuffing-external`: `--` (was `-`) — core prediction is lower attempt rate (sub-0.05/s human-paced) and breach-list personal identifiers or email-prefix patterns, not public wordlist generics. Observed rate 0.26/s matches mass-scanner profile, not credential-stuffing. Usernames are purely generic wordlist (not personal/email-prefix). Direct contradiction on both rate and username profile.

- `?compromise-followup`: `--` (was live) — core prediction is successful SSH login from 203.0.113.45 in forward window. Zero successful logins observed in forward window (09:14:51Z → 09:24:51Z) or preceding 30 min on any host. Direct positive evidence refuting core prediction.

**Verdict:** Single archetype `opportunistic-scanner` at `++` confidence. All competing hypotheses refuted on direct positive evidence. Adversarial hypothesis refuted (no successful compromise observed). No discriminating follow-on lead would reduce uncertainty further.

**Routing:** CONCLUDE

**Disposition:** 
- **matched_archetype:** opportunistic-scanner
- **confidence:** ++
- **recommendation:** true_positive (zero compromise risk; external mass-scanner detected via signature match, hostname scatter, rate profile, and confirmed zero-success forward window)

---

## Self-report

**Context wished for:** None — lead output provided complete visibility into the burst (username list, rate, timing, forward window). Data quality was sound.

**Claims uncertain:** None — all four hypotheses were decisively graded on direct positive evidence from the authentication-history-extended lead. No ambiguity in username classification (all generic wordlist), rate classification (0.26/s → mass-scanner), or forward-window status (zero successful logins confirmed).

**Anomalies or inconsistencies:** None detected in prior investigation log. Loop 1 and loop 2 assessments were appropriately conservative (`+` on both `?opportunistic-scanner` and `?targeted-brute-force` pending username scatter). Loop 3 evidence cleanly discriminates them. Refutation shapes were pre-committed and apply correctly.

