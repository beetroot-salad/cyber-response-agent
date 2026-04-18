# ANALYZE (loop 3)

**Evidence:**
- authentication-history-extended (wazuh, 30 min preceding + 10 min forward on 203.0.113.45 → prod-webserver-01):
  - Preceding window (2026-04-12T08:44:03Z → 09:14:51Z): 47 events, 20 distinct usernames, 0.26/s attempt rate, steady sweep ~4s per username.
  - Distinct usernames: `admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible`. **All 20 are generic public-wordlist entries; zero environment-specific names matching prod-webserver-01's application stack.**
  - Forward-window (09:14:51Z → 09:24:51Z): query errored (HTTP 504 Gateway Timeout from wazuh.indexer; cluster health yellow, index rotation in progress). **Forward-window success/failure status is unknown, not zero.**

**Assessment:**

- `?opportunistic-scanner`: `++` (was `+`) — Core prediction confirmed: ≥5 distinct generic usernames at wordlist pace (20 names, 0.26/s). Attempted refutation (usernames ≤2 OR include env-specific names) failed decisively. Username list matches default public-wordlist profile (hydra/ncrack/patator). Upgraded to `++` on direct evidence.

- `?targeted-brute-force`: `-` (was `++`) — Refutation condition met: all usernames are generic wordlist entries with zero environment-specific naming. Targeted-brute-force predicts environment-aware account names (service accounts, deployment patterns, internal naming conventions). Evidence shows pure generic wordlist, inconsistent with target-aware reconnaissance. Downgraded from `++` due to direct contradiction of core prediction. Prior upgrade to `++` on "dedicated scanner ASN" was circumstantial; username pattern overrides infrastructure signal.

- `?credential-stuffing-external`: `-` (unchanged) — Attempt rate (0.26/s) and generic wordlist profile contradict credential-stuffing, which predicts real-looking personal/email-prefix identifiers and lower rate. Weakened further by username commonality.

- `?compromise-followup`: live (unchanged) — Forward-window check cannot be performed (indexer error, not data absence). Adversarial hypothesis retained; refutation impossible at this loop due to infrastructure gap. Alternative path available: host-level auth.log inspection via host_query.

**Surviving hypotheses:** `?opportunistic-scanner` (++), `?targeted-brute-force` (-), `?credential-stuffing-external` (-), `?compromise-followup` (live).

**Next action:** HYPOTHESIZE — Forward-window refutation of `?compromise-followup` is the blocking discriminant. Alternative paths: retry forward-window query after indexer cluster recovery, OR escalate to host_query for auth.log inspection on prod-webserver-01 (native 5501/5715 equivalents in forward window). Host query is more reliable given indexer volatility. After resolving forward-window gap, disposition becomes clear: true_positive → opportunistic-scanner, no compromise risk (all evidence points to zero successful logins).

---

## Self-report

**Context wished for:**
- Confirmation that the indexer timeout is transient (cluster health recovery timeline). If recovery is expected within loop budget, retry may be faster than host_query. If not, host_query is the clear next step.
- Clarification on "environment-specific names matching prod-webserver-01's application stack" — the investigation assumes the app stack is not a standard public web framework (no `tomcat`, `nginx` service accounts present in the wordlist). If the target runs Apache/Nginx/Tomcat, those generic names overlap with service accounts, weakening the env-specific refutation. Investigation should have listed the known service accounts beforehand.

**Claims uncertain:**
- The upgrade of `?opportunistic-scanner` from `+` to `++` is solid on username pattern alone, BUT the prior upgrade of `?targeted-brute-force` to `++` on "dedicated scanner ASN + no DNS history" is now reinterpreted. The infrastructure signal is real but was over-weighted; wordlist usage is a stronger discriminator. The two-step reasoning (ASN → ++, then wordlist → downgrade) is correct but the initial `++` may have been premature.
- Whether "zero environment-specific names" is a hard refutation or a weak signal depends on whether the attacker deliberately mixed public and private names to evade detection. Investigation pre-committed to env-specific absence as refutation shape, which is reasonable but assumes attackers don't counter-measure. This is valid but worth noting.

**Anomalies or inconsistencies:**
- Loop 2 upgraded `?targeted-brute-force` from `+` to `++` on infrastructure alone (no username evidence yet), citing "sophisticated targeted adversaries prefer scanner ASNs to blend with noise." This reasoning is sound but leans heavily on an assumption about attacker operational security. Loop 3 evidence contradicts this via direct username pattern, showing the infrastructure signal was necessary but not sufficient. The downgrade to `-` is appropriate, but the initial `++` suggests the refutation bar for loop 2 may have been set too low (circumstantial infrastructure alone should stay `+`, pending username pattern).
- Forward-window check is unknown, but the preceding-window evidence is so clear (20 generic names, mass-scanner rate) that the adversarial hypothesis is now very weakly supported. However, per instructions, adversarial hypotheses remain live until explicitly refuted, so holding it at "live" is correct pending the host_query alternative.

**Routing compliance:**
- One hypothesis graded `++` (opportunistic-scanner) ✓
- No `--` grades issued ✓
- Adversarial hypothesis retained live with explicit rationale (indexer gap prevents direct refutation; alternative path available) ✓
- Discriminating follow-on lead identified (host_query on auth.log for forward-window success/failure) ✓
- Gate condition on follow-on leads: "No discriminating follow-on lead would materially reduce uncertainty" — fails. Host_query directly resolves the forward-window gap and would confirm or refute `?compromise-followup`. Route HYPOTHESIZE per gate.
