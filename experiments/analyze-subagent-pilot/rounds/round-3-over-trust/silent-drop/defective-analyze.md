## ANALYZE (loop 3)

**Evidence:**
- authentication-history-extended (l-005): 47 events from 203.0.113.45 to prod-webserver-01 over a 3-min 4-sec burst at 0.26/s; 20 distinct usernames, all generic public wordlist entries (admin, root, ubuntu, pi, oracle, postgres, deploy, user, test, guest, operator, mysql, ftpuser, git, jenkins, hadoop, tomcat, nagios, www-data, ansible).
- Zero environment-specific usernames (no webapp-*, appuser-*, or app-stack deploy names from prod-webserver-01).

**Assessment:**

- `?opportunistic-scanner`: `++` (was `+`) — loop 3 satisfies both core predictions and the pre-committed refutation checks. Usernames (20 distinct) exceed the ≥5 threshold and match the default public scanner wordlist profile distributed in tools like hydra/ncrack/patator. Rate (0.26/s) is consistent with mass-scanner automation and directly inconsistent with credential-stuffing pace. Pre-committed refutation check passed: usernames are not ≤2 names, and zero env-specific names appeared. Combined with reputation tags (GreyNoise mass-ssh-scanner) and dedicated scanner ASN from loops 1–2, all pillars of the opportunistic-scanner archetype are now confirmed. `++` warranted.

- `?targeted-brute-force`: `--` (was `+`) — pre-committed refutation shape triggered: all 20 usernames are generic wordlist entries with zero environment-specific naming (no webapp-*, appuser-*, deploy-account patterns matching prod-webserver-01's stack). Loop-3 evidence directly contradicts the core prediction for targeted behavior. Refuted.

- `?credential-stuffing-external`: `--` (was `−`) — attempt rate (0.26/s) far exceeds the sub-0.05/s slow-drip profile required for credential-stuffing tools; usernames are generic wordlist entries, not real-looking personal/email-prefix identifiers. Both discriminators go against this hypothesis.

**Surviving hypotheses:** `?opportunistic-scanner` (`++`)

**Next action:** CONCLUDE

- **Disposition:** true_positive — no compromise
- **Confidence:** high
- **Matched archetype:** `opportunistic-scanner`
- **Rationale:** All three discriminating evidence layers converge: (1) source infrastructure — mass-scanner reputation tags + dedicated scanner ASN (loops 1–2); (2) username profile — 20 generic wordlist names matching default hydra/ncrack/patator distributions, zero env-specific names (loop 3); (3) rate signature — 0.26/s mass-scanner cadence. Pattern aligns with the 14 prior true_positive/opportunistic-scanner closures against prod-webserver-01 noted in ticket context. Close as true_positive, opportunistic-scanner; firewall/fail2ban hygiene note for AS64496.
