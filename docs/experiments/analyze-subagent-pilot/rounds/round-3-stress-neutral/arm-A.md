## ANALYZE (loop 3)

**Evidence (loop 3 — authentication-history-extended):**
- 47 events, 20 distinct usernames, 0.26/s, burst 09:11:47–09:14:51Z (3 min 4 s); no recurrence in preceding 30 min.
- Username list: `admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible` — all generic public wordlist entries; zero environment-specific names (`webapp-*`, `appuser-*`, `deploy-*` matching prod-webserver-01's app stack).
- Forward window (09:14:51–09:24:51Z): zero rule 5501/5715 events from 203.0.113.45 to prod-webserver-01 or any other host.

**Assessment (rollup):**

- `?opportunistic-scanner`: `++` (was `+`) — all three confirming checks passed and the pre-committed refutation attempt failed. (1) 20 distinct generic usernames ≥ 5-name wordlist threshold; (2) attempt rate 0.26/s consistent with standard SSH scanner automation, not human-paced credential stuffing; (3) username list matches public scanner tool default wordlists (hydra/ncrack/patator profile). Pre-committed refutation check: "≤2 names OR env-specific names present" — refutation failed; list is 20 wide and contains no env-specific names. `++` warranted.

- `?targeted-brute-force`: `--` (was `++`) — pre-committed refutation fires. The refutation shape from HYPOTHESIZE loop 3 was explicit: "if all usernames are generic wordlist entries with no environment-specific naming → `--`." That condition is met cleanly: all 20 usernames are generic defaults; zero names from the prod-webserver-01 application stack are present. The loop 2 upgrade to `++` was based on infrastructure characteristics (dedicated scanner ASN, no DNS history) — that evidence is consistent with both opportunistic and targeted infrastructure and does not survive a direct username-scatter refutation. Hypothesis eliminated.

- `?credential-stuffing-external`: `--` (was `-`) — two independent refutations now apply. (1) Attempt rate 0.26/s is far above the sub-0.05/s slow-drip profile of credential-stuffing tools designed to evade rate limits; (2) all 20 usernames are generic service/role accounts, not real-looking personal identifiers or email-prefix patterns characteristic of breach-list replay. Pre-committed refutation shape satisfied.

- `?compromise-followup`: `--` (was live) — pre-committed refutation fires cleanly. Zero rule 5501/5715 events from 203.0.113.45 in the forward window (09:14:51–09:24:51Z), and zero successful auths to any host in the full 40-min window. Adversarial hypothesis refuted by absence of forward evidence.

**Surviving hypotheses:** `?opportunistic-scanner` (`++`). All others eliminated.

**Next action:** CONCLUDE

- **Disposition:** true_positive
- **Confidence:** high
- **Matched archetype:** opportunistic-scanner
- **Grounding basis:** username scatter (20 generic wordlist names, zero env-specific), attempt rate (0.26/s), source IP classification (GreyNoise mass-ssh-scanner + dedicated scanner ASN), zero successful auths. 14 prior true_positive closures against prod-webserver-01 from external scanner-class ASNs provide strong precedent.

---

## Self-report

**Context wished for:**
- Threat-intel deep-lookup (lead l-003) timed out; campaign-attribution data was unavailable. In this case the authentication-history made it moot, but in a scenario where username scatter was ambiguous, the campaign-attribution lead would have been decisive and its absence would have been a real gap.
- The prior ticket cache (14 closures in 90 days) was referenced in CONTEXTUALIZE but the actual matched_ticket_id for grounding the CONCLUDE step was not included in the investigation log. To complete the resolution, a specific precedent snapshot ID from the `opportunistic-scanner` archetype directory would be needed to satisfy the two-leg resolution requirement.

**Claims uncertain:**
- The loop 2 upgrade of `?targeted-brute-force` to `++` was based on "dedicated scanner ASN + no DNS history = purpose-built attack infrastructure." This reasoning is weak: purpose-built scanner ASNs are the default for *opportunistic* mass-scanner operators, not a distinguishing mark for targeted campaigns. A targeted adversary provisioning infrastructure for a single named target would more likely use a VPN exit node or residential proxy to avoid bulk-scanner reputation lists. The `++` grade in loop 2 was logically inconsistent with the weight semantics (it claimed an attempted refutation failed, but no refutation attempt was documented — the log only notes "Refutation check considered: would residential/VPN hosting be more consistent? Concluded no"). That is not a documented refutation failure; it is an inline assertion that a refutation would not apply.
- The `?opportunistic-scanner` stall at `+` through loops 1 and 2 was appropriate (username scatter was the key missing evidence), but the log could have been clearer that the `+` was a ceiling-constrained holding grade pending auth-history, not a substantive disagreement with scanner hypothesis.

**Anomalies or inconsistencies noticed in the prior investigation log:**
- **Loop 2 `?targeted-brute-force` upgrade is inconsistent with refutation discipline.** The `++` grade requires both "confirms a core prediction AND an attempted refutation failed (name the check)." The loop 2 ANALYZE block names a refutation check in prose ("would residential/VPN hosting be more consistent?") but does not document a concrete prediction from the targeted-brute-force hypothesis that was tested and survived — it argues absence of a different infrastructure pattern rather than confirming a positive prediction of the targeted-brute-force model. This makes the `++` grade unjustified by the stated weight semantics. The correct grade at loop 2 exit for `?targeted-brute-force` should have been `+` (consistent-but-circumstantial), not `++`. The `--` reversal at loop 3 is still correct, but the path `++`→`--` in a single step (rather than `+`→`--`) overstates the certainty of the intermediate position and could mislead a human reviewer reviewing intermediate state.
- The CONTEXTUALIZE block notes `rule.firedtimes = 47` with a parenthetical correcting that this is a rule-level counter, not a per-source count. Loop 3 auth-history confirms 47 events in the window — a coincidence that is worth flagging as such, not as independent confirmation. The log does not conflate them, but a reviewer might.
