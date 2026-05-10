## ANALYZE (loop 3)

**Evidence (loop 3 — authentication-history-extended):**
- 47 events over 184 seconds (09:11:47 → 09:14:51Z); attempt rate 0.26/s — consistent with automated SSH wordlist scanner, well above the sub-0.05/s slow-drip typical of credential-stuffing tools.
- 20 distinct usernames: `admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible` — all generic public-service or role accounts matching the default wordlist profile distributed in hydra / ncrack / patator.
- Zero environment-specific names: no `webapp-*`, `appuser-*`, deploy accounts matching the prod-webserver-01 app stack.
- Forward window (09:14:51 → 09:24:51Z, 10 min): zero rule 5501/5715 successes from 203.0.113.45 to any host.
- Single discrete burst, no re-occurrence in the 30-min preceding window.

**Assessment (rollup-aware):**

- `?opportunistic-scanner`: `++` (was `+`)
  Promoted from `+`. Confirmed wordlist profile: ≥5 generic names (20 observed), all from publicly distributed wordlists. Attempted refutation (check for env-specific names) failed — zero environment-specific names found. Attempt rate 0.26/s is automation-consistent. All three pre-committed prediction dimensions satisfied simultaneously. Per the named `++` check: "confirmed wordlist profile AND attempted refutation failing" is met.

- `?targeted-brute-force`: `--` (was `+`)
  Pre-committed refutation condition met: "all usernames are generic wordlist entries with no environment-specific naming." The 20 distinct names include zero names matching `webapp-*`, `appuser-*`, `deploy-*` or any prod-webserver-01-specific account pattern. This is a direct contradiction of the core prediction for targeted-brute-force, which requires environment-aware username selection. Demoted to `--`.

- `?credential-stuffing-external`: `--` (was `-`)
  Two independent pre-committed refutation conditions are both met: (1) attempt rate 0.26/s matches mass-scanner profile, not the slow-drip rate of stuffing tools; (2) usernames are purely generic wordlist entries, not personal identifiers or email-prefix patterns. Demoted to `--`.

- `?compromise-followup`: `--` (adversarial — now explicitly refuted)
  Pre-committed refutation shape satisfied: zero rule 5501/5715 from 203.0.113.45 in the full forward window (09:14:51 → 09:24:51Z, 10 min). Extended check confirms zero successes to any host in the ±40-min window. Mandatory adversarial hold lifted; adversary did not achieve a foothold.

**Surviving hypotheses:** `?opportunistic-scanner` (++)

**Next action:** CONCLUDE

All three active-threat hypotheses are explicitly refuted at `--` by pre-committed checks. `?opportunistic-scanner` is elevated to `++` with a failed attempted refutation. No surviving alternative or adversarial hypothesis. Sufficient evidence for confident resolution.

---

## Self-report

### Context I wished I had
- The exact names of accounts in the prod-webserver-01 app stack (the env-specific account list) — I had to rely on the lead output's cross-lead note stating "zero names match environment-specific patterns," rather than independently verifying. The lead output stated this authoritatively so I accepted it, but in a live investigation I would want that list independently available.
- Confirmation that the 10-min forward window is sufficient given the burst-to-window ratio (burst was ~3 min; 10 min forward feels tight for an attacker who pauses and retries). The pre-commitment specified "≥10 min after the burst" so the check was satisfied, but the margin is narrow.
- The timeout on threat-intel-deep-lookup (loop 2) left campaign attribution unresolved. For the `++` promotion, I relied on the username-scatter check rather than campaign-attribution, which is the correct approach per the pre-commitments — but noting the gap.

### Pre-commitment items I actually used vs ignored
- **Used:** All four named refutation checks were applied directly and deterministically:
  - `?opportunistic-scanner` → `++`: confirmed wordlist profile AND attempted refutation (env-specific name check) failed. Fired.
  - `?targeted-brute-force` → `--`: all usernames generic, zero env-specific. Fired.
  - `?credential-stuffing-external` → `--`: rate matches mass-scanner AND usernames purely generic. Both conditions fired.
  - `?compromise-followup` → `--`: zero 5501/5715 from source IP in forward window. Fired.
- **Used:** Prior weights carried forward as specified (loop 2 → loop 3 entry: `+`, `+`, `-`, live). No re-derivation from scratch.
- **Used:** Adversarial status for `?compromise-followup` — held the mandatory live status until explicitly refuting it with `--` in this loop.
- **Ignored (not applicable):** The pitfall warning about targeted attackers mixing generic and env-specific names to blend — this was relevant if partial env-specific names appeared; the evidence showed zero env-specific names, so the pitfall did not soften the `--` conclusion.
- **Ignored (not applicable):** The pitfall about scanner reputation alone not confirming opportunistic — this was relevant to earlier loops. Loop 3 used username-scatter as the primary confirming evidence, not reputation.

### Claims I felt uncertain about
- Promoting `?opportunistic-scanner` to `++` rather than `+`: the pre-commitment explicitly defines `++` as "confirmed wordlist profile AND attempted refutation failing (check for env-specific names)." Both conditions are satisfied by the lead output, so the promotion is mechanically clean — but the `++` elevation feels strong given that threat-intel attribution was never recovered. I accepted the promotion per the pre-committed rules; flagging that a reviewer might want to note the attribution gap even at `++`.
- The `trust_root_reached: v-001` note in the lead output — this flags that forensic depth ends at the external endpoint. This is expected and does not affect the disposition, but it is a structural ceiling on evidence quality that I incorporated implicitly rather than calling out explicitly in the body of the ANALYZE block.
