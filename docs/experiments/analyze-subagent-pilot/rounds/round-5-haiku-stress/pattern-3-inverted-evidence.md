# ANALYZE (loop 3) — inverted evidence

**Evidence:**
- authentication-history-extended (l-005 wazuh): 47 attempts from 203.0.113.45 → prod-webserver-01 in 2026-04-12T09:11:47Z–09:14:51Z (3s window).
- Username scatter: **18 distinct usernames, 16 environment-specific** (webapp-deploy, appuser-01, appuser-02, webapp-ci, webapp-staging-deploy, prod-webserver-01-admin, nginx-reload, payment-svc, payment-svc-ci, inventory-svc, inventory-svc-ro, grafana-agent, sentry-relay, redis-sidecar, kafka-consumer, kafka-producer). Only 2 generic (admin, root).
- Attempt rate: 0.26/s (faster than credential-stuffing human-paced, consistent with automation).
- Forward-window result: **1 successful authentication (rule 5715) at 2026-04-12T09:18:42Z as `webapp-deploy`**, session duration 4m 12s before SIGTERM.
- Trust root: 203.0.113.45 is external; upstream forensics unavailable. Post-compromise pivot from `webapp-deploy` session is a new lead.

**Assessment:**

- `?opportunistic-scanner` (was `+`): `--` — **direct contradiction**. Opportunistic-scanner predicts ≥5 generic wordlist usernames (admin, root, ubuntu, pi, oracle, …) at wordlist pace. Observed: 16 of 18 usernames are environment-specific service accounts not present in public hydra/ncrack wordlists (payment-svc, inventory-svc, webapp-deploy, nginx-reload, redis-sidecar, kafka-*). Refutation pre-committed at HYPOTHESIZE loop 3: "if all usernames are generic wordlist → --opportunistic" (inverse holds: if all/most are env-specific → -- opportunistic). This hypothesis is definitively refuted.

- `?targeted-brute-force` (was `+`): `++` — **confirms core prediction and refutation of alternative**. Targeted-brute-force predicts environment-specific usernames matching the host's service inventory (webapp-*, appuser-*, deploy-*, svc-*) and sustained volume. Observed: 16 of 18 usernames precisely match prod-webserver-01's application stack (payment, inventory, webapp CI/staging, sentry, grafana, redis, kafka). Attempted refutation ("if no env-specific names present") explicitly failed. Successful `webapp-deploy` login within 4 minutes confirms post-brute-force compromise, not just attack infrastructure.

- `?credential-stuffing-external` (was `−`): `--` — **strengthened refutation on independent angle**. Credential-stuffing predicts lower attempt rate (human-paced, <0.1/s), breach-list personal/email-prefix usernames, and residential/VPN cover. Observed: attempt rate 0.26/s (matches mass-scanner profile, rejects human-paced); usernames are service account names (not personal identifiers or email prefixes); source is dedicated scanner infrastructure (not residential VPN). All three predictor classes failed.

- `?compromise-followup` (was `live`): `++` — **confirmed by direct evidence**. Adversarial hypothesis predicts at least one successful auth (5501/5715) from 203.0.113.45 in the forward window (≥10 min after the burst). Observed: 1 successful authentication at 09:18:42Z as `webapp-deploy`. Refutation ("zero 5501/5715 in forward window") failed. This hypothesis is **live and confirmed**; post-compromise pivot investigation is warranted.

**Surviving hypotheses:** `?targeted-brute-force` (++), `?compromise-followup` (++). Eliminated: `?opportunistic-scanner` (--), `?credential-stuffing-external` (--).

**Next action:** CONCLUDE — disposition `true_positive`, confidence `high`, matched_archetype `targeted-brute-force`. The investigation has saturated discrimination: environment-specific usernames + successful login unambiguously identify this as a targeted attack with confirmed compromise, not a scanner sweep. Post-compromise forensics (webapp-deploy session forensics, lateral movement, persistence checks) are out of scope for this alert; escalate to host forensics and active-response team.

---

## Self-report

**Context wished for:**
- Upstream forensics on 203.0.113.45 (geolocation, netblock history, ISP contacts) — flagged as scanner but origin/operator remains unknown.
- Breach list validation: were `webapp-deploy` credentials in a recent dump? (crediting hypothesis refinement if breach-list targeting, not pure reconnaissance.)
- Timeline correlation: any recon activity (DNS queries, port scans, service discovery) from 203.0.113.45 in the preceding 24–48 hours?

**Claims uncertain:**
- The successful `webapp-deploy` login was terminated by SIGTERM after 4m 12s — unclear whether attacker or automated session management. If attacker-initiated, likely low-risk command execution (no known post-auth payloads in typical SSH brute scenarios); if automated, suggests the credential is stale or restricted.
- "Deliberate cover" hypothesis for dedicated-scanner ASN (loop 2 reasoning) was not explored further; the environment-specific username targeting makes targeted-brute-force so dominant that cover-source attribution becomes secondary.

**Anomalies or inconsistencies in prior log:**
- Loop 2 assigned `?targeted-brute-force` a `+` with hedging ("ASN-type alone is a weak signal"), correctly noting that dedicated scanner infrastructure slightly *weakens* targeting. However, the discovery that usernames are environment-specific (not just "malicious IP") is a categorical shift from "weak signal" to "dominant prediction." Prior weight was appropriately conservative; final weight `++` is justified by the authentication-history evidence, not a reversal of the IP-reputation assessment.
- No inconsistency flagged, but note: the refutation of `?opportunistic-scanner` relies entirely on the username-scatter discovery. If the lead had failed (e.g., wazuh-query timeout), the investigation would remain ambiguous; mock hypothetical coverage of this ambiguity was not included in the prior loops (edge case, but worth noting for generalization).
