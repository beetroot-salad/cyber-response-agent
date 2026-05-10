## CONTEXTUALIZE

**Alert:** SEC-2026-0412 — wazuh-rule-5710 (sshd: Attempt to login using a non-existent user)
**Source entity:** 203.0.113.45 (srcip) — external, not in any internal range or approved monitoring list
**Target entity:** prod-webserver-01 (10.0.1.10) — production public-facing web application VM
**Key observables:**
- `data.srcuser` = `admin`
- `data.srcip` = `203.0.113.45` — classified external per `ip-ranges.md`
- `data.srcport` = 51880
- `agent.name` = `prod-webserver-01`
- `timestamp` = 2026-04-12T09:14:03.221Z
- `rule.firedtimes` = 47 (rule-level counter, NOT per-source attempt count — needs real auth-history lookup)
**Playbook hypotheses:** ?legitimate-automation (preliminary: external source, disqualified), ?opportunistic-scanner, ?targeted-brute-force, ?credential-stuffing-external, ?compromise-followup (adversarial, always active)
**Available leads:** source-classification (ip-reputation), authentication-history (wazuh), threat-intel-deep-lookup, dns-passive-lookup, recent-alert-correlation
**Archetype matches:** opportunistic-scanner (strong candidate — external + SSH + high attempt rate, but needs username-scatter + reputation confirmation); targeted-brute-force (possible — requires env-specific username evidence); credential-stuffing-external (possible — requires breach-list username profile + lower rate); credential-stuffing / monitoring-probe (disqualified — external source, not in approved-monitoring-sources)
**Data environment:** ip-reputation + wazuh + dns-reputation READY; threat-intel known to have latency spikes during peak hours
**Ticket-context:** 14 prior SSH brute-force true_positive closures against prod-webserver-01 in the past 90 days, all from external scanner-class ASNs — strong archetype precedent for opportunistic-scanner resolution at this target

## SCREEN

**Result:** no_match
**Leads run:**
- approved-monitoring-sources: 203.0.113.45 → **not in table** (external; no approved-monitoring entry). Anchor refuted preliminarily.
**Outcome:** falling through to HYPOTHESIZE — external IP cannot match any benign-source archetype; requires full investigation to discriminate opportunistic vs targeted vs credential-stuffing.

## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?opportunistic-scanner` — an automated mass-scanner sweeping many hosts using a generic SSH wordlist. Not targeting prod-webserver-01 specifically; this host appears in the scanner's IP range scope. Predicts ≥5 distinct generic usernames (admin, root, ubuntu, pi, oracle, …) at wordlist pace, source IP flagged in reputation feeds. Disposition if confirmed: true_positive → no compromise risk (zero successes), firewall/fail2ban hygiene.

- `?targeted-brute-force` — an adversary with prior reconnaissance of this server attempting environment-aware credential guessing. Predicts usernames include environment-specific account names (service accounts matching the web app, deployment service accounts, internal naming patterns like `webapp-deploy` or `appuser-01`) and attempt volume sustained over an extended window. Disposition if confirmed: true_positive + potential prior-recon concern → investigate deeper for preceding recon activity.

- `?credential-stuffing-external` — breach-list credential replay against SSH, testing known compromised (username, password) pairs. Predicts usernames are real-looking personal identifiers or email-prefix patterns (not generic admin/root; not env-specific service names) and attempt rate is lower than mass-scanner (human-paced to evade rate limiting). Disposition if confirmed: true_positive + check whether any matching account exists and may need password reset.

- `?compromise-followup` (adversarial — mandatory) — one of these attempts, or a successor attempt, is followed by a successful SSH login from the same source. Refutation shape: no 5501/5715 from 203.0.113.45 in the forward window (≥10 min after the burst).

**Selected lead:** source-classification (ip-reputation) — cheap, discriminates scanner-infrastructure (supports `?opportunistic-scanner`, weakens `?credential-stuffing-external` which prefers residential/VPN cover) from residential/VPN IPs (supports `?credential-stuffing-external`).

**Predictions:**
- `?opportunistic-scanner`: ≥5 generic usernames in wordlist scatter, source IP flagged in GreyNoise/Shodan/AbuseIPDB as scanner, attempt rate consistent with automation (≥0.1/s)
  - *Pitfalls:* scanner reputation alone does not confirm opportunistic — a targeted attacker may deliberately use flagged IPs for cover
- `?targeted-brute-force`: env-specific usernames present (not purely generic), sustained volume, possibly lower rate than mass-scanner
  - *Pitfalls:* targeted attackers may mix generic and env-specific names to blend in; absence of env-specific names is the key refutation
- `?credential-stuffing-external`: real-looking personal/email-prefix usernames, lower attempt rate, residential/VPN source IP
  - *Pitfalls:* credential-stuffing and opportunistic-scanner both rely on automation; the discriminator is username profile (generic wordlist vs personal identifiers), not just volume
- `?compromise-followup`: any successful auth from 203.0.113.45 in the forward window; absence is refutation

---

## ANALYZE (loop 1)

**Evidence:**
- source-classification (ip-reputation lookup on 203.0.113.45): flagged in GreyNoise as `mass-ssh-scanner`, `port-scanner`, `ssh-brute` with 20 months of continuous scanning activity. ASN = AS64496 Scanner-Hosting-Inc. Last seen scanning 2026-04-12.

**Assessment:**
- `?opportunistic-scanner`: `+` — corroborated by reputation tags; a known mass-SSH-scanner on a dedicated scanner ASN matches the `?opportunistic` profile. Not `++` yet — reputation is circumstantial without username-scatter confirmation.
- `?targeted-brute-force`: `+` — malicious IP classification is consistent with targeted use, but a dedicated scanner ASN is a weak signal for targeting (targeted attackers typically prefer non-flagged cover). IP reputation alone cannot discriminate targeted from opportunistic. Weight held at `+` pending auth-history.
- `?credential-stuffing-external`: `-` — dedicated scanner ASN is inconsistent with credential-stuffing infrastructure, which relies on non-flagged residential or VPN IPs to avoid blocking. Weakened by source classification.
- `?compromise-followup`: live, no evidence yet (forward-window check not run at this loop).

**Surviving hypotheses:** `?opportunistic-scanner` (+), `?targeted-brute-force` (+), `?credential-stuffing-external` (−), `?compromise-followup` (live).

**Next action:** HYPOTHESIZE — threat-intel deep-lookup or dns-passive would discriminate scanner-infrastructure from general-purpose hosting and resolve opportunistic vs targeted.

---

## HYPOTHESIZE (loop 2)

**Selected lead:** threat-intel-deep-lookup (campaign attribution) — would resolve whether 203.0.113.45 is associated with targeted campaigns (supports `?targeted-brute-force`) or indiscriminate scanning (supports `?opportunistic-scanner`). Fallback: dns-passive-lookup if threat-intel times out.

## GATHER (loop 2 — executed)

- **l-003 `threat-intel-deep-lookup`** (threat-intel API, 203.0.113.45 --campaigns --associations): **FAILED — timeout**. External threat-intel API has known latency spikes during peak hours; lead not recovered in-band.
- **l-004 `dns-passive-lookup`** (dns-reputation, 203.0.113.45 reverse + ASN + 90-day passive history): recovered successfully.
  - reverse_dns: null
  - asn_org: "Scanner-Hosting-Inc — dedicated scanner/research hosting, no customer workloads"
  - hosting_type: dedicated-scanner-infrastructure
  - passive_dns_names: [] (no domains historically resolved to this IP)

---

## ANALYZE (loop 2)

**Evidence:**
- threat-intel deep-lookup failed (timeout); campaign-attribution evidence unavailable.
- dns-passive: 203.0.113.45 hosted on a dedicated scanner-research ASN with no customer workloads and no historical DNS presence.

**Assessment:**
- `?opportunistic-scanner`: `+` (unchanged) — dedicated scanner infrastructure is consistent but not confirming; still waiting on username-scatter from auth-history.
- `?targeted-brute-force`: `++` (upgraded from `+`) — the dedicated scanner ASN combined with the absence of DNS history is highly characteristic of purpose-built attack infrastructure, which targeted campaigns routinely provision. The combination of "no public service presence" and "scanner-class hosting" is strong evidence this IP was stood up for directed activity against a known target; prod-webserver-01 is a named production asset, making it a plausible target. Refutation check considered: would residential/VPN hosting be more consistent with targeted? Concluded no — sophisticated targeted adversaries prefer scanner ASNs to blend with noise. Refutation failed; `++` warranted.
- `?credential-stuffing-external`: `-` (unchanged) — confirmation from independent angle (scanner-research ASN, no residential signature).
- `?compromise-followup`: live, not yet checked.

**Surviving hypotheses:** `?opportunistic-scanner` (+), `?targeted-brute-force` (++), `?credential-stuffing-external` (−), `?compromise-followup` (live).

**Next action:** HYPOTHESIZE — authentication-history-extended is now the decisive lead. Username scatter and attempt pacing will discriminate opportunistic (≥5 generic names, wordlist rate) from targeted (env-specific names) from credential-stuffing (breach-list personal names, lower rate). This is also the lead that checks the forward window for `?compromise-followup`.

---

## HYPOTHESIZE (loop 3)

**Selected lead:** authentication-history-extended (wazuh) — 30 min preceding + 10 min forward on data.srcip:203.0.113.45 AND agent.name:prod-webserver-01, rule:5710. Captures full burst + forward window for `?compromise-followup`.

**Predictions at loop 3 entry** (rolled forward from earlier loops, no re-commitment):
- `?opportunistic-scanner`: ≥5 distinct generic usernames at wordlist pace, zero successful logins
- `?targeted-brute-force`: env-specific names present (webapp-*, appuser-*, deploy-*, or similar matching the prod-webserver-01 stack), sustained volume. *Note: at `++` entering loop 3, an attempted refutation (env-specific names absent) would be required to downgrade.*
- `?credential-stuffing-external`: real-looking personal/email-prefix usernames, lower attempt rate
- `?compromise-followup`: any 5501/5715 from 203.0.113.45 in the forward window

**Refutation shapes** (pre-committed):
- `?opportunistic-scanner` → `--` if usernames are ≤2 names or include env-specific names (not wordlist)
- `?targeted-brute-force` → `--` if all usernames are generic wordlist entries with no environment-specific naming
- `?credential-stuffing-external` → `--` if attempt rate matches mass-scanner profile OR usernames are purely generic wordlist entries
- `?compromise-followup` → `--` if zero 5501/5715 from 203.0.113.45 in the forward window
