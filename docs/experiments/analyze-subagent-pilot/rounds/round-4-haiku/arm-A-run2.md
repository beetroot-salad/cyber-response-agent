# Arm A — Run 2 — ANALYZE (loop 3, terminal)

## ANALYZE

**Evidence (loop 3 GATHER):**
- authentication-history-extended on 203.0.113.45 → prod-webserver-01, rule 5710, time window 2026-04-12T08:44:03Z → 09:24:03Z
  - 47 authentication attempts, 20 distinct usernames, attempt rate 0.26/s (mass-scanner profile)
  - Username profile: `admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible`
  - All 20 names match default public scanner wordlists; zero environment-specific names (no `webapp-*`, `appuser-*`, or prod-webserver-01 stack-specific accounts)
  - Forward window (09:14:51Z → 09:24:51Z): zero successful authentications (5501/5715) from 203.0.113.45 to any host

**Assessment:**

- `?opportunistic-scanner`: `++` (was `+`) — Core prediction confirmed: ≥5 distinct generic usernames at wordlist pace from mass-scanner IP. Refutation check (evidence of environment-specific or targeted naming, or credential-stuffing slow-drip rate) failed completely. All three discriminators align: dedicated scanner infrastructure (loop 1 ip-reputation), zero DNS history / scanner-research ASN (loop 2), pure generic wordlist username profile with mass-scanner attempt rate (loop 3). Disposition clear: true_positive, no compromise risk.

- `?targeted-brute-force`: `--` (was `+`) — Pre-committed refutation triggered: all usernames are generic wordlist entries with zero environment-specific naming. A targeted attacker with prior reconnaissance would predict or discover prod-webserver-01 stack accounts; the complete absence of such names refutes this hypothesis conclusively.

- `?credential-stuffing-external`: `--` (was `-`) — Pre-committed refutation triggered: attempt rate (0.26/s) matches mass-scanner automation, not credential-stuffing's sub-0.05/s slow-drip profile. Username profile is purely generic public service accounts (breach-list credential-stuffing would expect personal names, email prefixes, or real user identifiers). Double refutation confirms exclusion.

- `?compromise-followup`: `--` (was live) — Pre-committed refutation check: zero successful authentications (5501/5715) from 203.0.113.45 in the 10-minute forward window (09:14:51Z → 09:24:51Z) and zero successes to any host in the full 40-minute window. Hypothesis refuted: no post-burst successful login follows from this source.

**Surviving hypotheses:** None. All four hypotheses resolved. `?opportunistic-scanner` is the only confirmed archetype.

**Disposition decision:** CONCLUDE

- **matched_archetype:** opportunistic-scanner
- **confidence:** high (all discriminating evidence aligned, three independent refutation checks confirmed)
- **recommendation:** true_positive — no compromise risk (zero successful logins). Routine firewall/fail2ban hygiene sufficient.

---

## Self-report

**Context wished for:**
- None material. The investigation had clear path: ip-reputation → dns-passive (infrastructure type confirmation) → authentication-history (username discriminator + forward-window check). Each step narrowed the hypothesis space.

**Claims uncertain:**
- None. The evidence is deterministic:
  - Dedicated scanner ASN + scanner reputation is unambiguous (loop 1).
  - Scanner-research ASN with no customer workloads is unambiguous (loop 2).
  - 20-name generic wordlist profile vs environment-specific naming is unambiguous (loop 3).
  - Attempt rate (0.26/s) vs credential-stuffing profile (sub-0.05/s) is unambiguous (loop 3).
  - Zero successful logins in forward window is unambiguous (loop 3).

**Anomalies or inconsistencies:**
- None detected. The pre-committed refutation shapes (Section "Refutation shapes" in HYPOTHESIZE loop 3) predicted the exact discriminators observed:
  - `?targeted-brute-force` → `--` if all usernames generic ✓
  - `?credential-stuffing-external` → `--` if usernames purely generic wordlist ✓
  - `?compromise-followup` → `--` if zero forward-window successes ✓
  - `?opportunistic-scanner` → `++` if ≥5 generic names AND refutation attempts fail ✓
  
All weights follow deterministically from the evidence and pre-commitment contract.

**Refutation discipline integrity:**
- The investigation applied the contracted refutation checks at loop 3 GATHER:
  1. Username scatter: observed 20 names, all generic, zero environment-specific (refutes `?targeted-brute-force` and `?credential-stuffing-external`).
  2. Attempt rate: 0.26/s is consistent with mass-scanner, not credential-stuffing (refutes `?credential-stuffing-external`).
  3. Forward-window success check: zero 5501/5715 from 203.0.113.45 (refutes `?compromise-followup`).
  4. IP reputation + infrastructure consistency: dedicated scanner ASN matches opportunistic profile (supports `?opportunistic-scanner`).
  
The discipline was followed consistently; terminal disposition is warranted.
