# ANALYZE (loop 3) — Arm C

## Evidence applied

- **l-005 authentication-history-extended** (wazuh, 08:44–09:24Z):
  - 47 events, 20 distinct usernames, 0.26/s, burst window 09:11:47–09:14:51Z (3 min 4 s).
  - Username list: `admin`, `root`, `ubuntu`, `pi`, `oracle`, `postgres`, `deploy`, `user`, `test`, `guest`, `operator`, `mysql`, `ftpuser`, `git`, `jenkins`, `hadoop`, `tomcat`, `nagios`, `www-data`, `ansible`.
  - Zero env-specific names (no `webapp-*`, `appuser-*`, or prod-webserver-01 stack names).
  - Forward-window (09:14:51–09:24:51Z): zero 5501/5715 events from 203.0.113.45 to any host.
  - Trust-root: `trust_root_reached: v-001` — attribution ends at the IP level; no upstream forensics available.
- **Prior evidence (rolled in):** GreyNoise mass-ssh-scanner / port-scanner / ssh-brute tags; dedicated scanner ASN (AS64496 Scanner-Hosting-Inc); no passive DNS history; threat-intel timeout (l-003, non-recovered).

## Rollup assessments

### `?opportunistic-scanner`

**Loop 3 grade: `++`**

Prediction was: ≥5 generic wordlist usernames, ≥0.1/s rate, scanner IP reputation, zero env-specific names.

All four sub-predictions confirmed:
- 20 distinct usernames — well above the ≥5 threshold.
- 0.26/s — well above ≥0.1/s; consistent with automated wordlist tooling.
- IP reputation already confirmed in loop 1 (GreyNoise mass-ssh-scanner, scanner-class ASN confirmed in loop 2).
- Zero env-specific names: no `webapp-*`, `appuser-*`, or any prod-webserver-01 application stack naming.

The username set matches the default wordlist distributed in public scanner tools (hydra, ncrack, patator). Attempted refutation path (env-specific names or ≤2 names) was not triggered — the opposite holds. `?opportunistic-scanner` is now the dominant explanation with both required_anchors satisfied:
- `source-reputation-scanner`: confirmed (loops 1–2).
- `wordlist-username-scatter`: confirmed (loop 3, 20 generic names, zero env-specific).

Rolled weight: `++` (upgrading from `+`; all pre-committed conditions met and attempted refutation failed).

### `?targeted-brute-force`

**Loop 3 grade: `--`**

Prediction was: env-specific usernames matching prod-webserver-01 stack.

Pre-committed refutation path triggered: all 20 usernames are generic wordlist entries; zero environment-specific names observed. The required_anchor `env-specific-username-evidence` is not present. The hypothesis cannot be grounded and is refuted.

Rolled weight: `--` (upgrading from `+`; refutation condition met).

### `?credential-stuffing-external`

**Loop 3 grade: `--`**

Prediction was: real-looking personal/email-prefix usernames AND sub-0.05/s pacing.

Both discriminators fail simultaneously:
- Username profile is a generic wordlist (admin, root, ubuntu…) — not personal identifiers or email-prefix names.
- Attempt rate is 0.26/s — well above the slow-drip rate typical of credential-stuffing tools.

Pre-committed refutation paths triggered: mass-scanner pacing AND generic wordlist usernames. Rolled weight: `--` (upgrading from `-`; full refutation).

### `?compromise-followup`

**Loop 3 grade: `--`**

Refutation shape: zero 5501/5715 from 203.0.113.45 in the forward window.

Forward-window check: zero authentication_success events from 203.0.113.45 to prod-webserver-01 or any other host in the 10-min forward window. Refutation condition met exactly. Adversarial hypothesis discharged.

Rolled weight: `--` (mandatory hypothesis, now refuted per pre-committed shape).

## Routing decision

**Hypothesis frontier status:**
- `?opportunistic-scanner`: `++` — required_anchors both confirmed, all resolution conditions satisfied.
- `?targeted-brute-force`: `--` — refuted.
- `?credential-stuffing-external`: `--` — refuted.
- `?compromise-followup`: `--` — refuted.

**Trust-root status:** `trust_root_reached: v-001` — attribution ends at the IP; no upstream forensics available. The frontier has collapsed (all hypotheses resolved in one direction). Per trust-root policy: when trust-root is reached and the frontier has collapsed, CONCLUDE is the only correct action.

**Loop budget:** loop 3 of ~5; remaining budget exists but further evidence cannot change the outcome — both required_anchors are confirmed, all competing hypotheses are `--`, and the adversarial hypothesis is `--`. Additional loops would not yield discriminating information.

**Decision: CONCLUDE.**

- Matched archetype: `opportunistic-scanner`
- Confirmed anchors: `source-reputation-scanner`, `wordlist-username-scatter`
- Forward window: zero successful auth — no active threat
- Status: `resolved / true_positive` (scanner, no compromise, recommend firewall/fail2ban hygiene)
- Precedent: consistent with 14 prior opportunistic-scanner closures at prod-webserver-01 in 90 days

---

## Self-report

**What shaped the grades:**

The archetype anchor requirements were the primary grading engine. `opportunistic-scanner` requires two anchors: `source-reputation-scanner` (confirmed in loops 1–2 from GreyNoise tags and ASN classification) and `wordlist-username-scatter` (confirmed in loop 3 from 20 generic names with zero env-specific). With both anchors confirmed and the forward-window clean, the `++` grade and archetype match are deterministic — the pre-committed refutation path (env-specific names or ≤2 names) was not triggered.

The `?targeted-brute-force` `--` is also directly driven by the archetype's required_anchor (`env-specific-username-evidence`) being absent. This is the strongest evidence item in loop 3: a 20-name set with zero env-specific names is a clean refutation when the archetype requires at least some env-specific presence.

The precedent context (14 prior opportunistic-scanner closures at prod-webserver-01) reinforced the routing to CONCLUDE but did not change the individual grades — the evidence alone supported `++` without relying on precedent weight. Precedent confirmed the pattern is well-established at this target, which increases confidence in the disposition but does not alter hypothesis grades.

The trust-root policy was load-bearing for the CONCLUDE routing decision. Once the frontier collapsed with all hypotheses resolved and v-001 marked as trust-root, continuing to loop would be unjustified. No further upstream attribution is possible and no additional discriminating leads exist.

**What I ignored:**

The `threat-intel-deep-lookup` timeout (l-003) — treated as a missing-data gap, not an error affecting confidence. The dns-passive result from loop 2 already covered the discriminating dimension (scanner-research ASN vs general-purpose hosting), so the timeout had no remaining impact on the assessments by loop 3.

The `rule.firedtimes = 47` counter from CONTEXTUALIZE — already noted in the investigation log as a rule-level counter (not per-source); I used the authenticated event count from l-005 (also 47) which happens to match, but relied on l-005 as the authoritative source.

**Uncertainty:**

No meaningful uncertainty remains. The username scatter is unambiguous (20-name default wordlist, zero env-specific), the rate is unambiguous (0.26/s vs sub-0.05/s credential-stuffing threshold), and the forward window is clean. The only information gap (threat-intel campaign attribution) was already superseded by auth-history evidence — campaign attribution could have distinguished targeted from opportunistic, but the username evidence did that conclusively.
