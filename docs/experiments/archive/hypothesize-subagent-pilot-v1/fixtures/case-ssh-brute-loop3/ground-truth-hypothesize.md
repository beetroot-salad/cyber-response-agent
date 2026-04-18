## HYPOTHESIZE (loop 3)

**ASSESS verdict:** no / yes. Loop 2's ANALYZE already committed the next lead to `authentication-history-extended` — the same lead regardless of which classification is live. One query resolves all four hypotheses. The discriminating signal (username-list shape) is interpretation-vulnerable ("generic wordlist" vs. "env-specific" has a grey middle). This is structurally a GATHER with lead-level `predictions`, not HYPOTHESIZE.

**Stress-test expectation:** the subagent should recognize this as ceremonial HYPOTHESIZE and produce a minimal block — four one-hop hypotheses rolled forward with their weights, the selected lead named with pre-registered readings on the interpretive fields, and NO elaborate hypothesis narrative.

**Active hypotheses (rolled forward minimally):**

- `?opportunistic-scanner` (h-001, `+`) — proposed parent `{process, classification: opportunistic-mass-scanner}`. Predicts (p1): username list in the attempt burst is generic-wordlist-shaped (≥5 distinct, all from standard SSH wordlists).
- `?targeted-brute-force` (h-002, `+`) — proposed parent `{process, classification: targeted-actor}`. Predicts (p1): ≥1 environment-specific account name in the username list.
- `?credential-stuffing-external` (h-003, `-`) — proposed parent `{process, classification: credential-stuffing-tool}`. Predicts (p1): real-looking personal-identifier username shape, low volume (<5 distinct).
- `?compromise-followup` (h-004, adversarial, live) — attached to a hypothetical forward `authenticated_as` edge from v-001 → v-002. Predicts (p1): ≥1 5501/5715 event from 203.0.113.45 to prod-webserver-01 in T+10min.

**Selected lead:** `authentication-history` extended — single query, data.srcip=203.0.113.45 AND agent.name=prod-webserver-01, window T−30min to T+10min. Returns: username list, attempt timing/volume, any 5501/5715 events in the T to T+10min sub-window.

**Lead-level `predictions` (pre-registered readings on the interpretive username-profile field):**

- `lp1`: ≥5 distinct usernames all matching standard SSH wordlist entries (admin, root, ubuntu, pi, oracle, test, …) with no env-specific names, attempt rate consistent with automation — `read_as` h-001 supported (→ `++`); h-002 refuted (→ `--`); h-003 refuted (→ `--`).
- `lp2`: ≥1 username matching env-specific naming patterns for prod-webserver-01 (service accounts, deployment accounts, web-app-specific shapes) mixed with or instead of generic names — `read_as` h-002 supported (→ `+` or `++` per volume); h-001 weakened.
- `lp3`: 1–3 distinct usernames, real-looking personal-identifier or email-prefix shape, low volume — `read_as` h-003 partial recovery; h-001/h-002 weakened.
- `lp4`: forward-window sub-query returns ≥1 5501/5715 event — h-004 confirmed (→ `++`); immediate escalation regardless of lp1–lp3.
- `lp5` (fallback): ambiguous mix of generic + env-specific names (e.g., exactly 2 env-like names among 20 generics) — `read_as` does-not-discriminate; `advance_to` HYPOTHESIZE to refine h-001 vs. h-002 via a secondary lead (e.g., targeted reconnaissance artifacts on the target host preceding T).

**Pitfalls:**

- Treat `rule.firedtimes = 47` as a rule-level counter, not a per-source count.
- Env-specific names can arise from public web-app fingerprinting without internal recon — presence weakens h-001 but does not alone confirm h-002 to `++`.
- The 10-min forward-window bound is pragmatic; a slow-burn successful compromise later would not appear here.

**Why the block is deliberately sparse:** all the interpretive work is pre-registered at the lead level (lp1–lp5). The hypotheses themselves carry only their one-hop predicted attribute. This is the correct shape when one lead resolves all hypotheses — elaborate per-hypothesis narrative would be ceremonial padding.
