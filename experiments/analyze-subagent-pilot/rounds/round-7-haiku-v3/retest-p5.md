# ANALYZE (loop 3 — authentication-history-extended result)

**Evidence received:**
- 47 attempted SSH auths from 203.0.113.45 to prod-webserver-01, 2026-04-12T09:11:47Z–09:14:51Z
- **19 distinct usernames: 14 generic wordlist (admin, root, ubuntu, pi, oracle, postgres, deploy, user, test, guest, operator, mysql, git, jenkins) + 5 environment-specific (webapp-deploy, appuser-01, payment-svc, inventory-svc, nginx-reload)**
- Attempt rate 0.26/s (consistent with automation)
- Zero successful auths in forward window (09:14:51Z–09:24:51Z)

**Assessment:**

- `?opportunistic-scanner` — `+` (was `+`) — pure mass-scanner hypothesis weakened: an unmodified public wordlist would not include prod-webserver-01-specific service names (webapp-deploy, payment-svc, etc.). The presence of 5 env-specific names means either (a) a customized/hybrid wordlist seeded with leaked/reconnaissance names, or (b) opportunistic scanning at this particular host using a broader list. Both scenarios remain consistent with opportunistic-scanner behavior. Does NOT meet `++` bar because the naming pattern is not diagnostic: refutation would require 100% generic names; presence of env-specific names is expected in a customized wordlist. **Remain at `+`** — consistent but not uniquely diagnostic.

- `?targeted-brute-force` — `+` (was `+`) — the env-specific names (5/19) constitute weak support for targeted knowledge. However, 74% generic wordlist entries undermine the targeted hypothesis: a targeted actor with prior recon would carry primarily env-specific names, not a majority generic-wordlist baseline. The pattern (generic names + smaller set of app-specific names) is more consistent with a hybrid/customized opportunistic wordlist than with targeted reconnaissance. **Remain at `+`** because sibling `?opportunistic-scanner` also passed its individual refutation check (no clean refutation on evidence), so evidence is not discriminating. Both siblings earn `+` per rule 23. If we downgraded targeted to `-` solely on "fewer env-specific names than expected," we'd be over-applying absence-of-anomaly reasoning — the presence of env-specific names is positive evidence toward targeted, even if circumstantial.

- `?credential-stuffing-external` — `−` (was `−`, unchanged) — credential-stuffing usernames are real-looking personal/email patterns (john_smith, jane.doe, admin@example.com) or breach-list replay. These 19 names are all generic service/system names or obvious app-service names. Zero breach-list signature or personal identifier pattern. Remains refuted.

- `?compromise-followup` — `−` (was live, no evidence yet) — forward-window check complete: zero successful auth (5501/5715) from 203.0.113.45 in the 10-minute forward window, and zero successful auth from 203.0.113.45 to any host in the full 40-minute window. **Grade `−`** — the hypothesis predicts at least one successful login from the source in the forward window. Absence of successful auth is direct positive evidence (login logs are always recorded). This is not a data gap (query succeeded, zero results). **Rationale:** the core prediction is "an attempt succeeded, establishing a foothold." The evidence is "no successful auth logged." This is refutation by direct positive evidence (presence of login logs + zero matches), not by absence. Grade `−`.

**Surviving hypotheses:** `?opportunistic-scanner` (+), `?targeted-brute-force` (+), `?compromise-followup` (−).

**Routing gate assessment:**

- Gate 1: "Exactly one hypothesis is graded `++`, OR all `+` hypotheses share a single archetype and disposition." — TWO `+` hypotheses (`?opportunistic-scanner`, `?targeted-brute-force`) survive; they do NOT share a single archetype (opportunistic-scanner → true_positive/no-compromise; targeted-brute-force → true_positive/potential-prior-recon; different disposition branches). **GATE FAILS.** Must route HYPOTHESIZE.

- Evidence supports continued investigation: username composition (mixed generic + env-specific) remains ambiguous. A discriminating lead would resolve whether the env-specific names are (a) pre-baked in a popular hybrid wordlist (opportunistic signal) or (b) harvested via reconnaissance (targeted signal).

**Next action:** HYPOTHESIZE — recommend a follow-up lead to discriminate sibling hypotheses. Options:
  1. **app-stack-recon-timeline:** check whether a reconnaissance burst (DNS lookups, port scans, HTTP enum) from 203.0.113.45 preceded this SSH attempt by minutes to hours. If yes, supports targeted-brute-force; if no, supports opportunistic-scanner.
  2. **wordlist-provenance-check:** query threat-intel for whether the 19-name set matches a known public hybrid wordlist (e.g. rockyou + app-specific extensions). If yes, opportunistic; if no or unknown, targeted gains credibility.

Fallback if no further leads available: escalate with **`?opportunistic-scanner`** as leading hypothesis (flagged source, generic-wordlist base, zero successes) and escalate for manual disposition review due to env-specific name presence and prior-ticket precedent (14 opportunistic-scanner closures at this target in 90 days).

---

## Self-report

**Context wished for:**
- Whether threat-intel deep-lookup will be retried or time-out persists. Campaign attribution would strongly discriminate targeted vs. opportunistic.
- Whether app-stack-recon-timeline is feasible in this environment (DNS query logs, netflow, or IDS alerts preceding the SSH burst).

**Uncertain claims:**
- Grade of `?compromise-followup` as `−` rather than `--`: I assigned `−` because absence of login records *is* positive evidence (the logging infrastructure succeeded and returned zero results), and this directly contradicts the hypothesis's core prediction. However, the specification warns against "refutation by absence of anomaly." Here the anomaly we're checking for (presence of a login record) is logged deterministically for all auth attempts. This crosses the line from absence-of-anomaly (e.g., "no rotation detected" or "no alert spike") to absence-of-expected-record in a complete log. I believe `−` is justified, but flagging for review.

**Anomalies / inconsistencies in prior log:**
- None detected. The investigation progressed logically: cheap source-classification lead first, fallback dns-passive when threat-intel timed out, then decisive username-history lead. The mixed username composition is a genuine data pattern, not a logging error or query misalignment.

**Data-gap flags:**
- threat-intel-deep-lookup timeout unresolved; campaign attribution unavailable. If threat-intel latency spikes are expected during peak hours, recommend retry or escalate to out-of-band threat-intel review.
