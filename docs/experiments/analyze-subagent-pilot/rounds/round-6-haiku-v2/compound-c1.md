# ANALYZE (loop 3)

**Evidence:**
- authentication-history-extended (l-005): **FAILED — upstream indexer outage**. Wazuh indexer cluster health `yellow`, 2 of 4 shards unassigned for `wazuh-alerts-*`. Query timed out 504 Gateway Timeout on all 3 retry attempts. This is a **data availability gap**, not a "zero events" finding.
- No auth-history events recovered; no username scatter; no forward-window compromise-check possible from this lead.

**Assessment:**
- `?opportunistic-scanner`: `+` (was +) — remains consistent with dedicated scanner infrastructure + generic initial username in alert context, but full username-scatter confirmation deferred pending auth-history availability.
- `?targeted-brute-force`: `++` (was ++) — infrastructure evidence (purpose-built scanner ASN, no public DNS) remains strong. Attempted refutation (env-specific usernames absent) cannot be executed due to data gap. Grade held at `++` pending recovery of auth-history.
- `?credential-stuffing-external`: `−` (was −) — remains inconsistent with scanner-class hosting. Unchanged.
- `?compromise-followup`: live, unrefuted — forward-window check (5501/5715 from 203.0.113.45 in ≥10 min after burst) deferred pending auth-history recovery.

**Surviving hypotheses:** `?opportunistic-scanner` (+), `?targeted-brute-force` (++), `?credential-stuffing-external` (−), `?compromise-followup` (live).

**Routing decision:** HYPOTHESIZE

**Rationale for HYPOTHESIZE over CONCLUDE:**
1. The adversarial hypothesis (`?compromise-followup`) is retained live with explicit rationale: the forward-window check cannot be executed due to upstream data gap. Must remain live until checked.
2. The authentication-history lead is the decisive discriminator between `?opportunistic-scanner` and `?targeted-brute-force` on the username-scatter dimension, but failed due to infrastructure outage (not exhausted evidence). A discriminating follow-on lead exists: host-level SSH log inspection on prod-webserver-01 (`host_query` on `/var/log/auth.log`), which is independent of the indexer outage.
3. Routing gate criterion 4 fails: a materially discriminating lead (host-level logs or indexer recovery) remains available within budget.

**Selected lead:** host-level-ssh-logs (host_query on prod-webserver-01:/var/log/auth.log) — independent data path, bypasses indexer outage, recovers username scatter + attempt pacing + forward-window compromise check (SSHD successful-login events). Fallback: escalate with evidence from loops 1–2 if host access unavailable.

---

## Self-report

**Context wished for:**
- Host-level SSH log access on prod-webserver-01 to independently verify username patterns and forward-window for `?compromise-followup`.
- ETA on indexer shard recovery (flagged at 09:12Z, no operator update at time of analysis).

**Claims uncertain:**
- Whether env-specific usernames are present (required to differentiate `?targeted-brute-force` from `?opportunistic-scanner`). Current `++` on `?targeted-brute-force` is grounded in infrastructure evidence alone; username-scatter refutation cannot be attempted yet.
- Whether `?compromise-followup` occurred (forward-window check deferred).

**Anomalies or inconsistencies:**
- The upgrade of `?targeted-brute-force` from `+` to `++` in loop 2 rests on the claim that "sophisticated targeted adversaries prefer scanner ASNs to blend with noise" — this is an assumption, not a refutation proof. The claim is plausible but not load-bearing for a `++` under strict refutation semantics unless the alternative (dedicated scanner ASN would be *inconsistent* with opportunistic scanning) can be confirmed. The investigation log treats the absence of alternatives (no residential cover, no customer workloads in hosting) as equivalent to a refutation of the opportunistic hypothesis, which is a strong inference rather than a contradiction. Per the template, `++` requires a failed refutation attempt; the refutation shape for `?opportunistic-scanner` is "≤2 distinct usernames or env-specific names present." That check is still outstanding. Recommend holding `?targeted-brute-force` at `+` (infrastructure strongly consistent but not uniquely so) until username-scatter evidence resolves the discrimination — this would preserve conservative grading and trigger the host-level logs path without ambiguity.
