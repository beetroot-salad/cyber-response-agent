## HYPOTHESIZE (loop 1)

**ASSESS verdict:** borderline no / yes. SCREEN already ran the volume-count discriminator (6 events in 5min, 2 distinct usernames). Post-SCREEN, the next obvious lead is `process-lineage` on v-001 — same query regardless of which classification is live. The fork opens on a reading of the parent chain (is this chain "sanctioned", "bait", or "anomalous"?), which is interpretation-vulnerable. Strictly speaking this is a GATHER case with lead-level predictions; a HYPOTHESIZE block is ceremonial but defensible if kept lean.

**Stress-test expectation:** the subagent should recognize the mostly-mechanical character of the next step and output 2–3 lean one-hop hypotheses (no narrative), a single lead, and put the discriminating judgment in pre-registered lead-level `predictions`.

**Active hypotheses (minimal):**

- `?sanctioned-probe` (h-001) — proposed parent `{type: process, classification: sanctioned-monitoring-probe}` attached upstream of v-001 via `runs_on`. Predicts (p1): parent chain of the SSH client invocations is a scheduled monitoring invocation (cron / systemd-timer → probe script → ssh). Weight: null.

- `?unsanctioned-process` (h-002) — proposed parent `{type: process, classification: unsanctioned}` attached upstream of v-001 via `runs_on`. Predicts (p1): parent chain is not a scheduled monitoring invocation AND is not `monitoring_bait.sh`. Weight: null. Covers operator-mistake + adversary-controlled + bait-triggered-by-adversary — splits via hierarchical IDs after process-lineage resolves the parent.

- `?compromise-followup` (h-003, adversarial) — attached to a hypothetical forward `authenticated_as` edge from v-001 → target-endpoint. Predicts (p1): ≥1 5501/5715 event from 172.22.0.10 to target-endpoint within T+10min after the alert. Weight: null. Different anchor, so resolved by a different lead.

**Note on consolidation vs. the pre-consolidation draft:** `?bait-workload` is folded into `?unsanctioned-process` at this hop. The bait script is unsanctioned-by-classification for an SSH-invalid-user alert (it's an evaluation workload, not a monitoring workload), and process-lineage alone cannot distinguish "bait legitimately triggered by an operator" from "bait triggered by an adversary who knows the workload exists." That distinction is a refinement of h-002 via child IDs, not a parallel hypothesis at the same hop.

**Selected lead:** composite — `process-lineage` on v-001 (discriminates h-001 vs. h-002) + `authentication-history` forward-window T→T+10min on srcip=172.22.0.10 (resolves h-003). Same entity, independent queries.

**Lead-level `predictions` (pre-registered readings on interpretive fields of process-lineage):**

- `lp1`: parent chain = `cron`/`systemd-timer` → sanctioned probe script → ssh client, AND no interactive shell in ancestry — `read_as` h-001 supported.
- `lp2`: parent chain contains interactive shell (bash/zsh/sh with TTY attached), unknown binary, or a non-cron scheduler not in the sanctioned inventory — `read_as` h-002 supported; `advance_to` session-audit (who opened the shell?) or HYPOTHESIZE to split h-002 into operator-mistake vs. adversary-controlled.
- `lp3`: parent chain contains `monitoring_bait.sh` — `read_as` h-002 supported; `advance_to` HYPOTHESIZE to split h-002-01 (operator triggered bait) vs. h-002-02 (adversary triggered bait) — disambiguated by whether the bait invocation correlates with a documented evaluation run or an anomalous session.

**Pitfalls:**

- `?sanctioned-probe`: a sanctioned cron chain does not by itself refute adversary-control on a compromised host (attacker could inject into cron). Cadence verification is a separate discipline from lineage classification; weight cap at `+` from lineage alone.
- `?unsanctioned-process`: "anomalous" is a judgment call — always pre-register (lp2) before running the lead, not after.
- `?compromise-followup`: absence within the 10-min window refutes within the investigation's horizon only, not forever.

**Why no further splits at this hop:** retry-stuck vs. enumeration-misconfigured for h-001, and operator-mistake vs. adversary-controlled vs. bait-triggered-by-adversary for h-002, are all candidates for hierarchical decomposition *after* process-lineage confirms the parent. Splitting upfront would add predictions the current lead cannot discriminate.
