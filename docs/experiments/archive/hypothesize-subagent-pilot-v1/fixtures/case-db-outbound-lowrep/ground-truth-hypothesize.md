## HYPOTHESIZE (loop 1)

**ASSESS verdict:** yes / yes. Multiple plausible upstream explanations; the single discriminating lead (`process-execution-context`) returns outcome fields (callsite, ancestry, concurrent-SQL correlation) whose reading is interpretation-vulnerable ("anomalous" vs. "merely unusual" context).

All three hypotheses attach upstream of `e-001` (the `connect()` edge from `prod-db-03` to `45.77.192.41` at T) via `opened` — the proposed parent vertex is a process on `v-001` (prod-db-03) running under uid=postgres. Classifications differ; predicted attributes are features of that process's syscall context.

**Active hypotheses:**

- `?vendor-telemetry` (h-001) — proposed parent `{type: process, classification: sanctioned-telemetry-client}`. Predicts (p1): the `connect()` was issued by the main `postgres` process (no fork), from a callsite inside a known vendor-telemetry library path (`libpq` telemetry module, or an enterprise-build telemetry thread), with recurring cadence across the 90-day window once retention is extended to confirm. Refutation shape (r1): connect originated from a child process of postgres, OR callsite is not in a vendor-published telemetry code path, OR this is the only such connect in the retention window (no cadence). Weight: null.

- `?extension-driven-callout` (h-002) — proposed parent `{type: process, classification: extension-triggered-egress}`. Predicts (p1): the `connect()` was issued from within a postgres backend process, with an extension trampoline visible in the call context (plpython, plperl, dblink, postgres_fdw, http-extension, or similar), AND a user-initiated SQL statement exists in the query-log (or DDL/long-query excerpt) within T±2s that could plausibly have triggered the outbound call. Refutation shape (r1): no extension trampoline in the callsite AND no correlating SQL statement in the audit window. Weight: null.

- `?adversary-controlled-egress` (h-003, adversarial) — proposed parent `{type: process, classification: adversary-controlled}`. Predicts (p1): the `connect()` originated from an anomalous process context — a shell or scripting-runtime child of postgres, a non-postgres binary running under the postgres uid, or a postgres backend with no correlating SQL at T AND no extension trampoline on the call stack. Refutation shape (r1): connect context matches a sanctioned pattern (vendor-telemetry callsite OR extension trampoline with correlating SQL). Weight: null. Must remain active until explicitly refuted.

**Selected lead:** `process-execution-context` on `v-001`, scoped to the interval T ± 5 seconds, pulling: (a) the Falco syscall record that triggered the alert, including `proc.name`, `proc.pname`, `proc.aname[]` ancestry chain, and callsite if available; (b) all other syscall events on v-001 in the same interval involving processes under uid=postgres (spawns, execs, connects); (c) any concurrent SQL events from the DB query-log in T ± 2s, filtered by the postgres backend PID identified in (a).

Single lead, not composite — the three hypothesis predictions are all features of the same syscall-record + correlated-SQL bundle. One query returns the full discrimination.

**Lead-level `predictions` (pre-registered readings on interpretive fields):**

- `lp1`: if ancestry shows only `postgres` (no intervening shell/script), callsite resolves to a vendor-telemetry library path, AND no concurrent SQL correlates — `read_as` h-001 supported; `advance_to` `extension-inventory` (confirm no stray extension also matches) or `CONCLUDE` if vendor-telemetry endpoint registry confirms the destination.
- `lp2`: if ancestry shows only `postgres` AND an extension trampoline is present on the stack AND a concurrent SQL in T±2s could have triggered it — `read_as` h-002 supported; `advance_to` `extension-inventory` + query-log context lookup.
- `lp3`: if ancestry shows a shell / script-runtime child of postgres, OR a non-postgres binary under uid=postgres, OR a postgres backend with no correlating SQL and no extension trampoline — `read_as` h-003 supported; `advance_to` `session-audit` (backward-chain the authentication that opened the context).
- `lp4` (fallback): if the syscall record is missing callsite detail AND ancestry alone is insufficient to classify — `advance_to` `HYPOTHESIZE` to refine (propose sub-hypotheses that each call a different secondary lead).

**Pitfalls:**

- `?vendor-telemetry`: the passive-DNS record `api.postgresql-telemetry-eu.example` looks vendor-branded but is unverified against a published registry. A well-crafted adversary can register a lookalike domain resembling a vendor endpoint. Treat the domain name as attacker-controllable until it's matched against the DB vendor's published telemetry endpoint list via an authoritative source, not an inferred string match.
- `?extension-driven-callout`: short queries are NOT in the query-log audit (per environment data-source note). Absence of a correlating SQL event does NOT refute h-002 — it only weakens it. A full refutation requires both absence of extension trampoline AND absence of extension invocation in the most recent query-log snapshot (any time, not just T±2s).
- `?adversary-controlled-egress`: "anomalous context" is a judgment call. Pre-register the reading (lp3) to avoid post-hoc rationalization. Any callsite feature that could equally be produced by an extension should push to `?extension-driven-callout` first — the adversarial verdict requires an affirmative anomaly, not just absence of sanctioned context.

**Hypothesis refinement (deferred):**

h-003 will decompose via hierarchical IDs once the parent context is confirmed — {h-003-01 recon-probing, h-003-02 c2-beacon, h-003-03 active-exfiltration} distinguished by byte-volume and timing pattern in a follow-on `network-flow` lead. Do not pre-split here.
