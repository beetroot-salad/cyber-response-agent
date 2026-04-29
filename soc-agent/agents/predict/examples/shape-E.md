## Shape E — worked examples

You've already decided Shape E: one non-branching lead, three (or so) mutually-exclusive readings that route the next loop. The craft questions are **lead selection** (which observable is the cheapest discriminator?) and **reading geometry** (do the readings partition the lead's outcome space without overlap or gap?).

The dense form for Shape E is two `:L` blocks (`lead_preds` + `lead_preds.comparisons` when any reading is a deviation kind) plus the always-required `:R routing` block. No `:H hypotheses`, no `:P` sub-blocks, no story prose.

### Example 1 — outbound connection from a server, no prior context

**Alert:** server `host-A` emitted an outbound TCP connection to an unfamiliar destination. Prologue carries `v-source-host-A`, `v-dest-<ip>`, and an `outbound_connection` edge. No prior loops; no baseline yet for `host-A`'s normal egress profile.

**Lead-selection reasoning.** Three plausible discriminators:
- `destination-reputation` — fast, but a clean reputation doesn't rule out an authorized internal callout, and a flagged reputation doesn't tell you which process did it. Routes thinly.
- `peer-host-egress-comparison` — useful for "is this destination unusual for hosts of this role" but assumes role classification, which we don't have yet.
- `process-attribution` — names the parent process for the connection. Process identity is the strongest single discriminator: a system-update agent, a user-launched browser, and an unknown short-lived binary route the next loop into completely different forks.

`process-attribution` wins because its outcome space *naturally* partitions the next loop's question. The other two would force a Shape M fork with overlapping evidence.

**Reading geometry.** Three readings, mutually exclusive, covering the partition. None of them is a deviation kind (the discriminator is the parent-process *category*, a direct field-read on the gather output), so no `:L lead_preds.comparisons` block is needed:

```
predict loop=1 shape=E

:L lead_preds [id|kind|if|read_as|advance_to]
lp1|absolute|"the parent process is a system-managed service (package manager, telemetry agent, OS update daemon) running under its expected service identity"|system-service-egress|fork-at-service-authorization
lp2|absolute|"the parent process is a user-launched application running under an interactive user identity"|user-initiated-egress|fork-at-user-intent
lp3|absolute|"the parent process is unrecognized, short-lived, or running under an unexpected identity for its kind"|unknown-or-anomalous-process|escalate

:R routing
selected_lead         process-attribution
composite_secondary   -
override_data_source  -
rationale             "process-attribution outcome space naturally partitions next-loop fork; reputation/peer comparisons would force a Shape M with overlapping evidence"
```

**Pitfalls:**
- Don't add a `lp4: "destination is on threat-intel feed"` — that's a different lead's signal; mixing it in makes the readings non-disjoint (a system-service hitting a flagged destination matches both lp1 and lp4). Keep one lead per Shape-E branch_plan; if reputation is needed, escalate via lp3 and let the next loop fold it in.
- Don't write `lp1` as `"system-managed service AND destination is internal"` — that's compound; if the destination turns out to be external, the reading silently fails. The destination check belongs in the next loop, not this one.

---

### Example 2 — failed-login spike on a service account

**Alert:** authentication monitor reports a burst of failed logins against `account-svc-deploy` in the last 5 minutes. Prologue carries `v-account-svc-deploy` and a `failed_auth_burst` edge. No prior loops.

**Lead-selection reasoning.** Candidates:
- `source-ip-reputation` — tells you about *who*, not about whether this burst is anomalous for *this account*.
- `geographic-distribution-of-sources` — meaningful only if you already know the account's normal source geography.
- `authentication-history-for-account` (24h+ cadence + outcome baseline) — returns both the foreground burst and the account's recurring authentication shape in the same query, so the reading can compare.

Authentication baseline wins: **baseline is a first-class discriminator for any "is this burst real?" question.** A service account that normally shows hourly failed-auth clusters from a known set of automation hosts has a different routing path than one with a flat baseline that just spiked.

**Reading geometry.** This time the readings *are* deviation kinds (`geometry`, `novel-artifact`, `cadence`, `absence`), so a sibling `:L lead_preds.comparisons` block is required, and `:R routing.scope_override` extends the GATHER lookback to 24h:

```
predict loop=1 shape=E

:L lead_preds [id|kind|if|read_as|advance_to]
lp1|geometry|"the burst's source set, cadence, and failure-mode shape match the account's recurring 24h baseline on at least two recorded dimensions"|on-baseline-noise|halt
lp2|novel-artifact|"the burst introduces source identifiers absent from the account's recurring 24h baseline (any deviation from the zero-count baseline for that source set)"|novel-sources|fork-at-source-authority
lp3|cadence|"the burst's source set matches baseline but cadence or failure-mode shape deviates from the baseline distribution on at least one recorded dimension"|known-sources-anomalous-shape|fork-at-client-state
lp4|absence|"selector returns zero events (no recorded baseline for this account in the 24h window)"|no-baseline-establishable|fork-at-novel-account-context

:L lead_preds.comparisons [pred_ref|selector_kind|selector|dimension]
lp1|historical-self|"user.name:<account> AND outcome:failure [past 24h]"|source_set_cadence_failure_mode_geometry
lp2|historical-self|"user.name:<account> AND outcome:failure [past 24h]"|source_set
lp3|historical-self|"user.name:<account> AND outcome:failure [past 24h]"|cadence_failure_mode_geometry
lp4|historical-self|"user.name:<account> AND outcome:failure [past 24h]"|event-count

:R routing
selected_lead         authentication-history-for-account
composite_secondary   -
override_data_source  -
rationale             "baseline is the first-class discriminator for is-this-burst-real questions; one historical-self selector returns both foreground and baseline in one trip"

:R routing.scope_override [key|value]
window_hours|24
anchor|alert
```

**Pitfalls:**
- Don't write `lp2` as `"novel sources AND high failure rate"` — high failure rate is already implied by the alert; the *novelty* of sources is the load-bearing signal. Compound claims make the reading harder to grade.
- Don't pin a specific failure-rate threshold (*"> 50 failures/min"*) — that's a baseline-value leak. Name the deviation by role (*"deviates from the baseline distribution"*); the lead returns the concrete distribution.
- Don't omit `scope_override` — historical baselines need 24h+, GATHER's 1h default would return noise.
- **Don't drop `lp4`.** Without an `absence`-kind reading for the empty-baseline case, accounts with no recorded prior auth silently fall through every other reading and the lead has no reading to grade against. `kind=absence` still names a selector — declare *what* historical query is expected to return non-zero before claiming its absence (see the `lp4` row's comparison entry).

### When to skip `:L lead_preds.comparisons`

Only when *every* reading is `kind=absolute` or `kind=presence` — i.e., a direct field-read on the gather output (Example 1's parent-process category). Any single deviation kind on any single row pulls the comparisons block back in.

### Mapping the readings back to invlang

The handler composes lead-level predictions onto GATHER's pending lead entry as `predictions[]` (each `lp*` becomes one prediction with `if`/`read_as`/`advance_to` and an optional `comparison` sub-object). ANALYZE consumes that and grades against the foreground vs. paired-window observations. None of this requires authoring on your end — the handler does the YAML composition. Your job ends at the dense `:L`/`:R` blocks.
