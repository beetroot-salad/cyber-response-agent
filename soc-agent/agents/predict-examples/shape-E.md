## Shape E — worked examples

You've already decided Shape E: one non-branching lead, three (or so) mutually-exclusive readings that route the next loop. The craft questions are **lead selection** (which observable is the cheapest discriminator?) and **reading geometry** (do the readings partition the lead's outcome space without overlap or gap?).

### Example 1 — outbound connection from a server, no prior context

**Alert:** server `host-A` emitted an outbound TCP connection to an unfamiliar destination. Prologue carries `v-source-host-A`, `v-dest-<ip>`, and an `outbound_connection` edge. No prior loops; no baseline yet for `host-A`'s normal egress profile.

**Lead-selection reasoning.** Three plausible discriminators:
- `destination-reputation` — fast, but a clean reputation doesn't rule out an authorized internal callout, and a flagged reputation doesn't tell you which process did it. Routes thinly.
- `peer-host-egress-comparison` — useful for "is this destination unusual for hosts of this role" but assumes role classification, which we don't have yet.
- `process-attribution` — names the parent process for the connection. Process identity is the strongest single discriminator: a system-update agent, a user-launched browser, and an unknown short-lived binary route the next loop into completely different forks.

`process-attribution` wins because its outcome space *naturally* partitions the next loop's question. The other two would force a Shape M fork with overlapping evidence.

**Reading geometry.** Three readings, mutually exclusive, covering the partition:

```yaml
predict:
  loop: 1
  shape: E

  branch_plan:
    primary_lead: process-attribution
    predictions:
      - id: lp1
        if: "the parent process is a system-managed service (package manager, telemetry agent, OS update daemon) running under its expected service identity"
        read_as: "system-service-egress"
        advance_to: fork-at-service-authorization
      - id: lp2
        if: "the parent process is a user-launched application running under an interactive user identity"
        read_as: "user-initiated-egress"
        advance_to: fork-at-user-intent
      - id: lp3
        if: "the parent process is unrecognized, short-lived, or running under an unexpected identity for its kind"
        read_as: "unknown-or-anomalous-process"
        advance_to: escalate

  routing:
    selected_lead: process-attribution
    composite_secondary: []
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

**Reading geometry.**

```yaml
predict:
  loop: 1
  shape: E

  branch_plan:
    primary_lead: authentication-history-for-account
    predictions:
      - id: lp1
        if: "the burst's source set, cadence, and failure-mode shape match the account's recurring 24h baseline on at least two recorded dimensions"
        read_as: "on-baseline-noise"
        advance_to: halt
      - id: lp2
        if: "the burst introduces source identifiers absent from the account's recurring 24h baseline (any deviation from the zero-count baseline for that source set)"
        read_as: "novel-sources"
        advance_to: fork-at-source-authority
      - id: lp3
        if: "the burst's source set matches baseline but cadence or failure-mode shape deviates from the baseline distribution on at least one recorded dimension"
        read_as: "known-sources-anomalous-shape"
        advance_to: fork-at-client-state

  routing:
    selected_lead: authentication-history-for-account
    composite_secondary: []
    scope_override:
      window_hours: 24
      anchor: alert
```

**Pitfalls:**
- Don't write `lp2` as `"novel sources AND high failure rate"` — high failure rate is already implied by the alert; the *novelty* of sources is the load-bearing signal. Compound claims make the reading harder to grade.
- Don't pin a specific failure-rate threshold (*"> 50 failures/min"*) — that's a baseline-value leak. Name the deviation by role (*"deviates from the baseline distribution"*); the lead returns the concrete distribution.
- Don't omit `scope_override` — historical baselines need 24h+, GATHER's 1h default would return noise.

### Paired-window dispatch — attaching `comparison` blocks

When an `lp*` reading's `if` text contains baseline-deviation vocabulary (*recurring*, *baseline*, *matches/deviates from baseline*, *novel artifact*), attach an optional `comparison` block that names the comparison set, dimension, and selector kind. GATHER reads `comparison` and fetches paired-window observations (alert window + comparison set) in one trip; ANALYZE evaluates each `if` against the paired observations. This eliminates the loop-N-then-loop-N+1 round-trip where loop N fetches baseline and loop N+1 grades against it.

Selector kinds (closed): `historical-self` | `peer-class` | `population` | `cross-rule`. Skip the block when the discriminator is internal to the alert window or when the baseline is structurally zero (any presence is a deviation — no comparison set needed).

Same example as above, re-authored with `comparison` blocks. Note the new `lp4` covering the empty-comparison-set case — without it, an account with no recorded baseline silently drops through:

```yaml
predict:
  loop: 1
  shape: E

  branch_plan:
    primary_lead: authentication-history-for-account
    predictions:
      - id: lp1
        if: "the burst's source set, cadence, and failure-mode shape match the account's recurring 24h baseline on at least two recorded dimensions"
        read_as: "on-baseline-noise"
        advance_to: halt
        comparison:
          selector_kind: historical-self
          selector: "user.name:<account> AND outcome:failure [past 24h]"
          dimension: source_set_cadence_failure_mode_geometry
      - id: lp2
        if: "the burst introduces source identifiers absent from the account's recurring 24h baseline (any deviation from the zero-count baseline for that source set)"
        read_as: "novel-sources"
        advance_to: fork-at-source-authority
        comparison:
          selector_kind: historical-self
          selector: "user.name:<account> AND outcome:failure [past 24h]"
          dimension: source_set
      - id: lp3
        if: "the burst's source set matches baseline but cadence or failure-mode shape deviates from the baseline distribution on at least one recorded dimension"
        read_as: "known-sources-anomalous-shape"
        advance_to: fork-at-client-state
        comparison:
          selector_kind: historical-self
          selector: "user.name:<account> AND outcome:failure [past 24h]"
          dimension: cadence_failure_mode_geometry
      - id: lp4
        if: "comparison_set is empty (no prior failed-auth events for this account in the 24h window)"
        read_as: "no-baseline-establishable"
        advance_to: fork-at-novel-account-context

  routing:
    selected_lead: authentication-history-for-account
    composite_secondary: []
    scope_override:
      window_hours: 24
      anchor: alert
```

Composite-lead variant: when the primary lead returns one comparison set and a secondary lead returns another (different data source, different selector), each lead's readings carry their own `comparison` block. The `dimension` field tells ANALYZE which gather partition to consult.
