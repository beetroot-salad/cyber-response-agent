## Shape E — worked example (loop 1, no prior enrichment)

**Alert (Wazuh rule-5710, SSH invalid user):**

```
srcuser:   monitorprobe
srcip:     172.22.0.10
dstip:     10.0.7.44
outcome:   reject (unknown user on target)
```

**State at loop 1:** prologue has `v-source-172.22.0.10`, `v-target-10.0.7.44`, and an `attempted_auth` edge carrying `identity_on_wire: monitorprobe`. No prior loops. The source has no recorded baseline yet, so any mechanism fork (monitoring-probe vs. credential-stuffing vs. typo) would have to assert cadence shape, ancestry shape, or correlation signal *before* the loop has read any of them — predictions would drift into compound or speculative claims.

The cheapest next step is one lead — `authentication-history` — whose three plausible outcomes route the next loop unambiguously:
- forward-success in window → escalate (rejected attempt followed by success indicates credential discovery).
- periodic single-attempt cadence → next loop is Shape A on identity (monitoring-probe-shaped pattern; authority confirmation against `approved-monitoring-sources` is the open question).
- non-periodic / burst cadence → next loop forks on identity with a cadence-anomaly signal in the story.

Shape E. No `hypotheses` block. `branch_plan` carries the readings; `routing.selected_lead` names the lead.

```yaml
predict:
  loop: 1
  shape: E

  branch_plan:
    primary_lead: authentication-history
    predictions:
      - id: lp1
        if: "at least one successful authentication from 172.22.0.10 to 10.0.7.44 within ±60s of the rejected attempt"
        read_as: "forward-success-after-reject"
        advance_to: escalate
      - id: lp2
        if: "the source's rule-5710 history over the prior 24h is single-attempt clusters at a recurring inter-arrival cadence (max_cluster_size ≤ 3)"
        read_as: "periodic-monitoring-shaped"
        advance_to: fork-at-identity-authority
      - id: lp3
        if: "the source's rule-5710 history is non-periodic (bursts, multi-attempt clusters, or no recurrence)"
        read_as: "non-periodic"
        advance_to: fork-at-identity-with-cadence-anomaly

  routing:
    selected_lead: authentication-history
    composite_secondary: []
    scope_override:
      window_hours: 24
      anchor: alert
```

**Pitfalls:**
- Don't write `lp2` as `"cadence is periodic AND forward-success is absent"` — that's compound. The forward-success check belongs in `lp1`; mutually-exclusive readings keep the routing clean.
- Don't pin a specific cadence value (*"inter-arrival ≈ 600s"*) in `lp2` — that's a baseline-value leak. Name the deviation by role (*"recurring inter-arrival cadence"*); GATHER returns the concrete distribution.
- Don't add a fourth reading like *"empty result"* — empty is a GATHER-side trigger (`trigger: empty_result`), not a PREDICT-side reading.
