## Environment-relative predictions — worked examples

You've decided your shape (E / A / M) per the decision procedure. This file shows how to attach a `comparison` block to predictions or `lp*` readings when the claim is a deviation from this entity's normal. **The technique does not change shape selection** — it makes existing baseline-grounded predictions corpus-queryable and tells GATHER to fetch paired-window in one trip.

Use the technique when your claim's text contains baseline-deviation vocabulary: *recurring*, *baseline*, *matches the baseline geometry*, *deviates from the baseline distribution*, *novel artifact*, *materially outside cadence*. Skip when the claim is anchor-pinned (Shape A authorization), when the baseline is structurally zero, or when the discriminator is internal to the alert window.

Selector kinds (closed vocabulary):
- `historical-self` — same entity, prior window
- `peer-class` — entities of the same class as the alerted one
- `population` — alert-class population baseline
- `cross-rule` — different rule, related semantics on same entity

Mirror discipline: when two hypotheses (Shape M) split on environment-relative deviation, give each side mirror predictions on the same `comparison` block — same selector + dimension, opposite predicted direction. ANALYZE grades both against one paired observation. For Shape E, lp readings should cover (matches, deviates, comparison-set-empty) on the dimension.

### Example 1 — Shape M, two hypotheses sharing comparison sets across two dimensions

**Alert (DNS NXDOMAIN burst from one client):** Wazuh-rule-100110, src=10.0.4.12, 5-min window 412 NXDOMAIN, 387 distinct qnames, avg label entropy 3.82. Prologue carries `v-client-10.0.4.12` and an `emitted_queries` edge.

Two competing mechanisms diverge on **per-process concentration** AND **qname-entropy distribution** — both relative to this client's recurring DNS pattern. Mirror predictions, two comparison blocks (one per dimension), shared across both hypotheses:

```yaml
hypotheses:
  - id: h-001
    name: "?misconfigured-resolver-path"
    attached_to_vertex: v-client-10.0.4.12
    proposed_edge:
      relation: emitted_queries
      parent_vertex: {type: process_set, classification: client-resolver-consumers}
    story: |
      All DNS-consuming processes on the client share a broken
      resolver path. The NX burst is uniform across processes
      because every process hits the same broken path. The client's
      recurring 24h DNS pattern is multi-process, normal-entropy.
    predictions:
      - id: p1
        subject: proposed_edge
        claim: "alert-window per-process NX-query share is uniform across processes; matches the recurring multi-process baseline geometry"
        from_story_link: "uniform across processes because every process hits the same broken path"
        comparison:
          selector_kind: historical-self
          selector: "client.ip:10.0.4.12 AND query.response_code:NXDOMAIN [past 24h]"
          dimension: per_process_query_share_distribution
      - id: p2
        subject: proposed_edge
        claim: "alert-window qname-entropy distribution matches the recurring baseline qname-entropy distribution"
        from_story_link: "broken resolver path"
        comparison:
          selector_kind: historical-self
          selector: "client.ip:10.0.4.12 [past 24h]"
          dimension: qname_shannon_entropy_distribution
    refutation_shape:
      - {id: r1, refutes_predictions: [p1], claim: "alert-window per-process share concentrates in one process; deviates from the recurring multi-process baseline geometry"}
      - {id: r2, refutes_predictions: [p2], claim: "alert-window qname-entropy distribution shifts materially higher than the recurring baseline distribution"}
    weight: null

  - id: h-002
    name: "?single-process-algorithmic-qnames"
    attached_to_vertex: v-client-10.0.4.12
    proposed_edge:
      relation: emitted_queries
      parent_vertex: {type: process, classification: single-process-on-client}
    story: |
      One process on the client is generating algorithmically-derived
      names at a rate dominating the burst. The client's recurring
      24h DNS pattern is multi-process and normal-entropy; this burst
      deviates on both dimensions because a single non-baseline
      process is responsible.
    predictions:
      - id: p1
        subject: proposed_edge
        claim: "alert-window per-process NX-query share concentrates in one process; deviates from the recurring multi-process baseline geometry"
        from_story_link: "one process dominating the burst"
        comparison:
          selector_kind: historical-self
          selector: "client.ip:10.0.4.12 AND query.response_code:NXDOMAIN [past 24h]"
          dimension: per_process_query_share_distribution
      - id: p2
        subject: proposed_edge
        claim: "alert-window qname-entropy distribution shifts materially higher than the recurring baseline distribution"
        from_story_link: "algorithmically-derived names"
        comparison:
          selector_kind: historical-self
          selector: "client.ip:10.0.4.12 [past 24h]"
          dimension: qname_shannon_entropy_distribution
    refutation_shape:
      - {id: r1, refutes_predictions: [p1], claim: "alert-window per-process share is uniform; matches the recurring multi-process baseline geometry"}
      - {id: r2, refutes_predictions: [p2], claim: "alert-window qname-entropy distribution matches the recurring baseline distribution"}
    weight: null

routing:
  selected_lead: dns-pattern-paired
  composite_secondary: []
  scope_override: {window_hours: 24, anchor: alert}
```

Notes:
- Two `comparison` blocks (one per dimension), each shared across both hypotheses' p1/p2. GATHER returns one envelope partitioned by dimension.
- Each hypothesis pair (h-001.p1 / h-002.p1) is the *same* deviation question, opposite predicted directions. ANALYZE grades both against one paired observation.
- Claim text uses canonical deviation vocabulary; no value leaks.

### Example 2 — Shape E branch_plan with comparison readings (mirror + empty-baseline coverage)

**Alert (rule-5710 SSH reject, loop 1):** srcip=172.22.0.10, srcuser=monitorprobe, dstip=10.0.7.44. Loop-1 enrichment to characterize cadence.

Three readings cover the dimension space:

```yaml
shape: E
branch_plan:
  primary_lead: authentication-history
  predictions:
    - id: lp1
      if: "any forward-success edge appears within ±60s of the alert in alert_window observations"
      read_as: "downstream-success-correlation"
      advance_to: escalate
    - id: lp2
      if: "alert-window inter-event interval distribution matches the recurring baseline cadence distribution"
      read_as: "on-cadence-with-baseline"
      advance_to: fork-at-identity
      comparison:
        selector_kind: historical-self
        selector: "data.srcip:172.22.0.10 AND rule.id:5710 [past 24h]"
        dimension: inter_event_interval_distribution
    - id: lp3
      if: "alert-window inter-event interval distribution deviates from the recurring baseline cadence distribution"
      read_as: "off-cadence-from-baseline"
      advance_to: fork-at-identity-with-cadence-anomaly
      comparison:
        selector_kind: historical-self
        selector: "data.srcip:172.22.0.10 AND rule.id:5710 [past 24h]"
        dimension: inter_event_interval_distribution
    - id: lp4
      if: "comparison_set is empty (no prior 5710 from this srcip in the 24h window)"
      read_as: "no-baseline-cadence-establishable"
      advance_to: fork-at-identity-novel-source

routing:
  selected_lead: authentication-history
  composite_secondary: []
  scope_override: {window_hours: 24, anchor: alert}
```

Notes:
- `lp1` has no comparison — forward-success is structurally-zero baseline (any occurrence is meaningful regardless of history).
- `lp2`/`lp3` are mirror readings on the same dimension and same comparison block.
- `lp4` handles the empty-comparison-set case explicitly; without it, an entity with no recorded baseline silently drops through.

### Example 3 — composite leads each with their own comparison

**Alert (Shape M with composite dispatch):** when two leads return separate baselines for two hypotheses' dimensions. Primary lead's comparison covers one dimension; secondary's covers the other. Each lead's `comparison` is independent — *do not infer one from the other*.

```yaml
routing:
  selected_lead: process-lineage-baseline
  composite_secondary: [outbound-destination-baseline]
  scope_override: {window_hours: 168, anchor: alert}
  lead_hints:
    process-lineage-baseline: "Return alert-window child-process tree under nginx pid 1422 plus 7d historical baseline of nginx-spawned children on this host."
    outbound-destination-baseline: "Return any outbound TCP connections from the spawned shell plus 30d historical destination set for this host."
```

The two leads return distinct comparison_set partitions in one GATHER envelope. ANALYZE reads each prediction's `comparison.dimension` to know which partition to consult.

### Anti-patterns

- ❌ Comparison block on a Shape A authorization-anchor prediction — the anchor verdict already decides; comparison is redundant.
- ❌ Comparison `selector` written as prose intent ("baseline of normal activity") rather than a query/spec.
- ❌ `dimension` written compound (`destination_geometry AND volume_per_5min`). Split into two comparisons.
- ❌ Mirror predictions on different dimensions — mirrors must share `selector_kind` + `selector` + `dimension`, only the predicted direction differs.
- ❌ Letting the comparison technique change your shape decision — Shape E remains Shape E with comparison readings; Shape M remains Shape M with comparison-attached predictions; Shape A doesn't acquire a comparison.
