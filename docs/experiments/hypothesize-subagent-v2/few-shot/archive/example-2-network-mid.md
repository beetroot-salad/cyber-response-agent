# Example 2 — network, mid-investigation refinement (positive)

Signature: `wazuh-rule-100110`. Loop 2 HYPOTHESIZE after loop 1 GATHER
confirmed a parent mechanism. Shows refinement via hierarchical IDs.

## State at entry

Loop 1 had no HYPOTHESIZE (§ASSESS: enrichment-first signature). Main
agent ran GATHER with pre-registered readings:

- `parent-domain-classification`: eTLD+1 `svc.telemetry-collect.com`
  unknown to reputation anchor, first-seen ~2 days ago.
- `query-history-for-parent`: 187 queries to **162 distinct subdomains**
  from `host-app-03` over 45 min; all A-record; zero NXDOMAIN; even
  distribution, no gap > 40s.

Loop 1 ANALYZE: confirms `?dns-channel` (varied subdomains + single parent
+ sustained rate). Refutes `?one-shot-resolution` (162 ≠ isolated) and
`?candidate-probing` (zero NXDOMAIN ≠ probing). Sub-mechanism is the
next fork: data-encoding transport vs. beacon keepalive — distinct
observable shapes.

## HYPOTHESIZE output

```yaml
# Parent h-pre-001 ?dns-channel is confirmed at loop 1, shelved here
# for refinement. Children are independent (weight-history-wise).

hypothesize:
  shelved: [h-pre-001]
  hypotheses:
    - id: h-pre-001-001
      name: "?data-encoding-channel"
      attached_to_vertex: e-query-cluster-telemetry-collect
      proposed_edge:
        relation: classified_as
        parent_vertex:
          type: command
          classification: base-N-encoded-payload-channel
      predictions:
        - id: p1
          claim: "over the 162 labels, ≥95% of characters are drawn from
            a base32 / base64 / hex restricted alphabet, AND length
            distribution clusters near 32 / 44 / 63 char payload-block
            boundaries (not a single UUID-shaped mode at 32 or 36)"
      refutation_shape:
        - id: r1
          claim: "alphabet is unrestricted OR length distribution is
            unimodal near a UUID-shaped value with low variance"
      weight: null
    - id: h-pre-001-002
      name: "?beacon-heartbeat-channel"
      attached_to_vertex: e-query-cluster-telemetry-collect
      proposed_edge:
        relation: classified_as
        parent_vertex:
          type: command
          classification: templated-beacon-channel
      predictions:
        - id: p1
          claim: "labels share a common prefix or suffix (fixed template
            with 4–12 char unique segment), AND inter-query cadence
            coefficient of variation (stdev/mean) < 0.2 over the 45-min
            window"
      refutation_shape:
        - id: r1
          claim: "no common template emerges AND cadence CoV ≥ 0.2
            (bursty rather than periodic)"
      weight: null
```

**Selected lead:** `subdomain-shape` — single measurement over the 162
already-captured labels. Extracts alphabet-restriction fraction, length
distribution, longest common prefix/suffix, and cadence CoV in one pass.
Partitions the two children.

**Pitfalls:**
- h-pre-001-001: high-volume session-analytics telemetry can emit UUIDs
  whose hex alphabet (32 or 36 char) mimics base-N shape. If alphabet-
  restricted but length is tightly unimodal, reinstate `?sanctioned-
  telemetry` as an attribute check via anchor lookup before grading `++`.
- h-pre-001-002: sophisticated C2 varies template segments to defeat
  prefix/suffix detection. If no template but cadence CoV < 0.2, keep
  hypothesis active — periodic cadence alone sustains suspicion.

## Why this is good

- Parent `?dns-channel` is shelved (not deleted); children inherit no
  weight per §Refinement.
- Hierarchical IDs encode the lineage: `h-pre-001-001` / `h-pre-001-002`.
- Sub-mechanisms differ by observable *shape*, not by intent.
  Legitimacy-vs-adversarial is orthogonal and resolves at the anchor
  layer once shape is confirmed.
- Orthogonal prediction surfaces (alphabet+length vs. template+cadence).
- Predictions are quantified (≥95%, CoV < 0.2, 32/44/63-char bands).
