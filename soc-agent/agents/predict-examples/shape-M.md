## Shape M — worked example (loop 2, post-enrichment)

**Alert (Unbound NXDOMAIN spike from one client):**

```
client_ip:    10.42.7.18
nx_count_5m:  3,184 (baseline ~40)
qname_sample: ["yt3jq.example.net", "k9s2v.example.net", "qz1m4.example.net", ...]
```

**State at loop 2:** prologue has `v-client-10.42.7.18` and an `emitted_dns_queries` edge with the NX burst attached. Loop 1 ran `process-dns-attribution` (Shape E) and returned per-process NX counts and a per-process qname-entropy distribution for the burst window. The discriminator is now sitting in the data: either NX queries are spread across most of the client's resolving processes (resolver/path misconfiguration affects everyone) or one process dominates with high-entropy qnames (algorithmic generation under one program).

This is **not** an authorization fork — both mechanisms describe legitimate parent processes the client routinely runs; the question isn't *was this allowed*, it's *which mechanism produced the burst*. Adding an `authorization_contract` to either hypothesis wouldn't change the read; the survivability test for Shape A fails. Two hypotheses, diverging on already-observable fields (per-process NX share + qname-entropy distribution). Lead reads the discriminator directly. Shape M.

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?misconfigured-resolver-path"
      attached_to_vertex: v-client-10.42.7.18
      proposed_edge:
        relation: emitted_dns_queries
        parent_vertex: {type: host_config, classification: resolver-config-on-client}
      story: |
        A resolver-path or search-domain misconfiguration on
        10.42.7.18 is rewriting otherwise-valid lookups into
        an unresolvable suffix, so most processes that resolve
        names hit the same broken path. Loop 1 will show the
        NX share spread across the client's resolving processes
        rather than concentrated in one, with qname entropy
        matching the host's normal traffic mix.
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "no single process accounts for ≥ 70% of the burst's NX queries"
          from_story_link: "most processes that resolve names hit the same broken path"
        - id: p2
          subject: proposed_edge
          claim: "burst-window qname-entropy distribution matches the client's recurring baseline distribution on at least two recorded dimensions"
          from_story_link: "qname entropy matching the host's normal traffic mix"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "a single process accounts for ≥ 70% of the burst's NX queries"
        - id: r2
          refutes_predictions: [p2]
          claim: "burst-window qname-entropy distribution deviates from the client's baseline distribution on at least one recorded dimension"
      weight: null

    - id: h-002
      name: "?single-process-algorithmic-qnames"
      attached_to_vertex: v-client-10.42.7.18
      proposed_edge:
        relation: emitted_dns_queries
        parent_vertex: {type: process, classification: dns-emitting-process-on-client}
      story: |
        One process on 10.42.7.18 is generating qnames at a rate
        and shape inconsistent with the client's recurring DNS
        traffic — high concentration in one process, qname-entropy
        distribution shifted versus baseline. The mechanism is
        algorithmic name generation (a tool, library, or beaconing
        agent), regardless of intent.
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "a single process accounts for ≥ 70% of the burst's NX queries"
          from_story_link: "high concentration in one process"
        - id: p2
          subject: proposed_edge
          claim: "burst-window qname-entropy distribution deviates from the client's baseline distribution on at least one recorded dimension"
          from_story_link: "qname-entropy distribution shifted versus baseline"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "no single process accounts for ≥ 70% of the burst's NX queries"
        - id: r2
          refutes_predictions: [p2]
          claim: "burst-window qname-entropy distribution matches the client's baseline distribution on at least two recorded dimensions"
      weight: null
```

**Selected lead:** `dns-process-concentration` (composite with `dns-qname-entropy-baseline`) — partitions the fork from two angles. Per-process NX share answers p1/r1 on both hypotheses; qname-entropy comparison against the client's baseline answers p2/r2.

**Pitfalls:**
- Don't add an `authorization_contract` to `h-002` — the question isn't policy. If you find yourself wanting one, the actual fork is "is this benign algorithmic emission vs. beaconing?" — that's a downstream loop *after* h-002 is confirmed, not a peer to h-001.
- Don't write `p1` as `"single process dominates AND entropy is high"` — compound. Splitting into p1 (concentration) and p2 (entropy deviation) lets the lead pivot on either axis if the other is indeterminate.
- Don't pin specific qname-entropy thresholds in `p2` — name the deviation by role against the client's baseline; the entropy lead returns the concrete distribution.
