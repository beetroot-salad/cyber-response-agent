## Shape M — worked examples

You've already decided Shape M: two+ mechanisms, divergent on already-observable fields, no authorization contract because authorization isn't the open question. The craft questions are **story-driven prediction** (each story sentence licenses one prediction; predictions diverge where the stories diverge), and **discriminator selection** (the lead has to read the field where the stories actually disagree).

The pattern: write the parent's behavior as a concrete causal sentence, then derive predictions by asking *"what would I see if this story is true?"* — for each hypothesis. Predictions on h-001 and h-002 should be near-mirrors on the same observable, opposite verdicts. The lead measures that observable directly.

### Example 1 — DNS NXDOMAIN burst from one client

**Alert:** the recursive resolver logged 3,184 NXDOMAIN responses for client `client-X` in the last 5 minutes (baseline ≈ 40). Prologue carries `v-client-X` and an `emitted_dns_queries` edge with the burst attached. Loop 1 ran process-dns-attribution and returned per-process NX counts and a per-process qname-entropy distribution.

**Story-to-prediction derivation.** Two competing parents:

*h-001 ?misconfigured-resolver-path.* Story: "A resolver-path or search-domain misconfiguration on `client-X` is rewriting otherwise-valid lookups into an unresolvable suffix, so most processes that resolve names hit the same broken path."
- Sentence 1: *"most processes hit the same broken path"* → if true, NX share is **spread across processes**, no single one dominates. → `p1: no single process accounts for ≥ 70% of the burst's NX queries`.
- Sentence 2: *"otherwise-valid lookups"* → the underlying qnames are the host's normal traffic, just rewritten. The qname-entropy *distribution* should still resemble baseline. → `p2: burst-window qname-entropy distribution matches the client's recurring baseline distribution on at least two recorded dimensions`.

*h-002 ?single-process-algorithmic-qnames.* Story: "One process on `client-X` is generating qnames at a rate and shape inconsistent with the client's recurring DNS traffic — high concentration in one process, qname-entropy distribution shifted versus baseline. The mechanism is algorithmic name generation (a tool, library, or beaconing agent), regardless of intent."
- Sentence 1: *"high concentration in one process"* → `p1: a single process accounts for ≥ 70% of the burst's NX queries`.
- Sentence 2: *"qname-entropy distribution shifted versus baseline"* → `p2: burst-window qname-entropy distribution deviates from the client's baseline distribution on at least one recorded dimension`.

The two p1 claims are mirror predictions on per-process NX share; the two p2 claims are mirror predictions on entropy-distribution-vs-baseline. The lead reads both observables.

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?misconfigured-resolver-path"
      attached_to_vertex: v-client-X
      proposed_edge:
        relation: emitted_dns_queries
        parent_vertex: {type: host_config, classification: resolver-config-on-client}
      story: |
        A resolver-path or search-domain misconfiguration on
        `client-X` is rewriting otherwise-valid lookups into
        an unresolvable suffix, so most processes that resolve
        names hit the same broken path. The underlying qnames
        are the host's normal traffic, just rewritten — qname
        entropy distribution should still resemble baseline.
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "no single process accounts for ≥ 70% of the burst's NX queries"
          from_story_link: "most processes that resolve names hit the same broken path"
        - id: p2
          subject: proposed_edge
          claim: "burst-window qname-entropy distribution matches the client's recurring baseline distribution on at least two recorded dimensions"
          from_story_link: "qname entropy distribution should still resemble baseline"
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
      attached_to_vertex: v-client-X
      proposed_edge:
        relation: emitted_dns_queries
        parent_vertex: {type: process, classification: dns-emitting-process-on-client}
      story: |
        One process on `client-X` is generating qnames at a rate
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
- Don't write `p1` as `"single process dominates AND entropy is high"` — compound. Splitting into p1 (concentration) and p2 (entropy deviation) lets the lead pivot on either axis if the other is indeterminate.
- Don't pin specific qname-entropy thresholds in `p2` — name the deviation by role against the client's baseline; the entropy lead returns the concrete distribution.

---

### Example 2 — SMB session burst from a workstation to many internal hosts

**Alert:** network sensor reports `workstation-W` opened SMB sessions to 47 distinct internal hosts in the last 10 minutes (baseline ≈ 2 distinct hosts/10min for this workstation). Prologue carries `v-workstation-W`, the set of target hosts, and an `opened_smb_sessions` edge with the burst attached. Loop 1 ran process-attribution and target-set characterization, returning per-process session counts plus the target set's relationship to the workstation's prior SMB destinations.

**Story-to-prediction derivation.** Two competing parents:

*h-001 ?backup-tool-fanout.* Story: "A backup or sync tool on `workstation-W` is iterating through a configured target list (file shares, user-home backup mounts, or a NAS roster) and opening SMB sessions in sequence. The target set should be a stable subset that the workstation has touched before; one process accounts for the bulk of sessions."
- Sentence 1: *"iterating through a configured target list"* → one process dominates. → `p1: a single process accounts for ≥ 80% of the burst's SMB sessions`.
- Sentence 2: *"target set should be a stable subset that the workstation has touched before"* → target overlap with prior 30d targets is high. → `p2: at least 70% of the burst's target hosts appear in the workstation's 30d SMB-target history`.

*h-002 ?lateral-discovery-scan.* Story: "An interactive process (or a recently-launched short-lived binary) on `workstation-W` is sweeping the local subnet for SMB-reachable hosts. Targets are being enumerated rather than retrieved from a configured list; many hits will be hosts the workstation has never touched, and session shape will skew toward connect-and-close rather than sustained transfer."
- Sentence 1: *"enumerated rather than retrieved from a configured list"* → low overlap with prior targets. → `p1: fewer than 30% of the burst's target hosts appear in the workstation's 30d SMB-target history`.
- Sentence 2: *"session shape will skew toward connect-and-close rather than sustained transfer"* → per-session byte volume is small and uniform. → `p2: the burst's per-session byte-volume distribution is materially below the workstation's recurring SMB session-volume baseline on at least one recorded dimension`.

Note the predictions diverge on **two different observables**: target-overlap (p1 in both hypotheses) and process-concentration vs session-shape (p2 differs in axis). That's fine — what matters is that each hypothesis's predictions are observable and the lead reads both axes.

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?backup-tool-fanout"
      attached_to_vertex: v-workstation-W
      proposed_edge:
        relation: opened_smb_sessions
        parent_vertex: {type: process, classification: backup-or-sync-process-on-workstation}
      story: |
        A backup or sync tool on `workstation-W` is iterating
        through a configured target list (file shares, user-home
        backup mounts, or a NAS roster) and opening SMB sessions
        in sequence. The target set should be a stable subset
        that the workstation has touched before; one process
        accounts for the bulk of sessions.
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "a single process accounts for ≥ 80% of the burst's SMB sessions"
          from_story_link: "one process accounts for the bulk of sessions"
        - id: p2
          subject: proposed_edge
          claim: "at least 70% of the burst's target hosts appear in the workstation's 30d SMB-target history"
          from_story_link: "target set should be a stable subset that the workstation has touched before"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "no single process accounts for ≥ 80% of the burst's SMB sessions"
        - id: r2
          refutes_predictions: [p2]
          claim: "fewer than 70% of the burst's target hosts appear in the workstation's 30d SMB-target history"
      weight: null

    - id: h-002
      name: "?lateral-discovery-scan"
      attached_to_vertex: v-workstation-W
      proposed_edge:
        relation: opened_smb_sessions
        parent_vertex: {type: process, classification: discovery-scan-process-on-workstation}
      story: |
        An interactive process (or a recently-launched short-lived
        binary) on `workstation-W` is sweeping the local subnet
        for SMB-reachable hosts. Targets are being enumerated
        rather than retrieved from a configured list; many hits
        will be hosts the workstation has never touched, and
        session shape will skew toward connect-and-close rather
        than sustained transfer.
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "fewer than 30% of the burst's target hosts appear in the workstation's 30d SMB-target history"
          from_story_link: "many hits will be hosts the workstation has never touched"
        - id: p2
          subject: proposed_edge
          claim: "the burst's per-session byte-volume distribution is materially below the workstation's recurring SMB session-volume baseline on at least one recorded dimension"
          from_story_link: "session shape will skew toward connect-and-close rather than sustained transfer"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "at least 30% of the burst's target hosts appear in the workstation's 30d SMB-target history"
        - id: r2
          refutes_predictions: [p2]
          claim: "the burst's per-session byte-volume distribution matches the workstation's recurring SMB session-volume baseline on at least two recorded dimensions"
      weight: null
```

**Selected lead:** `smb-target-overlap-and-session-shape` (composite with `smb-target-history-baseline`) — measures target-set overlap against the workstation's 30d SMB-target history and the per-session byte-volume distribution against baseline.

**Pitfalls:**
- Don't write either story as just *"backup tool"* / *"scan"* — those are labels, not stories. The story has to name *what the parent does* in causal terms (iterates a list / sweeps a subnet) so that predictions derive from concrete behavior.
- Don't let the two p1 claims overlap (e.g. one says "≥ 80%", the other says "≤ 50%" — leaving 50–80% in no-man's-land). Mirror the threshold so the predictions partition the observable cleanly.
- Don't pin specific byte-volume thresholds — name the deviation by role against the workstation's baseline; the lead returns the distribution.
