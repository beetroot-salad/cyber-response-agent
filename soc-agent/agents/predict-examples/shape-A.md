## Shape A — worked example (loop 2, post-enrichment)

**Alert (Wazuh rule-5710, SSH invalid user):**

```
srcuser:   monitorprobe
srcip:     172.22.0.10
dstip:     10.0.7.44
outcome:   reject (unknown user on target)
```

**State at loop 2:** prologue has `v-source-172.22.0.10`, `v-target-10.0.7.44`, and an `attempted_auth` edge carrying `identity_on_wire: monitorprobe`. Loop 1 ran `authentication-history` (Shape E) and returned: 11 events in the 1h backward window, single-attempt clusters, mean inter-arrival ~576s (stddev 102s), no forward-success in ±60s. Enrichment has landed — cadence is periodic, no forward-success signal. The username `monitorprobe` matches a sentinel pattern, but this is pattern inference; no authority confirmation yet that the registered monitoring system was the specific actor on *this* tick. Shape A — authorization is the open question. One hypothesis with an `authorization_contract` against the approved-monitoring-sources anchor; no peer, because a "credentials-stolen-by-non-daemon" variant would need a divergent upstream mechanism (different parent process) that isn't testable with available leads — upstream loops will fork if the anchor returns unauthorized/indeterminate.

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?registered-actor-initiated"
      attached_to_vertex: v-source-172.22.0.10
      proposed_edge:
        relation: initiated_auth
        parent_vertex: {type: process, classification: monitoring-daemon-process-on-source}
      story: |
        The monitoring system daemon on 172.22.0.10 invoked
        `ssh monitorprobe@10.0.7.44` as a scheduled health-check
        tick. Loop 1 established a periodic cadence (11 events,
        mean interval 576s, single-attempt clusters) consistent
        with a fixed-schedule monitoring tool; this alert is
        on-cadence with that baseline. sshd on target rejected
        the user (expected — monitorprobe is not provisioned on
        10.0.7.44).
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "approved-monitoring-sources registry confirms the (172.22.0.10, monitorprobe, 10.0.7.44) triple as an active registered probe"
          from_story_link: "monitoring system daemon invoked ssh as a scheduled tick"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "the triple is not registered (or is marked inactive/revoked) in approved-monitoring-sources"
      authorization_contract:
        - id: ac1
          edge_ref: proposed
          anchor_kind: approved-monitoring-sources
          predicate: "(src, user, dst) triple listed as active approved monitoring probe"
          on_unauthorized: escalate
          on_indeterminate: escalate
      weight: null
```

**Selected lead:** `monitoring-probe` (playbook) — approved-monitoring-sources registry lookup for the triple. Resolves `h-001.ac1`; the anchor's verdict is dispositive. If `unauthorized` or `indeterminate`, escalate per the contract. If `authorized`, h-001 carries the disposition.

**Pitfalls:**
- Registry confirming the triple answers both *authorization* and *identity-of-use* — the registry names monitoring-daemon-process as the registered emitter of this triple, which is what `integrity_waived` captures. Don't re-introduce a "non-daemon process presented these credentials" peer — same edge, same predictions, verdict-in-name.

```yaml
selected_lead: monitoring-probe
```
