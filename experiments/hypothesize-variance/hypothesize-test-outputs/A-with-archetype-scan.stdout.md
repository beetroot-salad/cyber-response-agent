```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?ci-pipeline-exec"
      attached_to_vertex: v-003
      proposed_edge:
        relation: spawned
        parent_vertex:
          type: process
          classification: ci-runner-agent
      story: |
        A CI runner agent on the container host invoked runc (v-003) to exec
        bash into the target-endpoint container as a scripted one-shot pipeline
        step. `bash -c whoami` is characteristic of a CI identity-probe or
        environment-check job that completes and exits immediately. The invoking
        process is a recognized CI service binary (gitlab-runner, jenkins-agent,
        GitHub Actions runner, or equivalent). If this classification holds, prior
        pipeline runs targeting this image would have produced an established
        cadence of identical bash -c exec events visible in the container-baseline
        for image cyber-response-agent_devcontainer-target-endpoint; no prior
        baseline data has been gathered at this point in the investigation.
      legitimacy_contract:
        - id: lc1
          edge_ref: proposed
          anchor_kind: deploy-runs
          asks: authorization
      predictions:
        - id: p1
          subject: proposed_parent
          claim: >
            container-baseline for image
            cyber-response-agent_devcontainer-target-endpoint shows prior
            rule-100001 bash -c exec events with a recurring cadence consistent
            with automated pipeline execution rather than random or one-off timing
          from_story_link: "prior pipeline runs targeting this image would have produced an established cadence of identical bash -c exec events"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: >
            container-baseline shows zero prior rule-100001 events for this
            image (first-ever occurrence) or events with random non-periodic
            timing uncharacteristic of scheduled CI
      weight: null

    - id: h-002
      name: "?adversary-controlled-host-exec"
      attached_to_vertex: v-003
      proposed_edge:
        relation: spawned
        parent_vertex:
          type: process
          classification: adversary-controlled-host-exec-process
      story: |
        An adversary who obtained execution access on the container host — via
        exposed container socket, host compromise, or credential theft — invoked
        runc (v-003) to inject bash into the target-endpoint container. `bash -c
        whoami` is a one-shot reconnaissance probe: the attacker confirming what
        identity they hold inside the container before proceeding with follow-on
        activity. The invoking host-side process is not a recognized CI runner or
        operator tool. If this classification holds, the container-baseline for
        this image would show zero or only sparse prior bash -c exec events — no
        established CI automation pattern exists that would explain this exec as
        routine; no prior baseline data has been gathered at this point in the
        investigation.
      predictions:
        - id: p1
          subject: proposed_parent
          claim: >
            container-baseline for image
            cyber-response-agent_devcontainer-target-endpoint shows zero or only
            sparse prior rule-100001 events with no recurring cadence that would
            indicate established pipeline automation producing bash -c execs
          from_story_link: "no established CI automation pattern exists that would explain this exec as routine"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: >
            container-baseline shows prior bash -c exec events with a recurring
            cadence consistent with automated pipeline activity for this image
      weight: null
```

**Selected lead:** `container-baseline` — composite dispatch with `correlated-falco-events` per the playbook composition rule; baseline cadence for image `cyber-response-agent_devcontainer-target-endpoint` is the single observable whose predicted value diverges between h-001 (established recurring pattern) and h-002 (absent or sparse, non-periodic); co-firing check for rules 100002/100006/100007/100008 in the same `container.id=17bc2dde3fb0` within ±15 min is mandatory per the composition rule regardless of which hypothesis the cadence supports.

**Pitfalls:**
- h-001: irregular cadence in the baseline does not rule out CI — on-demand and event-triggered pipeline jobs produce irregular spacing. Recurring events without periodicity are consistent with both CI and a persistent attacker with repeated access. Cadence pattern alone cannot close lc1; the deploy-runs anchor is the required confirmation signal.
- h-002: baseline silence (zero prior events) may reflect Falco not previously watching this image rather than novel adversary activity — the container-baseline lead must distinguish "no events logged" from "no events occurred" via Falco's coverage data before treating absence as strong h-002 support.

```yaml
mode: fork
selected_lead: container-baseline
loop_n: 1
```
