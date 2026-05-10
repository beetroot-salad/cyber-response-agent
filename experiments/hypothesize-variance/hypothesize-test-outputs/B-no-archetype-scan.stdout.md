Past-investigation priors unavailable (corpus module error). Proceeding on alert telemetry and signature knowledge alone.

**Fork setup.** `pname=runc` is a runtime exec primitive — it unambiguously places this alert under the `?underlying-host` seed. The other two seeds (`?image-entrypoint`, `?runtime-process`) are pre-refuted by the alert telemetry and produce no hypotheses. Within `?underlying-host`, three archetypes are normally candidates:

- `k8s-exec-probe` → ruled out: `k8s.pod.name=null`, `k8s.ns.name=null`
- `operator-runtime-debug` → excluded from peer fork: `cmdline=bash -c whoami` uses `-c` (scripted). The archetype story explicitly requires an interactive cmdline (bare shell, `-i`, or no `-c`). The scripted pattern doesn't fit; including it as a peer hypothesis would require invoker-identity-as-classification discrimination, not mechanism discrimination.
- `ci-pipeline-exec` → candidate
- Adversarial host exec (no named archetype, but real mechanism) → candidate

The surviving fork is on what host-side process invoked runc.

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
        A CI runner agent on the host invoked runc (v-003) to exec bash into
        container 17bc2dde3fb0 as a scripted one-shot pipeline step. The cmdline
        `bash -c whoami` is consistent with an identity-check or environment-probe
        step in a CI job — the process runs, reports the container's effective
        user, and exits immediately. The host-side parent is a recognized CI agent
        binary (gitlab-runner, jenkins-agent, GitHub Actions runner, or equivalent);
        its ancestry on the host traces to a known CI service. The container image
        has an established cadence of similar bash -c invocations in the recent
        baseline, consistent with recurring pipeline runs. A matching CI run record
        exists in the deploy-runs log at T≈17:07:02Z targeting this container.
      legitimacy_contract:
        - id: lc1
          edge_ref: proposed
          anchor_kind: deploy-runs
          asks: authorization
      predictions:
        - id: p1
          subject: proposed_parent
          claim: >
            host-side ancestry of runc (v-003) traces to a recognized CI agent
            binary (gitlab-runner, jenkins-agent, GitHub Actions runner, or similar)
            with no interactive shell or unrecognized process in the chain
          from_story_link: "recognized CI runner agent on the host invoked runc"
        - id: p2
          subject: proposed_parent
          claim: >
            this container image shows a recurring pattern of bash -c invocations
            in the 7-30 day baseline consistent with periodic CI pipeline runs
            (regular cadence, identical or near-identical cmdlines)
          from_story_link: "scripted one-shot probe consistent with a recurring CI pipeline step"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "host-side lineage of runc traces to an interactive shell, cron daemon, unrecognized binary, or post-exploit chain — not a recognized CI agent binary"
        - id: r2
          refutes_predictions: [p2]
          claim: "container-baseline shows no prior bash -c events for this image, or events appear at irregular one-off intervals inconsistent with a CI schedule"
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
        An adversary-controlled process on the host — not a recognized CI agent
        or authorized operator tool — invoked runc (v-003) to inject bash into
        container 17bc2dde3fb0. The cmdline `bash -c whoami` is a reconnaissance
        probe: the attacker determining what identity they hold inside the container
        before proceeding with follow-on activity. The host-side process that invoked
        runc is not traceable to any registered CI runner binary or scheduled pipeline
        run. User loginuid=-1 (no PAM session) is consistent with a docker exec-style
        injection from any host-side process, authorized or not — it does not
        discriminate between CI and adversary origin. No CI run record in the
        deploy-runs log correlates with this container and timestamp.
      predictions:
        - id: p1
          subject: proposed_parent
          claim: >
            host-side ancestry of runc (v-003) traces to a process not associated
            with any recognized CI runner binary or authorized operator session on
            this host
          from_story_link: "adversary-controlled process — not a CI agent — invoked runc from the host"
        - id: p2
          subject: proposed_edge
          claim: >
            the exec invocation at T=17:07:02Z has no corresponding CI run record
            in the deploy-runs log for container 17bc2dde3fb0 or host target-endpoint
            within ±5 min of the alert timestamp
          from_story_link: "no CI pipeline run correlates with this timestamp and container"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "host-side lineage of runc resolves to a recognized CI runner agent binary"
        - id: r2
          refutes_predictions: [p2]
          claim: "deploy-runs returns a matching CI run record at T≈17:07:02Z targeting container 17bc2dde3fb0 or host target-endpoint"
      weight: null
```

**Selected lead:** `container-baseline` (composite dispatch with `correlated-falco-events`) — container-baseline tests h-001 p2 (recurring bash -c cadence for this image over 7-30 days) and provides the baseline anchor against which the timing of this alert is assessed; correlated-falco-events is a mandatory composition-rule check (playbook §Composition rules) for rules 100002/100006/100007/100008 from `container.id=17bc2dde3fb0` in a ±15 min window, required regardless of which hypothesis advances.

If container-baseline shows recurring cadence → supports h-001 p2, advances to deploy-runs anchor (lc1) and process-lineage for p1.
If container-baseline shows first-ever occurrence or off-cadence one-off → r2 fires against h-001, advances h-002.
If correlated-falco-events returns any of 100002/100006/100007/100008 → mandatory escalation per composition rule regardless of hypothesis weight.

**Pitfalls:**
- h-001: A recurring cadence in container-baseline is circumstantial support, not confirmation. Cadence alone cannot close lc1 — both the baseline cadence AND a matching deploy-runs run record are required for `disposition: benign`. An adversary who execs at regular intervals mimicking a CI schedule would produce the same cadence signal.
- h-002: Absence of dangerous co-firing Falco rules (100002/100006/100007/100008) in the ±15 min window does not refute h-002. A careful attacker issuing only `bash -c whoami` as an initial probe will not trigger downstream Falco rules in that window. Treat zero co-firing as non-evidence, not h-002 refutation.
- `correlated-falco-events` (composition rule): rule 100002 fires on sshd dup2 calls during normal SSH session setup — this is expected behavior for any accepted SSH connection into the container. Filter by `proc.name` before treating a 100002 event as the dangerous "network redirect" the composition rule targets. sshd-sourced 100002 events are lower-severity than shell- or unknown-process-sourced 100002.

```yaml
mode: fork
selected_lead: container-baseline
loop_n: 1
```
