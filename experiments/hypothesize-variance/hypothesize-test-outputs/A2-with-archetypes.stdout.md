The alert's `pname=runc` immediately collapses the three-way playbook seed fork: `?image-entrypoint` and `?runtime-process` are both refuted by the runtime exec primitive in the parent field. The surviving mechanism is `?underlying-host`. The remaining fork is at the sub-archetype layer — `ci-job-executor-process` vs `operator-terminal-process`. `k8s-exec-probe` is already ruled out (null k8s context). The cmdline `bash -c whoami` with its `-c` flag lightly favors the CI shape, but `?operator-runtime-debug` is not collapsed — operators do issue one-liner diagnostic execs. Cadence pattern from `container-baseline` is the most accessible discriminator.

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?ci-pipeline-exec"
      attached_to_vertex: v-002
      proposed_edge:
        relation: spawned
        parent_vertex: {type: process, classification: ci-job-executor-process}
      story: |
        A CI/CD job executor process on the container host was scheduled to run a
        pipeline step (post-deploy health check, smoke test, or similar). The executor
        invoked the container runtime (runc), which injected bash into the container
        namespace carrying `bash -c whoami` — a non-interactive, single-shot scripted
        exec that exits immediately once the command completes. If the parent is
        genuinely a CI executor, the same image will show prior similar shell
        invocations at the cadence of the pipeline schedule in the 7-30 day baseline.
      predictions:
        - id: p1
          subject: proposed_parent
          claim: "the proposed ci-job-executor parent will have exec'd into this container image on prior pipeline runs, producing a cadence of similar bash -c shell events from runc visible in the container-baseline 7-30 day window"
          from_story_link: "scheduled to run a pipeline step... non-interactive, single-shot exec"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "container-baseline shows no prior similar bash -c events from runc for this image in the 7-30 day window (first occurrence or irregular)"
      legitimacy_contract:
        - id: lc1
          edge_ref: proposed
          anchor_kind: deploy-runs
          asks: authorization
      weight: null

    - id: h-002
      name: "?operator-runtime-debug"
      attached_to_vertex: v-002
      proposed_edge:
        relation: spawned
        parent_vertex: {type: process, classification: operator-terminal-process}
      story: |
        An operator's docker client (or equivalent runtime CLI) on the container
        host issued a quick ad-hoc diagnostic one-liner — `docker exec <container>
        bash -c whoami` — to rapidly check process identity without opening a full
        interactive session. Runc received the exec call and injected bash. If the
        parent is an operator terminal, this event has no regular cadence: it is
        isolated or irregular, tied to a specific troubleshooting event rather than
        a pipeline schedule.
      predictions:
        - id: p1
          subject: proposed_parent
          claim: "the proposed operator-terminal-process parent produces no recurring cadence of similar shell invocations for this image; container-baseline shows this event is isolated or pattern-irregular in the 7-30 day window"
          from_story_link: "ad-hoc diagnostic one-liner... no regular cadence"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "container-baseline shows a regular cadence of bash -c events from runc for this image consistent with a pipeline schedule"
      legitimacy_contract:
        - id: lc1
          edge_ref: proposed
          anchor_kind: oncall-schedule
          asks: authorization
        - id: lc2
          edge_ref: proposed
          anchor_kind: change-windows
          asks: authorization
      weight: null
```

**Selected lead:** composite of `container-baseline` + `correlated-falco-events` — `container-baseline` measures cadence for image `cyber-response-agent_devcontainer-target-endpoint` over the 7-30 day window; regular pipeline cadence confirms h-001, absent/irregular cadence supports h-002. `correlated-falco-events` is mandatory per the composition rule: any co-firing of 100002/100006/100007/100008 in `container.id=17bc2dde3fb0` within ±15 min of 17:07:02Z forces immediate escalation regardless of which hypothesis the cadence favors.

**Pitfalls:**
- h-001: A genuine first-ever CI run against this image produces no baseline cadence — absence of prior events in `container-baseline` cannot by itself distinguish "new pipeline" from "operator one-liner." The `deploy-runs` anchor (lc1) is the required tiebreaker; absent cadence alone must not drive h-001 to `--`.
- h-002: `bash -c whoami` is an operator one-liner pattern but also exactly what a CI smoke test produces. Cmdline shape cannot confirm operator identity. An operator who habitually uses `-c` one-liners is observationally indistinguishable from a CI step on the alert alone; anchor consultation (lc1 `oncall-schedule` or lc2 `change-windows`) is required before h-002 reaches `++`.

```yaml
mode: fork
selected_lead: container-baseline
loop_n: 1
lead_hint: "dispatch composite with correlated-falco-events per playbook rule; container-baseline characterizes cadence for image cyber-response-agent_devcontainer-target-endpoint over 7-30 days; correlated-falco-events checks rules 100002/100006/100007/100008 in container.id 17bc2dde3fb0 ±15 min of 2026-04-22T17:07:02Z"
```
