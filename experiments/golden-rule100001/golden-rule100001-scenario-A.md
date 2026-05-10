# Golden reference — rule 100001 scenario A

**Alert shape**: Falco `Terminal shell in container`, `bash -c whoami`, `pname=runc`, container `target-endpoint`, user `root`, single event, monitoring-probe timing.

This is what the ideal investigation for this exact alert class should look like end-to-end. Used as a reference target for prompt / retrieval / validator work — compare live subagent outputs against the structural points below.

---

## CONTEXTUALIZE — prologue (post-fix-2, parent vertex promoted)

```yaml
prologue:
  vertices:
    - id: v-001
      type: container
      classification: devcontainer
      identifier: "target-endpoint (17bc2dde3fb0)"
    - id: v-002
      type: endpoint
      classification: internal-server
      identifier: "wazuh.manager"
    - id: v-003
      type: process
      classification: shell-process
      identifier: "bash"
      attributes:
        cmdline: "bash -c whoami"
        tty: "34816"
    - id: v-004                                 # ← promoted by fix (2)
      type: process
      classification: runtime-exec-primitive
      identifier: "runc"
    - id: v-005
      type: identity
      classification: local-account
      identifier: "root"
  edges:
    - id: e-001
      relation: spawned                         # ← load-bearing edge
      source_vertex: v-004
      target_vertex: v-003
      authority: {kind: runtime-audit, source: "Falco (rule 100001)"}
    - id: e-002
      relation: runs_in
      source_vertex: v-003
      target_vertex: v-001
    - id: e-003
      relation: runs_on
      source_vertex: v-001
      target_vertex: v-002
    - id: e-004
      relation: executed
      source_vertex: v-005
      target_vertex: v-003
```

**Narrative must acknowledge**:
- `pname=runc` ⇒ in-container-app archetypes (`container-init-script`, `app-spawned-shell`) are pre-refuted — the parent is a host-side runtime primitive, not an in-container daemon.
- Seed-layer fork is therefore collapsed; the *grandparent layer* (what host-side process spawned runc) is the live question.

## HYPOTHESIZE — one mechanism hypothesis, contract-gated (loop 1)

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?runtime-exec-from-host"
      attached_to_vertex: v-004                 # runc, not bash
      proposed_edge:
        relation: spawned
        parent_vertex:
          type: process
          classification: host-side-runtime-invoker
      story: |
        A process on the container host invoked `runc exec` to inject bash
        into the target-endpoint container. The syscall shape alone cannot
        distinguish invoker identity — legitimate invokers include CI runner
        agents, operator terminal sessions, and scheduled maintenance jobs;
        an adversary with docker-socket access or host compromise produces
        the same shape. The disposition depends on whether the invoking
        host-side process is authorized to exec into this container now —
        not on which kind of process it is.
      predictions:
        - id: p1
          subject: proposed_parent
          claim: "host-side ancestry of runc resolves to a named host process (CI binary, operator shell, scheduled job, or unrecognized)"
          from_story_link: "a process on the container host invoked runc exec"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "ancestry terminates inside the container namespace, OR runc is orphan (no reachable parent on host)"
      legitimacy_contract:
        - id: lc1
          edge_ref: proposed
          anchor_kind: deploy-runs
          asks: authorization
        - id: lc2
          edge_ref: proposed
          anchor_kind: oncall-schedule
          asks: authorization
      weight: null
```

**What's structurally right**:
- **One** mechanism hypothesis. Classification is authorization-neutral (`host-side-runtime-invoker`, not `ci-runner-agent` nor `adversary-controlled-*`).
- Two-contract legitimacy: an authorized verdict from either anchor satisfies the benign path; both returning `unauthorized` or `indeterminate` forces escalation.
- Attach point is `v-004` (runc), not `v-003` (bash) — the grandparent is what's being explained.
- Archetypes (`ci-pipeline-exec`, `operator-runtime-debug`, `post-exploit-interactive`) are **disposition-routing sub-cases**, resolved at CONCLUDE by the contract verdict + process-name enrichment from the lineage lead. They are NOT peer hypotheses at this stage.

**Selected lead**: composite — `process-lineage` (walk runc's ancestry on host via `host_query`) + `correlated-falco-events` (±15min, same container.id; playbook composition rule for 100002 / 100006 / 100007 / 100008).

## GATHER + ANALYZE — one loop

The composite lead's outcome determines disposition:

| Ancestry resolves to | Composition check | Anchor verdicts | Disposition | Archetype |
|---|---|---|---|---|
| Known CI binary (e.g. `gitlab-runner`, `github-runner`) | clean | `deploy-runs: authorized` | `benign` / `high` | `ci-pipeline-exec` |
| Interactive TTY under operator identity | clean | `oncall-schedule: authorized` OR `change-management: authorized` | `benign` / `high` | `operator-runtime-debug` |
| Scheduled job (cron / systemd-timer) | clean | `change-windows: authorized` | `benign` / `high` | `scheduled-maintenance` |
| Unrecognized binary or dropped/network-connected process | any | any | `escalated` / `high` | `post-exploit-interactive` |
| Any | **any dangerous co-fire (100002/100007/100008)** | any | `escalated` / `high` | `post-exploit-interactive` (composition-rule mandate) |
| Ancestry unreachable (host-query denied / host down) | — | — | `escalated` / `medium` | null (trust-root ceiling) |
| Ancestry resolves but all anchors `indeterminate` | clean | all `indeterminate` | `escalated` / `medium` | null (anchor gap) |

**ANALYZE grading**:
- `++` on `h-001.p1` only when ancestry is reached AND matches a specifically-classified upstream (not just "a process was there").
- `--` on `h-001.p1` requires `r1` to be met (ancestry in-container or orphan) — empirically rare for this alert.

## CONCLUDE

- Disposition routes from the ANALYZE table.
- `matched_ticket_id` when the confirming deploy-runs / change-management record exists and is cited inline.
- `trust_anchors_consulted` carries one entry per anchor queried, with `result: confirmed | indeterminate | unreachable` and `verdict: authorized | unauthorized | indeterminate`.

## Target metrics (orchestrator harness, Sonnet-main)

| Phase | Wall target | Historical min observed |
|---|---|---|
| CONTEXTUALIZE preload (parallel) | < 120s | 118.6s |
| HYPOTHESIZE loop 1 | < 200s | 144s (observed range 144-324s, see meta-finding #17) |
| GATHER + ANALYZE loop 1 | < 280s | 258s (125.9s + 132.8s) |
| CONCLUDE | < 45s | 25.7s |
| **Total single-loop** | **< 720s** | ~640s |

Two-loop investigations (when loop-1 can't resolve authorization) roughly double ANALYZE + GATHER; target < 1200s.

## Anti-patterns (negative examples from runs #43 and experiments A2/B3)

- ❌ Peer hypotheses on invoker identity (`?ci-pipeline-exec` vs `?adversary-controlled-host-exec`) — same mechanism, different legitimacy verdicts. Collapse to one hypothesis + `legitimacy_contract`.
- ❌ Peer hypotheses on two benign invokers (`?ci-pipeline-exec` vs `?operator-debug`) — two mechanisms with the same upstream edge shape and the same discriminator; still collapsible to one mechanism. Only split when predictions genuinely diverge beyond the contract anchor (rare at loop 1).
- ❌ Treating archetypes as peer hypotheses. Archetypes are candidate stories under one mechanism seed, resolved at CONCLUDE — not the fork shape at HYPOTHESIZE.
- ❌ Naming a hypothesis `?adversary-controlled-*` when the mechanism is the same as the benign alternative. The adversarial case lives in the `unauthorized` branch of the contract.
- ❌ Building refutation narratives on falco co-fires' description text ("possible reverse shell") without pulling the discriminating fields (`proc.name`, `evt.type`, connection tuple) via `--raw`. Documented failure class across runs #11, #27, #28, #38.
