# Loop 3 — HYPOTHESIZE decision: recovery-A

## Decision: no HYPOTHESIZE block — emit GATHER only

```yaml
gather:
  - id: l-003
    loop: 3
    name: host-process-attribution
    target: v-shell-bash
    observations:
      - id: obs-001
        source_type: runtime-audit
        record: "type=SYSCALL syscall=execve pid=29441 comm=bash ppid=29437 parent_comm=runc exe=/usr/bin/bash tty=pts/0 uid=0"
        read_as: "bash was spawned directly by runc (pid 29437), not by node or any in-container-runtime-descendant process — the pid-namespace view in the Falco aname chain was an artifact of the container's PID namespace, not the host-side parent"
      - id: obs-002
        source_type: authoritative-source
        record: "kubectl API audit log: pods/exec subresource invoked on this container by sa-deploy-bot at alert timestamp"
        read_as: "exec primitive was a kubectl exec invocation by service-account sa-deploy-bot; origin is a runtime exec injection, not an in-container workload action"
    assessments:
      - hypothesis: h-001
        weight: "--"
        rationale: >
          Host-side auditd (runtime-audit edge) shows runc as the direct parent of bash.
          The loop-1 ++ grading was based solely on the container's pid-namespace aname view,
          which does not reflect the true host-side parent. An adapter-error blocked the
          extended ancestry walk at loop 1; that gap should have prevented any grading.
          The auditd record is the authoritative source and directly contradicts
          p1 of h-001 (no runtime exec primitive in the chain). h-001 is refuted.
      - hypothesis: h-002
        weight: null
        note: >
          h-002 ?underlying-host was shelved at loop 1 and cannot be un-shelved (append-only).
          No weight entry is added. The auditd and kubectl evidence is recorded here as
          direct SIEM/audit evidence; the CONCLUDE step will resolve to runtime-exec-injection
          based on this loop's observations, without relying on h-002's prior weight.
```

Selected lead: `host-process-attribution`

Pitfalls:
- (no active hypotheses; h-001 is now refuted by `--`; h-002 remains shelved with no weight entry; no new hypothesis was opened)

---

## Recovery rationale

**Option chosen:** emit no HYPOTHESIZE block; let loop 3 be a pure GATHER that records the auditd and kubectl audit evidence, producing `--` on h-001 in the ANALYZE step.

**Why not a new hypothesis:** the discipline says "no HYPOTHESIZE without a fork — enter only when ≥2 competing classifications have predictions that diverge on already-observable fields." At this point there is no fork. The auditd record is definitive: `runc` is the direct parent. A mechanism fork between `in-container-runtime-descendant` and `runtime-exec-injection` can only be written when the discriminating data is not yet known. Here it is known — the distinction has already collapsed. Emitting a new hypothesis named `?underlying-host` or `?runtime-exec-injection` would be writing a hypothesis whose outcome is already determined by the evidence in hand; the discipline explicitly says emit GATHER with lead-level `read_as` in that case, not a speculative HYPOTHESIZE block.

**Why not re-open h-002:** append-only means shelved hypotheses stay shelved. h-002's weight history is frozen at the loop-1 state. There is no "un-shelve" operation in the schema. This is not a loss: h-001's cumulative assessment is now `++ then --`, which nets to a refuted hypothesis. CONCLUDE can resolve to the `runtime-exec-injection` archetype without h-002 having an active weight — the conclusion follows from h-001 being refuted and the auditd/kubectl evidence naming the mechanism directly.

**How append-only is respected:** the loop-1 `++` entry on h-001 is not touched. A new `--` weight entry is added in loop-3 ANALYZE. Both entries coexist in the append-only log. The CONCLUDE step reads the full weight history and derives the net assessment. h-002's shelved status is similarly untouched.

**The loop-1 gap:** the adapter-error on the extended ancestry walk should have blocked the loop-1 `++` grading (the evidence was insufficient). Recording this in the loop-3 `rationale` field is the appropriate place to document the prior grading error — the investigation log is append-only, but rationale text can acknowledge what the prior evidence failed to establish.
