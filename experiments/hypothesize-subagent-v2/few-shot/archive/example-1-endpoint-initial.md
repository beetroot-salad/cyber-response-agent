# Example 1 — endpoint, initial loop (positive)

Signature: `wazuh-rule-100001`. Loop 1 HYPOTHESIZE. Shows a clean
mechanism fork when the alert's `aname` is truncated.

## Alert

```
rule.id:          100001
container.image:  registry.internal/web-frontend:2.3.1
proc.name:        bash
proc.cmdline:     "bash"                # interactive-looking, no -c
proc.pname:       sh
proc.aname[2..4]: ["sh", "node", "/app/launcher.sh"]
proc.aname[5+]:   <truncated at runtime-capped depth>
proc.tty:         != 0
```

## State at entry

CONTEXTUALIZE confirmed prologue (`v-shell-bash`, `v-container-3f9a1c2d`,
`v-image`). Archetype scan: `app-spawned-shell` / `post-exploit-interactive`
both moderate (under `?runtime-process`); `operator-runtime-debug` weak.
No ticket-context co-firing. ASSESS: above the truncation the chain
could either continue to container init (`?runtime-process`) or cross
into host via `runc`/`containerd-shim` (`?underlying-host`). Fork exists.

## HYPOTHESIZE output

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?runtime-process"
      attached_to_vertex: v-shell-bash
      proposed_edge:
        relation: spawned
        parent_vertex:
          type: process
          classification: in-container-runtime-descendant
      predictions:
        - id: p1
          claim: "ancestry above aname[4]=/app/launcher.sh resolves to an
            in-container init wrapper (tini / dumb-init / custom launcher)
            with no runtime exec primitive in the chain"
      refutation_shape:
        - id: r1
          claim: "runc / containerd-shim / docker-exec / crictl appears in
            the extended chain above /app/launcher.sh"
      weight: null
    - id: h-002
      name: "?underlying-host"
      attached_to_vertex: v-shell-bash
      proposed_edge:
        relation: spawned
        parent_vertex:
          type: process
          classification: runtime-exec-injection
      predictions:
        - id: p1
          claim: "extending ancestry shows a runtime exec primitive
            (runc / containerd-shim / docker-exec / crictl) immediately
            above /app/launcher.sh"
      refutation_shape:
        - id: r1
          claim: "chain continues to a container-init wrapper with no
            exec primitive crossing to host"
      weight: null
```

**Selected lead:** `shell-context` (extended ancestry walk) — query the
container runtime API for the full process tree of `v-shell-bash`,
bypassing the event's depth cap. Single measurement partitions the fork.

**Pitfalls:**
- h-001: the same topology is consistent with a post-exploit shell spawned
  *through* node (RCE) — mechanism confirmation does not discriminate
  benign-vs-adversarial. That is an image-baseline anchor question.
- h-002: a long-lived operator `docker exec` session left running across
  user actions produces the same truncated chain as an attacker injection.
  Mechanism is topology only; *who invoked the exec* resolves at anchor
  time via `oncall-schedule` / `deploy-runs`.

## Why this is good

- One proposed parent vertex per hypothesis, one predicted attribute each.
- Third mechanism (`?image-entrypoint`) pruned by observable: `aname[4]`
  is `/app/launcher.sh`, not a boot-time entrypoint.
- No parallel adversarial hypothesis — adversarial-vs-benign is deferred
  to anchor layer, as called out in the pitfalls.
- Single-lead discrimination; no composite needed.
