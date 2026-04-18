```yaml
gather:
  - id: l-001
    loop: 1
    name: shell-context
    target: v-shell-bash
    predictions:
      - {id: lp1, if: "exec caller maps to a named operator identity (kubectl exec audit log, SSH session, or interactive terminal tied to a registered user)", read_as: "sanctioned-operator-action", advance_to: container-baseline}
      - {id: lp2, if: "exec caller maps to an automated process or service account with no change-window record", read_as: "unsanctioned-automation-origin", advance_to: correlated-falco-events}
      - {id: lp3, if: "exec caller is unresolvable (no audit event, no session record)", read_as: "unattributed-exec", advance_to: correlated-falco-events}
```

Note: HYPOTHESIZE skipped — the direct parent of `v-shell-bash` is already observable as `runc` (`proc.pname`), confirming a runtime-exec primitive in the chain. The mechanism classification (`runtime-exec-injection`) is resolved by the alert itself; no competing parent-vertex classifications remain. The open question is the sanctioned/adversarial attribute of the exec caller, which is an identity attribute resolved by trust-anchor lookup, not a mechanism fork. GATHER routes directly to that lookup.

Selected lead: `shell-context` — resolves exec-caller identity from runtime audit log or `kubectl exec` API server record. Single dispatch against the container runtime or orchestrator audit trail.

Pitfalls:
- (no hypotheses, so no per-hypothesis pitfalls to list; lead-level trap: a legitimate operator may have invoked the exec without filing a change ticket — absence of a ticket does not classify as adversarial; check registered-operator identity first, then change-window compliance)
