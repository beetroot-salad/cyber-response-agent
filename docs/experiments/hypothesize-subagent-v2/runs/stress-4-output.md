```yaml
gather:
  - id: l-002
    loop: 2
    name: container-baseline
    target: v-image-processor-2.1.0
    predictions:
      - {id: lp1, if: "prior 100001 events from registry.internal/image-processor:2.1.0 exist with proc.pname=node and proc.tty != 0", read_as: "interactive shell is in-class for this image; disposition leaning benign pending correlated-falco check", advance_to: correlated-falco-events}
      - {id: lp2, if: "no prior 100001 events from this image across the environment", read_as: "first-observed pattern; disposition ambiguous; weight of adversarial possibility increases", advance_to: correlated-falco-events}
      - {id: lp3, if: "prior 100001 events from this image exist but proc.pname differs (e.g., npm, python, sh — not node)", read_as: "image has shell history but not through this parent; partial baseline match; treat as lp2 for disposition", advance_to: correlated-falco-events}
  - id: l-003
    loop: 2
    name: correlated-falco-events
    target: v-container-a4c7d1e3
    predictions:
      - {id: lp1, if: "no co-firing 100002/100006/100007/100008 in ±5 min window for container a4c7d1e3", read_as: "isolated shell event; no escalation signal from co-firing", advance_to: conclude-on-baseline}
      - {id: lp2, if: "one or more of 100002 (file write to sensitive path) / 100006 (network connect from shell) / 100007 (privilege escalation attempt) / 100008 (credential file read) co-fire", read_as: "severity-escalating signals present; escalate regardless of baseline outcome", advance_to: conclude-escalate}
```

Note: HYPOTHESIZE is skipped for this loop. The confirmed `h-001 ?runtime-process` parent is settled; the remaining question is whether this image's behavior is in-class or out-of-class — a disposition attribute resolved by a trust-anchor lookup (`container-baseline`), not a mechanism sub-mechanism fork. No ≥2 competing classifications with diverging predictions on already-observable fields exist; the discriminating data is not yet known.

Selected lead: `container-baseline` — query historical 100001 events for `registry.internal/image-processor:2.1.0` across the environment, filtering to `proc.pname=node` and `proc.tty != 0`, to establish whether this image has a prior interactive-shell pattern.

Pitfalls:
- l-002: a single historical hit could represent a prior compromise of the same image, not a sanctioned shell-out pattern; confirm baseline events are spread across multiple container instances and/or correlate with known maintenance windows before grading as in-class.
- l-003: absence of co-firing Falco events does not confirm benign disposition — a sophisticated post-exploit operator may have already exited before the 5-min window, or may be operating slowly to avoid detection; co-firing absence removes one severity escalator, it does not add positive benign weight.
