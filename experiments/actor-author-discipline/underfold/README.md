# Underfold stress test

Focused stress test on **one variable**: does the actor author fold an observation into an existing lesson whose teaching covers it, or does it create a new sibling file?

Lives inside the broader `actor-author-discipline/` experiment but uses its own seeds + probes + harness wrapper to keep the signal clean.

## Layout

```
underfold/
  seeds/lessons-actor/{tradecraft,environment}/*.md   # 3 hand-crafted seeds
  probes/actor_observations.jsonl                     # 4 probes
  probes/runs/{probe_run_id}/actor_story.md           # minimal source bundles
  run.sh                                              # wrapper around ../harness.py
  analyze.py                                          # per-probe outcome tabulator
  runs/trial-{1..4}/                                  # harness output
  results.md                                          # final tabulation + decision
```

## Seeds

| Channel | Slug | Targeted by |
|---|---|---|
| tradecraft | `credential-spray-stagger` | P1 (fold), P4 (fold-extends) |
| tradecraft | `dev-container-label-cover` | — (distractor; no probe should land here) |
| environment | `docker-exec-args-not-in-audit` | P2 (fold) |

## Probes

| ID | Expected | Targets seed |
|---|---|---|
| P1 | fold | tradecraft/credential-spray-stagger |
| P2 | fold | environment/docker-exec-args-not-in-audit |
| P3 | new | (none — distractor; guards against pure-fold prior) |
| P4 | fold-extends | tradecraft/credential-spray-stagger |

## Decision

- Fold rate ≥ 3/4 on P1+P2 with P3 staying `new` → underfolding **not** dominant.
- Fold rate ≤ 2/4 on P1 or P2 → underfolding confirmed; iterate prompt.
- P4 ~50% split → expected gray zone.
