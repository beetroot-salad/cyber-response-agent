---
title: A/B test visibility-aware vs visibility-blind learning-loop actor
status: done
groups: learning-loop, actor, experiment
---

**Result (2026-05-08): blind wins.** 4 fixtures × {blind, aware} × N=1,
$1.10. Blind produced 3 actionable findings (2 playbook reformulations,
1 observability-finding); aware produced 0 (4/4 duplicates of existing
leads). Decision logged in `docs/learning-loop-actor-design.md`. Run
artifacts in `/tmp/ab-exp/`.

---

Resolve the one open question in `docs/learning-loop-actor-design.md`:
should the adversarial actor see `defender/skills/{system}/` Visibility
surface excerpts as part of its input?

**Hypothesis.** Visibility-blind actor produces lessons that extend
playbooks (defender-internal). Visibility-aware actor produces lessons
that extend the systems tree (deployment posture). For the
investigation-learning purpose of this loop, blind is the better
default.

**Setup.**
- Single actor prompt with a `{visibility_block}` slot. Blind arm =
  empty; aware arm = relevant Visibility surface excerpts injected.
- Fixtures: existing 8 trials at `/tmp/actor-exp/exposure-2/` plus
  synth-01-ssh (where T1550.001 was the held-out lesson).
- Same judge across both arms.

**Decision criterion.**
- Judge tags each finding with `target_surface ∈ {playbook, archetype,
  systems, observability_gap}`.
- Compare arms on (a) distribution of `target_surface` and
  (b) fraction of breaking-evidence queries that resolve to a feasible
  defender dispatch.
- Pick the arm with higher playbook-shaped lesson rate. On a small
  split, default to blind.

**Out of scope until A/B settles.** Visibility-block scoping (which
systems' surface to inject when aware), orchestrator implementation,
judge prompt revisions.
