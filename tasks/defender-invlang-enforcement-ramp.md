---
title: Defender invlang validator — deferred rules blocked on spec self-contradictions
status: todo
groups: defender, invlang, reliability
---

**Shipped.** `defender/hooks/invlang_validate.py` enforces the current
invlang spec on `investigation.md` writes, **blocking** (exit 2) on any
violation. Five rules, all crisp current-spec (rules in
`defender/skills/invlang/validate.py`):

1. parse-clean — any parser `ParseWarning` blocks.
2. append-only — `​```invlang` block count must not shrink.
3. edge-authority — `++`/`--` resolutions must cite a
   siem-event/runtime-audit/authoritative-source edge.
4. closed-vocab — vertex `type`, edge `rel`, authz `anchor_kind`, edge
   `auth_kind` ∈ `vocab`.
5. benign-gating — `disposition: benign` requires no open `??` slot and
   every surviving-hypothesis authz contract resolved `authorized`.

Pre-MVP, historical runs on earlier invlang variants are expected to fail
— intentional. `test_skill_worked_examples_all_pass` guards that the
runtime SKILL never teaches invlang the hook blocks (the stale Example A —
`type=endpoint`, `file:binary`, prose-cited resolutions — was fixed to
current grammar as part of this work).

**Open: two more current-spec rules are deferred because the spec
contradicts its own worked examples.** Don't enforce them until the spec
is reconciled, or they'll false-positive on valid current writes:

- **Per-type class-slot grammar.** `skills/invlang/SKILL.md` §Classification
  grammar defines slash-tuples per type with slot enums in `vocab.py`, but
  its §Open-questions worked example uses `class=monitoring-agent/…` while
  `COMPUTE_ROLE` only has `monitoring` (no `monitoring-agent`). A strict
  per-slot check would reject the spec's own example. *Fix:* reconcile the
  role enum vs the examples (add `monitoring-agent`, or correct the
  examples to `monitoring`), settle the `??` / `{a,b,c}` / `unclassified-*`
  / `ambiguous-*-or-*` escape grammar, then implement + enforce.
- **Sibling-fork topological uniqueness.** §Sibling-fork uniqueness says
  sibling hypotheses must differ on a topological axis
  (`parent_type`/`parent_class`/`attached_to`/`rel`), but the
  §Discovery-hypotheses worked example forks `h-001`/`h-002` that are
  identical on all four axes (both `v-001|runs_on|process|unclassified-process`),
  differing only on `?name` + predictions — which that same section
  explicitly endorses when `parent_class` is unknown. *Fix:* decide
  whether name+prediction divergence counts as distinctness (and how to
  detect it), update the spec, then enforce.

Both are spec-owner decisions, not validator bugs. File-and-hold here
until the canonical SKILL is internally consistent.
