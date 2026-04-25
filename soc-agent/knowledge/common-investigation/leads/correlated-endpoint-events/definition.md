---
name: correlated-endpoint-events
data_tags: [endpoint-events]
baseline: required       # Lead returns structured `baseline:` alongside foreground `characterization:` per §Baseline output shape. Co-fire patterns are interpretable only against the entity's recurring co-fire baseline.
---

## Goal

Retrieve and characterize correlated endpoint events around an alert — events from the same endpoint entity (container, host, workstation) in a tight window around the alert timestamp, to surface co-firing signals (other detection rules tripping on the same entity at the same time) and the structural shape of each co-fire.

## What to Characterize (required output)

Each bullet below MUST be reported on, even if the answer is "not available" or "not observed." Omission is ambiguous to the main agent.

- **Co-firing rule set**: distinct rule ids that fired on the entity in the foreground window, with per-rule event count.
- **Per-rule geometry**: for each co-fired rule, the structural dimensions visible in the raw events that make the event distinguishable — actor process attributes, network tuple direction, file path, syscall kind, identity-of-use. Compress dimensions that are uniform across the rule's events; list distinct values when not. The vendor template names the specific fields that carry these dimensions.
- **Temporal relationship to alert**: timing of co-fires relative to the alerting event — before, after, overlapping. If clustered, note the cluster span and gap.
- **Distinct artifact kinds**: enumerate the kinds of artifacts the co-fires reference (e.g., network connections, file reads, binary drops, credential operations). The set itself is the discriminator — not whether any kind appears, but which.
- **Composition-rule triggers**: if the dispatching playbook names a "co-fire forces escalation" rule set, list which (if any) of those rules appear in the foreground. Report by rule id, not by category.

## Common Pitfalls

- **Treating co-fire presence as a refutation.** A rule firing on the same entity is not, by itself, an escalation signal — many endpoints have recurring background co-fire patterns (system services, agent keepalives, scheduled jobs, log rotation). The discriminator is whether the foreground co-fires deviate from the entity's baseline geometry, not whether they fire at all. The `## Baseline` output makes this comparison explicit.
- **Surface labels can lie.** A rule's surface label or the actor's reported name can misidentify the underlying mechanism — a binary may be reported under a different name than its actual executable, a network rule's tuple may describe the connection from a perspective that obscures the direction. Always read whichever raw fields are load-bearing for the discrimination question, not just the rule's headline. The vendor template enumerates which fields disambiguate which surface labels.
- **Window boundaries.** Co-fire windows are typically ±15 min around the alert. Events at the edges may be coincidental; events that cluster near the alert timestamp (within seconds) and events that span the entire window have different interpretations. Report the cluster shape, not just the count.

## Baseline

- **When needed:** Always — this lead's output is meaningless without comparison. "26 events of rule X fired in the ±15min window" says nothing until the entity's recurring co-fire pattern is known. Same artifact kind at the same cadence with the same geometry is benign noise; deviation on geometry / cadence / artifact-kind is the discriminating signal.
- **Shift query:** Re-run the same entity-scoped query against a 7-day window with the same entity binding, no time-of-day restriction. Aggregate per-rule counts and extract recurring geometries (top dimensions per rule across the 7d window). This captures the entity's "what tends to fire alongside what" pattern — the comparison surface for foreground deviation predicates.
- **Output shape:** GATHER returns `baseline:` alongside `characterization:` with the same keys. Values come from the 7d aggregation: `co_firing_rule_set` is the per-rule count distribution over 7d (so foreground "26 events of rule X in 15min" can be compared to baseline "~340 events of rule X over 7d, mean ~25 per ±15min cluster"); `per_rule_geometry` lists the recurring dimensions per rule (so foreground geometry can be compared dimension-by-dimension); `distinct_artifact_kinds` is the set of kinds the entity has historically produced. `scope:` is `same-entity-7d` by default; the vendor template documents alternates (e.g., `same-image-7d` when the container.id rotates faster than the meaningful baseline window).
- **Interpretation:** The discriminator is *deviation from the baseline geometry*, not co-fire presence. Refutation predicates that name "deviation from the recurring baseline geometry on at least one recorded dimension" or "an artifact kind absent from the 7d baseline" are the falsifiable shapes; "rule X fired" is a presence-test (per `agents/predict.md` §Story authoring — Baseline grounds predictions). When the baseline returns empty (entity is new, no 7d history), report that — a `0 → N` foreground appearance with no baseline is stronger evidence than the same N against an established baseline.

## Templates

Per-vendor query templates live under `templates/{vendor}.md`. The template enumerates the entity-field mappings, the discriminator fields that disambiguate per-rule geometry, and the vendor-specific shift-query syntax.
