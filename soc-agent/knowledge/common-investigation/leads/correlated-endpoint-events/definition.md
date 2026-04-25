---
name: correlated-endpoint-events
data_tags: [endpoint-events]
baseline: required       # Lead returns structured `baseline:` alongside foreground `characterization:` per §Baseline output shape. Co-fire patterns are interpretable only against the entity's recurring co-fire baseline.
---

## Goal

Retrieve and characterize correlated endpoint events around an alert — events from the same endpoint entity (container, host) in a tight window around the alert timestamp, to surface co-firing signals (other detection rules tripping on the same entity at the same time) and the geometric shape of each co-fire (parent process, network tuple, file path, etc.).

## What to Characterize (required output)

Each bullet below MUST be reported on, even if the answer is "not available" or "not observed." Omission is ambiguous to the main agent.

- **Co-firing rule set**: distinct rule ids that fired on the entity in the foreground window, with per-rule event count. Report as a list `[rule_id: count, …]`.
- **Per-rule geometry**: for each co-fired rule, name the discriminator dimensions visible in the raw events — parent process (`proc.pname`), local port (`fd.lport`), remote IP class (`fd.sip` against the entity's known address), executable path (`proc.exepath`), connection direction, file path. Compress dimensions that are uniform across the rule's events; list distinct values when not.
- **Temporal relationship to alert**: timing of co-fires relative to the alerting event — before, after, overlapping. If clustered, note the cluster span and gap.
- **Distinct artifact kinds**: enumerate the kinds of artifacts the co-fires reference (e.g., network connections, file reads, binary drops). The set itself is the discriminator — not whether any kind appears, but which.
- **Composition-rule triggers**: if the dispatching playbook names a "co-fire forces escalation" rule set, list which (if any) of those rules appear in the foreground. Report by rule id, not by category.

## Common Pitfalls

- **Treating co-fire presence as a refutation.** A rule firing on the same entity is not, by itself, an escalation signal — many endpoints have recurring background co-fire patterns (sshd dup2 events from a JDK-bundled sshd, periodic agent-keepalive rules, log-rotation file reads). The discriminator is whether the foreground co-fires deviate from the entity's baseline geometry, not whether they fire at all. The `## Baseline` output makes this comparison explicit.
- **Conflating Falco's `proc.name` with the actual binary identity.** Falco populates `proc.name` from the binary's argv[0] / executable basename, which can be misleading when a binary impersonates another (the JDK-bundled sshd shows `proc.name=sshd` with `proc.exepath=/usr/share/.../jdk/bin/java`). Always read `proc.exepath` from the raw event before reasoning about which binary actually fired the rule.
- **Direction-ambiguous network tuples.** A network rule's `fd.sip` / `fd.lport` describe the connection from the *event-capturing endpoint's* perspective. An inbound connection from the network on local port 22 with `fd.sip` = the connecting client is structurally indistinguishable in surface fields from an outbound connection to the same remote — read the raw event's evt.type / evt.dir field, not just the tuple.
- **Window boundaries.** Co-fire windows are typically ±15 min around the alert. Events at the edges may be coincidental; events that cluster near the alert timestamp (within seconds) and events that span the entire window have different interpretations. Report the cluster shape, not just the count.

## Baseline

- **When needed:** Always — this lead's output is meaningless without comparison. "26 rule:100002 events fired in the ±15min window" says nothing until the entity's recurring co-fire pattern is known. Same artifact kind at the same cadence with the same geometry is benign noise; deviation on geometry / cadence / artifact-kind is the discriminating signal.
- **Shift query:** Re-run the same entity-scoped query against a 7-day window with the same entity binding, no time-of-day restriction. Aggregate per-rule counts and extract recurring geometries (top dimensions per rule across the 7d window). This captures the entity's "what tends to fire alongside what" pattern — the comparison surface for foreground deviation predicates.
- **Output shape:** GATHER returns `baseline:` alongside `characterization:` with the same keys. Values come from the 7d aggregation: `co_firing_rule_set` is the per-rule count distribution over 7d (so foreground "26 rule:100002 events in 15min" can be compared to baseline "~340 rule:100002 events over 7d, mean ~25 per ±15min cluster"); `per_rule_geometry` lists the recurring dimensions per rule (so foreground geometry can be compared dimension-by-dimension); `distinct_artifact_kinds` is the set of kinds the entity has historically produced. `scope:` is `same-entity-7d` by default, `same-image-7d` for container entities when image is more discriminating than container.id (see template).
- **Interpretation:** The discriminator is *deviation from the baseline geometry*, not co-fire presence. Refutation predicates that name "deviation from the recurring baseline geometry on at least one recorded dimension" or "an artifact kind absent from the 7d baseline" are the falsifiable shapes; "rule X fired" is a presence-test (per `agents/predict.md` §Story authoring — Baseline grounds predictions). When the baseline returns empty (entity is new, no 7d history), report that — a `0 → N` foreground appearance with no baseline is stronger evidence than the same N against an established baseline.

## Templates

Per-vendor query templates live under `templates/{vendor}.md`. Currently: `wazuh.md`.
