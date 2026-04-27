---
title: Move key-entity enrichment into CONTEXTUALIZE (CMDB-style + mechanical extraction)
status: doing
groups: contextualize, cost-optimization, signature-content
---

**Goal.** Resolve key alert entities (source IP, identity tuple, target host, container/image where applicable) into typed context at CONTEXTUALIZE time, before PREDICT runs loop 1. The two operations:

1. **Mechanical extraction** — for entity classes whose category is derivable by matching the alert field against a static reference (`knowledge/environment/context/ip-ranges.md`, `identity-patterns.md`, similar). Source-classification, username-classification, and target-classification fall here. No SIEM, no subagent — pure handler-side string matching against the reference files.
2. **CMDB-style lookup** — for entity classes whose authoritative state lives outside the alert (registered-actor approval, host inventory metadata, deployment role). Org-authority registry lookups (`approved-monitoring-sources`, `scheduled-jobs`) and host-state probes (`host_query.py service-status`, `package-installed`) belong here when the question is "what is this entity, baseline, regardless of this specific alert."

Both produce typed prologue facts that PREDICT consumes as known state — not as predictions to test.

## Why

Run `20260426-020541-rule5710` postmortem: ~40–45% of the ~26-minute wall clock was pre-fork or off-contract enrichment work that the lead-catalog framing forced into GATHER. Loop 1 ran source-classification + username-classification through `gather-composite` (Sonnet, 193s). Both are static lookups against reference files that `contextualize-prologue` already has access to. Loop 2's anchor confirmation (`approved-monitoring-sources` triple match) was structurally an entity-state question, not a hypothesis-discriminating question — it would have been answerable at CONTEXTUALIZE if the registry lookup were a CONTEXTUALIZE primitive. PREDICT loop 1 therefore had to fork on differentiators it didn't yet have classified evidence for, which dragged subsequent loops into re-litigating "is this an approved monitoring source" rather than "what is this monitoring source doing that's anomalous."

The pattern generalizes beyond 5710. Every signature has alert fields whose category is alert-shape-derivable (any srcip vs ip-ranges, any srcuser vs identity-patterns, any container.image vs known-image-baselines). Doing that work in GATHER taxes Sonnet on dispatches that Haiku-or-Python could do for free.

## Scope

**In:**
- New CONTEXTUALIZE handler step: `entity_enrichment.py` — runs after `contextualize-prologue` returns, before phase transitions to SCREEN/PREDICT. Reads alert.json + the matching `knowledge/environment/context/*.md` reference files; emits typed entries into `prologue.entity_classifications: []` (new top-level field on the prologue YAML block).
- A registered-CMDB-lookup primitive — initial implementations: `approved-monitoring-sources` (registry table lookup), `host_query.py service-status` for the source/target host. Each lookup is gated by the matching `prologue.vertices[].kind` so a lookup that doesn't apply (e.g. host-state when there's no hostname vertex) is skipped without dispatch.
- Update `agents/predict.md` Shape descriptions: PREDICT consumes `entity_classifications` as preloaded state; predictions framed against entity baseline are first-class (see related task `tasks/predict-baseline-deviation-shape.md`).
- Migrate `source-classification` and `username-classification` lead definitions: deprecate from the lead catalog, replace with mechanical-extraction entries in the new CONTEXTUALIZE step. Existing GATHER calls become a no-op fallback (phase still emits a `gather:` block with `status: skipped, reason: classifications_in_prologue`) to keep older signatures' playbooks compiling without rewrite.
- Add invlang validator rule: a hypothesis whose predictions reference an entity classification must cite it from `prologue.entity_classifications`, not redeclare it.

**Out:**
- Hypothesis-discriminating queries (auth history, baseline cadence, correlated-falco-events). Those stay in GATHER — they're per-hypothesis evidence, not per-entity classification.
- Adversarial-refutation lookups (audit-channel queries). Those are PREDICT-driven refutations, not entity baseline.
- Multi-vendor CMDB integration (Service Now / Jira / etc.). Initial scope is the static-table + `host_query.py` set already in `knowledge/environment/`. External-CMDB onboarding is a separate task.

## Acceptance

- One mature-playbook fixture (rule 5710 scenario A) runs **without dispatching `source-classification` or `username-classification` as gather leads**. Both classifications appear in `prologue.entity_classifications` with `kind: ip-class` / `kind: identity-class` and the matched reference rule cited.
- One mature-playbook fixture exercises the CMDB-style lookup primitive (`approved-monitoring-sources` triple match for 5710 scenario A). The match appears in CONTEXTUALIZE output before SCREEN, not as a GATHER lead in loop 2.
- PREDICT loop 1 prompt size drops measurably (target: −30% on the 5710 scenario A baseline run #14 prompt).
- No regression on the orchestrator full-loop fixtures (5710 bait, 100001 whoami): same disposition, same matched_archetype, same trust_anchors_consulted citations.
- Author skill updated: signature playbooks can declare which mechanical-extraction reference files apply (so a wazuh-rule-100001 author can opt out of identity-class enrichment if it's not relevant).

## Reference

- Run #34 baseline (5710 scenario A, pre-refactor): full loop ~24min, ~Use.32. Loop-1 entirely on enrichment.
- Run `20260426-020541-rule5710` (the run that surfaced this): 14-phase history, ~26m45s, ~40–45% pre-fork enrichment.
- `soc-agent/knowledge/environment/context/ip-ranges.md` and `identity-patterns.md` — the existing reference files that mechanical extraction consults.
- `soc-agent/knowledge/environment/operations/approved-monitoring-sources.md` — the registry table the CMDB-style lookup primitive targets first.
- Related: `tasks/predict-baseline-deviation-shape.md` — the PREDICT-side companion that consumes entity classifications as preloaded state.