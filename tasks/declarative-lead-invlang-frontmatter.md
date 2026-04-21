---
title: Declarative lead-output invlang frontmatter
status: backlog
groups: state-machine-migration, invlang
---

Replace the `screen-invlang` subagent with mechanical handler composition driven by declarative frontmatter on lead definitions. Same shape may extend to ANALYZE lead transcription later.

## Motivation

SCREEN (and potentially future phases) today asks a Haiku subagent to translate raw lead observations into schema-correct invlang `gather:` entries. This works, but depends on the subagent correctly inferring per-lead output shape at runtime:

- classification leads → `outcome.attribute_updates`
- anchor leads → `outcome.trust_anchor_result`
- telemetry/history leads → `outcome.observations`
- target vertex/edge depends on lead semantics (source-classification → source endpoint, username-classification → identity, approved-monitoring-sources → attempted_auth edge)

The mapping is stable per lead but currently lives in two places the agent must reconcile: the lead's `definition.md` body text, and the invlang schema. An LLM is the bridge.

## Target design

Each `knowledge/common-investigation/leads/{name}/definition.md` frontmatter gains a `screen_output:` block declaring the lead's screen-mode invlang shape:

```yaml
---
name: source-classification
data_tags: [...]
screen_output:
  variant: attribute_updates    # attribute_updates | trust_anchor_result | observations
  target_role: source_endpoint  # source_endpoint | target_endpoint | identity | attempted_auth_edge | ...
  attribute_key: classification # required when variant == attribute_updates
---
```

A validator rule (new, in `hooks/scripts/invlang_validate.py` or a sibling) enforces: every lead named in any signature's `## Screen` table has `screen_output` frontmatter with required subfields. Missing or malformed → PreToolUse rejection of the playbook write.

Handler composes gather entries mechanically by reading each `leads_run` entry's lead definition frontmatter and the prologue; no Haiku call needed. `screen-invlang` subagent is retired.

## Decision trigger

Ship this when either:

1. Haiku `screen-invlang` shows invlang-shape regressions in production (observable via `runs/audit.jsonl` validator-rejection rate).
2. A new signature's Screen table references a lead whose shape `screen-invlang` cannot infer cleanly, forcing prompt-engineering firefights.

Until either trigger, Path B (two-subagent) is the deliberate choice — product promise is "edit the playbook, nothing else," and the validator hook is the safety net.

## Scope

- Add `screen_output` frontmatter schema to lead-definition spec docs (+ example in `_template`).
- Migrate existing leads referenced in any current `## Screen` table (~4-6 leads: source-classification, username-classification, approved-monitoring-sources, authentication-history, and whatever rule-5710 / rule-100001 reference today).
- New validator rule + tests.
- Replace `_invoke_screen_invlang` in `scripts/handlers/screen.py` with mechanical composition. Delete `agents/screen-invlang.md`.
- Update handler tests to exercise the composition in Python; drop the screen-invlang mock.

## Non-scope

- Extending frontmatter to non-screen phases (GATHER/ANALYZE) — evaluate separately after SCREEN migration settles.
- Changing the invlang schema itself.
