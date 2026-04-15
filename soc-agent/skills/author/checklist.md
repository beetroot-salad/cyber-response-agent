# Authoring Self-Check

Run through before calling an edit done. Quick pre-flight, not a replacement for the validation probes.

## Completion

- [ ] Every file I said I'd change actually changed?
- [ ] Every ripple file I identified is either touched or explicitly deferred with a stated reason?
- [ ] No files left in a half-edited state?
- [ ] If I created or renamed an archetype: did the playbook's archetype table get updated?

## Consolidation

- [ ] Could any of this content have been consolidated into an existing file instead of creating new ones?
- [ ] Did I avoid creating a new lead / lesson / archetype for something already covered in a sibling?
- [ ] If I created a new file, is there a clear reason an existing file couldn't hold this?

## Knowledge base boundaries

- [ ] Portable methodology lives in `knowledge/common-investigation/`?
- [ ] Org-specific deployment knowledge lives in `knowledge/environment/`?
- [ ] Per-signature content lives in `knowledge/signatures/{id}/`?
- [ ] No environment details leaking into `common-investigation/`?
- [ ] No signature-specific logic leaking into `environment/`?
- [ ] No portable methodology trapped inside a single signature?

## Phrasing

- [ ] Is my phrasing tight? Did I avoid padding, hedging, restating what the reader already knows?
- [ ] Does every claim carry weight? Does every constraint feel load-bearing?
- [ ] Did I cut verbose lead-ins, redundant transitions, and empty caveats?

## Grounding

- [ ] Every non-trivial claim cites a concrete source (ticket, handbook rule, sibling pattern, user material)?
- [ ] No invented archetype patterns or synthetic precedents?
- [ ] If I marked something TODO, does it say what's missing and what data would resolve it?

## Conservatism

- [ ] Prescriptive language (MUST / REQUIRED / NEVER) maintained or strengthened, not weakened?
- [ ] At least one adversarial archetype present for the signature?
- [ ] Any archetype resolving to non-escalation still declares its `required_anchors`?
- [ ] Screen pattern match conditions not widened without regression evidence?

## Query template tagging

Only when a lead query template (`leads/{name}/templates/{vendor}.md`) was touched or added.

- [ ] Ran `list_lead_tags.py --check <template>` and reviewed every flag as an explicit decision (reuse, introduce deliberately, or rename)?
- [ ] Every tag is snake_case?
- [ ] Tag-search probe ran with two Haiku runners on different framings, and the declared tags overlap the search terms from both runners — or the gap is an accepted narrowing, not an oversight?

## Validation

- [ ] Deterministic checks ran clean (resolve_imports, schema tests, Grep cross-refs, tag vocabulary)?
- [ ] Appropriate probes ran — reconstruction + comprehension always; coherence for multi-file; replay for destructive or signature-creation; tag-search when a query template changed?
- [ ] Self-reflected on information loss, contradiction, and regression?
- [ ] Stayed within the 10-probe sanity cap?
- [ ] Surfaced unresolved concerns to the user instead of papering over them?
