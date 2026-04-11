# Authoring Self-Check

Run through this checklist before accepting an edit as done. It's a quick pre-flight, not a replacement for the validation probes.

## Grounding

- [ ] Is every new claim backed by a concrete source (past ticket, handbook rule, sibling pattern, user-provided material)?
- [ ] Did I avoid inventing archetype patterns for which I have no historical data?
- [ ] For any pattern marked as "common" or "typical", do I have evidence it's actually common?

## Scope discipline

- [ ] Did I edit only under `knowledge/` or `config/signatures/`?
- [ ] Did I avoid touching `schemas/`, `scripts/`, `hooks/`?
- [ ] Did I check ripple files (other files referencing what I changed)?
- [ ] If I didn't touch a ripple file, did I explain why in the final summary?

## Conservatism

- [ ] For any prescriptive statement (MUST / REQUIRED / NEVER), did I maintain or strengthen it, not weaken it?
- [ ] Does the signature still have at least one adversarial hypothesis?
- [ ] Does any archetype that resolves to non-escalation still list all its `required_anchors`?
- [ ] Did I avoid widening any screen pattern's match conditions without explicit regression evidence?

## Validation

- [ ] Did I run the deterministic checks (resolve_imports, schema tests, cross-refs via Grep)?
- [ ] Did I run the probes appropriate to this edit's classification (see SKILL.md)?
- [ ] Did I self-reflect on the three questions — information loss, contradiction, regression?
- [ ] Did I stay within the 10-probe sanity cap?
- [ ] Did I surface any unresolved concerns to the user rather than papering over them?

## Git hygiene

- [ ] Did I leave git state clean (no unauthorized commits or pushes)?
- [ ] Did I resist the urge to run git operations "just to clean up"?
- [ ] If the user asked for a commit, did I delegate to `/ship`?

## Honesty

- [ ] If I flagged something as TODO, does the TODO explain *what* is missing and *what data* would resolve it?
- [ ] Did I avoid claiming completeness on files I couldn't fully validate?
- [ ] Did I distinguish what I changed from what was already there in the summary?
