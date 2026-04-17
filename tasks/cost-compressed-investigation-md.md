---
title: Rewrite investigation.md phase templates in SKILL.md (compressed YAML-style notation)
status: deferred
groups: cost
---

investigation.md is the agent's working document, consumed by itself and the Tier 2 judge. It currently uses full prose narratives (4K chars per ANALYZE section alone). The judge needs structured evidence and assessment weights (++/+/-/--), not prose.

Switch SKILL.md phase templates to terse structured notation. Each phase section should be ~30-50% of current size. Preserve: hypothesis names, assessment weights with 1-line reasoning, specific observations (IPs, counts, timestamps), lead names, and phase headers. Remove: narrative transitions, repeated context, explanatory prose.

Report.md (analyst-facing) stays verbose.

Estimated savings: ~$0.15-0.20/run (60-70% less output tokens for investigation.md writes, plus reduced context growth).

Acceptance criterion: run a manual test with a compressed investigation.md against the Tier 2 judge before shipping. The judge prompt references "investigation log" and checks for assessment blocks and hypothesis outcomes — confirm it still produces VERDICT:PASS on a valid compressed run.