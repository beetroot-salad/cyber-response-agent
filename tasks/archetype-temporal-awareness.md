---
title: Precedent-matching temporal awareness
status: backlog
groups: archetype, v3-rewrite
---

When the ticket-context subagent ranks past tickets as candidate precedents, it must filter out temporal anchor confirmations: a past ticket whose anchors_at_time included temporal: true entries (on-call windows, change tickets, deploy runs) does not transfer forward in time without re-confirmation.

The skill at the matching step should surface "this past ticket matches shape + entity class, BUT its grounding depended on temporal state that has since elapsed — the current investigation must re-confirm the equivalent anchor today."

Judge Tier 2 already does this semantic check (GROUNDING_MATCH criterion); the skill side needs the same logic applied at match time to avoid surfacing stale matches as confident.
