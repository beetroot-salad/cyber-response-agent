---
title: Per-signature ticket-context demote list (high-baseline noise rule families)
status: backlog
groups: dns, knowledge
---

Signatures should declare a `ticket_context_demote: [rule_id, ...]` field in the playbook frontmatter, listing rule families that are known high-baseline noise for this signature's investigations (e.g. 100110 playbook demotes 510/550/553/554/533).

The ticket-context subagent would then surface those clusters in `maybe` rather than `definite`, reducing the weight the main agent places on them.

Blunt but effective; complements the SKILL.md "related alerts are seeds, not evidence" rule at the structural layer.
