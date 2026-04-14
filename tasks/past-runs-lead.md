---
title: Expose past investigations as a lead (leads/past-investigations/)
status: backlog
group: reliability
---

Follows the same shape as every other lead: leads/past-investigations/definition.md + per-vendor templates (single template pointing at the local index).

Lead takes the current alert's entity set as input, returns the top-N matching past runs ranked by entity similarity + recency + Tier 2 pass, plus a one-line summary of each.

Main agent can select it at HYPOTHESIZE just like any other lead.
