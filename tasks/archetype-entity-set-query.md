---
title: Ticket-context subagent: entity-set past-ticket query at CONTEXTUALIZE
status: backlog
group: archetype
---

Extend the ticket-context subagent to query the ticketing system for past resolved tickets matching the current alert's entity set (srcip, srcuser, host, container image, etc.) — not just by signature or time window.

CONCLUDE should then be able to cite a specific matched_ticket_id grounded in a real past ticket, without a second subagent round-trip.

Related: the existing CONTEXTUALIZE precedent-scan subagent scans cached KB snapshots under archetypes/*/*.json, which are hand-curated. The ticketing-system query is the live source of truth that those snapshots cache.
