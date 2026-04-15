---
title: Archetype auto-extraction pipeline from ticketing system
status: backlog
groups: archetype, knowledge, post-mortem
---

Currently KB precedent snapshots under archetypes/\*/{TICKET-ID}.json are hand-curated. Long-term: build a sync pipeline that automatically captures snapshots from the real ticketing system when tickets close under an archetype.

Requires deciding: which ticketing system (ServiceNow / Jira / Linear / ...), what fields map to the schema, how to mark temporal anchors at capture time.