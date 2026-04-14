---
title: New host-state-baseline lead (FIM/rootcheck/port-change rate check)
status: backlog
groups: dns, knowledge
---

Create a dedicated lead for FIM/rootcheck/port-change rule families (rule.id:510, 550, 553, 554, 533 in Wazuh).

The failure mode: both models folded raw host-state counts ("45 rootcheck events") into DNS-alert dispositions without ever checking whether the rate is baseline for this host.

A named lead makes the baseline check a reachable instruction instead of an ad-hoc query. Include a Wazuh template that runs the query + its 7-day shifted baseline in one pass.
