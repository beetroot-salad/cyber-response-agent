---
title: Populate lead definitions in common/leads/ (authentication-history, network-analysis, etc.)
status: backlog
groups: knowledge
---

common/leads/ is scaffolded but lead definitions are sparse. Priority order based on 100110 stress eval findings:
1. recent-alert-correlation — most-used, drives FIM/rootcheck volume-vs-baseline failure mode
2. network-analysis — no templates dir at all yet
3. authentication-history — already has a Wazuh template, needs a baseline query alongside it
