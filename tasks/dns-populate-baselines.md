---
title: Populate baseline content in existing lead definitions
status: backlog
groups: dns, knowledge
---

The _template/definition.md now declares an optional baseline: frontmatter field and a ## Baseline section. Existing leads (recent-alert-correlation, network-analysis, authentication-history) still ship without baseline content.

Priority order:
(a) recent-alert-correlation — most-used, drives the FIM/rootcheck volume-vs-baseline failure mode that Opus #2 hit
(b) network-analysis — no templates dir at all yet
(c) authentication-history — already has a Wazuh template, needs a baseline query alongside it

Each lead needs shift-query patterns and σ-framed interpretation guidance.
