---
title: Populate lead definitions in common/leads/ (authentication-history, network-analysis, etc.)
status: done
groups: knowledge
---

common/leads/ is scaffolded but lead definitions are sparse. Priority order based on 100110 stress eval findings:
1. ~~recent-alert-correlation~~ — **removed**: duplicated the ticket-context subagent's job (CONTEXTUALIZE already covers the three query dimensions, clustering, centrality reasoning, and fast-resolve ranking). Lead dir deleted; no dispatcher or playbook referenced it.
2. network-analysis — **done**: definition.md gets `baseline: optional` + `## Baseline` section; added `templates/wazuh.md` with availability caveat, health check, entity mapping, worked examples, and paired shift queries.
3. authentication-history — **done**: definition.md gets `baseline: optional` + `## Baseline` section; `templates/wazuh.md` gets a **Baseline (Shift Query)** block with paired current/baseline invocations.

4. source-reputation — **done**: `baseline: not-applicable` (binary reputation/asset-inventory lookups).
5. user-analysis — **done**: renamed from `username-analysis`, `baseline: not-applicable` (account existence + pattern matching are binary).
6. process-lineage — **done**: `baseline: optional` + `## Baseline` section (rate/rarity claims need a shift query; structural claims like "web-server → /bin/sh" are self-interpreting).

Templates still missing for: process-lineage, source-reputation, user-analysis. These are lower priority — rule-5710 runs rarely reach for them (4–15 references each across 69 runs vs 67 for authentication-history), and process/identity data availability in Wazuh varies by decoder.

Design doc `docs/design-v3-tool-execution.md` tree updated to drop recent-alert-correlation and rename to user-analysis.