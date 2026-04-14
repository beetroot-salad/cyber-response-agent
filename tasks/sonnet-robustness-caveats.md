---
title: Sonnet robustness caveats: eval sweep gaps to cover before production
status: backlog
groups: sonnet-migration, reliability
---

The 4 Sonnet runs were on a medium-quality harness with relatively short investigations (≤6 phases, ≤2 hypothesis loops). Production conditions NOT exercised:

- Missing or degraded data sources (Wazuh backlog, SIEM index gap, data-source-debug lead fires)
- Stale knowledge (ip-ranges.md with terminated monitoring sources, anchor docs referencing deprecated tickets)
- Longer investigation loops (5+ hypothesis loops; coherence decay over long contexts)
- Novel alert shapes outside playbook archetype space requiring first-principles enumeration
- Ambiguous anchor confirmations (change ticket in weird state, on-call schedule in transition)
- Rate-limited or noisy SIEM queries (production indexes with 10×–100× event volume)

Path forward before production: eval sweep on a harder signature (100001 or novel) post-scaffolding-maturation, plus at least one eval with deliberately degraded data source.
