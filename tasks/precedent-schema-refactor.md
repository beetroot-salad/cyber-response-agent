---
title: Refactor precedent schema: abstract environment out of key_indicators
status: backlog
groups: knowledge, archetype
---

monitoring-probe-001.json has literal environment values (srcip: 10.0.1.50) baked into key_indicators and alert_data, which conflicts with the actual playground network (172.22.0.0/16) and doesn't generalize to any real deployment.

Sub-tasks:
- Move literal values (IPs, hostnames, ticket-specific timestamps) out of key_indicators and alert_data
- Introduce a sibling tickets/ directory per precedent containing the raw alerts that resolved via this story, so historical matching can work without the precedent file claiming specific values
- key_indicators should carry semantic classifications (source_classification: internal-monitoring-host, username_classification: monitoring-pattern), matching the shape the new 5710 screen indicators already use
- Update precedent.py schema validator + test_kb_schema.py accordingly
- Migrate monitoring-probe-001.json and brute-force-001.json as first pass
