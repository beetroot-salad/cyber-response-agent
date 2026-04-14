---
title: Tool discovery refactor: split data availability from tool mechanics
status: backlog
group: phase-2
---

Split into two concerns:
1. Data availability: main agent consults knowledge/environment/data-sources/ to know what questions can be answered
2. Tool mechanics: lead subagent consults knowledge/environment/systems/ for query patterns

Also: not all tools are MCP — agent may need to call APIs via scripts.
