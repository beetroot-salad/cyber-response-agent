---
name: ad-hoc
data_tags: []
---

## When this applies

The main agent requested a lead with no pre-built definition or script.

## Checklist

1. Identify the data type needed from the goal description
2. Search data-sources/ for matching tags or related data types
3. Run health checks on candidate systems
4. Report findings to main agent:
   - Available data sources and their health status
   - Relevant field names from systems/{vendor}/ field quirks documentation
   - Suggested query approach (if straightforward)
   - Caveats and gaps
5. Do NOT execute queries without explicit ad-hoc instructions from main agent

## Why fail fast

Budget is limited. An undefined lead means the main agent's mental model
and the knowledge base are misaligned. The main agent needs this signal
to either reformulate the lead, use the debugging framework to explore
available data, or escalate.
