# New Signature Template

## How to create a new signature

### 1. Setup

1. Copy this directory: `cp -r _template/ {signature-id}/`
2. Remove this README.md from the copy (it's only for onboarding)
3. Create permissions: `cp -r ../../config/signatures/_template/ ../../config/signatures/{signature-id}/`

### 2. Research past tickets

Before writing any knowledge, study real data for this signature:

1. **Pull the signature definition** from the SIEM — detection logic, fields, severity, related rules
2. **Query past alerts** for this signature (aim for 20-50+ if available). Note:
   - Volume and base rate — how often does this fire?
   - Common dispositions — what % were benign vs escalated?
   - Recurring patterns — same source IPs, usernames, time-of-day clusters?
3. **Review closed tickets** — read analyst notes, resolution reasoning, and any false positive annotations
4. **Identify distinct outcome clusters** — group tickets by what actually happened (monitoring probe, brute force, misconfiguration, etc.). These become your hypothesis catalog.
5. **Extract useful investigation tricks** — what queries or checks did analysts use to resolve quickly? What dead ends wasted time?
6. **Select representative tickets** for precedents — pick 1-2 per outcome cluster that best illustrate the pattern

This research phase is the foundation. The context, playbook, and precedents should reflect what actually happens with this signature, not what might theoretically happen.

### 3. Fill in knowledge files

**context.md:**
- Update all frontmatter fields (signature_id, name, severity, etc.)
- Signature logic — from the SIEM definition + your understanding of what it actually detects
- Threat model — grounded in what you saw in real tickets
- Known false positives — from the recurring benign patterns you identified
- Risk indicators — the fields and values that actually discriminated outcomes in past tickets

**playbook.md:**
- Update frontmatter (signature_id, last_updated)
- Hypothesis catalog — from the outcome clusters you identified in research (must include at least one adversarial hypothesis)
- Leads with per-hypothesis predictions — based on what queries/checks actually resolved past tickets
- Screen patterns (optional, recommended) — identify the most common benign outcomes with clear, mechanical indicators. These enable fast resolution without the full investigation loop. Only include patterns where every indicator is unambiguous. Prioritize adding screen patterns during post-mortem review when you have real outcome data.
- Escalation and auto-close criteria — derived from real resolution patterns

**precedents/:**
- Copy `precedents/_template.json` to `precedents/{slug}.json` for each representative ticket
- Fill from the real investigation flow, not hypothetical scenarios

## Directory structure after setup

```
{signature-id}/
├── context.md       # Signature reference (detection logic, threat model, FPs)
├── playbook.md      # Hypothesis catalog, leads, escalation criteria
└── precedents/      # Past resolved investigations (JSON)
    └── {slug}.json
```

## References

- v3 architecture: `docs/design-v3-architecture.md` sections 3.2 (context), 3.3 (playbook), 3.4 (precedents)
- Example signature: `wazuh-rule-5710/`
- Precedent schema: `schemas/precedent.py`
