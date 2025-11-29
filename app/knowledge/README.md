# Knowledge Base

This directory contains the agent's investigation knowledge - the "tribal knowledge" that enables automated security alert triage.

## Structure

```
knowledge/
├── common/                    # Cross-cutting knowledge (shared across signatures)
│   ├── lessons/              # Lessons applicable to many rules
│   └── utilities/            # Shared scripts and query templates
│
└── signatures/               # Per-signature modules
    └── {signature-id}/
        ├── rule.md           # Rule documentation (logic, fields, data sources)
        ├── playbook.md       # Investigation playbook (steps, actions, escalation)
        ├── lessons.md        # Lessons learned (tips, pitfalls, patterns)
        ├── utilities/        # Signature-specific scripts
        └── past-tickets/     # Resolved tickets as reference (JSON)
```

## Knowledge Types

| Type | Purpose | Format | Updates |
|------|---------|--------|---------|
| **rule.md** | Rule logic, data sources, field mappings | Markdown | Rarely (when rule changes) |
| **playbook.md** | Investigation steps, approved actions, escalation | Markdown | When procedures change |
| **lessons.md** | Tribal knowledge, tips, patterns from experience | Markdown bullets | Grows over time |
| **utilities/** | Scripts, query templates, automations | Code/Markdown | As needed |
| **past-tickets/** | Raw resolved tickets as reference | JSON files | After each resolution |

## How Knowledge Evolves

1. **Past tickets** are added after each resolved investigation (raw data)
2. **Lessons learned** are distilled from tickets - tips, patterns, pitfalls
3. **Utilities** are created when automation opportunities emerge
4. Cross-cutting knowledge moves to `common/` when useful to multiple signatures

## Adding a New Signature

1. Create directory: `signatures/{signature-id}/`
2. Add `rule.md` with rule documentation
3. Add `playbook.md` with investigation steps
4. Create empty `lessons.md` (will grow over time)
5. Create `utilities/` and `past-tickets/` directories
