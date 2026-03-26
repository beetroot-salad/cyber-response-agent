---
name: common-investigation
description: Portable investigation methodology — checklist, lead definitions, lessons, and investigation vocabulary. Applicable across all signatures and environments.
---

# Common Investigation Knowledge

Portable methodology for hypothesis-driven security alert investigation.

## Available Resources

### checklist.md
**Read this at CONTEXTUALIZE and verify before CONCLUDE.** Self-check guide covering:
- Investigation completeness criteria
- Adversarial hypothesis requirements
- Report structure requirements
- Common mistakes to avoid

### leads/
Shared investigation vocabulary — reusable lead definitions. Each specifies what to characterize, pitfalls to avoid, and `data_tags` connecting to `knowledge/environment/data-sources/`. Browse the directory for available leads.

### lessons/
Cross-cutting lessons from past investigations.

## Investigation Vocabulary

### Hypotheses
Prefix with `?` — e.g., `?monitoring-probe`, `?brute-force`. Each hypothesis is a candidate explanation for the alert.

### Leads
Evidence-gathering actions that discriminate between hypotheses. A good lead has different predictions under different hypotheses.

### Assessments
Weight evidence against hypotheses using:
- `++` strongly supports
- `+` weakly supports
- `-` weakly refutes
- `--` strongly refutes

### Trace
A compressed one-line summary of the investigation path: `lead1(result)->lead2(result)->disposition`
