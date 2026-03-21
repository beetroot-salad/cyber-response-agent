---
name: common-investigation
description: Common investigation utilities and knowledge applicable across all signatures. Includes IP classification, query pattern examples, investigation vocabulary, and the investigation checklist.
---

# Common Investigation Knowledge

Shared resources for hypothesis-driven security alert investigation.

## Available Resources

### checklist.md
**Read this at CONTEXTUALIZE and verify before CONCLUDE.** Self-check guide covering:
- Investigation completeness criteria
- Adversarial hypothesis requirements
- Report structure requirements
- Common mistakes to avoid

### lessons/ip-classification.md
How to classify IP addresses:
- RFC1918 private ranges (internal)
- Cloud provider ranges
- Known infrastructure IPs

### utilities/
Query pattern examples for specific SIEM tools. These are **examples** — adapt to whatever tools are available in your environment.
- `wazuh-queries.md` — Example query patterns for Wazuh SIEM

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

## When to Use

This skill supplements signature-specific skills. Use it for:
- IP address analysis
- Query pattern reference (adapt examples to your SIEM)
- Cross-cutting investigation patterns
- Understanding the hypothesis-driven flow language
- Self-checking investigation quality via checklist.md
