---
name: common-investigation
description: Common investigation utilities and knowledge applicable across all signatures. Includes IP classification, Wazuh query patterns, and hypothesis-driven investigation vocabulary.
---

# Common Investigation Knowledge

Shared resources for hypothesis-driven security alert investigation.

## Available Resources

### lessons/ip-classification.md
How to classify IP addresses:
- RFC1918 private ranges (internal)
- Cloud provider ranges
- Known infrastructure IPs

### utilities/wazuh-queries.md
Common Wazuh query patterns:
- Search by source IP
- Search by username
- Time-window queries
- Aggregation patterns

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
- Building SIEM queries
- Cross-cutting investigation patterns
- Understanding the hypothesis-driven flow language
