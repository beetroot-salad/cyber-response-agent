---
name: common-investigation
description: Common investigation utilities and knowledge applicable across all signatures. Includes IP classification, Wazuh query patterns, and cross-cutting lessons.
---

# Common Investigation Knowledge

Shared resources for security alert investigation, applicable across all signature types.

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

## When to Use

This skill supplements signature-specific skills. Use it for:
- IP address analysis
- Building SIEM queries
- Cross-cutting investigation patterns
