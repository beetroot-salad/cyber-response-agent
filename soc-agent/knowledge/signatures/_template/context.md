---
signature_id: SIGNATURE-ID
name: SIGNATURE NAME
severity: low|medium|high|critical
data_sources: []
created_at: YYYY-MM-DD
updated_at: YYYY-MM-DD
mitre:
  tactics: null
  techniques: null
references: null
related_signatures: []
base_rate:
  benign_pct: null
  sample_size: null
---

# Rule: SIGNATURE-ID

## Signature Logic

What triggers this rule. Include the log pattern and example.

## Alert Fields

| Field | JSON Path | Description | Example |
|-------|-----------|-------------|---------|

## Key Observables

The fields that define this alert's identity — what makes THIS alert THIS alert. Used by subagents to extract the right entities for SIEM queries (ticket-context) and to compare shape against archetype stories (archetype-scan). Each entry names the observable, its JSON path, and why it matters for this signature.

| Observable | JSON Path | Why It Matters |
|-----------|-----------|----------------|

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|

## Threat & Motivation

What an attacker would be trying to achieve. MITRE context. Blast radius.

## Known False Positives

List known benign patterns that trigger this rule, with references to precedents.

## Risk Indicators

### Lower Risk
1. ...

### Higher Risk
1. ...

## Field Notes

Environment-specific observations and tips that accumulate over time.

## Impact

What happens if this is a true positive. Stakes and escalation urgency.

## Operational Notes

Environment-specific patterns that don't fit elsewhere. Tribal knowledge.

## Tuning Guidance

How to reduce noise without losing detection.

## Detection Gaps

What this rule does NOT catch. Helps the agent know when to investigate further.
