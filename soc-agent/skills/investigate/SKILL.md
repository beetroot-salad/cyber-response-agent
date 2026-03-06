---
name: investigate
description: Investigate a security alert by analyzing alert data, querying SIEM, matching patterns against knowledge base, and producing structured findings with a confidence assessment.
arguments:
  - name: alert_json
    description: JSON string containing the alert data (must include ticket_id, signature_id, agent)
    required: true
---

# Investigate Security Alert

## Workflow

1. **Parse alert data** from the provided JSON. Validate required fields: `ticket_id`, `signature_id`, `agent`.

2. **Load knowledge base**:
   - Read `knowledge/signatures/{signature_id}/SKILL.md` for signature-specific guidance
   - Read `knowledge/signatures/{signature_id}/playbook.md` for investigation steps
   - Read `knowledge/signatures/{signature_id}/rule.md` for rule details
   - Read `knowledge/signatures/{signature_id}/past-tickets/` for precedent matching
   - Read `knowledge/common/SKILL.md` for cross-cutting knowledge

3. **Discover SIEM tools** by reading `config/siem-mapping.json`. Use the mapped tool names for queries.

4. **Invoke investigator subagent** with:
   - The alert data
   - Knowledge base context
   - SIEM tool mapping
   - Instructions to produce structured findings JSON + narrative report

5. **Return findings** - The subagent output must contain a fenced JSON block with:
   ```json
   {
     "recommendation": "benign|false_positive|true_positive|escalate",
     "confidence": "high|medium|low",
     "matched_ticket": "TICKET-ID or null",
     "matched_tier": "gold|silver|bronze|null",
     "evidence": {},
     "reproduction_request": null
   }
   ```

## Error Handling

If investigation fails for any reason, return default-safe findings:
```json
{
  "recommendation": "escalate",
  "confidence": "low",
  "matched_ticket": null,
  "matched_tier": null,
  "evidence": {"error": "description of failure"},
  "reproduction_request": null
}
```
