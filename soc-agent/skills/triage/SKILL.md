---
name: triage
description: Main entry point for SOC alert triage. Validates alert, investigates, calculates deterministic confidence score, and routes to auto-close, reproduce, or escalate.
arguments:
  - name: alert_json
    description: JSON string with alert data (required fields: ticket_id, signature_id, agent)
    required: true
  - name: asset_criticality
    description: Asset criticality level - "standard", "elevated", or "critical" (default: "standard")
    required: false
---

# SOC Alert Triage

## Orchestration Flow

This skill ties together investigation, scoring, and routing. It replaces the Python orchestrator with deterministic bash scoring and Claude Code native primitives.

### Step 1: Validate Alert

Parse the alert JSON. Required fields:
- `ticket_id` - Unique ticket identifier
- `signature_id` - Detection signature ID
- `agent` - Host/agent where alert originated

If validation fails, immediately escalate (fail-safe).

### Step 2: Load Permissions

Read `config/signatures/{signature_id}/permissions.yaml`. If not found, use conservative defaults (escalate everything).

### Step 3: Check Escalation Patterns

Before investigating, check if the alert matches any escalation patterns from permissions. If matched, skip investigation and escalate immediately with the reason.

To check, run the decision router:
```bash
echo '{"scorer_output":{"confidence_score":0,"decision":"escalate"},"alert_data":{...},"permissions_file":"config/signatures/{id}/permissions.yaml"}' | hooks/scripts/decision-router.sh
```

### Step 4: Investigate

Invoke `/soc-agent:investigate` with the alert data. This returns structured findings JSON with recommendation, confidence, matched_ticket, matched_tier, and evidence.

### Step 5: Score (Deterministic)

Run the confidence scorer via Bash, piping the investigation findings:

```bash
echo '{
  "agent_confidence": "{findings.confidence}",
  "matched_tier": "{findings.matched_tier}",
  "has_precedent": {findings.matched_ticket != null},
  "asset_criticality": "{asset_criticality}",
  "signature_severity": "{alert.severity}",
  "reproduction_result": null
}' | hooks/scripts/confidence-scorer.sh
```

This outputs `{"confidence_score": X.XX, "decision": "auto_close|reproduce|escalate"}`.

### Step 6: Route

Run the decision router with scorer output, alert data, and permissions:

```bash
echo '{
  "scorer_output": {scorer_output},
  "alert_data": {alert},
  "signature_id": "{signature_id}",
  "permissions_file": "config/signatures/{id}/permissions.yaml",
  "recommendation": "{findings.recommendation}"
}' | hooks/scripts/decision-router.sh
```

### Step 7: Act on Decision

**If AUTO_CLOSE** (and enabled in permissions):
- Write audit entry via: `echo '{...}' | hooks/scripts/audit-logger.sh`
- Output closure summary with disposition, confidence score, and key evidence

**If REPRODUCE** (and enabled in permissions, and hypothesis available):
- Invoke `/soc-agent:reproduce` with the hypothesis from findings
- Re-run scorer with `reproduction_result` set to the outcome
- Re-run router with updated scorer output
- If now AUTO_CLOSE -> close; if ESCALATE -> escalate

**If ESCALATE**:
- Write enriched escalation report with all gathered context
- Write audit entry
- Output escalation summary with what was investigated and why escalation is needed

### Step 8: Write Summary

Write `investigation-summary.json` to the run directory:
```json
{
  "ticket_id": "...",
  "signature_id": "...",
  "decision": "auto_close|reproduce|escalate",
  "disposition": "benign|false_positive|true_positive|escalated|inconclusive",
  "confidence_score": 0.95,
  "findings": {...},
  "timestamp": "..."
}
```

## Key Design Principle

**Scoring is NEVER done by LLM judgment.** The confidence score and routing decision come from `confidence-scorer.sh` and `decision-router.sh` - deterministic bash scripts. The LLM (investigation subagent) provides structured findings; the scripts make the math-based decision. This ensures zero false negatives are preserved regardless of LLM behavior.
