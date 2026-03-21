---
name: triage
description: Triage a security alert through hypothesis-driven investigation. Validates alert, loads permissions, creates run directory, and spawns investigator subagent.
arguments:
  - name: alert_json
    description: "JSON string with alert data. Required fields: ticket_id, signature_id, agent. Alert-specific fields (srcip, srcuser, etc.) go in alert_data."
    required: true
  - name: mode
    description: "'recommend' (default) or 'act'. MVP only supports recommend."
    required: false
---

# SOC Alert Triage

Entry point for hypothesis-driven security alert investigation.

## Orchestration Flow

### Step 1: Parse and Validate Alert

Parse the `alert_json` argument. Required top-level fields:
- `ticket_id` — Unique ticket identifier
- `signature_id` — Detection signature ID (e.g., `wazuh-rule-5710`)

The alert should also contain `alert_data` with signature-specific fields.

If validation fails, output an error and stop. Do not investigate invalid input.

### Step 2: Check Mode

Read the `mode` argument (default: `recommend`). If `mode=act`, output a warning that act mode is not yet implemented and proceed with recommend.

### Step 3: Load Permissions

Read `config/signatures/{signature_id}/permissions.yaml`. If not found, log a warning and use conservative defaults:
- Assume `mode: recommend`
- Assume no auto-close
- Assume all dispositions allowed

### Step 4: Pre-Investigation Escalation Check

Before investigating, check if the alert matches any `escalation_patterns` from permissions. If matched, skip investigation and output an immediate escalation recommendation with the reason.

### Step 5: Create Run Directory

Create a unique run directory. The base path is configurable via `SOC_AGENT_RUNS_DIR` env var (defaults to `runs/` within the plugin directory):
```bash
mkdir -p ${SOC_AGENT_RUNS_DIR:-runs}/{ticket_id}-$(date +%Y%m%d-%H%M%S)
```

Store the run directory path for use by the investigator.

### Step 6: Save Alert Data

Write the alert JSON to `{run_dir}/alert.json` for audit trail.

### Step 7: Spawn Investigator

Invoke the `investigator` subagent with:
- The alert data (ticket_id, signature_id, alert_data fields)
- The run directory path
- Instructions to follow the hypothesis-driven investigation loop

The investigator will:
1. Write `investigation.md` with phase-by-phase notes
2. Write `state.json` via `hooks/scripts/write_state.py` at each transition
3. Write `report.md` with YAML frontmatter at conclusion

### Step 8: Output Summary

After the investigator completes, read `{run_dir}/report.md` and output a summary:

```
## Triage Result: {ticket_id}

**Status:** {resolved|escalated}
**Disposition:** {disposition}
**Confidence:** {confidence}
**Leads Pursued:** {count}
**Trace:** {trace line}

{2-3 sentence summary from report}
```

If the report is missing or fails validation, output an error indicating the investigation may have failed.

## Key Principles

- **MVP is recommend-only** — No auto-close actions, no ticket updates. Output recommendations for human review.
- **The investigator decides** — This skill orchestrates; the investigator subagent does the analytical work.
- **Audit trail** — Every run produces alert.json, investigation.md, state.json, and report.md in the run directory.
- **Fail safe** — If anything goes wrong, output what was gathered and recommend escalation.
