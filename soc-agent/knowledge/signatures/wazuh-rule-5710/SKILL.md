---
name: wazuh-rule-5710
description: "Investigate SSH invalid user alerts (Wazuh rule 5710). Hypothesis-driven triage for failed SSH login attempts with non-existent usernames. Covers monitoring probes, brute force, credential stuffing, and service account rotation. NOTE: This is an example signature for the Wazuh SIEM — use as a reference when building signatures for your own SIEM and detection rules."
---

# Wazuh Rule 5710: SSH Invalid User

> **Example signature.** This signature is provided as a working reference for the Wazuh SIEM. Use it as a template and testing fixture when building signatures for your own environment and detection tools.

This skill provides context for investigating SSH invalid user alerts using hypothesis-driven methodology.

## When to Use

Activate this skill when investigating alerts with:
- Signature ID: `wazuh-rule-5710`
- Alert type: SSH authentication failure with invalid username

## Available Resources

### context.md
Signature reference including:
- What the rule detects and why
- Key fields (srcip, srcuser, agent)
- Related rules to cross-reference
- Known false positive patterns with precedent references
- Risk indicators and threat motivation

### playbook.md
Hypothesis-driven investigation guide:
- Hypothesis catalog (?monitoring-probe, ?brute-force, ?credential-stuffing, ?service-account-rotation)
- Lead list with per-hypothesis predictions
- Escalation and auto-close criteria
- Recommended starting lead

### precedents/
Past resolved investigations in v3 format:
- `monitoring-probe-001.json` — Internal IP + monitoring username -> benign
- `brute-force-001.json` — External IP + multiple usernames -> escalated

## Quick Reference

**Hypothesis catalog:**
- `?monitoring-probe` — Automated health check from internal system
- `?brute-force` — Credential guessing attack (external, high volume)
- `?credential-stuffing` — Leaked credential replay (external, low volume)
- `?service-account-rotation` — Password rotation failure (internal, scheduled)

**Start with:** `authentication-history` lead — discriminates all four hypotheses
