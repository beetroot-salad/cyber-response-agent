---
name: wazuh-rule-5710
description: Investigate SSH invalid user alerts (Wazuh rule 5710). Use when triaging failed SSH login attempts with non-existent usernames. Covers monitoring probes, user typos, service accounts, and brute force patterns.
---

# Wazuh Rule 5710: SSH Invalid User

This skill provides context for investigating SSH invalid user alerts.

## When to Use

Activate this skill when investigating alerts with:
- Signature ID: `wazuh-rule-5710`
- Alert type: SSH authentication failure with invalid username

## Available Resources

### rule.md
Signature documentation including:
- What the rule detects
- Key fields (srcip, srcuser, agent)
- Related rules to check
- Risk indicators (lower/higher)

### playbook.md
Step-by-step investigation guide:
- IP classification (internal vs external)
- Username pattern matching
- Context gathering queries
- Decision criteria for each outcome

### lessons.md
Lessons learned from past investigations (grows over time).

### past-tickets/
Example resolved tickets showing:
- Monitoring probe false positives
- User typo patterns
- Brute force escalations
- Service account activity

## Quick Reference

**Common benign patterns:**
- Internal IP + monitoring username (testuser, probe, nagios)
- Failed login followed by success within 60s (typo)
- Service account pattern (svc-*, backup-*)

**Escalation triggers:**
- External IP
- Multiple distinct usernames
- High volume (>5 failures in 5 min)
- No matching pattern
