---
name: signature-template
description: Template for signature-specific investigation skills. Copy this directory for new signatures and customize all files.
---

# Signature Investigation Skill

This is a template. Copy the entire directory for a new signature and customize:

1. Update the `name` and `description` in the frontmatter
2. Fill in `context.md` with signature details, threat model, and known false positives
3. Fill in `playbook.md` with hypothesis catalog and leads
4. Add precedents to `precedents/` as investigations are resolved

## Files

- **context.md** - Signature reference (detection logic, threat motivation, known false positives, risk indicators)
- **playbook.md** - Hypothesis catalog, lead list with predictions, escalation/auto-close criteria
- **precedents/** - Past resolved investigations in v3 format (JSON with hypotheses, flow, trace, reasoning)
