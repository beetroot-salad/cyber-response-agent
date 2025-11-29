---
name: signature-template
description: Template for signature-specific investigation skills. Copy this directory for new signatures.
---

# Signature Investigation Skill

This is a template. Copy the entire directory for a new signature and customize:

1. Update the `name` and `description` in the frontmatter
2. Fill in `rule.md` with signature details
3. Fill in `playbook.md` with investigation steps
4. Add past tickets to `past-tickets/` as they are resolved

## Files

- **rule.md** - Signature documentation (what it detects, key fields, related rules)
- **playbook.md** - Investigation playbook (steps, patterns, decision criteria)
- **lessons.md** - Lessons learned from past investigations
- **past-tickets/** - Resolved ticket examples (JSON files)
