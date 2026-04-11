---
name: lead-name-here
data_tags: [tag1, tag2]
---

## Goal

<!-- What investigative question does this lead answer? One sentence. -->

## What to Characterize

<!-- Required output schema. Each bullet MUST be reported on, even if the
     answer is "not available in this data source" or "not observed."
     Omission is an error — the main agent cannot distinguish between
     "observed and not noted" and "not observed." -->

- **Observable 1**: Description of what to measure and how to classify it.
- **Observable 2**: Description.

## Common Pitfalls

<!-- What would cause a wrong conclusion? Each bullet is a trap that has
     burned past investigations or would mislead an experienced analyst. -->

- Pitfall description — why it's misleading and how to detect it.

## Templates

Per-vendor query templates live under `templates/{vendor}.md` (one file per SIEM or data source). Each template **must** start with YAML frontmatter declaring its classification and field mappings. See `authentication-history/templates/wazuh.md` for a reference example.

### Frontmatter schema

```yaml
---
lead: {lead-name}              # matches this lead's directory name
vendor: {vendor}               # matches the filename stem (wazuh, splunk, ...)
tags: [...]                    # flat list of classification tags — see below
entity_fields:
  {entity-type}: {field-path}  # how entities map to vendor field paths
indexes: [...]                 # which indexes/sources this template reads
---
```

### Tag categories

Tags are a flat list. Pick values from these categories — the intent is that each template declares its position in the 4-layer resolution chain plus its analysis type, so the agent can grep sibling templates by tag overlap when constructing novel queries.

- **Abstract operation (layer 1):** `auth`, `process`, `network`, `file`, `identity`, `asset`
- **Concrete operation (layer 2):** free-form per vendor — `ssh`, `ad`, `sudo`, `sysmon`, `dns`, ...
- **Source (layer 3):** identifies the specific index/source — `wazuh-alerts`, `splunk-windows-security`, ...
- **Analysis type:** what investigative question the template answers — `profile`, `correlation`, `discriminate`, `scope`

Layer 4 (access method) is already captured by the `vendor` field and the CLI invocation in the template body — no tag needed.
