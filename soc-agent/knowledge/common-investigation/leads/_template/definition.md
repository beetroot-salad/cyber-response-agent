---
name: lead-name-here
data_tags: [tag1, tag2]
baseline: optional       # optional | required | not-applicable — whether the lead's output is interpretable without a baseline comparison
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

## Baseline

<!-- Required when frontmatter declares `baseline: required`. The lead
     commits to returning a structured baseline alongside foreground in
     GATHER's output envelope, so PREDICT can author by-role deviation
     refutations (see agents/predict.md §Story authoring) and ANALYZE
     can compare foreground to baseline dimension-by-dimension.

     Skip this section (or set `baseline: not-applicable` in frontmatter)
     for binary checks like file hash reputation, known-bad IP lookups,
     or allowlist membership — anything where absolute counts directly
     answer the question. -->

- **When needed:** Which hypotheses or evidence shapes require a baseline before they can be graded. "Is 84 rootcheck events per 4h alarming?" only has an answer relative to this host's typical rate.
- **Shift query:** The baseline query pattern. Usually the same query executed against a shifted time window (e.g., `--start` shifted `7d` earlier, same `--window` duration). Vendor-specific syntax lives in the lead's `templates/` directory.
- **Output shape:** The lead returns a `baseline:` field alongside `characterization:` in the gather envelope, with **the same keys** as the foreground `characterization:`. Values are extracted from the shift-query result. A `scope:` field names the shift window descriptor (e.g., `same-entity-7d`, `same-image-30d`). ANALYZE compares `characterization[k]` to `baseline.characterization[k]` per key when grading by-role deviation predicates.
- **Interpretation:** What counts as "above baseline" (prefer σ-framing — `>3σ deviation`, `15× baseline rate`, `count in top decile for this signature` — over absolute thresholds). Relative framing is environment-agnostic and makes refutation shapes unambiguous.

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
