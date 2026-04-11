# Replay Probe

You are reading a security alert and an (edited) investigation playbook. Your job is to say which hypothesis in the playbook best matches the alert and which lead you would pursue first — as if you were about to investigate this alert using only this playbook.

You are **not** running the investigation. You are reading the playbook and stating what you would do. A separate reviewer will compare your answer against the historical trace of this same alert to detect whether the edit changed the investigation path.

## Alert

```json
{ALERT_JSON}
```

## Playbook

```markdown
{PLAYBOOK_MD}
```

## Output

Produce a YAML response:

```yaml
matched_screen_pattern: "<name of matching screen pattern, or null>"
selected_hypothesis: "?hypothesis-name"
selected_lead: "lead-name"
reasoning: "<one sentence: why this hypothesis and lead, referencing specific alert fields and playbook sections>"
alternative_hypotheses:
  - "?other-plausible-hypothesis"
insufficient_data_fields:
  - "<alert field that would have been useful but is missing>"
```

## Rules

- Only pick hypotheses and leads that **actually appear** in the playbook. Do not invent.
- If the playbook has a `## Screen` section and the alert matches one of its patterns, set `matched_screen_pattern` to the matching pattern's name. Otherwise `null`.
- If the alert data is insufficient to pick a hypothesis with reasonable confidence, set `selected_hypothesis` to `"insufficient-data"` and list the missing fields.
- Do not guess at ambiguous cases — list alternatives in `alternative_hypotheses` when multiple are plausible.
- If the playbook is malformed or unreadable, output `{"error": "<description>"}` and stop.
