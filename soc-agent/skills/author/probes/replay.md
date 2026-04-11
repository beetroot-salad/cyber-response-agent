# Replay Probe

You are reading a security alert and an (edited) investigation playbook. Trace **two steps** of what an investigator reading only this playbook would do — the first hypothesis and lead, then what happens next under two plausible outcomes of that lead.

You are not running the investigation. You are reading the playbook and saying what it would lead you through. A reviewer will compare your trace against the historical trace of this same alert to detect whether the edit changed the investigation path beyond step 1.

## Alert

```json
{ALERT_JSON}
```

## Playbook

```markdown
{PLAYBOOK_MD}
```

## Output

```yaml
matched_screen_pattern: "<name of matching screen pattern, or null>"
step_1:
  hypothesis: "?hypothesis-name"
  lead: "lead-name"
  reasoning: "<one sentence: why this hypothesis and lead, referencing specific alert fields>"
step_2:
  scenario_a:
    assumed_outcome: "<a plausible characterization that would CONFIRM the step 1 hypothesis, e.g., 'source IP has 47 failures in 60s with username rotation'>"
    next_hypothesis: "?surviving-hypothesis"
    next_lead: "<lead name, or null if the playbook would conclude here>"
    disposition_at_this_point: "<benign | escalated | continue>"
  scenario_b:
    assumed_outcome: "<a plausible characterization that would REFUTE the step 1 hypothesis, e.g., 'source IP has 1 failure total, from a known internal monitoring host'>"
    next_hypothesis: "?different-hypothesis"
    next_lead: "..."
    disposition_at_this_point: "..."
alternative_initial_hypotheses:
  - "?other-plausible-hypothesis-you-considered-for-step-1"
insufficient_data_fields:
  - "<alert field that would have been useful but is missing>"
```

## Rules

- Only pick archetypes, hypotheses, and leads that **actually appear** in the playbook. Do not invent.
- If the playbook has a `## Screen` section and the alert matches a screen pattern, set `matched_screen_pattern` and you may stop after that field — screen match short-circuits the rest.
- For step 2, pick outcomes that are **plausible** given the alert (not strawmen). Scenario A should be the most-likely confirmation of step 1; scenario B should be the most-likely refutation.
- If the playbook is ambiguous about what to do next given a scenario, set `next_lead` to `"unclear"` rather than guessing.
- If the alert data is insufficient to pick a step 1 hypothesis, set `step_1.hypothesis` to `"insufficient-data"` and list the missing fields.
- Do not make up details not in the playbook.
- If the playbook is malformed or unreadable, output `{"error": "<description>"}` and stop.
