---
id: elastic.cross-tier-alerts-window
status: established
filter_keys:
  index: .internal.alerts-security.alerts-default-*
  window: {start: start, end: end}
  predicates:
    - {event_attr: rule, op: eq, param: rule_id}
---

## Goal

Retrieve Kibana security detection alerts from the internal alerts index filtered by `rule_id` within a time window. Use to determine whether specific detection rules fired during the investigation period, or to enumerate all alert instances for a rule (e.g., `v2-cross-tier-ssh-pivot`, `v2-sshd-success-after-failures`).

## What to summarize

- Count of matched alerts per `kibana.alert.rule.rule_id`
- `kibana.alert.workflow_status` for each alert
- `@timestamp` for each alert
- `host.name` and `user.name` associated with each alert
- `kibana.alert.rule.name` for human-readable rule label

## Filter binding

- `${rule_id}` — exact `kibana.alert.rule.rule_id` value (or OR-list for multiple rules)
- `${start}`, `${end}` — time window bounds

## Query

```
kibana.alert.rule.rule_id: "${rule_id}"
```

Use `.internal.alerts-security.alerts-default-*` as the index. For multiple rules: `kibana.alert.rule.rule_id: ("${rule_id1}" OR "${rule_id2}")`.

## Common pitfalls

- **Internal index, not logs alias**: Alerts live in `.internal.alerts-security.alerts-default-*`. Using `logs-*` returns nothing. This index requires the `read` privilege on `.internal.alerts-*` for the querying role.
- **Rule ID vs rule name**: `kibana.alert.rule.rule_id` is the programmatic identifier set at rule creation, not the human-readable display name in `kibana.alert.rule.name`. Use the rule_id from the alert source document or deployment documentation.
