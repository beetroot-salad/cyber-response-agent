---
id: elastic.falco-authorized-keys-rule
status: established
filter_keys:
  index: logs-*
  dataset: falco.alerts
  predicates:
    - {event_attr: rule_name, op: eq, param: rule_name}
    - {event_attr: container, op: eq, param: container}
---

## Goal

Falco sensor events for a specific Falco rule scoped to a single container, within a time window. Queries `data_stream.dataset:"falco.alerts"` under `logs-*`. Use when both a rule name and a container name are known — for example, confirming whether "Adding ssh keys to authorized_keys" fired on a specific workload in a post-auth window.

## What to summarize

- Count of events matching the rule in the window for the specified container
- Presence or absence of any matching event (0 returned = rule did not fire on this container in the window)

## Query

```
data_stream.dataset:"falco.alerts" AND falco.rule:"${rule_name}" AND falco.output_fields.container.name:"${container}"
```

## Common pitfalls

- **Raw event stream, not detection engine.** This template queries the Falco event stream (`logs-*`, `data_stream.dataset:"falco.alerts"`), not the Kibana detection engine alerts index. A result of 0 does not mean no detection rule fired on this workload; check `elastic.cross-tier-alerts-window` for the detection engine view.
