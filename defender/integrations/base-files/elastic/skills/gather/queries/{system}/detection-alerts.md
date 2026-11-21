---
id: {system}.detection-alerts
status: established
verb: alerts
params: [end, start, sort]
---

## Goal

Detection-engine alerts over a window: which rules fired, how often, at what severity, and on which hosts and
entities. Use it to see the whole detection picture around an incident, to confirm a referenced rule fired, or to tell a
one-off from a campaign. Keyword recall: detection alert, signal, kibana.alert, rule, rule_id, severity, risk score,
alert status, correlate alerts, prior alerts.

This is a **wide/superset** query: it matches every alert and carries no rule or entity predicate. **You
narrow it to the lead** by adding the predicates the lead constrains.

## Query

Lucene, the verb's default alerts index. The clause is an exists test: it matches every alert that names a rule.

```
kibana.alert.rule.rule_id: *
```

**Narrowing examples:**

- *One rule*: add `AND kibana.alert.rule.rule_id: "<rule id>"`.
- *One host's alerts*: add `AND host.name: "<host>"`.
- *Only what still needs triage*: add `AND kibana.alert.workflow_status: "open"`.

For a histogram of rules and severities over a window, aggregate with `esql` over the same index: group by
`kibana.alert.rule.name` and `kibana.alert.severity`.

## Pitfalls

- **An alert is the rule's match, not the evidence.** Read the events beneath it, through `query`, for the
  discriminating signal.
- **Correlation and sequence rules fire on a pattern across hosts,** so their `host.name` can be null. The rule name
  and count are the finding; read the alert document for per-alert detail.
- **Nested fields.** Alert documents carry the rule under `kibana.alert.rule.*` and a copy of the matched event's
  fields. Predicates on the copied fields match the event as it was when the rule fired.
- **The alerts index is a separate target from events.** `alerts` reads it by default; a `query` over the events index
  never returns an alert.
