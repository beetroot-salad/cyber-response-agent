---
id: elastic.unexpected-udp-traffic
status: established
filter_keys:
  index: logs-falco.alerts-*
  window: {start: start, end: end}
  predicates:
    - {event_attr: container_id, op: eq, param: container_id}
    - {event_attr: rule, op: eq, value: "Unexpected UDP Traffic"}
---

## Goal

Retrieve Falco "Unexpected UDP Traffic" alerts for a specific container over a time
window. Used to identify containers emitting UDP traffic on ports outside their expected
service profile — a signal for DNS exfiltration, covert-channel beaconing, or
misconfigured services.

## What to summarize

- count of "Unexpected UDP Traffic" events in the window
- source and destination IPs and ports from `falco.output_fields.fd.sip` / `fd.dip` /
  `fd.sport` / `fd.dport` for each event
- process name and cmdline generating the UDP traffic
- whether destination IPs are loopback, container-internal, or external

## Query

```
falco.output_fields.container.id: "${container_id}" AND falco.rule: "Unexpected UDP Traffic" AND @timestamp:[${start} TO ${end}]
```

## Parameters

- `container_id` — 12-character Docker container ID
- `start` / `end` — ISO timestamps (inclusive bounds)
- index: `logs-falco.alerts-*`

## Common pitfalls

- **Exact rule name:** `falco.rule: "Unexpected UDP Traffic Seen"` (with "Seen" suffix)
  returns zero results. The stored rule name is exactly `"Unexpected UDP Traffic"`.
- **Broad message-substring alternatives are unreliable:** `message: *"Unexpected UDP Traffic"*`
  matches the full all-events bucket (372 KB+) because the text appears in many event
  messages, not only UDP-specific ones. Use the `falco.rule` field filter.

## Baseline (when applicable)

Run the same query on a prior quiet period to establish whether UDP traffic from this
container is a known recurring pattern or first-seen.
