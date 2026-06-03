---
id: elastic.zeek-outbound-by-source
status: established
---

## Goal

Zeek network connection log entries (`zeek.connection`) originating from a specific source IP within a time window. Use after a successful SSH login to a host to enumerate outbound connections the host initiated — useful for detecting lateral movement, C2 beaconing, data exfiltration, or unexpected external connections following a session start. Complements `elastic.ip-to-host-search` (which resolves an IP to a hostname) by answering "what did this host reach out to" rather than "who is this IP".

## What to summarize

- count of outbound connection events in the window
- distinct destination IPs (`destination.ip`) and ports (`destination.port`)
- any destination IPs outside the internal address space (potential exfiltration or C2)
- distinct protocols or services observed (`network.transport`, port patterns)
- presence of long-duration or high-volume connections

## Filter binding

- `${source_ip}` — IP address of the host to track outbound connections from
- `${start}`, `${end}` — time window bounds (e.g., post-login period)
- `${limit}` — row cap; 100 covers most 30-minute windows

## Query

```
data_stream.dataset: "zeek.connection" AND source.ip: "${source_ip}"
```

## Common pitfalls

- **Bind the host's IP, not its hostname.** This template uses `source.ip`, not `host.name`. Resolve the host's current IP from Elastic Agent telemetry (`elastic.host-agent-by-ip`) before binding `${source_ip}`.
- **Internal traffic dominates.** Bulk of results in a monitored network are internal connections (health checks, metrics, DB replication). Focus on destinations outside the internal subnet when investigating exfiltration.
