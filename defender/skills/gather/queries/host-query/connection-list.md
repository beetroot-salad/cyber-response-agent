---
id: host-query.connection-list
status: established
---

## Goal

Currently established TCP connections on the host (source and destination IPs and ports). Answers what outbound channels the host has open now, used to characterize active communication or detect command-and-control channels.

## What to characterize

- established connection count (total)
- local IP and port pairs (source side)
- remote IP and port pairs (destination side)
- distinct remote hosts (cardinality)
- ports in use (common ones: 443 https, 80 http, 22 ssh, 53 dns)

## Query

```
connection-list
```

No parameters.

## Common pitfalls

- **No process attribution**: the adapter returns 4-tuples (src_ip:src_port → dst_ip:dst_port) without the owning process ID or process name. For "which process opened this connection," route to Wazuh syscall audit.
- **Established only**: the listing includes only TCP connections in `ESTABLISHED` state; connections in `LISTEN` or `SYN_SENT` are not included. For listening ports, use `listening-sockets`.
- **Live-host race**: the connection snapshot is taken at dispatch time. Connections that were active at the alert timestamp may have closed. Pair with Wazuh event stream for time-windowed connection history.
- **No DNS resolution**: the output is raw IP addresses. No reverse-DNS lookups or service name resolution is performed.
