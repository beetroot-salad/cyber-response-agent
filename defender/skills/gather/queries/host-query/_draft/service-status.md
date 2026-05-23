---
id: host-query.service-status
status: draft
---

## Goal

Current systemd/sysv service state (active, inactive, failed, not-found). Answers whether a service is installed and running on a host.

## What to summarize

- service installation state (found or not found)
- service state if present (active, inactive, or failed)

## Query

```
service-status --name ${service_name}
```

## Common pitfalls

- Service name differs from package name. `apt-mirror` is the package; the service may be named `apt-mirror` or a variant. Check systemd with `systemctl list-unit-files` or sysv in `/etc/init.d/` for the actual service name.
- `service-status` distinguishes "not-found" (service unit does not exist) from "inactive" (unit exists but is stopped). This distinction matters for authorization.
