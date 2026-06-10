---
name: non-container-host-persistence-paths-outside-falco
description: Falco monitors container workloads only; crontab spool and home-directory writes on non-container prod-tier hosts produce no events — name these as ceiling_test gaps instead of planning leads against absent telemetry.
telemetry_source: [falco, auditd, fim]
attack_phase: [persistence]
source_signature: [v2-cross-tier-ssh-pivot]
source_finding_ids:
  - live-cross-tier-pivot-3/2
created_at: 2026-06-04T00:00:00Z
---

Falco's eBPF monitoring targets container workloads. When a prod-tier host (bare-metal or VM, not a container) is the lateral-movement landing point, Falco produces no file-write events for that host. The absence of events is not authoritative — the monitored surface stops at the container boundary.

The persistence paths on non-container hosts that fall outside Falco coverage:
- `/var/spool/cron/crontabs/<user>` — crontab installation for a named account
- `~/.config/`, `~/.local/`, or any home-directory path — beacon or persistent script placement
- `/etc/cron.*`, `/etc/systemd/system/` — system-level persistence

**The rule:** If the target host is a non-container prod-tier host and the deployment has no host-level auditd or FIM, do not plan a Falco or SIEM lead targeting writes at these paths. There is no telemetry to retrieve.

Record each unmonitored persistence path by name in a `ceiling_test` gap: "crontab spool write on jump-box-1 (/var/spool/cron/crontabs/svc.config-mgmt) not retrievable — no host-level FIM or auditd in deployment." A generic note ("file writes not retrieved") understates the gap and does not name the specific paths the persistence story would have touched.
