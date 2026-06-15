# gather_summary — per-lead telemetry actuals (disposition-free)

What each defender lead **actually returned** for this case: real counts, baselines,
identity resolutions, and cadences this deployment emitted. Telemetry only — no disposition.

## l-004 — container network-tool history & fleet baseline

```json
{
  "gather_lead": "l-004",
  "goal": "Establish whether container 7e76d1cea7c4 has prior history of network tool launches",
  "system": "elastic",
  "baseline_window": {
    "start": "2026-06-07T00:00:00Z",
    "end": "2026-06-14T19:10:26Z",
    "duration_days": 7
  },
  "alert": {
    "timestamp": "2026-06-14T19:10:26Z",
    "container_id": "7e76d1cea7c4",
    "pattern": "nc -z -w1 jump-box-1 22"
  },
  "network_tool_cadence": {
    "total_executions_7d": 9189,
    "tool_type": "nc (netcat)",
    "parent_process": "bash",
    "user_ids": [
      1001,
      1002
    ],
    "command_pattern": "nc -z -w1 <target> <port>",
    "unique_timestamps": 39,
    "temporal_distribution": "periodic/scheduled"
  },
  "ssh_port_check_pattern": {
    "specific_pattern": "nc -z -w1 jump-box-1 22",
    "occurrences_in_baseline": 6,
    "timestamps": [
      "2026-06-14T18:29:35.523Z",
      "2026-06-14T18:39:55.646Z",
      "2026-06-14T18:47:57.746Z",
      "2026-06-14T18:48:26.754Z",
      "2026-06-14T18:57:44.874Z",
      "2026-06-14T19:06:17.012Z"
    ],
    "interval_pattern_minutes": "8-10 minutes (periodic)",
    "prior_history": true
  },
  "interval_analysis": {
    "interval_1": "10m 20s",
    "interval_2": "8m 2s",
    "interval_3": "29s",
    "interval_4": "9m 18s",
    "interval_5": "8m 33s",
    "mean_interval_minutes": 8.5
  },
  "cadence_classification": "periodic/regular",
  "fleet_context": {
    "window": "2026-06-14T18:00:00Z to 2026-06-14T19:10:26Z",
    "total_fleet_alerts": 314,
    "container_7e76d1cea7c4_share": "140 of 314 (44.6%)",
    "other_affected_containers": 10,
    "pattern_consistency": "identical_fleet_wide"
  },
  "queries_executed": [
    {
      "query_id": "elastic.launch-network-tool-container",
      "lead_id": "l-004",
      "sequence": 0,
      "result_count": 9189,
      "payload_path": "gather_raw/l-004/0.json"
    },
    {
      "query_id": "elastic.falco-suspicious-network-rule",
      "lead_id": "l-004",
      "sequence": 1,
      "result_count": 314,
      "payload_path": "gather_raw/l-004/1.json"
    }
  ]
}
```

## l-004

**query** `elastic.launch-network-tool-container`  (ok)
  - param: `falco.output_fields.container.id: "7e76d1cea7c4" AND falco.rule: "Launch Suspicious Network Tool in Container" AND @timestamp:[2026-06-07T00:00:00Z TO 2026-06-1`
  - result_count: n/a
  - sample: `{"index": "logs-falco.alerts-*", "total": 9189, "returned": 100, "truncated": true, "hits": [{"agent": {"name": "soc-playground", "id": "bfaae2d3-4889-4c77-b214-8d6f00a0b730", "type": "filebeat", "ephemeral_id": "4ac06a1e-84ea-4a09-a7fa-09453d384c75", "version": "9.3.3"}, "log": {"file": {"path": "/var/log/falco/falco.…`

**query** `elastic.falco-suspicious-network-rule`  (ok)
  - param: `falco.rule: "Launch Suspicious Network Tool in Container" AND @timestamp:[2026-06-14T18:00:00Z TO 2026-06-14T19:10:26Z]`
  - result_count: n/a
  - sample: `{"index": "logs-falco.alerts-*", "total": 314, "returned": 314, "truncated": false, "hits": [{"agent": {"name": "soc-playground", "id": "bfaae2d3-4889-4c77-b214-8d6f00a0b730", "type": "filebeat", "ephemeral_id": "4ac06a1e-84ea-4a09-a7fa-09453d384c75", "version": "9.3.3"}, "log": {"file": {"path": "/var/log/falco/falco.…`

## l-005

**query** `host-state.container-identity-and-uid`  (ok)
  - param: `7e76d1cea7c4`
  - result_count: n/a
  - sample: `{"container_id": "7e76d1cea7c4", "captured_at": "2026-06-14T19:36:59Z", "name": "scanner-1", "image": "soc-playground/host-plain:24.04"}`

**query** `host-state.container-identity-and-uid`  (ok)
  - param: `scanner-1`
  - result_count: n/a
  - sample: `{"host": "scanner-1", "captured_at": "2026-06-14T19:37:07Z", "entries": ["root:x:0:0:root:/root:/bin/bash", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", "bin:x:2:2:bin:/bin:/usr/sbin/nologin", "sys:x:3:3:sys:/dev:/usr/sbin/nologin", "sync:x:4:65534:sync:/bin:/bin/sync", "games:x:5:60:games:/usr/games:/usr/sbin/no…`

**query** `host-state.container-identity-and-uid`  (ok)
  - param: `scanner-1`
  - result_count: n/a
  - sample: `{"host": "scanner-1", "captured_at": "2026-06-14T19:37:15Z", "ps_output": "    PID    PPID USER     STAT     ELAPSED CMD\n  25381       0 root     Rs         00:00 ps -eo pid,ppid,user,stat,etime,cmd --forest\n      1       0 root     Ss      10:00:53 /usr/bin/tini -- /usr/local/bin/host-entrypoint.sh /usr/sbin/sshd -D…`

**query** `ad-hoc`  (error)
  - (query errored — no result)

**query** `ad-hoc`  (ok)
  - result_count: n/a

## l-006

**query** `elastic.falco-container-timeline`  (ok)
  - param: `data_stream.dataset:"falco.alerts" AND falco.output_fields.container.id:"7e76d1cea7c4" AND @timestamp:[2026-06-14T18:55:26Z TO 2026-06-14T19:25:26Z]`
  - result_count: n/a
  - sample: `{"index": "logs-falco.alerts-*", "total": 90, "returned": 90, "truncated": false, "hits": [{"agent": {"name": "soc-playground", "id": "bfaae2d3-4889-4c77-b214-8d6f00a0b730", "ephemeral_id": "4ac06a1e-84ea-4a09-a7fa-09453d384c75", "type": "filebeat", "version": "9.3.3"}, "log": {"file": {"path": "/var/log/falco/falco.js…`

## l-007

**query** `identity.health-check`  (error)
  - (query errored — no result)

**query** `identity.health-check`  (ok)
  - result_count: n/a

**query** `identity.get-user`  (ok)
  - param: `svc.monitoring`
  - result_count: n/a
  - sample: `{"username": "svc.monitoring", "email": "svc-monitoring@soc-playground.local", "first_name": "Monitoring", "last_name": "Service", "enabled": true, "realm_role": "service-account", "authorized_hosts": ["canary-1", "ci-1", "config-mgmt-1", "db-1", "dev-ws-1", "jump-box-1", "office-ws-1", "office-ws-2", "scanner-1", "web…`

**query** `identity.can-access`  (ok)
  - param: `svc.monitoring`
  - result_count: n/a
  - sample: `{"authorized": true, "via": "override", "role": "service-account", "shell": "/usr/sbin/nologin", "sudo": false}`

**query** `identity.list-roles`  (ok)
  - result_count: n/a
  - sample: `{"sre-ops": {"name": "sre-ops", "hosts": ["web-1", "web-2", "db-1", "jump-box-1", "dev-ws-1", "office-ws-1", "office-ws-2", "canary-1"], "shell": "/bin/bash", "sudo": true, "sudo_hosts": null}, "developer": {"name": "developer", "hosts": ["jump-box-1", "dev-ws-1"], "shell": "/bin/bash", "sudo": false, "sudo_hosts": nul…`

