# gather_summary — per-lead telemetry actuals (disposition-free)

What each defender lead **actually returned** for this case: real counts, baselines,
identity resolutions, timings, and cadences this deployment emitted. Telemetry only — no
disposition, no analysis conclusions.

## l-001

**query** `elastic.sshd-auth-sequence-v2`  (ok)
  - param: `data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND source.ip: "172.18.0.25"`
  - result_count: 9
  - sample: `{"index": "logs-system.auth-*", "total": 9, "returned": 9, "truncated": false, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "type": "filebeat", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7103484, "syslog": {"hostname": "jump-box-1", "app…`

**query** `elastic.doc-fetch-by-id`  (ok)
  - param: `_id: ("AZ7KPaPk6cqAU2JctPMJ" OR "AZ7KPaPk6cqAU2JctPML" OR "AZ7KPaPk6cqAU2JctPMM" OR "AZ7KPaPk6cqAU2JctPMO")`
  - result_count: 4
  - sample: `{"index": ".ds-logs-system.auth-default-2026.05.24-000002", "total": 4, "returned": 4, "truncated": false, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "type": "filebeat", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7101483, "syslog": {"h…`

## l-002

**query** `elastic.sshd-baseline-7d`  (ok)
  - param: `data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND source.ip: "172.18.0.25"`
  - result_count: 796
  - sample: `{"index": "logs-system.auth-*", "total": 796, "returned": 500, "truncated": true, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "type": "filebeat", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7101483, "syslog": {"hostname": "jump-box-1", "…`

**query** `elastic.sshd-successful-sources-7d`  (ok)
  - param: `data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND (message: *"Accepted password"* OR message: *"Accepted publickey"*)`
  - result_count: 78022
  - sample: `{"index": "logs-system.auth-*", "total": 78022, "returned": 1000, "truncated": true, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "type": "filebeat", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7102758, "syslog": {"hostname": "jump-box-1"…`

**query** `elastic.sshd-failures-7d`  (ok)
  - param: `data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND (message: *"Failed password"* OR message: *"authentication failure"*)`
  - result_count: 78022
  - sample: `{"index": "logs-system.auth-*", "total": 78022, "returned": 1000, "truncated": true, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "type": "filebeat", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7102758, "syslog": {"hostname": "jump-box-1"…`

## l-003

**query** `cmdb.hostname-by-ip`  (error)
  - param: `172.18.0.25`
  - (query errored — no result)

**query** `ad-hoc`  (ok)
  - result_count: 11
  - sample: `{"total": 11, "hosts": [{"name": "canary-1", "role": "canary", "criticality": "sandbox", "owner": "team.sre", "change_window": null, "os": {"distro": "ubuntu", "version": "22.04"}, "service": null, "trust_edges_out": [], "users": [{"username": "svc.monitoring", "shell": "/usr/sbin/nologin", "sudo": false}, {"username": "svc.config-mgmt", "shell": "/bin/bash", "sudo": true}]}, {"name": "ci-1", "rol…`

**query** `cmdb.host-trust-edges`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"name": "jump-box-1", "role": "jump-box", "criticality": "prod", "owner": "team.sre", "change_window": "tue 02:00-04:00 UTC", "os": {"distro": "ubuntu", "version": "24.04"}, "service": null, "trust_edges_out": ["web-1", "web-2", "db-1", "dev-ws-1"], "users": [{"username": "svc.monitoring", "shell": "/usr/sbin/nologin", "sudo": false}, {"username": "svc.config-mgmt", "shell": "/bin/bash", "sudo": …`

## l-004

**query** `identity.user-profile`  (ok)
  - param: `dev.gabe`
  - result_count: n/a
  - sample: `{"username": "dev.gabe", "email": "gabe@soc-playground.local", "first_name": "Gabe", "last_name": "Iverson", "enabled": true, "realm_role": "developer", "authorized_hosts": ["dev-ws-1", "jump-box-1"], "sudo_hosts": []}`

**query** `identity.access-check`  (ok)
  - param: `dev.gabe`
  - result_count: n/a
  - sample: `{"authorized": true, "via": "role", "role": "developer", "shell": "/bin/bash", "sudo": false}`

## l-005

**query** `elastic.falco-alerts`  (ok)
  - param: `data_stream.dataset:"falco.alerts" AND falco.output_fields.container.name:"jump-box-1" AND @timestamp:[2026-06-15T07:45:34Z TO 2026-06-15T08:45:34Z]`
  - result_count: 0
  - sample: `{"index": "logs-*", "total": 0, "returned": 0, "truncated": false, "hits": []}`

**query** `elastic.zeek-outbound-by-source`  (ok)
  - param: `data_stream.dataset: "zeek.connection" AND source.ip: "172.18.0.18"`
  - result_count: 145
  - sample: `{"index": "logs-*", "total": 145, "returned": 145, "truncated": false, "hits": [{"container": {"id": "soc-playground_zeek_logs"}, "agent": {"name": "soc-playground", "id": "bfaae2d3-4889-4c77-b214-8d6f00a0b730", "ephemeral_id": "4ac06a1e-84ea-4a09-a7fa-09453d384c75", "type": "filebeat", "version": "9.3.3"}, "log": {"file": {"path": "/var/lib/docker/volumes/soc-playground_zeek_logs/_data/conn.log"}…`

**query** `elastic.sudo-commands-svc-config-mgmt`  (ok)
  - param: `data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND (message: *"sudo"* OR message: *"COMMAND"*)`
  - result_count: 49
  - sample: `{"index": "logs-*", "total": 49, "returned": 49, "truncated": false, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "type": "filebeat", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7108497, "syslog": {"hostname": "jump-box-1", "appname": "ss…`

**query** `elastic.sshd-auth-events`  (ok)
  - param: `data_stream.dataset: "system.auth" AND host.name: "jump-box-1" AND message: *"dev.gabe"*`
  - result_count: 49
  - sample: `{"index": "logs-*", "total": 49, "returned": 49, "truncated": false, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "type": "filebeat", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7108497, "syslog": {"hostname": "jump-box-1", "appname": "ss…`

**query** `elastic.falco-authorized-keys-rule`  (ok)
  - param: `data_stream.dataset:"falco.alerts" AND falco.rule:"Adding ssh keys to authorized_keys" AND falco.output_fields.container.name:"jump-box-1"`
  - result_count: 0
  - sample: `{"index": "logs-*", "total": 0, "returned": 0, "truncated": false, "hits": []}`

**query** `ad-hoc`  (ok)
  - param: `data_stream.dataset:"falco.alerts" AND (host.name:"jump-box-1" OR falco.output_fields.container.name:"jump-box-1")`
  - result_count: 0
  - sample: `{"index": "logs-*", "total": 0, "returned": 0, "truncated": false, "hits": []}`

**query** `ad-hoc`  (ok)
  - param: `data_stream.dataset:"system.auth" AND host.name:"jump-box-1"`
  - result_count: 54
  - sample: `{"index": "logs-*", "total": 54, "returned": 54, "truncated": false, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "type": "filebeat", "version": "9.3.3"}, "process": {"name": "runuser"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7109365, "syslog": {"hostname": "jump-box-1", "appname": …`

**query** `ad-hoc`  (ok)
  - param: `data_stream.dataset:"falco.alerts"`
  - result_count: 424
  - sample: `{"index": "logs-*", "total": 424, "returned": 424, "truncated": false, "hits": [{"agent": {"name": "soc-playground", "id": "bfaae2d3-4889-4c77-b214-8d6f00a0b730", "ephemeral_id": "4ac06a1e-84ea-4a09-a7fa-09453d384c75", "type": "filebeat", "version": "9.3.3"}, "log": {"file": {"path": "/var/log/falco/falco.json"}, "offset": 574883278}, "elastic_agent": {"id": "bfaae2d3-4889-4c77-b214-8d6f00a0b730",…`

## l-006

**query** `elastic.host-agent-by-ip`  (ok)
  - param: `host.ip: "172.18.0.25"`
  - result_count: 599295
  - sample: `{"index": "logs-*", "total": 599295, "returned": 20, "truncated": true, "hits": [{"agent": {"name": "dev-ws-1", "id": "512ff451-c344-41e9-8c0f-9fc7ac20055f", "ephemeral_id": "3a9b1964-19b0-4199-8a37-3a5fa11d1480", "type": "filebeat", "version": "9.3.3"}, "otelcol.signal": "logs", "service.name": "metricbeat", "log": {"file": {"inode": "1919982", "path": "/var/lib/elastic-agent/data/elastic-agent-9…`

**query** `elastic.ip-to-host-search`  (ok)
  - param: `source.ip: "172.18.0.25" OR client.ip: "172.18.0.25"`
  - result_count: 567301
  - sample: `{"index": "logs-*", "total": 567301, "returned": 50, "truncated": true, "hits": [{"container": {"id": "soc-playground_zeek_logs"}, "server": {"address": "172.18.0.9"}, "agent": {"name": "soc-playground", "id": "bfaae2d3-4889-4c77-b214-8d6f00a0b730", "ephemeral_id": "4ac06a1e-84ea-4a09-a7fa-09453d384c75", "type": "filebeat", "version": "9.3.3"}, "log": {"file": {"path": "/var/lib/docker/volumes/soc…`

**query** `elastic.sshd-source-activity`  (ok)
  - param: `host.name: "jump-box-1" AND process.name: "sshd" AND message: *"172.18.0.25"*`
  - result_count: 254155
  - sample: `{"index": "logs-system.auth-*", "total": 254155, "returned": 100, "truncated": true, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "type": "filebeat", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7112354, "syslog": {"hostname": "jump-box-1"…`

**query** `elastic.host-verify-control`  (ok)
  - param: `host.name: "jump-box-1"`
  - result_count: 506187
  - sample: `{"index": "logs-system.auth-*", "total": 506187, "returned": 10, "truncated": true, "hits": [{"agent": {"name": "jump-box-1", "id": "88aac31f-bbf3-4736-bedb-214e1c59b06c", "type": "filebeat", "ephemeral_id": "3ee56387-119f-41ef-bee6-b6a88d982b8b", "version": "9.3.3"}, "process": {"name": "sshd"}, "log": {"file": {"path": "/var/log/auth.log"}, "offset": 7112354, "syslog": {"hostname": "jump-box-1",…`

## l-007

**query** `host-state.authorized-keys-root`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "root", "path": "/root/.ssh/authorized_keys", "captured_at": "2026-06-15T08:07:35Z", "keys": []}`

**query** `host-state.passwd`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "captured_at": "2026-06-15T08:07:39Z", "entries": ["root:x:0:0:root:/root:/bin/bash", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", "bin:x:2:2:bin:/bin:/usr/sbin/nologin", "sys:x:3:3:sys:/dev:/usr/sbin/nologin", "sync:x:4:65534:sync:/bin:/bin/sync", "games:x:5:60:games:/usr/games:/usr/sbin/nologin", "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin", "lp:x:7:7:lp:/var/sp…`

**query** `host-state.authorized-keys-ubuntu`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "ubuntu", "path": "/home/ubuntu/.ssh/authorized_keys", "captured_at": "2026-06-15T08:07:47Z", "keys": []}`

**query** `host-state.authorized-keys-sre-alice`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "sre.alice", "path": "/home/sre.alice/.ssh/authorized_keys", "captured_at": "2026-06-15T08:07:52Z", "keys": []}`

**query** `host-state.authorized-keys-sre-ben`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "sre.ben", "path": "/home/sre.ben/.ssh/authorized_keys", "captured_at": "2026-06-15T08:07:58Z", "keys": []}`

**query** `host-state.authorized-keys-sre-chen`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "sre.chen", "path": "/home/sre.chen/.ssh/authorized_keys", "captured_at": "2026-06-15T08:08:03Z", "keys": []}`

**query** `host-state.authorized-keys-dev-dana`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "dev.dana", "path": "/home/dev.dana/.ssh/authorized_keys", "captured_at": "2026-06-15T08:08:10Z", "keys": []}`

**query** `host-state.authorized-keys-dev-ethan`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "dev.ethan", "path": "/home/dev.ethan/.ssh/authorized_keys", "captured_at": "2026-06-15T08:08:16Z", "keys": []}`

**query** `host-state.authorized-keys-dev-fatima`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "dev.fatima", "path": "/home/dev.fatima/.ssh/authorized_keys", "captured_at": "2026-06-15T08:08:21Z", "keys": []}`

**query** `host-state.authorized-keys-dev-gabe`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "dev.gabe", "path": "/home/dev.gabe/.ssh/authorized_keys", "captured_at": "2026-06-15T08:08:26Z", "keys": []}`

**query** `host-state.authorized-keys-dev-hira`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "dev.hira", "path": "/home/dev.hira/.ssh/authorized_keys", "captured_at": "2026-06-15T08:08:34Z", "keys": []}`

**query** `host-state.authorized-keys-dba-ivy`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "dba.ivy", "path": "/home/dba.ivy/.ssh/authorized_keys", "captured_at": "2026-06-15T08:08:39Z", "keys": []}`

**query** `host-state.authorized-keys-svc-config-mgmt`  (ok)
  - param: `jump-box-1`
  - result_count: n/a
  - sample: `{"host": "jump-box-1", "user": "svc.config-mgmt", "path": "/home/svc.config-mgmt/.ssh/authorized_keys", "captured_at": "2026-06-15T08:08:45Z", "keys": ["ssh-rsa AAAAB3rotated1779798526 svc.config-mgmt@rotation", "ssh-rsa AAAAB3rotated1779882594 svc.config-mgmt@rotation", "ssh-rsa AAAAB3rotated1779886135 svc.config-mgmt@rotation", "ssh-rsa AAAAB3rotated1780576495 svc.config-mgmt@rotation", "ssh-rsa…`

