## CONTEXTUALIZE

**Alert:** 1777243680.22 — EDR: SQL Server engine spawned PowerShell with outbound connection
**Key observables:**
- agent: edr-mssql-prod-01 / 10.0.6.27 (production-database-server)
- proc.name: powershell.exe with `-EncodedCommand <b64>`
- proc.pname: sqlservr.exe (pid 4488) — the MSSQL engine itself
- user.name: MSSQL$PROD (engine service account)
- child_outbound_connection: 164.92.71.108:8443 (TCP)
- timestamp: 2026-04-26T09:48:00.221Z
**Playbook hypotheses:** ?xp_cmdshell-misuse-via-stored-proc, ?dba-batch-script-via-sqlagent, ?sqli-rce-pivot, ?legitimate-cdc-extension
**Available leads:** sql-server-child-baseline, host-egress-baseline, sqlagent-job-correlation, recent-stored-proc-changes, encoded-command-decoder
**Archetype matches:**
- xp_cmdshell-misuse — candidate — `sqlservr.exe → powershell.exe -EncodedCommand` is the textbook xp_cmdshell-via-SQLi pivot pattern; the destination IP being an off-baseline VPS is consistent.
- sqlagent-batch — candidate — sometimes DBAs script administrative jobs via sqlagent that spawns powershell, but the engine itself (sqlservr.exe) isn't the typical parent — sqlagent.exe is.
- cdc-extension — candidate — change-data-capture or replication addins occasionally invoke powershell from the engine for sync hooks, but rare and historically logged.
**Adversarial archetype:** xp_cmdshell-misuse — worst-case is an attacker reached SQL injection on a public-facing app and pivoted to powershell with outbound C2.
**Data environment:** reachable: sysmon_indexer, edr_query, sql_audit_api, threat_intel, network_flow, playground_ticket; degraded: none

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: production-database-server
    identifier: 10.0.6.27
    attributes:
      hostname: edr-mssql-prod-01
      host_role: production-database-server
  - id: v-002
    type: process
    classification: powershell-process
    identifier: pid-8821
    attributes:
      proc_name: powershell.exe
      cmdline_shape: '-EncodedCommand <b64>'
      user: 'MSSQL$PROD'
  - id: v-003
    type: external_endpoint
    classification: external-ip
    identifier: 164.92.71.108
    attributes:
      port: 8443
  edges:
  - id: e-001
    relation: spawned
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-26T09:48:00.221Z'
    attributes:
      parent_proc: sqlservr.exe
      parent_pid: 4488
    authority:
      kind: siem-event
      source: EDR process tree
  - id: e-002
    relation: opened_outbound_connection
    source_vertex: v-002
    target_vertex: v-003
    when:
      timestamp: '2026-04-26T09:48:00.221Z'
    attributes:
      port: 8443
      proto: tcp
    authority:
      kind: siem-event
      source: EDR network telemetry
```
