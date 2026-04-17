---
lead: authentication-history
vendor: wazuh
tags: [auth, ssh, wazuh_alerts, profile]
entity_fields:
  ip: data.srcip
  user: data.srcuser
  host: agent.name
indexes: [wazuh-alerts-*]
---

# Wazuh Query Template: authentication-history

## Entity Field Mapping

| Entity type | Wazuh field     | Notes                                              |
|-------------|-----------------|----------------------------------------------------|
| ip          | data.srcip      | Source IP of the auth attempt                      |
| user        | data.srcuser    | SSH only. For Windows AD use data.dstuser instead  |
| host        | agent.name      | Target host, not source. See field-quirks.md       |

## Base Query

```
rule.groups:sshd AND {entity_field}:{entity_value}
```

This scopes to SSH authentication events only (not PAM, not Windows AD).
For Windows AD auth, replace `rule.groups:sshd` with `rule.groups:windows`
and adjust the entity field per the mapping above.

## Example Invocations

Query SSH auth events for a source IP, last 2 hours:
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcip:10.0.0.5' \
  --start 2026-04-04T10:00:00Z --window 2h
```

Query SSH auth events for a username, specific time range:
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcuser:admin' \
  --start 2026-04-04T08:00:00Z --end 2026-04-04T12:00:00Z
```

Query all SSH events for a host (baseline comparison):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND agent.name:web-server-01' \
  --start 2026-04-03T10:00:00Z --window 24h
```

## Baseline (Shift Query)

To grade a rate claim, run the same query against a prior window of
equal duration — shift `--start` back 7 days, keep `--window`
identical. Compare event counts between the two windows.

Current window (observed):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcip:10.0.0.5' \
  --start 2026-04-17T10:00:00Z --window 2h
```

Baseline window (same entity, 7 days earlier, same duration):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcip:10.0.0.5' \
  --start 2026-04-10T10:00:00Z --window 2h
```

For per-host failure-rate baselines, swap the entity field to
`agent.name` and narrow to failed-auth rules (e.g.,
`AND rule.id:(5710 OR 5712 OR 5716)`). If the baseline window is
empty, report that explicitly — `0 → N` is stronger than
`N → 10N` at the same absolute count.

## Customization Notes

- To filter specific rule IDs (e.g., failed auth only): add `AND rule.id:5710`
- To get raw JSON for programmatic parsing: add `--raw`
- Unfiltered count (data source health) is included automatically in formatted output
