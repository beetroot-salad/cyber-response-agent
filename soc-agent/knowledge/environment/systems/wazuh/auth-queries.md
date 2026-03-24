---
tags: [wazuh, auth-events, queries]
---

# Wazuh: Authentication Query Patterns

Query patterns for Wazuh SIEM authentication events. Adapt to your Wazuh deployment.

## Failed SSH Logins (Rule 5710)

```
rule.id:5710 AND data.srcip:{srcip}
```
Time range: Last 5 minutes

## Successful SSH Logins (Rules 5501, 5715)

```
(rule.id:5501 OR rule.id:5715) AND data.srcip:{srcip}
```
Time range: Last 60 seconds after alert

## All SSH Events from Source

```
rule.groups:sshd AND data.srcip:{srcip}
```

## Aggregations

### Count Events by Source IP

```
Query: rule.id:{rule_id}
Aggregation: terms on data.srcip
```

### Distinct Usernames from Source

```
Query: rule.id:5710 AND data.srcip:{srcip}
Aggregation: terms on data.srcuser
```

## Time Filters

- Events in last N minutes: `timestamp:[now-{N}m TO now]`
- Events after specific time: `timestamp:[{alert_timestamp} TO {alert_timestamp}+60s]`

## Field Reference

- Use `data.*` prefix for extracted fields from logs
- Always specify time ranges to limit results
- Wazuh MCP server provides tools for these queries
