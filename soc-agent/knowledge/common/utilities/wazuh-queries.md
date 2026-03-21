# Example: Wazuh Query Patterns

> **Example queries for the Wazuh SIEM.** Adapt these patterns to your own SIEM and query tools. The query syntax and field names are Wazuh-specific.

Query templates for Wazuh SIEM investigations.

## Authentication Events

### Failed SSH Logins (Rule 5710)
```
rule.id:5710 AND data.srcip:{srcip}
```
Time range: Last 5 minutes

### Successful SSH Logins (Rules 5501, 5715)
```
(rule.id:5501 OR rule.id:5715) AND data.srcip:{srcip}
```
Time range: Last 60 seconds after alert

### All SSH Events from Source
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

## Time-Based Patterns

### Events in Last N Minutes
Add to query: `timestamp:[now-{N}m TO now]`

### Events After Specific Time
Add to query: `timestamp:[{alert_timestamp} TO {alert_timestamp}+60s]`

## Notes

- Wazuh MCP server provides tools for these queries
- Always specify time ranges to limit results
- Use `data.*` prefix for extracted fields from logs
