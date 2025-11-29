# Investigation Playbook: [SIGNATURE-ID]

> Replace this template with actual playbook

## Quick Reference

| Pattern | Disposition | Confidence |
|---------|-------------|------------|
| [Pattern 1] | benign | high |
| [Pattern 2] | escalate | low |

## Investigation Steps

### Phase 1: Initial Triage
1. Check source IP classification (internal vs external)
2. Review username pattern
3. Check time of day

### Phase 2: Context Gathering
1. Query SIEM for related events (same IP, same user)
2. Check for successful logins before/after
3. Review historical patterns

### Phase 3: Pattern Matching
Compare against known patterns from past tickets.

## Approved Auto-Close Conditions

The following conditions, when ALL met, allow automatic closure:

1. [Condition 1]
2. [Condition 2]
3. [Condition 3]

## Escalation Criteria

Escalate immediately if ANY of:

- [ ] [Escalation condition 1]
- [ ] [Escalation condition 2]
- [ ] [Escalation condition 3]

## SIEM Queries

### Related Events Query
```
[Query to find related events]
```

### Historical Pattern Query
```
[Query to check historical occurrences]
```
