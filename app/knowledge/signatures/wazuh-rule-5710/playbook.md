# Investigation Playbook: SSH Invalid User (5710)

## Phase 1: Initial Triage

### 1.1 Classify Source IP
- Is the IP internal or external?
- See: [IP Classification](../../common/lessons/ip-classification.md)

### 1.2 Evaluate Username
- Does it match monitoring patterns? (`testuser`, `probe`, `nagios`, `zabbix`, `healthcheck`)
- Does it match service account patterns? (`svc-*`, `backup-*`, `cron-*`, `ansible-*`)
- Is it a common attack target? (`admin`, `root`, `user`, `test`)

## Phase 2: Context Gathering

### 2.1 Query Failed Attempts
- Search: Failed logins from same `srcip` in last 5 minutes
- Count total attempts
- List distinct usernames attempted

### 2.2 Check for Subsequent Success
- Search: Successful logins from same `srcip` within 60 seconds after alert
- If found: likely user typo scenario

### 2.3 Assess Pattern
- Single attempt vs repeated?
- Same username or multiple?
- Regular timing (cron-like) or irregular?

## Phase 3: Pattern Matching

Match against known scenarios:

| Pattern | Indicators | Likely Outcome |
|---------|------------|----------------|
| **Monitoring probe** | Internal IP + monitoring username + single attempt | Lower risk |
| **User typo** | Failure followed by success within 60s | Lower risk |
| **Service misconfiguration** | Service account name + internal + regular timing | Lower risk, needs remediation |
| **Brute force** | External IP + multiple failures + multiple usernames | Higher risk |

## Phase 4: Decision

### Auto-Close Criteria (All must be true)
- Pattern matches known lower-risk scenario
- Confidence score >= 0.90
- No escalation triggers present

### Escalation Triggers (Any one triggers escalation)
- External IP with >5 failures
- Multiple distinct usernames from same IP
- No matching pattern found
- Critical asset involved
- Uncertainty about classification

## Approved Actions

| Action | When | Notes |
|--------|------|-------|
| **Auto-close** | High confidence match to lower-risk pattern | Document reasoning |
| **Escalate** | Higher-risk indicators OR uncertainty | Include gathered context |
| **Create remediation ticket** | Service misconfiguration pattern | For credential fix |

## Evidence to Collect

Before any decision, gather:
- [ ] Source IP classification (internal/external)
- [ ] Failed attempt count (last 5 min)
- [ ] Distinct usernames attempted
- [ ] Successful login check (last 60s)
- [ ] Asset criticality of target host
