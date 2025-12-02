Update the utilities and lessons at the end of a session
reproduction flow needs refinement
build investigation agent resources

enumrate dispostions from common knowledge
build app config class

make investigation agent call sub agent for actual invetigation and lower level judgement? maybe use claude code task feature (how to trigger reliably? and can you provide relevant task context?)

## Backlog Ideas

### Retention Policy

- Implement retention script for reproduction run data (`app/agent/reproduction/runs/`)
- Policy-driven cleanup with audit logging (not per-run cleanup)
- Consider `REPRODUCTION_RETAIN_DAYS` env var for configurable retention period
- Add disk usage monitoring/alerting for runs directory



### Analytics Suite

- High-volume alert detection: track alert frequency per signature over time windows
- Should this live at SIEM level or application level? Probably SIEM correlation rules
- Consider: alert fatigue metrics, auto-close rate tracking, escalation patterns

### Knowledge learning

- Impose increasing costs per token appendedd to the lessons learned or script added to the utlities to avoid slope (decrease costs when removing tokens)
-
