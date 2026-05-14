---
lead: correlated-endpoint-events
vendor: wazuh
tags: [endpoint, correlation, wazuh_alerts, discriminate]
entity_fields:
  container: data.output_fields.container.id
  host: agent.name
indexes: [wazuh-alerts-*]
---

# Wazuh Query Template: correlated-endpoint-events

## Entity Field Mapping

| Entity type | Wazuh field                          | Notes                                                                                              |
|-------------|--------------------------------------|----------------------------------------------------------------------------------------------------|
| container   | data.output_fields.container.id      | Falco-populated container identifier; used when the alerting rule is Falco (rule.id 1XXXXX range). |
| host        | agent.name                           | Wazuh agent identity; used when the entity is a host endpoint, not a container.                    |

### Discriminator fields (not entities — inspect in raw JSON)

| Field                          | Purpose                                                                                                |
|--------------------------------|--------------------------------------------------------------------------------------------------------|
| data.output_fields.proc.pname  | Parent process name — geometry discriminator for process-spawn rules.                                  |
| data.output_fields.proc.exepath | Executable path — disambiguates `proc.name` impersonation (sshd-named binaries that are actually Java). |
| data.output_fields.fd.lport    | Local port — direction discriminator for network rules.                                                |
| data.output_fields.fd.sip      | Remote IP from the event endpoint's perspective — direction discriminator combined with `fd.lport`.    |
| data.output_fields.evt.type    | Event syscall type (e.g., `dup2`, `execve`, `open`) — refines the artifact kind.                       |
| rule.id                        | The co-firing rule's id — the primary aggregation key.                                                 |

## Base Query

```
{entity_field}:{entity_value}
```

The base query scopes to all events on the entity. The dispatching agent / playbook narrows further by adding rule-id range filters via `lead_hint` when the signature has a relevant correlation set. Examples:

- 100001 (Falco container shell): co-fires of interest are Falco rules 100002 / 100006 / 100007 / 100008 — add `AND rule.id:[100000 TO 100099]` to the base.
- 5710 (SSH invalid user): co-fires of interest are sibling SSH rules from the same source IP / username — add `AND rule.groups:sshd` to the base.

The agent should always exclude the alerting rule itself from the foreground query (`AND NOT rule.id:{alerting_rule_id}`) so the lead surfaces *correlated* rather than *self*-events.

## Example Invocations

Co-fires on a container in ±15 min around the alert (T0 = 15:02:23Z; bracket starts at T0−15min):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'data.output_fields.container.id:17bc2dde3fb0 AND rule.id:[100000 TO 100099] AND NOT rule.id:100001' \
  --start 2026-04-24T14:47:23Z --window 30m
```

Co-fires on a host in ±15 min around the alert (T0 = 17:48:27Z; bracket starts at T0−15min):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'agent.name:web-server-01 AND rule.groups:sshd AND NOT rule.id:5710' \
  --start 2026-04-24T17:33:27Z --window 30m
```

## Baseline (Shift Query)

The baseline is the entity's recurring co-fire pattern over a 7d window — same entity binding, no time-of-day restriction. Compare foreground per-rule counts and geometry against the 7d aggregation. The baseline query is structurally identical to the foreground except for window:

Foreground (±15 min around alert; T0 = 15:02:23Z; bracket starts at T0−15min):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'data.output_fields.container.id:17bc2dde3fb0 AND rule.id:[100000 TO 100099] AND NOT rule.id:100001' \
  --start 2026-04-24T14:47:23Z --window 30m
```

Baseline (same entity, 7d window):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'data.output_fields.container.id:17bc2dde3fb0 AND rule.id:[100000 TO 100099] AND NOT rule.id:100001' \
  --start 2026-04-17T15:17:23Z --window 7d
```

For container entities, prefer `same-image-7d` over `same-container-7d` when the container.id rotates faster than the meaningful baseline window — swap the entity filter to `data.output_fields.container.image.repository:{image}`. The lead returns the chosen `scope` in its output so ANALYZE can interpret what comparison was actually made.

## Customization Notes

- **Composition triggers.** When a signature playbook names rules whose co-fire forces escalation (e.g., 100001's composition rule lists 100002/100006/100007/100008), the foreground report should explicitly enumerate which (if any) of those rules appeared, separately from the general co-fire characterization. This is the playbook layer's signal, surfaced through the lead's `characterization`, not a built-in property of the lead.
- **Direction discriminators.** For network rules (rule range varies by vendor / ruleset), always paste the raw event's `fd.lport` / `fd.sip` / `evt.type` into the characterization — the by-role baseline compare in ANALYZE relies on these dimensions being legible per event, not summarized into prose.
