---
signature_id: wazuh-rule-5710
purpose: Field-level quirks for shape comparison. Read by archetype-scan and other subagents that extract observables from the alert. Not a substitute for context.md — just the gotchas.
---

# Field Quirks — wazuh-rule-5710

## Key observables

| Observable | JSON path | Why it matters for shape comparison |
|-----------|-----------|-------------------------------------|
| Attempted username | `data.srcuser` | Primary shape discriminator — sentinel (`nagios`, `probe`, `healthcheck`) vs service-account (`svc-*`, `backup-*`) vs wordlist (`admin`, `root`) vs real-looking (`alice.smith`, `jenkins`) |
| Source IP | `data.srcip` | Trust axis — internal RFC1918 vs external unknown. Classification drives which half of the archetype catalog applies |
| Target host | `agent.name` | Scope — targeted vs spray-and-pray |
| Timestamp | `timestamp` | Cadence anchor — single vs burst vs periodic |

## Field gotchas

- **`data.srcuser` is the *attempted* username (the target of the login attempt), not the user who connected.** The connecting party has no host account by definition — that's why the rule fires. Do not read `srcuser` as "who initiated the connection."
- **`data.srcip` may be a NAT egress IP**, not the actual attacker's address. Internal-vs-external classification is still meaningful, but two alerts sharing `srcip` do not necessarily share an actor.
- **`data.dstuser` and `agent.name`** are self-explanatory (destination user on the target host; Wazuh agent name = target host).
