---
signature_id: wazuh-rule-100110
purpose: Field-level quirks for shape comparison. Read by archetype-scan and ticket-context subagents that extract observables from the alert. Not a substitute for context.md — just the gotchas.
---

# Field Quirks — wazuh-rule-100110

## Key observables

| Observable | JSON path | Why it matters for shape comparison |
|-----------|-----------|-------------------------------------|
| Queried domain | `data.dns_domain` | The full FQDN — primary event identity. The leading label (≥12 alphanumerics) is what tripped the rule |
| Query type | `data.dns_query_type` | A / AAAA / TXT / ... — TXT is unusual for real traffic and correlates with tunneling |
| Target host | `agent.name` | Scope — the endpoint whose dnsmasq resolver saw the query. Process attribution is **not** in this event |
| Timestamp | `timestamp` | Cadence anchor — burst vs sustained periodic (beacon candidate) |

## Field gotchas

- **`data.srcip` is almost always `127.0.0.1`.** dnsmasq runs locally on the endpoint, so `srcip` is the loopback. It is **not** the originating process or the real client on the LAN. Use `agent.name` for the endpoint; process attribution requires auditd / Falco / EDR correlation.
- **Rule fires on label length, not entropy.** A 12-character English word (`administration.example.com`) matches the same regex as a 12-character random string. Do not assume the alert implies randomness.
- **No pre-split parent domain.** `dns_domain` is the full FQDN. Extracting the eTLD+1 requires public-suffix-list logic — the field doesn't pre-split it.
