---
signature_id: wazuh-rule-100001
purpose: Field-level quirks for shape comparison. Read by archetype-scan and ticket-context subagents that extract observables from the alert. Not a substitute for context.md — just the gotchas.
---

# Field Quirks — wazuh-rule-100001

## Key observables

| Observable | JSON path | Why it matters for shape comparison |
|-----------|-----------|-------------------------------------|
| Shell process | `data.output_fields.proc.name` | The shell binary that spawned (`bash`, `sh`, `zsh`, ...) — primary event identity |
| Parent process | `data.output_fields.proc.pname` | **Strongest discriminator**: app-spawned (python/node) vs operator-driven (docker/kubectl) vs init-script (entrypoint, tini) |
| Container | `data.output_fields.container.id` | Scope — short (12-char) Docker/containerd ID; pairs with `container.name` when present. Defines which workload is under inspection |
| Target host | `agent.name` | Scope — the node where the container is running |
| Timestamp | `timestamp` | Cadence anchor — one-off vs burst vs periodic |

## Field gotchas

- **`pname` means parent name, not process name.** `proc.name` is the shell itself; `proc.pname` is who spawned it. Mixing them up inverts the entire story.
- **`data.output_fields` is nested in the indexed event**, even though the original Falco JSON uses dotted keys (`"container.id"`). Query the nested form: `data.output_fields.container.id`, not `"data.output_fields.container\\.id"`.
- **`proc.aname[2..n]`** = grandparent, great-grandparent, etc. Walk this when `pname` is itself a generic shell/interpreter and you need further ancestry.
- **`data.priority` is Falco's priority, not Wazuh's level.** They can differ — don't conflate them.
