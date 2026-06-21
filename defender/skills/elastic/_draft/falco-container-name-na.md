---
id: elastic.falco-container-name-na
status: draft
scope: system-wide
affects: all-falco-templates
discovered_in: verify-debug-flow-prior-alert-105543Z
---

# Falco `container.name` (and `container.image.repository`) emitted as `<NA>`

## Pattern

Falco events in `logs-falco.alerts-*` sometimes carry:

```
falco.output_fields.container.name: "<NA>"
falco.output_fields.container.image.repository: null
```

while `falco.output_fields.container.id` resolves normally (e.g. `7e76d1cea7c4`).
The sentinel appears verbatim in `falco.output` / raw `message` as
`container=<NA> (id=<short-id> image=<NA>)`.

## Root cause

Falco's container plugin resolves container metadata (name, image) by querying
the Docker socket at event-capture time. When the lookup fails — timing race,
brief socket unavailability, plugin startup lag — the plugin writes `<NA>` for
name and image while still recording the raw `container.id` from the kernel
namespace walk. The container.id comes from a different path (cgroup/nsfs) and
is unaffected by Docker-socket state.

## Workaround

**In-document substitute**: Use `falco.output_fields.container.id` (always
resolved when Falco identifies a container at all) as the container identifier
in place of `container.name`.

**Cross-source resolution** (recovers the container name): Query the same index
for other Falco events against the same container ID — events where the Docker
lookup succeeded will have `container.name` resolved:

```bash
defender/scripts/adapters/elastic_cli.py query \
  'falco.output_fields.container.id: "7e76d1cea7c4"' \
  --index 'logs-falco.alerts-*' \
  --limit 10
```

Filter the results for hits where `falco.output_fields.container.name != "<NA>"`.
If found, that value is the container name. If all events for this container ID
carry `<NA>`, the container may have been ephemeral or the plugin was degraded
for its full lifetime — treat `container.id` as the terminal identifier.

## Notes

- `falco.hostname` in the Elastic document is the Falco container's own
  hostname (not the monitored container), so it is not a substitute.
- `host.name` is always `soc-playground` (the Docker host VPS) for all Falco
  events — useless for per-container attribution.
- The SKILL.md Gaps section already notes "Per-container attribution lives in
  `falco.output_fields.container.name`" but does not document the `<NA>`
  sentinel or the container.id fallback. Fold this draft as an addendum to
  that gap entry.
