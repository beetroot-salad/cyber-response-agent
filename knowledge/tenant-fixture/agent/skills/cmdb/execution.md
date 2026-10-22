# Fixture CMDB — execution

Fixture content for tests (#1108 P4). It describes no real environment.

Read this file when gather is dispatched against `system: cmdb`. Call
`list_verbs(system="cmdb")` for the verbs you may run and the params each binds.

## Common pitfalls

- **Inventory names, not telemetry names.** `get-host` is keyed by the inventory's host
  name; resolve a telemetry hostname to it first, or the lookup answers "not found".
