---
name: asset-stub
contract: LookupContract
purpose: Stub CMDB + IdP backing the contextualize-leads (endpoint-context, identity-context). Local JSON fixture, no upstream — used for tests and dev runs. Real deployments swap this for vendor adapters (servicenow_assets_cli.py, okta_users_cli.py, ...).
---

# asset-stub

Reference LookupContract adapter. Returns asset records (CMDB-shape) keyed
by IP or hostname, and identity records (IdP-shape) keyed by username.

## Invocation

    python3 scripts/tools/stub_asset_cli.py health-check
    python3 scripts/tools/stub_asset_cli.py lookup ip   <ip>
    python3 scripts/tools/stub_asset_cli.py lookup user <username>
    python3 scripts/tools/stub_asset_cli.py lookup host <hostname>

`SOC_AGENT_ASSET_DATA_PATH` must point at a JSON file matching the
`{ips, users, hosts}` schema. The contextualize-leads call this CLI once
per matching prologue vertex; not-found is a valid result (returned as
`{"found": false, "record": null}`).

## Output

stdout is one JSON object per call. `lookup` shape:

    {"found": true|false, "record": {...}|null, "key_field": "...", "key_value": "...", "error": null}

`record` keys are vendor-specific — for the playground fixture, asset
records carry `hostname`, `role`, `owner_team`, `env`; identity records
carry `display_name`, `type`, `owner_team`, `mfa`.
