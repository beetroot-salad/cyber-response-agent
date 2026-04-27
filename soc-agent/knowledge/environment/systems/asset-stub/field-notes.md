# asset-stub field notes

- Records are returned verbatim — no schema normalization. Field names
  in the stub fixture are illustrative; production CMDBs/IdPs differ.
- `lookup` returns `{"found": false, "record": null}` for missing keys;
  this is a valid result, not an error. Exit code 0 in both cases.
- The stub has no auth surface. `health-check` only confirms the data
  file loads. Real connectors must probe the upstream auth endpoint.
- The fixture's `hosts` bucket is keyed by Wazuh agent name (`agent.name`
  in alerts). For deployments where `agent.name` is a UUID rather than
  a hostname, the bucket key has to match what the alert carries.
