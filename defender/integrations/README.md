# `integrations/` — data-source adapters

Each connected system has a `{system}_adapter.py` adapter here, paired with a
`defender-{system}` shim in `../bin/`. The gather subagent only ever calls
the shim, never the script directly — see `../../bin/README.md` for the
shim contract and `../../docs/system-skill-shape.md` for the per-system
knowledge an adapter is paired with.

(Every file here is an adapter `*_adapter.py` or the shared `_stub_transport.py`
they import. The gather pipe-tools, run-dir tooling, and analytics that used
to share this dir now live under `investigation/`, `presentation/`,
and the repo-root `scripts/` tree.)

## House conventions — what `/connect` conforms to

This is a **populated** tree, so when `/connect` onboards another system it
**conforms to the conventions below instead of installing its own greenfield
seed** (`../../skills/connect/examples/_adapter.py`). These are the recurring
answers; the connect interview confirms them rather than re-deriving them per
system. One shared module for the tree — extend it in place, never fork a
second one.

- **Shared module — `_stub_transport.py`.** Every adapter imports it for
  `load_config(system, prefix)` and the transport helpers (`http_get`/`http_post`,
  `http_timed`, `health_check`). New verbs are plain annotated functions registered in the
  adapter's `VERBS` mapping, keyed by verb name — each *returns* its JSON
  payload as a dict (the query tool renders it), never prints; usage errors
  come from the `faults.py` taxonomy (bad params → exit 64). The contract
  lives here.
- **Transport — the credential proxy, only.** A system is reached through the
  proxy because its settings folder holds an `access.yaml` naming its `base`, its
  auth scheme and any non-GET reads or writes; there is no other access method and
  no access-method key (#1391 P1). The proxy adds the stored credential and its
  route check is the system's guard (#1163 A6); only Elastic adds its own endpoint
  and index confinement before sending (P3). host-state is HTTP too: an
  endpoint-security product's query API (#1391 O5).
- **Auth — the proxy's.** An adapter never holds a credential: the declaration
  names the scheme (bearer, basic, header, OAuth client credentials) and the proxy
  injects the credential stored for the tenant and system.
- **Config — the keys the adapter declares, and no others** in
  the run's tenant's `settings/systems/{system}/config.env`
  (`$DEFENDER_DATA_ROOT/<tenant>/knowledge/`; the adapter reads `ctx.tenant.systems`, the
  record resolved from that folder when the run began), each key prefixed with the system
  name (e.g. `IDENTITY_TIMEOUT_SEC`). Non-secret only. The base is the declaration's, never
  a key; any key the adapter does not declare is refused by name (#1391 Q4).
  An exported variable does not override a key: the run's record is the one source.
- **Settings check — `check_settings(tenant)`, in every adapter.** A pure
  function of the run's tenant record that raises `ConfigFault` for every
  settings fault any verb can raise (`_stub_transport.check_settings_of` for the
  stubs and the ready-made adapters' shared rules: undeclared keys, required keys,
  the declaration). The run judges each granted system with it
  once, at start: one that fails is down for the run with that reason, and no
  verb of it is called (#1256). A system needing no settings
  declares one that never raises.
- **Exit codes — `0` ok / `1` query rejected / `2`
  unreachable / `64` bad invocation.** The circuit breaker counts only genuine
  `2`s as infra failures, so keep agent-side mistakes (bad flag, unknown
  subcommand) on `64`. A `ConfigFault` at call time is never counted: it means
  the settings check missed a key, and the system goes down as not configured.

To add an adapter: copy the closest sibling here, keep the conventions
above, register its shim per `../../bin/README.md`, and run the scaffold
validator — `python3 defender/skills/connect/validate_scaffold.py {system}`.
