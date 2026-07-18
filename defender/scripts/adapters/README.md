# `scripts/adapters/` — data-source adapters

Each connected system has a `{system}_adapter.py` adapter here, paired with a
`defender-{system}` shim in `../bin/`. The gather subagent only ever calls
the shim, never the script directly — see `../../bin/README.md` for the
shim contract and `../../docs/system-skill-shape.md` for the per-system
knowledge an adapter is paired with.

(Every file here is an adapter `*_adapter.py` or the shared `_stub_transport.py`
they import. The gather pipe-tools, run-dir tooling, and analytics that used
to share this dir now live under `scripts/gather_tools/`, `scripts/visualize/`,
and the repo-root `scripts/` tree.)

## House conventions — what `/connect` conforms to

This is a **populated** tree, so when `/connect` onboards another system it
**conforms to the conventions below instead of installing its own greenfield
seed** (`../../skills/connect/examples/_adapter.py`). These are the recurring
answers; the connect interview confirms them rather than re-deriving them per
system. One shared module for the tree — extend it in place, never fork a
second one.

- **Shared module — `_stub_transport.py`.** Every adapter imports it for
  `load_config(system, prefix)` and the transport helpers
  (`docker_exec_curl`, `http_get`/`http_post`, `health_check`,
  `split_status`). New verbs are plain annotated functions registered in the
  adapter's `VERBS` mapping, keyed by verb name — each *returns* its JSON
  payload as a dict (the query tool renders it), never prints; usage errors
  come from the `faults.py` taxonomy (bad params → exit 64). The contract
  lives here.
- **Transport — `docker --context soc-playground exec <bastion> curl …`.**
  The systems are services on the playground compose network, reached by
  shelling out through the bastion named in `BASTION_HOST`, not by direct
  HTTP from this host. `host_state_adapter.py` runs `docker exec → command
  output` (no HTTP) instead; both route through `_stub_transport`.
- **Auth — none.** The stubs are auth-less on the compose network, so this
  tree has no `resolve_auth` / `AUTH_TYPE` layer. The connect skill's
  example carries one because a *credentialed* deployment needs it; a system
  here that genuinely needed credentials would name its secret env vars in
  `config.env` (names, never values) and resolve them in the adapter — but
  nothing in this tree does today.
- **Config — `URL_BASE`, `BASTION_HOST`, `TIMEOUT_SEC`** in
  `../../knowledge/environment/systems/{system}/config.env`, each key
  prefixed with the system name (e.g. `IDENTITY_URL_BASE`). Non-secret only;
  an env var of the same prefixed name overrides the file for CI/per-run use.
- **Exit codes — `0` ok / `1` query rejected / `2`
  unreachable-or-misconfigured / `64` bad invocation.** The circuit breaker
  counts only genuine `2`s as infra failures, so keep agent-side mistakes
  (bad flag, unknown subcommand) on `64`.

To add an adapter: copy the closest sibling here, keep the conventions
above, register its shim per `../../bin/README.md`, and run the scaffold
validator — `python3 defender/skills/connect/validate_scaffold.py {system}`.
