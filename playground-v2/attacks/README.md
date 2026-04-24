# playground-v2/attacks/ — attack scenario surface (batch 10)

Parameterized, seed-reproducible attack scenarios that generate realistic
threat telemetry across the three signal categories called out in
`docs/playground-environment-v2.md §Attack-simulation surface`:
auth/metadata, execution, and data access.

Dispatches happen from the devcontainer against the remote compose stack
on the Hetzner VPS, via `docker --context soc-playground exec`. Each run
writes a manifest to `runs/<run_id>/meta.json` — the time-window raw
material the fixture-capture pass (batch 10b) will use to bound its
Elasticsearch queries.

## Quick reference

```bash
cd /workspace/playground-v2/attacks

# List available scenarios:
./runner.py list

# Quiesce baseline activity first — otherwise synthetic benign traffic
# contaminates the capture window:
sed -i 's/^V2_BASELINE_ENABLED=.*/V2_BASELINE_ENABLED=false/' ../.env \
  || echo 'V2_BASELINE_ENABLED=false' >> ../.env
docker --context soc-playground compose -f ../compose.yml up -d \
  --force-recreate web-1 web-2 db-1 jump-box-1 dev-ws-1 office-ws-1 office-ws-2 canary-1

# Run a scenario:
./runner.py run ssh-brute-force-canary --seed 42

# Overrides (any subset):
./runner.py run living-off-the-land --intensity 3 --seed 7
./runner.py run cross-tier-ssh-probe --user sre.alice --target web-1

# Preview without dispatching:
./runner.py run persistence-authorized-keys --dry-run
```

After the run, re-enable baseline (`V2_BASELINE_ENABLED=true` + `compose up -d --force-recreate <hosts>`) to return the stack to steady state.

## Scenario catalog

Each scenario in `catalog.yaml` declares source host + identity, target host, and a step list with command templates. The runner resolves `${host}`, `${target}`, `${user}`, `${iteration}`, `${intensity}` placeholders per step and dispatches via `docker exec` (with `-u <user>` when non-root).

See `catalog.yaml` for the full schema header; see the scenarios in the same file for worked examples.

## Run manifest

`runs/<run_id>/meta.json` fields:

- `run_id`, `scenario_id`, `category`, `description`
- `seed`, `overrides`, `resolved` (intensity / source_user / target_host after defaults apply)
- `started_at`, `finished_at` (UTC ISO8601, second precision) — fixture-capture queries use this window
- `aborted` — true iff a non-`allow_fail` step returned non-zero
- `steps[]` — per-step `{source_host, source_user, cmd, rc, stdout_tail, stderr_tail, started_at, ended_at, duration_s}` (outputs truncated to 500 bytes each)

`runs/` is gitignored except for its `.gitignore`.

## Design notes

- **Reproducibility.** PRNG is seeded per-iteration as `sha256(scenario_id:seed:step_index:iteration)`. Same seed + same catalog + same compose stack → same dispatches. Scenario CLIs should not introduce un-seeded randomness.
- **Baseline coexistence.** The runner does NOT touch baseline activity. Operators are expected to quiesce + re-enable around a capture window — separation of concerns, and the kill-switch (`V2_BASELINE_ENABLED`) already exists from batch 8.
- **Source/target realism.** Source hosts and identities are real compose containers + realm users, so telemetry (Keycloak events, Zeek conns, sshd/auth.log, Falco syscall events) carries the right labels. `office-ws-1` with `dev.dana` reaching `db-1` looks like a compromised workstation — because the user has no account on `db-1` and office-ws has no `trust_edges_out` to db per inventory.
- **Deferred to batch 10b.** Capturing the agent's tool-call surface during these runs and packaging as eval fixtures — the `wazuh_cli.py --replay` mode described in `docs/evaluation-and-chaos-design.md §Tool intercept`. The run manifests here are the upstream input for that pass.
