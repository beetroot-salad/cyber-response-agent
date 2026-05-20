# playground-v2/attacks/ — attack scenario surface

Parameterized attack scenarios that generate realistic threat telemetry
across the three signal categories called out in
`docs/playground-environment-v2.md §Attack-simulation surface`:
auth/metadata, execution, and data access.

Dispatches happen from the devcontainer against the remote compose stack
on the Hetzner VPS, via `docker --context soc-playground exec`. Attacks
fire into the live environment with baseline activity left on — the
agent's job is signal-vs-noise discrimination, and a quiesced capture
window evaluates against a strawman. Each run writes a manifest to
`runs/<run_id>/meta.json` (start/end timestamps + per-step rc) as an
investigation-context hint. Post-mortem reproduction of a specific
investigation comes from the soc-agent tool audit log
(`audit_tool_calls.py` records `tool_input` + `tool_response` per call);
historical query reproducibility relies on Elastic ILM retention, not on
per-run determinism.

## Quick reference

```bash
cd /workspace/playground-v2/attacks

# List available scenarios:
./runner.py list

# Run a scenario (baseline stays on — fire into live noise):
./runner.py run ssh-brute-force-canary --seed 42

# Overrides (any subset):
./runner.py run living-off-the-land --intensity 3 --seed 7
./runner.py run cross-tier-ssh-probe --user sre.alice --target web-1

# Preview without dispatching:
./runner.py run persistence-authorized-keys --dry-run

# Stage CR context before firing (exercises agent's CR scope-check):
./runner.py run cross-tier-ssh-probe --cr-mode valid
./runner.py run ssh-brute-force-canary --cr-mode stale
./runner.py run living-off-the-land --cr-mode scope-mismatch
```

## `--cr-mode` — synthetic change-request context

A run with `--cr-mode {valid|stale|scope-mismatch}` POSTs a synthetic CR to the `change-mgmt` stub immediately before the attack fires. The CR is captured in `meta.json.pre_run` and lives in change-mgmt's STORE until the next container restart. CR ids use the prefix `CHG-RUNNER-<run_id_short>` so the runner artifact and the CR record are easy to correlate.

| `--cr-mode` | CR scope | Intended agent verdict |
|---|---|---|
| `none` (default) | — (no CR posted) | Unauthorized — classic escalate. |
| `valid` | target host + current window, requester = source user | Authorized-window cover. The agent should resolve the legitimacy contract as `authorized` *iff* it also confirms host + identity + timing match. |
| `stale` | target host but window is in the past (now-3h..now-1h) | Tests the agent's temporal-scope check. CR exists but doesn't cover *now*. |
| `scope-mismatch` | a different host (sibling in same inventory role, or `canary-1` fallback) | Tests the agent's host-scope check. CR exists for the wrong host. |

Posting happens via `docker exec change-mgmt python -c …` so the runner doesn't need an SSH tunnel and adds no new Python dependencies — it reuses the docker context it already uses for `exec`-based dispatch.

## Scenario catalog

Each scenario in `catalog.yaml` declares source host + identity, target host, and a step list with command templates. The runner resolves `${host}`, `${target}`, `${user}`, `${iteration}`, `${intensity}` placeholders per step and dispatches via `docker exec` (with `-u <user>` when non-root).

See `catalog.yaml` for the full schema header; see the scenarios in the same file for worked examples.

## Run manifest

`runs/<run_id>/meta.json` fields:

- `run_id`, `scenario_id`, `category`, `description`
- `seed`, `overrides`, `resolved` (intensity / source_user / target_host after defaults apply)
- `pre_run` — `{cr_mode, cr_request?, cr_post_rc?, cr_post_response?}` capturing the synthetic CR (when `--cr-mode != none`)
- `started_at`, `finished_at` (UTC ISO8601, second precision) — investigation-context hint, not a hard query boundary
- `aborted` — true iff a non-`allow_fail` step returned non-zero
- `steps[]` — per-step `{source_host, source_user, cmd, rc, stdout_tail, stderr_tail, started_at, ended_at, duration_s}` (outputs truncated to 500 bytes each)

This manifest is intentionally lean — it bounds *when* the attack happened, not *what the agent saw*. The agent's investigation surface is captured in the soc-agent run dir's `tool_audit.jsonl` (each tool call's input + response, written by the `audit_tool_calls.py` PostToolUse hook). That's the post-mortem record; the runner doesn't pre-snapshot host state because it can't predict which leads the agent will run.

`runs/` is gitignored except for its `.gitignore`.

## Design notes

- **Live environment, no quiesce.** Attacks fire into baseline noise. Signal-vs-noise discrimination is the agent's job; a clean capture window evaluates against a strawman. Recreating hosts to flip the baseline kill-switch would itself inject a synthetic boundary (sshd restart, fresh agent check-in, `agent.id` churn on rebuild) the agent could latch onto.
- **Reproducibility lives at the pattern layer, not the dispatch layer.** Per-iteration PRNG seeding (`sha256(scenario_id:seed:step_index:iteration)`) keeps dispatches stable for debugging, but the agent's tool surface is broader than any time-windowed Elastic replay — host state (processes, FDs, FIM) is non-replayable. Recurring patterns at scale + Elastic retention make investigations reproducible at the eval layer; specific-run reproducibility comes from `tool_audit.jsonl` recording what the agent actually queried and what came back.
- **Source/target realism.** Source hosts and identities are real compose containers + realm users, so telemetry (Keycloak events, Zeek conns, sshd/auth.log, Falco syscall events) carries the right labels. `office-ws-1` with `dev.dana` reaching `db-1` looks like a compromised workstation — because the user has no account on `db-1` and office-ws has no `trust_edges_out` to db per inventory.
- **Retention is the fixture surface.** Eval and replay rely on ILM keeping the relevant data streams queryable for the fixture lifetime. Pin retention before treating any run as a stable reference.
