# `connect` — the CLI-adapter path

Read this when the interview routes to a generated CLI adapter — the
system has no maintained MCP server, or the maintainer wants the capture
path, output control, or consistency with other adapters. The other path
is `mcp.md`. `SKILL.md` is the entrypoint and owns the common steps
(per-system knowledge, test, commit); this file is only how you build the
adapter.

## The shape to copy

Two files ship with this skill:

- `examples/_adapter.py` — the shared support module. It owns argument
  parsing, non-secret config loading, the exit codes, and credential
  resolution. You do not rewrite it; you install it and import it.
- `examples/example_cli.py` — one complete, environment-agnostic adapter
  built on `_adapter.py`. It is the shape you copy into
  `defender/scripts/tools/{system}_cli.py`.

Read both before you write anything. Then:

1. **Install the shared module** (idempotent): if
   `defender/scripts/tools/_adapter.py` does not already exist, copy
   `examples/_adapter.py` to it. If it exists, leave it — every adapter
   shares the one copy.
2. **Copy the example** to `defender/scripts/tools/{system}_cli.py`,
   change `SYSTEM`, and adapt the verbs and response parsing to the real
   API. Keep the contract below intact.

## The contract `_adapter.py` gives you for free

Build on `_adapter.py` and you inherit the contract; don't reimplement
its parts.

- **Subcommands.** `AdapterArgumentParser` with `health-check` plus one
  subcommand per verb. Name verbs for what they measure (`query`,
  `lookup`, `get-host`), not why the defender asked.
- **Exit codes.** `EXIT_OK` (0, success — a connected-but-empty result is
  still 0), `EXIT_QUERY_ERROR` (1, the system rejected the query),
  `EXIT_CONN_ERROR` (2, unreachable / unauthed / misconfigured),
  `EXIT_USAGE` (64, bad invocation — emitted automatically by the parser).
- **Config.** `load_config(system)` reads
  `knowledge/environment/systems/{system}/config.env` (non-secret; an env
  var of the same name overrides a declared key). Use
  `die(EXIT_CONN_ERROR, hint)` for a missing key.
- **`--raw`.** `print_raw(system, endpoint, args, result)` emits the
  stable JSON envelope the gather capture persists by-ref. Keep the
  envelope stable across adapters — drift breaks replay.
- **Native query pass-through.** A query source takes its native language
  (Lucene/KQL/SPL/SQL) unmodified; a lookup source keys on an identifier.
  No translation, no field renaming.

What you write: the verbs and the **transport** (the `_request` body in
the example). That's the part that legitimately differs per system.

## Credentials

The credential boundary is one audited path — `resolve_auth(system,
config)` — and you route every adapter through it. You declare the scheme
in `config.env` (non-secret) and name the env vars that hold the secrets;
`resolve_auth` returns the request headers. Built-in `AUTH_TYPE` values:

| `AUTH_TYPE` | config.env keys (non-secret) | secret source |
|---|---|---|
| `none` | — | — |
| `bearer` | `TOKEN_ENV` | env var named by `TOKEN_ENV` |
| `basic` | `USERNAME`, `PASSWORD_ENV` | env var named by `PASSWORD_ENV` |
| `header` | `AUTH_HEADER`, `AUTH_KEY_ENV` | env var named by `AUTH_KEY_ENV` |

`config.env` never holds a secret value — only the *name* of the env var
that does. For a scheme the table doesn't cover (mTLS, SigV4, OAuth
client-credentials), implement it in the adapter and note why in
`execution.md`; keep secrets in env vars regardless. **Never** accept a
pasted token, password, or auth-bearing cURL — if the maintainer offers
one, stop and remind them it belongs in an env var.

## Transport

The example's `_request` does HTTP via `urllib` with the resolved auth
headers and the configured timeout. Swap that one method for whatever the
environment needs — direct HTTP, SSH, an existing CLI you shell out to
and parse, or (on the v2 playground) `docker exec`. The rest of the
adapter — parsing, config, exit codes, auth, the `--raw` envelope — does
not change with transport.

## Conform the CLI to the client — the alignment loop

The gather subagent (Haiku) is the consumer of this CLI. The goal is a
CLI it would have *guessed*, so it needs almost no instruction to drive.
That means: **on anything cosmetic, the CLI yields to the client.**

Run a probe early — before you finalize the flags, not as an
afterthought:

1. Spawn a fresh-context **Haiku** subagent (it must match the runtime
   gather model). Hand it only the adapter's `--help` output and a
   realistic task (*"find the 5 most recent failed SSH logins on host
   `web-1` in the last hour — what exact command would you run?"*).
2. Compare what it emits to your CLI. For each divergence, ask: **is this
   a correctness/vendor constraint, or a cosmetic choice I happened to
   make first?**
   - **Cosmetic** (it reached for `--limit` and you wrote `--max`; it
     assumed the verb is `search` and you wrote `query`; it expected
     newest-first and that's free to provide) → **change the CLI to match
     Haiku.** Do not document around it.
   - **Irreducible** (the vendor field really is `customField1`; the API
     really pages with an opaque cursor) → document it minimally in
     `execution.md` / the system `SKILL.md`, and make the `--help`
     example show the real shape.
3. Re-run until Haiku drives the CLI on the first try with no guessing.

Two forces point the same way. Conforming to Haiku's priors shrinks the
docs. So does staying consistent with the example and any sibling
adapters — Haiku's prior from one adapter transfers to the next only if
they share a shape. Diverge from the example's flag and verb conventions
only when the system genuinely demands it.

## Dependencies and packaging

Python 3.11+, stdlib first (`urllib`, `json`, `ssl`, `argparse`,
`subprocess` cover most adapters). Reach for a vendor SDK only when the
API genuinely needs one (SigV4 signing, streaming, proprietary auth).
When a dep is required, add it as a named extra in
`defender/pyproject.toml`, mirror it into `[dev]`, and rebuild the venv:

```bash
cd defender && uv pip install --python .venv/bin/python -e '.[dev]'
```

Adapters run under `defender/.venv/bin/python3`; `uv.lock` is committed.

## Register the shim

Drop a shim at `defender/bin/defender-{system}`, copied from the example
shim (or a sibling) with the CLI filename swapped, and make it executable
(`chmod +x`). Per `bin/README.md`, any `defender-*` shim not listed in
`NON_ADAPTER_SHIMS` (`hooks/_cmd_segments.py`) is automatically treated as
a data-source adapter by the runtime gate hooks, and the
`Bash(defender-* *)` allow rule already covers it — no hook edit, no
allowlist edit. Dropping the shim *is* the registration.

## Fetch docs when unsure

Training knowledge is a starting point, not the source of truth. When
uncertain about API shape, field names, auth flow, or pagination, fetch
the vendor's *current official* docs. WebFetch is deliberately not
pre-approved — each call falls through to the maintainer's permission
settings and prompts interactively, because an LLM fetching
attacker-controlled content is a prompt-injection vector. Say which URL
and why, in one line, so the approval is a one-second decision.

## Before you hand off

Run the validator on the system you just built:

```bash
python3 defender/skills/connect/connect_check.py {system}
```

Fix any FAIL before returning to `SKILL.md` for the test and commit
phases.
