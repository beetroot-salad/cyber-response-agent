# `connect` — the CLI-adapter path

Read this when the interview routes to a generated CLI adapter — the
system has no maintained MCP server, or the maintainer wants the capture
path, output control, or consistency with other adapters. The other path
is `mcp.md`. `SKILL.md` is the entrypoint and owns the common steps
(per-system knowledge, test, commit); this file is only how you build the
adapter.

## The shape to copy

**First, check what's already there.** If `scripts/adapters/` already holds
sibling adapters, you are extending a populated deployment, not seeding a
fresh one — **conform to the established pattern rather than introducing a
second one.** If the tree documents its adapter conventions
(`scripts/adapters/README.md`), read that first: it names the shared module
and the recurring transport / auth / config choices you're conforming to,
so you don't reverse-engineer them from the source. Then read the closest
sibling adapter and the shared module it imports; reuse *that* module, its
config-key scheme, and its transport convention. The files this skill ships are the **greenfield seed** for a
tree with no adapters yet — do not install them alongside an existing
shared module and create two parallel conventions. If the siblings' shared
module is missing a piece you need, extend it in place rather than forking
a new one.

On a greenfield tree, two files ship with this skill:

- `examples/_adapter.py` — the shared support module. It owns argument
  parsing, non-secret config loading, the exit codes, and credential
  resolution. You do not rewrite it; you install it and import it.
- `examples/example_cli.py` — one complete, environment-agnostic adapter
  built on `_adapter.py`. It is the shape you copy into
  `defender/scripts/adapters/{system}_cli.py`.

Read both (and the closest sibling, if any) before you write anything.
Then:

1. **Reuse or install the shared module** (idempotent): if a shared
   adapter module already exists — the bundled `_adapter.py`, or whatever
   module the siblings import — import *that*. Only when none exists, copy
   `examples/_adapter.py` to `defender/scripts/adapters/_adapter.py`. One
   shared module per tree, never two.
2. **Copy the closest example** to `defender/scripts/adapters/{system}_cli.py`
   — a sibling adapter if one exists, else `examples/example_cli.py` —
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
  `knowledge/environment/systems/{system}/config.env` (non-secret; a
  `{SYSTEM}_`-prefixed env var — e.g. `ASSETDB_URL_BASE` — overrides a
  declared key, scoped per system so overrides can't collide across
  adapters). Use `die(EXIT_CONN_ERROR, hint)` for a missing key.
- **JSON is the only output, and it is the payload itself.** Every command
  prints its result as JSON on stdout — unconditionally, with no wrapper
  envelope around it. There is no human pretty-print mode: the gather agent
  consumes the payload and `defender-sql` reduces it (`FROM data` binds the
  payload's own top-level keys), so prose output has no reader. Keep each
  command's payload shape stable across releases — drift breaks replay. The
  `--raw` flag is still accepted (the gather SKILL, query templates, and
  `defender-sql` recipes pass it) but no longer toggles anything.
- **Native query pass-through, native aggregation first.** A query source
  takes its native language unmodified; a lookup source keys on an
  identifier. No translation, no field renaming. When the source can
  aggregate server-side, expose *that* interface — see "Prefer native
  aggregation" below.

What you write: the verbs and the **transport** (the `_request` body in
the example). That's the part that legitimately differs per system.

## Prefer native aggregation

Before choosing verbs, place the source on this ladder — it decides the
adapter's shape:

1. **Native aggregating query language** (ES|QL, SPL, KQL, SQL) — expose
   it and let the model write it. The aggregation runs in the source,
   exact; the adapter returns the answer, not a payload. This is the
   default for any source rich enough to support it. Exemplar:
   `elastic_cli.py esql` (`POST /_query` -> `{columns, row_count, values}`)
   — not a Lucene filter that returns documents.
2. **Filter-only source** — expose the native filter passthrough and
   return the rows; the model aggregates them downstream with
   `defender-sql`, which keeps it in SQL — a language it knows.
   `defender-sql` exposes the piped payload as a table named `data`
   (`read_json_auto` inference, so structs/lists work) and runs the SQL in
   a sealed sandbox (no file/network access):

   ```bash
   defender-{system} query '<native filter>' \
     | defender-sql "SELECT h.user AS user, count(*) c \
         FROM (SELECT unnest(hits) h FROM data) \
         GROUP BY user ORDER BY c DESC"
   ```

   The adapter's stdout **is** the table — there is no wrapper envelope to
   reach through. A top-level object yields one row whose columns are its
   keys (so `unnest(hits)` for an `{index, total, returned, truncated,
   hits}` payload); a top-level array yields one row per element.
   `DESCRIBE data` names the columns a given payload actually has —
   projecting one it lacks is a Binder Error, not an empty result. Note
   `unnest` does not always give you a struct: an ES|QL `values` is a
   positional `JSON[]`, so you index it 1-based and unwrap
   (`v[2]->>'$'`) rather than naming a field.

   This downloads before it reduces, so it's the fallback, not the goal —
   reach for it only when the source genuinely can't aggregate. When a
   source lands here, record the concrete `defender-sql` recipe for *its*
   row shape (the column that carries the rows, the fields on them) in that
   system's `execution.md`, where gather reads it at dispatch — not in the
   credential-free `SKILL.md`.
3. **No query language** (pure REST / lookup) — key on an identifier and
   return the record.

A hand-rolled filter DSL or an adapter-side reducer is the anti-pattern
the gather redesign removed — never the recommended shape.

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
headers and the configured timeout. Swap that one method for whatever your
environment needs — direct HTTP, a shell-out (curl, an SSH command, an
existing CLI you wrap and parse), or a vendor SDK call. The right transport
is a property of *your* deployment, not of this skill; the rest of the
adapter — parsing, config, exit codes, auth, the JSON payload — does
not change with it.

One thing *does* need care when you leave urllib: **the exit-code
contract.** The urllib example gets the HTTP-status → exit-code mapping for
free from `urllib.error.HTTPError.code`. A shell-out transport has no such
exception, so reconstruct the status and route it through the shared
mapping (`die_for_http_status`) instead of hand-rolling the
401/403-vs-4xx branches:

```python
# Shell-out transport: capture the body AND the HTTP status, then map via
# _adapter. Wrap the same curl in `ssh <host> …` or `docker exec <name> …`
# when the service is only reachable through a jump host or a container.
proc = subprocess.run(
    ["curl", "-sS", "-w", "\n%{http_code}", "--max-time", str(timeout),
     *header_args, url],
    capture_output=True, text=True, timeout=timeout + 5,
)
if proc.returncode != 0 and not proc.stdout:
    die(EXIT_CONN_ERROR, f"{SYSTEM}: transport failed: {proc.stderr.strip()}")
body, _, code = proc.stdout.rpartition("\n")
die_for_http_status(SYSTEM, int(code or 0), body)   # exits on failure
return json.loads(body)
```

Two traps when the transport shells out:

- **`die()` and the parser raise `SystemExit`.** Keep them *outside* any
  broad `except Exception` — a `try/except Exception` around
  `subprocess.run` will swallow the exit and mask the failure. Catch only
  the specific transport errors (`subprocess.TimeoutExpired`,
  `FileNotFoundError`).
- **Inspect a real response before writing the formatter.** Shapes vary —
  a `/roles` endpoint may return a dict keyed by name, not a list. Run the
  real call once, look at the JSON, then format; don't assume the
  example's shape.

## Conform the CLI to the client — the alignment loop

The gather subagent (Haiku) is the consumer of this CLI. The goal is a
CLI it would have *guessed*, so it needs almost no instruction to drive.
That means: **on anything cosmetic, the CLI yields to the client.**

Run a probe early — before you finalize the flags, not as an
afterthought:

1. Spawn a fresh-context **Haiku** subagent (it must match the runtime
   gather model). Hand it only the adapter's `--help` output and a
   realistic task (*"find the 5 most recent failed SSH logins on host
   `host-01` in the last hour — what exact command would you run?"*). If you
   can't pin a subagent to Haiku (a headless or unattended run), fall back
   to modeling the verbs and flags on the closest sibling adapter plus your
   own read of `--help` — the goal is unchanged: a CLI the gather subagent
   would have guessed.
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

## Run the scaffold validator

Run it on the system you just built:

```bash
python3 defender/skills/connect/validate_scaffold.py {system}
```

Fix any FAIL before going further.

## Human review checkpoint

Stop here and put a human in the loop **before the adapter runs against
the live system or anything is committed** — not only at the final diff.
This is generated code that resolves real credentials and will query the
maintainer's systems, so it gets read before it executes.

Present the generated `{system}_cli.py` and its shim to the maintainer and
ask them to review it. Call out anything you're unsure about by name — an
auth scheme you improvised beyond `resolve_auth`, a transport quirk, a
field or enum you guessed at, any departure from the example's shape. Do
**not** run the live health-check / sample query (`SKILL.md` Phase 5)
until they approve. If they want changes, make them, then re-run the
validator and the alignment probe before asking again.

In an **unattended run** with no human to ask, this checkpoint is a hard
stop, not a skip: do not run the live test or commit. Leave the generated
`{system}_cli.py` and shim in place and report that they await review.
("You test integrations directly" in `SKILL.md` means *you*, in a normal
session, run the tests after approval — not that an unattended run may
self-approve.)

Only after explicit approval do you return to `SKILL.md` for the test and
commit phases.
