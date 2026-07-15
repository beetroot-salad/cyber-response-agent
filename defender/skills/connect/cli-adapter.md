# `connect` — the generated-adapter path

Read this when the interview routes to a generated adapter — the system
has no maintained MCP server, or the maintainer wants the capture path,
output control, or consistency with other adapters. The other path is
`mcp.md`. `SKILL.md` is the entrypoint and owns the common steps
(per-system knowledge, test, commit); this file is only how you build the
adapter.

## What an adapter is (and is not)

An adapter is **not a CLI**. Since #611 a data-source call is not a bash
string the model authors and no subprocess runs one — the adapter is a
Python module the runtime imports **in-process** and calls through the
typed `query` tool. So there is:

- **no argparse, no `--help`, no `main()`, no subcommands, no shim** — the
  model never names a program or a flag; and
- **no `sys.exit` and no exit-code printing** — a `SystemExit` is a
  `BaseException` that unwinds straight out of the run, writing no queries
  row for the very failure the taxonomy exists to record.

A module is an adapter iff it exposes one module-level name:

```python
VERBS = {"health-check": health_check, "get-host": get_host, ...}
```

`VERBS` maps a **verb name** (kebab-case, what the model passes as
`verb=`) to a **verb function**. That mapping is the whole model-facing
surface. Everything else in the module is private support the model cannot
reach.

## The shape to copy

**First, check what's already there.** If `scripts/adapters/` already holds
sibling adapters, you are extending a populated deployment, not seeding a
fresh one — **conform to the established pattern rather than introducing a
second one.** If the tree documents its adapter conventions
(`scripts/adapters/README.md`), read that first: it names the shared
transport module and the recurring transport / config / auth choices you're
conforming to. Then read the closest sibling adapter and the shared module
it imports; reuse *that* module, its config-key scheme, and its transport
convention. If the siblings' shared module is missing a piece you need,
extend it in place rather than forking a new one.

The reference to copy ships with this skill:

- `examples/example_cli.py` — one complete, environment-agnostic adapter:
  a `VERBS` mapping, verb functions that take a `VerbContext` and return a
  dict, and a transport that raises `faults`. It is the shape you copy into
  `defender/scripts/adapters/{system}_cli.py`.

The live tree's own `scripts/adapters/<system>_cli.py` modules are the same shape built
on the shared `_stub_transport.py`; read it and the closest sibling before
you write anything. Then:

1. **Reuse the shared transport module** if one exists (the siblings'
   `_stub_transport.py`, or whatever they import) — import *that*. Only on a
   truly greenfield tree do you write your own transport, modelled on
   `example_cli.py`'s `_request`. One shared transport per tree, never two.
2. **Copy the closest example** to `defender/scripts/adapters/{system}_cli.py`
   — a sibling adapter if one exists, else `examples/example_cli.py` —
   change `SYSTEM`, and adapt the verbs and response parsing to the real
   API. Keep the contract below intact.

## The verb contract

A verb is a plain annotated function. The whole contract is in its
signature and its return:

```python
from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import faults

def get_host(ctx: VerbContext, *, host: str) -> dict:
    """One host's record. `host` is a declared param; a call that omits it,
    misspells it, or passes a non-string is rejected with exit 64 before the
    body runs."""
    return _request(ctx, f"/hosts/{host}")
```

- **`VerbContext` is harness carriage, passed positionally.** It carries the
  RUN's `defender_dir` (resolve `config.env` from HERE, never an import-time
  constant — a worktree or an eval's tmp tree must read its own config) and
  the RUN's scrubbed `env` (hand it to any child you fork; the driver's
  `os.environ` holds provider keys). The model never supplies it and cannot
  bind it.
- **The keyword-only params ARE the param contract.** Everything the model
  may pass is spelled `*, name: type`. The query tool's validator reads the
  signature and rejects an unknown / missing / mistyped param with exit 64,
  naming the declared roster — so there is no `--help` to author. Give each
  param a real type (`limit: int`, `enabled: bool`); the validator enforces
  it, so a quoted `"20"` or `"false"` is caught before it reaches the body.
- **A native-query verb declares its engine.** A verb whose body IS a query
  language — an ES|QL pipe, a Lucene/KQL/SQL string that lives whole in ONE
  param — imports `verb` from `defender.runtime.verbs` and carries a
  `@verb(engine=…, body_param=…)` decoration: `engine=` names the language
  (`esql`, `lucene`, `sql`, …) and `body_param=` names the single param the query
  body rides in. It only stamps two attributes and returns the function unchanged,
  so the validator still reads the signature. Declaring it is what lets a template
  put in-body `${…}` substitutions into the query text — a param-only verb requires
  every `${…}` to be a *declared param*, so an undeclared body placeholder makes
  `validate_scaffold` reject the template. `elastic_cli.py`'s `esql`
  (`@verb(engine="esql", body_param="query")`) and `query`/`alerts`
  (`@verb(engine="lucene", body_param="native_query")`) are the exemplars;
  `get-host` above is param-only and carries no decoration.
- **A verb RETURNS its payload** — a dict or list of the upstream JSON,
  unmodified. It does not print and it does not exit. The query tool
  captures the returned value by-ref under `gather_raw/`.
- **`health-check` is required.** It returns a small status dict (e.g.
  `{"system": SYSTEM, "connected": True}`); a failed reach raises a fault.

Name verbs for what they measure (`query`, `lookup`, `get-host`), not why
the defender asked.

## Faults, not exit codes

Import the taxonomy from `scripts/adapters/faults.py` and **raise** the
member that matches the condition. The query tool turns the fault into the
queries-table row and the exit code the circuit breaker keys on — you never
write an exit code yourself:

| Fault | Exit | Meaning |
|---|---|---|
| `ConfigFault` | 2 | `config.env` missing/incomplete — the system is down (infra). |
| `TransportFault` | 2 | the transport failed: unreachable, timed out, a 5xx (infra). |
| `UpstreamFault` | 1 | the system was reached and rejected the query — a 4xx, a bad field. The agent's own to fix. |

Each fault carries a `detail` string — pass the **upstream** diagnosis
verbatim (the vendor's own error body, the docker error, the missing config
path). That `detail` becomes the row's `payload_digest`, the sole input to
the pitfalls-curation lane; a generic `str(e)` dries that lane up silently.

Exit **64** is the fourth member of the taxonomy and you never raise it: it
is the query tool's own validator rejecting a malformed call (unknown verb,
unknown/missing/mistyped param). It never trips the breaker, so a model's
typo can't mask a working system.

## Prefer native aggregation

Before choosing verbs, place the source on this ladder — it decides the
adapter's shape:

1. **Native aggregating query language** (ES|QL, SPL, KQL, SQL) — expose it
   as ONE query-body param (declared `@verb(engine=…, body_param=…)`; see **The
   verb contract**) and let the model write it. The aggregation runs
   in the source, exact; the verb returns the answer, not a payload. This is
   the default for any source rich enough to support it. Exemplar:
   `elastic_cli.py`'s `esql` verb (`POST /_query` → `{columns, row_count,
   values}`) — not a Lucene filter that returns documents.
2. **Filter-only source** — expose the native filter passthrough as a
   `native_query` param and return the rows; the model aggregates them
   downstream with `defender-sql`, which keeps it in SQL — a language it
   knows. `defender-sql` exposes the returned payload as a table named
   `data` (`read_json_auto` inference, so structs/lists work) and runs the
   SQL in a sealed sandbox (no file/network access):

   ```bash
   defender-sql "SELECT h.user AS user, count(*) c \
       FROM (SELECT unnest(hits) h FROM data) \
       GROUP BY user ORDER BY c DESC"
   ```

   The verb's returned JSON **is** the table — there is no wrapper envelope
   to reach through. A top-level object yields one row whose columns are its
   keys (so `unnest(hits)` for an `{index, total, returned, truncated,
   hits}` payload); a top-level array yields one row per element.
   `DESCRIBE data` names the columns a given payload actually has. This
   downloads before it reduces, so it's the fallback, not the goal — reach
   for it only when the source genuinely can't aggregate. When a source
   lands here, record the concrete `defender-sql` recipe for *its* row shape
   in that system's `execution.md`, where gather reads it at dispatch — not
   in the credential-free `SKILL.md`.
3. **No query language** (pure REST / lookup) — key on an identifier and
   return the record.

A hand-rolled filter DSL or an adapter-side reducer is the anti-pattern the
gather redesign removed — never the recommended shape.

## Credentials

Secrets are read from **environment variables and nowhere else**. The verb
receives the RUN's scrubbed env as `ctx.env`; the transport reads the secret
from there by the variable *name* `config.env` declares. `config.env` holds
non-secret config only — endpoints, timeouts, `AUTH_TYPE`, and the *names*
of the env vars that hold secrets — never a secret value. Name a key that
carries a secret's env-var name with an `_ENV` suffix
(`API_TOKEN_ENV=MYSYS_API_TOKEN` — the *name* of the env var to read); a bare
`PASSWORD` / `TOKEN` / `SECRET` / `API_KEY` key is read as an inline secret and
`validate_scaffold` FAILs it. Nothing in the adapter reads a secret from
`config.env`, logs one, or returns one in a captured payload. This is the single most important property of the layer;
keep it that way.

For a scheme beyond a bearer token / basic auth (mTLS, SigV4, OAuth
client-credentials), implement it in the transport and note why in
`execution.md`; keep secrets in env vars regardless. **Never** accept a
pasted token, password, or auth-bearing cURL — if the maintainer offers one,
stop and remind them it belongs in an env var.

## Transport

`example_cli.py`'s `_request` does HTTP via `urllib`; the live tree's
`_stub_transport.py` shells out to `docker --context … exec … curl`. Swap
that one layer for whatever your environment needs — direct HTTP, an SSH
command, an existing CLI you wrap and parse, or a vendor SDK call. The right
transport is a property of *your* deployment, not of this skill; the VERBS
surface above it — verb signatures, the returned payload, the faults —
does not change with it.

Two rules the transport always obeys:

- **Fork with `ctx.env`, never bare.** A child forked with no `env=`
  inherits the driver's `os.environ`, provider keys included. Every
  `subprocess.run` in the transport passes `env=dict(ctx.env)`.
- **Always set a `timeout=` on the fork.** The outer wall-clock budget died
  with the capture subprocess, so the transport's own `subprocess.run(...,
  timeout=…)` is the only real kill left. Map a `TimeoutExpired` to a
  `TransportFault`.

Inspect a real response before writing the parser — shapes vary (a `/roles`
endpoint may return a dict keyed by name, not a list). Run the real call
once, look at the JSON, then parse; don't assume the example's shape.

## Conform the adapter to the client — the alignment loop

The gather subagent (Haiku) is the consumer of these verbs. The goal is a
verb roster and param set it would have *guessed*, so it needs almost no
instruction to drive. That means: **on anything cosmetic, the adapter yields
to the client.**

Run a probe early — before you finalize the verb and param names, not as an
afterthought:

1. Spawn a fresh-context **Haiku** subagent (it must match the runtime
   gather model). Hand it only the verb roster + declared params (as the
   injected catalog would present them) and a realistic task (*"find the 5
   most recent failed SSH logins on host `host-01` in the last hour — what
   exact `query(...)` call would you make?"*). If you can't pin a subagent to
   Haiku, fall back to modelling the verbs and params on the closest sibling
   adapter — the goal is unchanged.
2. Compare what it emits to your roster. For each divergence, ask: **is this
   a correctness/vendor constraint, or a cosmetic choice I happened to make
   first?**
   - **Cosmetic** (it reached for a `limit` param and you named it `max`; it
     assumed the verb is `search` and you wrote `query`) → **change the
     adapter to match Haiku.** Do not document around it.
   - **Irreducible** (the vendor field really is `customField1`; the API
     pages with an opaque cursor) → document it minimally in `execution.md`
     / the system `SKILL.md`.
3. Re-run until Haiku drives the verbs on the first try with no guessing.

Conforming to Haiku's priors shrinks the docs; so does staying consistent
with the example and any sibling adapters — Haiku's prior from one adapter
transfers to the next only if they share a shape. Diverge from the example's
verb and param conventions only when the system genuinely demands it.

## Dependencies and packaging

Python 3.11+, stdlib first (`urllib`, `json`, `ssl`, `subprocess` cover most
adapters). Reach for a vendor SDK only when the API genuinely needs one
(SigV4 signing, streaming, proprietary auth). When a dep is required, add it
as a named extra in `defender/pyproject.toml`, mirror it into `[dev]`, and
rebuild the venv:

```bash
cd defender && uv pip install --python .venv/bin/python -e '.[dev]'
```

Adapters run under `defender/.venv/bin/python3`; `uv.lock` is committed.

## No shim to install

There is no `bin/` shim and no allowlist edit — dropping the
`{system}_cli.py` module with its `VERBS` mapping under
`scripts/adapters/` **is** the registration. The verb registry
(`runtime/verbs.py`) discovers every `*_cli.py` in that directory by glob and
reads its `VERBS` at prompt-build time. A module that exposes no `VERBS`
mapping is discovered but *unreachable* (its verb set is empty and the tool
rejects it), not unfiltered — so an incomplete adapter fails closed.

## Fetch docs when unsure

Training knowledge is a starting point, not the source of truth. When
uncertain about API shape, field names, auth flow, or pagination, fetch the
vendor's *current official* docs. WebFetch is deliberately not pre-approved —
each call falls through to the maintainer's permission settings and prompts
interactively, because an LLM fetching attacker-controlled content is a
prompt-injection vector. Say which URL and why, in one line.

## Run the scaffold validator

Run it on the system you just built:

```bash
python3 defender/skills/connect/validate_scaffold.py {system}
```

Fix any FAIL before going further.

## Human review checkpoint

Stop here and put a human in the loop **before the adapter runs against the
live system or anything is committed** — not only at the final diff. This is
generated code that resolves real credentials and will query the maintainer's
systems, so it gets read before it executes.

Present the generated `{system}_cli.py` to the maintainer and ask them to
review it. Call out anything you're unsure about by name — an auth scheme you
improvised, a transport quirk, a field or enum you guessed at, any departure
from the example's shape. Do **not** run the live health-check / sample query
(`SKILL.md` Phase 5) until they approve. If they want changes, make them,
then re-run the validator and the alignment probe before asking again.

In an **unattended run** with no human to ask, this checkpoint is a hard
stop, not a skip: do not run the live test or commit. Leave the generated
`{system}_cli.py` in place and report that it awaits review. ("You test
integrations directly" in `SKILL.md` means *you*, in a normal session, run
the tests after approval — not that an unattended run may self-approve.)

Only after explicit approval do you return to `SKILL.md` for the test and
commit phases.
