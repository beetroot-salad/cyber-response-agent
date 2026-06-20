---
name: connect
description: Onboard one system of record (SIEM, EDR, identity, CMDB, asset DB, threat intel, custom API) to this defender deployment. Interviews the maintainer, routes to an MCP or a generated-CLI integration, scaffolds the per-system knowledge the gather subagent needs, tests it, and opens a review branch. Assumes nothing is connected yet; one system per invocation.
---

# Connect a system of record

You connect **one** system of record to this defender deployment — the
first one on a fresh install, or another later. Assume nothing is
connected yet: you don't rely on any existing adapter, and you bring your
own example to copy. The end state is a system the gather subagent can
query, the per-system knowledge it needs to route and read results, and a
clean review branch.

There are two ways to reach a system, and they are **peers**, not a
hierarchy:

- **MCP** — a maintained server the maintainer has (or will) configure.
  Light: no code to write. See `mcp.md`.
- **Generated CLI adapter** — a small Python CLI you write. Heavier, but
  it gives output control, the query-capture path, and consistency across
  adapters. See `cli-adapter.md`.

The interview decides which. Writing a CLI is more work than pointing at
an MCP server, but neither is the "real" way to connect — surface the
trade-off honestly and let the maintainer choose (`decisions.md` has the
one defender-specific tilt).

## Your lane

You write the adapter (or record the MCP reach), the per-system skill,
its config, and a couple of seed query templates. You do **not** author
lessons (the learning loop owns `lessons/`), pre-build the query catalog
(the offline lead-author grows it from real runs), run investigations
(that's `run.py`), or touch another system's files, `hooks/`, or
`learning/`. If the maintainer asks for something outside connecting one
system, stop and point them at the right surface.

You run as a maintainer skill in a normal session, not inside the
`run.py` hook regime — so you test integrations directly, and the runtime
gates (`block_main_loop_raw_access.py`, the record-query wrapper) are
properties you verify the *shape* of, not constraints on you.

## Source of truth

Read the doc you need; don't duplicate it into what you scaffold.

- `cli-adapter.md` / `mcp.md` — the two build paths.
- `decisions.md` — why the skill is shaped this way (for grounding a call).
- `defender/docs/system-skill-shape.md` — the per-system `SKILL.md` /
  `execution.md` split and its fields.
- `defender/skills/gather/queries/SCHEMA.md` — the query-template format.
- `defender/bin/README.md` — the shim contract.
- `defender/skills/handbook/` — runtime loop and run-dir reference, on demand.

## Workflow

Six steps: **Orient → Interview → Route → Scaffold → Test → Commit.**
Sequential; if a step blocks, diagnose and fix before moving on.

### 1. Orient

```bash
ls defender/scripts/tools/ defender/bin/ defender/skills/
```

If the system already has an adapter, shim, and `skills/{system}/` dir,
stop and ask: replace it, or did they mean a different system? A re-run
on an existing system is a deliberate update — branch
`connect/{system}-update` first so the diff stays clean. If this is a
fresh deployment, expect these to be empty; that's normal.

Also note whether *other* systems are already connected. If they are,
you're extending a populated deployment: there's an established shared
adapter module and house conventions (config keys, transport, auth
posture, output shape) to **conform to**, not duplicate. Before the
interview, read the deployment's adapter-conventions note if it has one
(`scripts/tools/README.md`) and the closest sibling adapter — between them
they settle the recurring answers (which shared module, transport, auth
posture, config scheme), so you **confirm** those instead of asking cold
(see `cli-adapter.md` → "The shape to copy"). If `scripts/tools/` is empty,
you're greenfield and the bundled example is your seed.

### 2. Interview

Ask one question at a time, conversationally. You need enough to build a
working integration and no more.

On a populated tree, the conventions note and sibling adapters you read in
Orient have likely already settled the recurring answers — transport (2)
and auth posture (4). Don't re-ask those cold: state what the house
convention is and ask the maintainer to confirm or flag an exception.
Spend the interview on what's genuinely system-specific (1 and 3). On a
greenfield tree there's nothing cached yet, so ask all four.

1. **What system are you connecting?** A well-known name gives you the API
   shape from training; verify it against the real docs during the build.
   For something obscure, ask for a docs pointer.
2. **How do you reach it from this environment?** This drives the route:
   direct API (endpoint + token) → CLI; an existing CLI/script → CLI
   wrapper; reachable only over `docker exec` / SSH → CLI with that
   transport; a configured MCP server → MCP; reachable only by SSHing to
   a bastion and running tools there → **stop**, the agent must run on the
   bastion, not here.
3. **What questions does this system answer for an investigation?**
   Freeform — "host inventory and trust edges", "who is authorized on a
   host", "auth events", "IoC reputation". You need this for the
   Visibility surface; refine it after the sample query.
4. **What env vars hold the credentials, if any?** Names, not values. Some
   read sources are auth-less. You never ask for a secret value, token, or
   auth-bearing cURL — if one is offered, refuse and say it belongs in an
   env var. This is the credential boundary; it is non-negotiable.

### 3. Route and build

Pick the path with the maintainer and follow its doc end-to-end:

- **MCP** → `mcp.md`.
- **CLI adapter** → `cli-adapter.md` (it installs the shared `_adapter.py`,
  writes `scripts/tools/{system}_cli.py`, registers the `bin/` shim, runs
  the Haiku alignment loop, and **pauses at a human review checkpoint**
  before the live test — generated code is read by a human before it runs).

Come back here for the common steps below once the integration exists.

### 4. Scaffold the per-system knowledge

Both paths produce the same per-system skill. Read
`defender/docs/system-skill-shape.md` for the exact shape; if a sibling
system already exists, mirror the closest one. The bar is **lean** —
everything here grows post-merge.

`defender/skills/{system}/`:

- **`SKILL.md`** — the **Visibility surface**, frontmatter
  `name: defender-{system}` + a one-line `description`. Read by the
  orchestrating defender to *route*, never by anything that holds
  credentials. Covers what the system can and cannot answer here and how
  to read its output (the Visibility fields in `system-skill-shape.md`).
  Keep a one-line `## Execution` pointer to `execution.md`. **Declare
  `gaps` loudly** — what the system *cannot* answer here, including
  silent-failure shapes (e.g. a lookup that returns `unknown` on a miss
  rather than an error). A declared gap separates "we didn't ask" from
  "we can't ask."
- **`execution.md`** — the **Execution surface**, read only by gather at
  dispatch. For a CLI: the invocation pattern, flags, query syntax, exit
  codes. For MCP: the server and tool names (see `mcp.md`). Credential and
  connectivity detail live here, never in `SKILL.md` — the split exists so
  the orchestrator physically can't ingest it.

`defender/knowledge/environment/systems/{system}/config.env` — non-secret
config (endpoint, timeout, `AUTH_TYPE`, the *names* of secret env vars).
Track it in git when it holds no secrets; gitignore it only if it would
encode a sensitive deployment. Secrets are always env vars.

`defender/skills/gather/queries/{system}/` — write only the **couple of
seed templates you're certain of** (an entry-point measurement, a by-key
lookup), per `queries/SCHEMA.md` (`id: {system}.{template-id}`, Goal, What
to summarize, a parameterized Query body, Common pitfalls). Do **not** build a
catalog from API docs — the offline lead-author mints the rest from real
runs.

### 5. Test

For the CLI path, the human review checkpoint in `cli-adapter.md` must be
cleared first — running the adapter here executes generated code against
the live system.

- **Health check.** Confirm the system is reachable and authed (CLI: run
  the adapter's `health-check`; MCP: call the status tool). A red health
  check stops you here — diagnose (refused/DNS → network; 401 →
  credentials; timeout → endpoint; cert → SSL) and fix.
- **Sample query.** Run the simplest real query/lookup and show the
  maintainer the output: **do these results look right?** Iterate if the
  fields are garbled or missing. Zero results may just mean the window is
  too narrow — *widen* it (1h → 24h → 7d), never drop the time bound, then
  confirm whether the source holds data in the wider range.

### 6. Validate and commit

For a **CLI** integration, run the scaffold validator and fix every FAIL:

```bash
python3 defender/skills/connect/validate_scaffold.py {system}
```

Skip it on the **MCP** path — it checks the adapter and shim files an MCP
system doesn't have, so it would FAIL on things that aren't yours to fix.
Either way, walk `${CLAUDE_SKILL_DIR}/checklist.md` for the judgment items
the script can't check. Then, in a git repo (the normal
case), branch and stage — if the tree isn't under version control, skip
the branch and just leave the files in place for review:

```bash
git checkout -b connect/{system}
git add defender/scripts/tools/ defender/bin/defender-{system} \
        defender/skills/{system}/ \
        defender/knowledge/environment/systems/{system}/config.env \
        defender/skills/gather/queries/{system}/
# add pyproject.toml / uv.lock only if a dependency was added
```

**You do not merge or push.** Present a summary: files touched,
health-check result, one line of sample output, env vars the maintainer
must set, open items, and what to expect next (the first runs will hit
query-composition friction; the catalog fills in post-merge via the
offline lead-author). Tell them: "Review the diff and merge when ready."
Then stop. `/ship` can open the PR.

## Ground rules

### Hard limits (non-negotiable)

- **Never handle credential values.** Tokens, passwords, API keys, pasted
  auth-bearing cURL — all forbidden. If offered one, stop and redirect it
  to an env var. Credentials resolve through one audited path
  (`_adapter.resolve_auth`); the skill never sees a value.
- **Stay in your lane.** Write only the adapter, its shim,
  `skills/{system}/`, that system's `config.env`, and its seed templates
  (plus `pyproject.toml` / `uv.lock` if a dep was added). Never `hooks/`,
  `learning/`, `lessons/`, the runtime `defender/SKILL.md`, the invlang
  skill, or another system's files.
- **Fail loud on ambiguity.** Never silently substitute a default,
  placeholder, or guessed value for something the maintainer didn't
  confirm. Surface it and ask.

### Defaults (right for most connections, overrideable with cause)

- **Native queries pass through unmodified** (or key on an identifier for
  a lookup source).
- **One system per invocation.** Note any others and suggest re-running.
- **Generate fresh; don't ship a vendor template library, and don't
  pre-build the query catalog.**
- **The CLI conforms to the gather subagent**, not the reverse (see
  `cli-adapter.md`).

When a request legitimately falls outside the defaults — a homegrown
tool, an odd access topology — help anyway: build what's needed, surface
the divergence explicitly for human review, and let the review gate catch
anything you got wrong. The hard limits always hold.
