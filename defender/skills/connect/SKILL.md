---
name: connect
description: Onboard a new system of record (SIEM, EDR, identity, CMDB, asset DB, threat intel, custom REST API) into the defender agent. Interviews the maintainer, generates an adapter CLI mirroring the existing ones, registers its shim, tests it end-to-end, and scaffolds the per-system visibility/execution skill the gather subagent reads. One system per invocation.
---

# Connect a system of record

You wire a new data source into `defender/`. One system per invocation —
SIEM, EDR, identity platform, asset DB, threat intel, a v2-stub-style
read API, or a custom REST endpoint. The end state is: an adapter CLI
that mirrors the existing ones, a `bin/` shim that registers it, the
per-system skill the gather subagent reads at dispatch, a tested
`health-check`, and a clean review branch.

You are **not** authoring lessons here — that's the offline learning
loop (`defender/learning/`). You are **not** writing the bulk of the
query catalog — that grows post-merge from real runs via the offline
lead-author. You are **not** running investigations — that's the runtime
loop (`defender/run.py`). Stay in your lane. If the maintainer asks for
something outside onboarding a system, stop and point them at the right
surface.

You run as a **maintainer skill in a normal session**, not inside the
`run.py` hook regime. The runtime gate hooks
(`block_main_loop_raw_access.py`, `block_unwrapped_adapter_calls.py`,
`approve_shim_invocations.py`) and `run-settings.json` govern the
`claude -p` investigation loop — not you. So you test adapters by
invoking the venv python on the CLI directly; the shim + record-query
wrapping you generate are for the runtime, and you verify their *shape*,
not by running an investigation.

## Source of truth

These docs own the shapes you generate. Read the one you need rather
than guessing; do not duplicate their content into what you scaffold.

- **`defender/docs/system-skill-shape.md`** — the per-system `SKILL.md`
  (Visibility surface) / `execution.md` (Execution) split and the
  Visibility fields. Authoritative for what each file holds and which
  consumer reads it.
- **`defender/docs/state-surface-adapters.md`** — the adapter CLI
  contract (subcommands, `--raw` envelope, exit codes), the
  `docker exec … curl` transport for v2-stub-style sources, and config
  conventions.
- **`defender/bin/README.md`** — the shim contract and how a dropped-in
  shim auto-gates as an adapter.
- **`defender/skills/gather/queries/SCHEMA.md`** — the query-template
  file format, for the handful of seed templates you write.
- **`defender/skills/handbook/`** — on-demand reference for runtime
  loop shape and run-dir contracts. Consult it; don't re-derive it.

The reference adapters are `defender/scripts/tools/elastic_cli.py`
(credentialed, direct HTTP) and the `_stub_transport.py`-based stubs
(`cmdb_cli.py`, `identity_cli.py`, …; HTTP over `docker exec`). Read the
one closest to the system you're connecting and copy its shape.

## Workflow

Five sequential phases: **Interview → Generate → Test → Scaffold →
Commit**, after a quick orient. Don't skip ahead. If a phase blocks,
diagnose and fix before moving on; don't paper over it.

### Phase 0: Orient

See what already exists before you touch anything:

```bash
ls defender/scripts/tools/ defender/bin/ defender/skills/
```

If the system already has an adapter (`{system}_cli.py` + a
`defender-{system}` shim + a `skills/{system}/` dir), stop and ask: do
they want to replace it, or did they mean a different system? Re-running
connect on an existing adapter is a deliberate update, not an accidental
overwrite. If they confirm an update, branch off main
(`git checkout -b connect/{system}-update`) so the review diff is clean.

### Phase 1: Interview

Ask targeted questions, one at a time in a conversational thread, not as
a wall of form fields. You need enough to generate a working adapter and
no more.

1. **What system are you connecting?** (Splunk, Elastic, CrowdStrike, a
   v2 stub, a custom REST API, etc.) A well-known name gives you the API
   shape from training — use it as a starting point, but plan to verify
   against the real docs in Phase 2. For something obscure, ask for a
   pointer to API documentation.

2. **How do you reach it from this environment?** Roughly in order of
   what defender already does:
   - **HTTP over `docker exec`** — the v2-stub pattern. The adapter
     shells out to `docker --context soc-playground exec <host> curl …`
     and parses the response. No port management, no new auth surface.
     This is the default for anything on the playground network.
   - **Direct API** — endpoint + token/basic auth, reached directly
     (the `elastic_cli.py` shape). The adapter resolves its own
     connection and credentials.
   - **Existing CLI or script** — the org already has a wrapper; your
     adapter shells out and parses its output.
   - **MCP server** — a server already configured for the agent. See
     the MCP-vs-CLI section below.
   - **Bastion / jump host** — they reach the system only by SSHing
     somewhere and running tools there. Then the agent runs on the
     bastion, not here. Stop, tell them, and exit cleanly.

3. **What questions does this system answer for an investigation?**
   Freeform — "host inventory and trust edges", "who is authorized on a
   host", "auth events", "IoC reputation". You need this for the
   Visibility surface's `available_queries` / `when_to_use`. It's okay
   if it's vague now; you refine it after the sample query in Phase 3.

4. **What environment variables hold the credentials, if any?** Names,
   not values. Many v2-style read sources are auth-less (their
   `config.env` is non-secret and tracked in git). A credentialed system
   reads its secrets from env vars; you tell the maintainer which names,
   never the values.

You do **not** ask for credential values, tokens, passwords, API keys,
or endpoint URLs that encode auth material. Those go in env vars. If the
maintainer pastes one, refuse and remind them where it belongs. This is
non-negotiable — it's the credential boundary.

#### MCP vs CLI adapter — maintainer preference, not a technical winner

Both paths work; both are supported. **Defender's existing systems are
all CLI adapters — v2 chose CLI for simplicity** (one stable shim token,
a stdlib transport, full control over the `--raw` envelope the gather
capture persists). That's the path of least resistance and keeps a new
system consistent with the rest of the directory. But the choice is the
maintainer's, and there are real axes where MCP wins. You present the
trade-off honestly and let them pick; you are not opinionated here.

| Axis | MCP server | Generated CLI adapter |
|---|---|---|
| **Effort upfront** | If a maintained server already exists and is configured: ~0 code. | Write + test a Python CLI per system. |
| **Effort ongoing** | Upstream version bumps, bugs against someone else's codebase. | Local iteration, under your control. |
| **Customization** | Whatever the server author chose — output shape, pagination, errors. | Full control: `--raw` envelope, exit codes, error text, the verbs you expose. |
| **Consistency** | A new shape in a directory where everything else is a CLI adapter. | Matches `elastic_cli.py` / the stubs; the gather subagent's prior transfers. |
| **Capture / audit** | The runtime tags MCP output, but it doesn't flow through the `--raw` → `gather_raw/` path the queries table depends on. | Emits the stable `--raw` envelope the gather capture wrapper persists by-ref. |
| **Ownership** | Consumer relationship; forking is awkward. | You own the source you depend on. |

Walk these questions: Is there a maintained MCP server for this system?
Is it already configured? Do you need a custom output shape or the
`--raw` capture path? Do you prefer owning the source? If no MCP server
exists, or the answers lean toward control and consistency, generate a
CLI adapter (Phase 2). If a maintained server is already configured and
the maintainer prefers it, take the MCP path: skip Phase 2, and in
Phase 4 record in the system `SKILL.md` that the system is reached via
MCP `<server-name>` and list the specific tool names gather should use
(e.g. `mcp__splunk__query_spl`). You do not write to `.mcp.json` or the
user's Claude config — that's their configuration to manage.

### Phase 2: Generate the adapter

Skip this phase if the maintainer chose the MCP path — jump to Phase 4.

Read the closest reference adapter and copy its shape. For a playground /
HTTP-over-`docker exec` read source, that's a `_stub_transport.py`-based
stub (e.g. `cmdb_cli.py`); for a credentialed direct source, that's
`elastic_cli.py`. Read `defender/docs/state-surface-adapters.md` for the
contract before you start.

#### The adapter contract

There is no ABC to inherit — the contract is the convention the existing
adapters follow. Match it exactly:

- **`argparse` with one subcommand per verb, plus `health-check`.** The
  verb names *are* the surface; pick names for what they measure
  (`get-host`, `list-hosts`, `query`, `lookup`), not why the defender
  asked.
- **Pass-through native query language.** A query-shaped system (SIEM,
  log store) takes its native query (Lucene/KQL/SPL/SQL) unmodified —
  no translation, no DSL of your own, no field renaming. The agent knows
  these languages from training; a translation layer is perpetual bug
  surface. A lookup-shaped system (CMDB, identity, threat intel) keys on
  an identifier instead (`get-host <name>`, `lookup <ip>`); the verb
  *is* the contract there.
- **`--raw` emits a stable JSON envelope** matching the sibling adapters
  (see `state-surface-adapters.md` for the v2-stub envelope; `elastic`
  has its own). Gather persists this by-ref to `gather_raw/`, so envelope
  drift breaks replay. Default (non-`--raw`) output is short formatted
  text — a one-line summary plus key extracts.
- **Exit codes:** `0` success (a connected-but-empty result is still
  `0` — zero hits is a finding, not an error), `1` query error
  (malformed query, unknown field or index), `2` connectivity/auth
  failure, `64` usage error (bad flag, unknown subcommand, missing
  argument). The `64` path comes for free from the shared
  `AdapterArgumentParser` in `_stub_transport.py` — copy the shape and
  you inherit it; don't reinvent it.
- **Config from `defender/knowledge/environment/systems/{system}/config.env`**
  via the `DEFENDER_DIR / knowledge/environment/systems/{system}/config.env`
  pattern the existing adapters use. Non-secret keys only — the stub
  transport reads `{SYSTEM}_URL_BASE` / `{SYSTEM}_BASTION_HOST` /
  `{SYSTEM}_TIMEOUT_SEC`, while `elastic_cli.py` uses its own set
  (`ELASTICSEARCH_URL`, …); copy the sibling's exact key names rather
  than these illustrative ones. **Secrets come from environment
  variables only.**
- On missing config or a missing secret env var, print a specific hint
  pointing at the fix and exit `2`. On import failure (a missing vendor
  SDK), print the bootstrap command (below) and exit `2`.
- **Examples in `--help` are load-bearing.** The gather subagent
  pattern-matches against whatever example a subcommand's help shows. Use
  *real* field names and values the maintainer confirmed, not generic
  placeholders.
- **Do not** implement `--run-dir` salt wrapping. Untrusted-data tagging
  is the runtime's job (`hooks/tag_tool_results.py`); the adapter just
  emits clean output.

#### Language, dependencies, packaging

**Python 3.11+.** Security tooling and vendor SDKs are Python-first;
don't generate adapters in another language. Use stdlib (`urllib`,
`json`, `ssl`, `argparse`, `subprocess`) as the first choice — a stub
that shells `docker exec … curl` needs nothing else. Reach for a vendor
SDK only when the API genuinely needs one (SigV4 signing, streaming,
proprietary auth).

When a dep is required, add it as a named extra in
`defender/pyproject.toml` (and mirror into `[dev]`), then rebuild the
single venv:

```bash
cd defender && uv pip install --python .venv/bin/python -e '.[dev]'
```

All adapters run under `defender/.venv/bin/python3`. `uv.lock` is
committed.

#### Register the shim

Drop a shim at `defender/bin/defender-{system}`, copied from a sibling
(`bin/defender-cmdb`) with the CLI filename swapped. Make it executable
(`chmod +x`). This is the registration step: per `bin/README.md`, any
`defender-*` shim that isn't in `NON_ADAPTER_SHIMS`
(`hooks/_cmd_segments.py`) is automatically treated as a data-source
adapter by all three runtime gate hooks, and the `Bash(defender-* *)`
allow rule in `run-settings.json` already covers it — **no per-hook edit
and no allowlist edit are needed.** Verify `run-settings.json`: in the
current layout the `defender-* *` glob is the only entry adapters need;
add an explicit per-CLI fallback entry only if the repo has moved back
to listing tools individually. This is the one runtime-config file
connect touches — flag any change to it in the Phase 5 summary.

At runtime the gather subagent invokes the adapter wrapped for capture:

```
defender-record-query --lead {lead_id} --query-id {id} -- defender-{system} <verb> … --raw
```

You don't run that form (it needs a live run dir) — you verify the
wrapping shape exists and matches `queries/SCHEMA.md`.

#### When in doubt, fetch the docs

Your training knowledge is a starting point, not the source of truth.
When uncertain about API shape, field names, auth flow, or pagination,
request a WebFetch against the vendor's *current official* docs. WebFetch
is deliberately not pre-approved — each call falls through to the
maintainer's permission settings and prompts interactively, because an
LLM fetching attacker-controlled content is a prompt-injection vector.
Tell them which URL you want and why, in one line, so the approval is a
one-second decision. Prefer official docs over blogs, current over
archived.

### Phase 3: Test end-to-end

You're in a maintainer session, so invoke the CLI directly under the
venv python. Two tests, in order. Don't skip either.

#### 3.1 Health check

```bash
defender/.venv/bin/python3 defender/scripts/tools/{system}_cli.py health-check
```

- Exit `0`, prints connected: proceed.
- Exit `2` (connectivity/auth): diagnose the class and guide the fix —
  connection refused / DNS → network path (is the container up? right
  `--context`?); `401` → credentials (env vars set? token expired?);
  timeout → endpoint reachable but slow; `certificate verify failed` →
  SSL (ask about the CA cert; don't silently disable verification).
- Iterate until green. Don't proceed with a red health check.

#### 3.2 Sample query

Pick the simplest call in the system's native shape — "return any 5
recent events" for a query source, a single known-good key for a lookup
source — and run it with `--raw`:

```bash
defender/.venv/bin/python3 defender/scripts/tools/{system}_cli.py <verb> '<simple_input>' --limit 5 --raw
```

Show the output and ask the maintainer: **do these results look right?**
If the fields are legible and match what they expect, the gather
subagent will be able to consume them. If it's garbled or missing
fields, iterate.

Zero results is not necessarily a failure — the query may be too narrow.
For a time-bounded source, **widen the window** (1h → 24h → 7d); *do not
drop the time bound entirely* — an unbounded query against a real source
can be huge or rate-limited. Widen, then confirm whether the source
actually holds data in the broader range.

#### 3.3 Optional: field-model probe

Run this when the vendor or deployment is unfamiliar and you want a cheap
check on whether the per-system surfaces you're about to write are
thick enough. Skip it when the field knowledge is already grounded in
what the maintainer told you or their docs confirm. The probe targets
**obvious gotchas**, not a complete field reference.

The runtime gather subagent is Haiku, so probe with the same model.
Spawn a short-lived Haiku subagent with a clean context. Hand it *only*
the adapter's `--help` output plus the draft `execution.md` and the
`gaps` / `read_guidance` of the draft system `SKILL.md`. Give it a
concrete task (*"find the 5 most recent failed SSH logins on host
`web-1` in the last hour — what exact command would you run, and what
are you unsure about?"*). Read the result and triage each ambiguity:

- **Add to the surface now** — an obvious vendor-specific gotcha Haiku
  got wrong: an aliased field name, a non-default enum, a null semantic
  the maintainer can confirm in one line. Field-of-data facts go in the
  system `SKILL.md` (Visibility); dispatch-shape facts go in
  `execution.md`.
- **Add an explicit "don't use X, use Y" note** — Haiku reached for a
  wrong field from training priors. Worth naming even while leaving the
  rest thin.
- **Leave it** — a subtle detail that isn't a Day-1 gotcha. Real runs
  will reveal which of these matter; the offline lead-author and the
  learning loop catch them post-merge. Adding them speculatively is the
  opposite of the lean-scaffold approach.

The probe is evidence, not a verdict. When in doubt, lean toward leaving
things out — the scaffold is grown, not polished.

### Phase 4: Scaffold the per-system knowledge

The adapter runs. Now record just enough for the gather subagent to
dispatch against it and the defender to route to it. The bar is **lean**,
not comprehensive — everything here grows post-merge. Read
`defender/docs/system-skill-shape.md` and mirror an existing sibling
(`skills/cmdb/` for a lookup source, `skills/elastic/` for a query
source) for the exact shape; the fields below drift, the siblings don't.

#### Per-system skill — the two-file split

`defender/skills/{system}/` — create it.

- **`SKILL.md`** — the **Visibility surface**, frontmatter
  `name: defender-{system}` + a one-line `description`. Read by the
  orchestrating defender (routing), the offline author, and the
  actor-reviewer judge — *never* by anything that holds credentials.
  Covers the Visibility fields from `system-skill-shape.md`
  (`available_queries` / `gaps` / `read_guidance` /
  `when_to_use`·`when_not_to_use`; match the sibling's exact field
  names). Keep a one-line `## Execution` pointer to `execution.md`.
  Critically: **declare `gaps` loudly** — what the system *cannot*
  answer here, including silent-failure shapes (e.g. a threat-intel stub
  returning `verdict: unknown` on a miss rather than 404). A declared
  gap is what separates "we did not ask" from "we cannot ask."
- **`execution.md`** — the **Execution surface**, read only by gather at
  dispatch. CLI invocation pattern, flag conventions, query syntax, index
  scoping, connectivity, exit codes. This is where credential/connectivity
  detail lives — the split exists so the orchestrator physically cannot
  ingest it (issue #261). Include the authoritative line: *"Do not Read
  `{system}_cli.py` source to discover flags — this doc plus `--help` is
  the surface."*

#### Config

`defender/knowledge/environment/systems/{system}/config.env` — non-secret
keys with the deployment's values. **Track it in git when it holds no
secrets** (the v2-stub norm — endpoints, host, timeouts). **Gitignore it
only when it would encode a sensitive deployment** (the `wazuh/config.env`
precedent in the root `.gitignore`). Secrets never live here — they're
env vars, regardless of this file's tracking.

#### Seed query templates — a couple, not a catalog

Write only the handful of `defender/skills/gather/queries/{system}/{id}.md`
templates you're *certain* of — the obvious entry-point measurements
(e.g. `list-all-hosts`, a by-key lookup). Follow `queries/SCHEMA.md`:
frontmatter `id: {system}.{template-id}`, then `## Goal` (write for
keyword recall), `## What to summarize`, `## Query` (system-native, with
`${param}` placeholders), `## Common pitfalls`. Mark them
`status: established`.

Do **not** pre-build the full catalog. The bulk grows post-merge: the
offline lead-author (`learning/lead_author.py`) mints `_draft/{verb}.md`
skeletons under the system's `queries/{system}/_draft/` from real gather
runs and curates them. Speculative templates from API docs are unbounded
(which measurements matter for this vendor?) and rot. Friction on the
first few runs is the cost of admission; post-merge compounds it away.

#### What you do NOT scaffold

- **Lessons.** `defender/lessons/` is the learning loop's output, not
  yours.
- **The bulk query catalog.** Seeds only; the lead-author grows the rest.
- **Other systems' skills, the runtime `defender/SKILL.md`, the invlang
  skill, the hooks, or `learning/`.** Out of your lane.

### Phase 5: Commit

Re-run the health check to confirm the system is still green. Then:

```bash
git status && git diff
git checkout -b connect/{system}
git add defender/scripts/tools/{system}_cli.py \
        defender/bin/defender-{system} \
        defender/skills/{system}/ \
        defender/knowledge/environment/systems/{system}/config.env \
        defender/skills/gather/queries/{system}/
# if a dep was added:
# git add defender/pyproject.toml defender/uv.lock
# if run-settings.json needed an explicit entry (rare — see Phase 2):
# git add defender/run-settings.json
```

**You do not merge or push.** The human review gate is the trust
boundary for generated code. Present a summary:

- Files created / modified (relative paths).
- Health-check result and one line of sample-query output.
- Environment variables the maintainer must have set (if any).
- Open items left in the scaffolded knowledge.
- **What to expect next:** the first few runs against this system will
  hit friction on query composition (field names, enum values). That's
  expected — the query catalog for this system fills in post-merge via
  the offline lead-author (which proposes `_draft/` templates from real
  runs) and the learning loop, not here.

Then walk `${CLAUDE_SKILL_DIR}/checklist.md` item by item; surface any
unchecked item in the summary. Tell the maintainer: "Review the diff and
merge when ready." Then stop. (`/ship` can open the PR once they're
happy.)

## Ground rules

Tiers. Hard limits are non-negotiable and protect safety properties.
Defaults are right for ~90% of connections and are the path of least
resistance, but can be overridden *deliberately and transparently* when
the maintainer has a real reason.

### Hard limits (non-negotiable)

- **Never handle credentials.** Tokens, passwords, API keys, pasted
  cURL with auth headers — all forbidden. If offered one, stop and
  remind them it belongs in an env var. This is the single most
  important property of the flow.
- **Stay in your lane.** Write only: `scripts/tools/{system}_cli.py`,
  `bin/defender-{system}`, `skills/{system}/`,
  `knowledge/environment/systems/{system}/config.env`,
  `skills/gather/queries/{system}/` (seeds), and — only if needed —
  `pyproject.toml` / `uv.lock` / `run-settings.json`. Never touch
  `hooks/`, `learning/`, `lessons/`, the runtime `defender/SKILL.md`,
  the invlang skill, or another system's files. If the task genuinely
  needs one of those, stop and tell the maintainer.
- **Fail loud on ambiguity.** Never silently substitute a default, a
  placeholder, or a guessed value for something the maintainer didn't
  confirm. Surface it and ask.

### Defaults (right for most connections, overrideable with cause)

- **Pass-through native queries.** The adapter takes the native query
  unmodified, or keys on an identifier for a lookup source. Override
  only if the upstream genuinely has no query language and no clean key,
  and document the override in the system `SKILL.md`.
- **One system per invocation.** If the maintainer names three systems,
  note the others and suggest re-running connect for each. Override only
  if they're truly co-located (same vendor sharing an auth flow).
- **CLI adapter, Python, stdlib-first, at `scripts/tools/{system}_cli.py`.**
  This is what every existing adapter does and where gather looks.
  Override (e.g. MCP) only via the explicit conversation in Phase 1.
- **Don't rewrite the reference adapters.** `elastic_cli.py` and the
  stubs are the shape to copy, not to refactor. Note a divergence if you
  see one; don't fix it here.
- **Adapter updates are a deliberate re-run.** If `{system}_cli.py`
  already exists, stop and confirm before touching it (Phase 0).
- **Consult the docs / handbook on demand** rather than re-deriving KB
  layout or runtime rules.

### When a request falls outside both

Sometimes the maintainer is integrating something genuinely weird — a
homegrown tool, an org-specific shell pipeline, a legacy log scraper.
That's fine; the skill exists to help. Generate what's needed, surface
the divergence explicitly for human review, and let the review gate catch
anything you got wrong. The hard limits still apply; everything else is
negotiable.
