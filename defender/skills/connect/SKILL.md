---
name: connect
description: Connect one system of record (SIEM, EDR, identity, CMDB, asset DB, threat intel, ticketing, custom API) to one tenant of this defender deployment. Configures an adapter the product already carries or generates a new one. Agrees the check that proves the system works before anything is built, scaffolds the per-system knowledge the gather subagent needs, and hands the operator the records, credential steps and that check. One system per invocation. Also records a tacit-knowledge sanction — "we have signed off on this actor doing this on these hosts" — into the human-authored registry, via tacit.md.
---

# Connect a system of record

You connect **one** system of record to one tenant: the first one on a fresh install, or another
later. The end state is a system the tenant's runs can reach through the credential proxy, the
per-system knowledge the gather subagent needs to route and read results (when the system has
tools for it), an ordered handoff the operator applies, and a check, agreed before anything was
built, that says whether it works.

> **Recording a tacit-knowledge sanction? Go to `tacit.md` instead.**
> "We've signed off on this actor doing this on these hosts" is not an
> onboarding — the system is already connected, and its data is a
> version-controlled file a human commits. `tacit.md` is that route: it
> interviews for the entry, writes it, validates it and leaves a branch.
> The workflow below is for connecting a system that is not here yet, and
> none of its steps apply to adding one sanction.

There are two paths, chosen by one fact: does the product already carry an adapter for this
system?

- **Configure** — the product carries it (`tenant.py catalog` lists it). Nothing is generated:
  you write the tenant's records, and its per-system knowledge if the adapter has tools the
  investigator calls. See `configure.md`.
- **Generate** — it does not. You write a small Python adapter module the runtime imports
  in-process, reached only over HTTP through the credential proxy. See `adapter.md`.

Both paths start from the same agreed check and end at the same final step.

**Reaching a system through an MCP server is coming (#1494), not available yet.** If the
maintainer wants to connect a system that way, say it is planned and stop; if the system also has
an HTTP API, offer the paths above.

## Your lane

You write the adapter (generate path only), the per-system skill and a couple of seed query
templates (only for a system with investigator tools), and the handoff the operator applies. You
do **not** author lessons (the learning loop owns the tenant's `agent/lessons/`), pre-build the
query catalog (the offline lead-author grows it from real runs), run investigations (that's
`run.py`), write the tenant's records or credential (the operator's), or touch another system's
files, `hooks/`, or `learning/`. If the maintainer asks for something outside connecting one
system, stop and point them at the right surface.

You run as a maintainer skill in a normal session, not inside the `run.py` hook regime. You
**cannot** call an adapter against the live system from here: every adapter call goes through
the credential proxy with a signed pass, and this session holds neither the pass nor the proxy's
address. Do not try to work around that — the final check is the operator's (step 7).

## Source of truth

Read the doc you need; don't duplicate it into what you scaffold.

- `configure.md` / `adapter.md` — the two paths.
- `tacit.md` — the separate route for recording one tacit-knowledge
  sanction into the tenant's `agent/skills/tacit-knowledge/registry.yaml`.
- `decisions.md` — why the skill is shaped this way (for grounding a call).
- `defender/docs/system-skill-shape.md` — the per-system `SKILL.md` /
  `execution.md` split and its fields.
- `defender/skills/gather/query-schema.md` — the query-template format.
- `defender/kit/faults.py` + `defender/kit/verbs.py` — the
  fault taxonomy and the `VerbContext` / `VERBS` contract an adapter implements.
- `defender/skills/handbook/` — runtime loop and run-dir reference, on demand.

## Workflow

**Orient → Interview → Agree the check → Build → Scaffold the knowledge → Validate → Hand off.**
Sequential; if a step blocks, diagnose and fix before moving on.

### 1. Orient

```bash
python3 defender/cli/tenant.py catalog
ls $DEFENDER_DATA_ROOT/{tenant}/exports/$(cat $DEFENDER_DATA_ROOT/{tenant}/exports/current)/agent/skills/
```

`catalog` lists every adapter the product carries, with the settings each reads and its tools
(`tools: none` is an adapter the investigator never calls, such as a ticket system that only
takes the run-end comment). If the system is listed, you are on the **configure** path; never
generate a second adapter for it.

Ask the operator for the tenant's current records:

```bash
python3 defender/cli/tenant.py systems {tenant} --export <dir>
```

It writes each stored system as a `config.env` / `access.yaml` folder and says each one's version.
You need it for the handoff (`--replaces`, step 7), to see whether the system is already
configured, and to copy a sibling's access declaration. If the system already has a record, this
is a deliberate update: ask what is changing, and branch `connect/{system}-update` on the
generate path so the diff stays clean.

On the generate path, note whether *other* adapters exist. If they do, you're extending a
populated deployment: there's an established shared adapter module and house conventions
(config keys, transport, auth posture, output shape) to **conform to**, not duplicate. Before
the interview, read the deployment's adapter-conventions note if it has one
(`integrations/README.md`) and the closest sibling adapter, so you **confirm** the recurring
answers instead of asking cold (`adapter.md` → "The shape to copy").

### 2. Interview

Ask one question at a time, conversationally. You need enough to configure or build the system
and no more. On the configure path the adapter already settles transport and output shape;
spend the interview on the settings `catalog` lists and the access declaration (`configure.md`).

1. **What system are you connecting?** A well-known name gives you the API
   shape from training; verify it against the real docs during the build.
   For something obscure, ask for a docs pointer.
2. **How do you reach it from this environment?** An adapter reaches its system only over HTTP,
   through the credential proxy, at the base its `access.yaml` declares (`adapter.md` → "Access
   declaration"). A system reachable only through a CLI or script, or by SSHing to a bastion, has
   no HTTP API the proxy can call → **stop** and say so: it cannot be connected. One reachable
   only through an MCP server waits for #1494.
3. **What is it for here?** Freeform — "host inventory and trust edges", "who is authorized on a
   host", "auth events", "IoC reputation", "the ticket each alert belongs to; findings go there
   as a comment". You need this for the Visibility surface and for the check (step 3).
4. **What credentials does it need, if any?** Names, not values. Some
   read sources are auth-less. You never ask for a secret value, token, or
   auth-bearing cURL — if one is offered, refuse it: it never goes in a file you
   write or in this conversation. This is the credential boundary; it is
   non-negotiable. A credential is stored by the operator in the secret
   store (`tenant.py set-credentials`, write-only); you need only its
   scheme and the field names the scheme reads (`adapter.md` →
   "Credentials").

### 3. Agree the check — before anything is built

Before you configure or write anything, agree with the maintainer the one check that will say
whether the system works. Writing it first keeps it honest: a check written after the build is
shaped by what was built.

- **The question.** For a system the investigator reads, one real lookup or query
  ("is web-01 in the inventory, and who owns it?"). For a system the product writes to, such as
  a case system that takes the run-end comment, the write itself: one comment on a ticket the
  maintainer names as **disposable**. Never a write to a real case: later investigations read a
  ticket's comments as its history.
- **The expected answer, falsifiable.** A concrete value a wrong credential, base URL or alert
  mapping would not produce: "web-01, owned by team payments", not "results came back". For a
  write: "the comment appears on ticket TEST-1".
- **A negative control.** The same call with an input that must **not** give the answer: an
  unknown host, a time range with no data, or for a write, reading a ticket that does not carry
  the comment. The control's failure is the red that shows the check can tell working from
  broken.
- **Which tool answers it.** On the configure path, name the adapter tool (`catalog` lists them)
  and its inputs. On the generate path the tools don't exist yet: write the check as the
  question and its answer, then pick the tool once the code exists, and show that pick to the
  maintainer at the review checkpoint (`adapter.md`).

Write the check into the handoff as `<handoff>/check.md`: the question, the tool and inputs, the
expected answer, the control, and the disposable target for a write. If the maintainer cannot
give a falsifiable answer, say the check is weak and why; do not invent one.

### 4. Build

- **Configure** → `configure.md`: the records for the operator, nothing generated.
- **Generate** → `adapter.md`: it writes `integrations/{system}_adapter.py` — a `VERBS` mapping
  of `VerbContext`-taking functions that raise `faults` — on the shared transport module, runs
  the Haiku alignment loop, and **pauses at a human review checkpoint** (generated code is read
  by a human before it runs anywhere). Dropping the module under `integrations/` is the whole
  registration; there is no shim. It then writes the handoff's `config.env` and `access.yaml` as
  below.

The handoff is a folder outside both repos that you give the operator, never a file in the
tenant's repo or in this one:

- `<handoff>/{system}/config.env` — exactly the keys the adapter reads (`catalog`'s settings, or
  the new adapter's `REQUIRED_CONFIG_KEYS`, prefixed; any other key is refused by name). No
  secret.
- `<handoff>/{system}/access.yaml` — the system's base, auth scheme and routes (`adapter.md` →
  "Access declaration"). No secret.
- `<handoff>/check.md` — step 3's check.
- For a case system, `<handoff>/case-record.yaml` and the alert-mapping line (`configure.md`).

### 5. Scaffold the per-system knowledge — only for a system with investigator tools

A system whose adapter offers the investigator no tool beyond `health-check` (`catalog` says
`tools: none`, or only `health-check`) has nothing for gather to route to or query: skip this
step.

Otherwise, read `defender/docs/system-skill-shape.md` for the exact shape; if a sibling system
already exists in the tenant's knowledge, mirror the closest one. The bar is **lean** —
everything here grows post-merge.

The per-system skill and its seed templates are the tenant's knowledge, not this repo's: they
belong in the tenant repo's `agent/` tree. Write them into a **staging folder** of your own,
outside this repo and empty to begin with (`<staged>` below), shaped like that `agent/` root.
Step 6 validates it and proposes it to the tenant's repo.

`<staged>/skills/{system}/`:

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
  dispatch: query syntax, exit codes (including 64 for a param mistake), and the
  VALUE constraints a signature cannot state (an enum a param accepts, a clamp,
  a required timestamp format). Do **not** hand-author the verb roster or each
  verb's params here — gather gets those from the `list_verbs` tool, read off the
  live signatures, and a prose copy only drifts from them (#900); point at
  `list_verbs` instead. Credential and connectivity detail live here, never in
  `SKILL.md` — the split exists so the orchestrator physically can't ingest it.

`<staged>/skills/gather/queries/{system}/` — write only the **couple of
seed templates you're certain of** (an entry-point measurement, a by-key
lookup), per `query-schema.md` (`id: {system}.{template-id}`, `verb:`,
`params:`, Goal, What to summarize, a parameterized Query body, Common
pitfalls). `verb:` is **required**; `id:` and `params:` are **checked** in
step 6 against the directory and the adapter's live signature — the `{system}`
half of the `id:` must be the directory the file sits in, a `params:` entry
the verb does not declare as a model-bindable param is a FAIL, and so is a
`${placeholder}` that is neither a declared param nor a listed
`body_substitutions:` entry. There is no longer any fallback that guesses a
verb from the query body. Do **not** build a catalog from API docs — the
offline lead-author mints the rest from real runs.

**Grant rows — one row per verb the adapter declares, `health-check` included.** The tenant's
own `settings/verb-grants.yaml` must decide every verb: grant to `gather` the verbs an
investigation should be able to call; a verb you are deliberately leaving unreachable gets
`roles: []` **and a written reason**. The template withholds every verb, so until the tenant's
table grants them, no run can call the system. On the **generate** path the adapter is new
shared code, so also add its rows to `knowledge/tenant-template/settings/verb-grants.yaml`
(withheld, `roles: []` with a reason) and `knowledge/tenant-fixture/settings/verb-grants.yaml`
(granted as the tests need) in this repo: CI (`lint_verb_disposition_census.py`) fails on a
declared verb with no row there, and `tenant.py check <tenant>` reports one a tenant's table
leaves undecided. A catalog adapter's template and fixture rows already exist.

The allowlist is deliberate, not bookkeeping. It is authored so that
dropping an adapter into the tree grants it nothing — a system is not
reachable until a human says which of its verbs may be called. Do not
"simplify" it by deriving it from the adapters on disk; that is the one
change the design exists to prevent.

### 6. Validate

Run the scaffold validator and fix every FAIL. It judges the handoff exactly as the record store
will when the operator writes it — each FAIL there is the sentence the operator would be refused
with, naming the file — and prints the comment route a case adapter sends.

For a system with investigator tools (either path):

```bash
python3 defender/skills/connect/validate_scaffold.py {system} --handoff <handoff>/{system} --staged <staged>
```

For a case system with no investigator tools (e.g. Jira, ServiceNow):

```bash
python3 defender/skills/connect/validate_scaffold.py {system} --handoff <handoff>/{system} --case <handoff>/case-record.yaml
```

Then walk `${CLAUDE_SKILL_DIR}/checklist.md` for the judgment items the script can't check.

### 7. Hand off

**Generate path — the product half.** In a git repo (the normal case), branch and stage; if the
tree isn't under version control, leave the files in place for review:

```bash
git checkout -b connect/{system}
git add defender/integrations/{system}_adapter.py \
        knowledge/tenant-template/settings/verb-grants.yaml \
        knowledge/tenant-fixture/settings/verb-grants.yaml
# add pyproject.toml / uv.lock only if a dependency was added
```

**The tenant half** (a system with investigator tools) — the system skill and its seed templates
go to the tenant's own repo as one pull request, never into this one:

```bash
python3 defender/cli/tenant.py propose {tenant} <staged>
```

`propose` adds or replaces the staged files under the tenant's `agent/` and opens the pull
request on the tenant's forge; a human merges it there. It refuses (`[tenant.py] ...`) a
staged file outside a folder of `agent/`; fix what it names and propose again. The grant table
lives under the tenant repo's `settings/`, which `propose` does not touch: branch and stage it
there, and run `python3 defender/cli/tenant.py check --folder <that repo>` to see the census
over it.

**The operator's steps**, in this order — give them as one list with the handoff folder. You run
none of them: they write the tenant's records and its secret, which are the operator's.

1. Generate path only: merge and deploy the adapter. The store refuses a record naming an adapter
   the running product does not carry.
2. `python3 defender/cli/tenant.py set-system {tenant} {system} <handoff>/{system} --replaces <its current version from the export, 0 if none>`
3. `python3 defender/cli/tenant.py set-credentials {tenant} {system} <credential file> --for-version <the version stored> --token-file <operator token>`
4. Case system only: `python3 defender/cli/tenant.py set-case {tenant} <handoff>/case-record.yaml --replaces <current, 0 if none>`,
   then the alert mapping's `case_key` line **only if** the stored mapping lacks it or names another field
   (`configure.md` → "The ticket key").
5. A system with investigator tools: merge the tenant's PR(s) (skill and seeds, grant table) and
   publish them (`tenant.py update {tenant}`).
6. `python3 defender/cli/tenant.py check {tenant}` — it judges the stored records, the grants and
   the case system together.
7. **The final check:** run `check.md`'s check and its control through the credential proxy.
   Done means the check gives the agreed answer and the control does not.

**The final check cannot be run from a connect conversation yet** (#1493 adds the pass and the
runner). Say so plainly. Until then, the first signal is the operator's first real run on the
tenant — for a case system, the first run started with `--update-ticket` on a real alert, whose
run page shows the ticket receipt. Leave `check.md` in the handoff so it is run once the runner
exists.

**You do not merge or push.** Present a summary: files touched, the agreed check, the
validator's result, the operator's ordered steps, open items, and what to expect next (the first
runs will hit query-composition friction; the catalog fills in post-merge via the offline
lead-author). Tell them: "Review the diff and merge when ready." Then stop. `/ship` can open the
PR.

## Ground rules

### Hard limits (non-negotiable)

- **Never handle credential values.** Tokens, passwords, API keys, pasted
  auth-bearing cURL — all forbidden. If offered one, stop and refuse it.
  `config.env` and `access.yaml` hold no secret and no reference to one: the operator
  stores the value in the secret store (`tenant.py set-credentials`), and the skill never
  sees it.
- **Never write a check against a real case.** A state-changing check targets only an object the
  maintainer names as disposable.
- **Stay in your lane.** Write only the `{system}_adapter.py` adapter (generate path), the
  staged `skills/{system}/` and seed templates (a system with investigator tools), the handoff
  folder, and the system's rows in the grant tables (plus `pyproject.toml` / `uv.lock` if a dep
  was added). Never `hooks/`, `learning/`, `agent/lessons/`, the runtime `defender/SKILL.md`,
  the invlang skill, or another system's files. On the `tacit.md` route the lane is narrower
  still: the staged `skills/tacit-knowledge/registry.yaml`, plus the template's `SKILL.md`
  beside it for a tenant that has none, and nothing else.
- **Never author a sanction.** On the `tacit.md` route you transcribe what
  a human states and record them as its author. An entry written under
  your name, or with a scope you inferred, is the system vouching for
  itself — the one thing that registry's design exists to prevent.
- **Fail loud on ambiguity.** Never silently substitute a default,
  placeholder, or guessed value for something the maintainer didn't
  confirm. Surface it and ask.

### Defaults (right for most connections, overrideable with cause)

- **Native queries pass through unmodified, and aggregate in the source
  where the source can** (or key on an identifier for a lookup source).
  See `adapter.md` -> "Prefer native aggregation."
- **One system per invocation.** Note any others and suggest re-running.
- **Generate fresh; don't ship a vendor template library, and don't
  pre-build the query catalog.**
- **The adapter conforms to the gather subagent**, not the reverse (see
  `adapter.md`).

When a request legitimately falls outside the defaults — a homegrown
tool, an odd access topology — help anyway: build what's needed, surface
the divergence explicitly for human review, and let the review gate catch
anything you got wrong. The hard limits always hold.
