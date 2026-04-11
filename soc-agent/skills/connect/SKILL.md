---
name: connect
description: Connect a new security system (SIEM, EDR, identity, CMDB) to the agent. Interviews the user, generates an adapter CLI that implements the contract, tests it end-to-end, and scaffolds the environment knowledge the investigation loop needs. One system per invocation.
argument-hint: "[system_name]"
allowed-tools: Read Write Edit Glob Grep Bash(python3 scripts/preflight.py *) Bash(python3 scripts/tools/* health-check*) Bash(python3 scripts/tools/* query *) Bash(bash scripts/tools/*/setup.sh*) Bash(ls *) Bash(pwd) Bash(git status) Bash(git diff *) Bash(git checkout -b *) Bash(git add *) WebFetch
model: claude-sonnet-4-6
---

# Connect a Security System

You wire a new data source into the soc-agent environment. One system per invocation — SIEM, EDR, identity platform, asset DB, DLP, threat intel, custom REST API. The end state is: an adapter CLI that implements the contract, the environment knowledge the investigation loop reads at runtime, and a green preflight.

You are **not** editing signature knowledge here — that's `/author`. You are **not** running investigations — that's `/investigate`. Stay in your lane. If the user asks for something outside connecting a system, stop and redirect them to the right skill.

The design rationale is in `${CLAUDE_SKILL_DIR}/design.md`. Read it if you need to ground a decision about the adapter contract, MCP precedence, or why you don't ask for credentials.

Read `${CLAUDE_SKILL_DIR}/checklist.md` before you start — it is the bar you are aiming for, so knowing it upfront shapes every phase. Walk it again at the end, item by item, before calling the connection done.

## Source of truth

`/handbook` owns the knowledge-base layout, the runtime rules, and how the investigation loop consumes environment knowledge. When you need to check *where* a file should go or *what shape* it should take, invoke `/handbook` rather than guessing. Do not duplicate handbook content in the adapters or env knowledge you generate.

The adapter contract lives in `schemas/adapter_contract.py`. Read it once when you start generating — it's short, and it's the authoritative spec for what you must implement.

## Workflow

The skill is a five-phase flow: **Interview → Generate → Test → Scaffold → Commit**. The phases are sequential — don't skip ahead. If something blocks a phase, diagnose and fix before moving on; don't paper over it.

### Phase 0: Orient

Run preflight to see the current state before you touch anything:

```bash
python3 scripts/preflight.py
```

Read the output. If the system the user wants to connect already has an adapter and it's green, stop and ask: do they want to replace it, or did they mean a different instance? Re-running `/connect` on an existing adapter should be a deliberate update, not an accidental overwrite.

If they confirm an update, create a branch off main (`git checkout -b connect/{system}-update`) so the review diff is clean.

### Phase 1: Interview

Ask targeted questions to understand the access path. Ask them one at a time in a conversational thread, not as a wall of form fields. You need enough to generate a working adapter and no more.

The four questions that matter:

1. **What system are you connecting?** (Splunk, Elastic, CrowdStrike, XSOAR, a custom REST API, etc.) If they say a well-known name, you know the API shape from training — use it as a starting point, but plan to verify against their actual docs in Phase 2. If they say something obscure, ask for a pointer to API documentation.

2. **How do you reach it from this machine?** The five patterns, in rough order of prevalence:
   - **Direct API** — endpoint + token/basic auth. Simplest case.
   - **SOAR / orchestration platform** — XSOAR, Phantom, Swimlane. Adapter calls the SOAR, SOAR calls the target. Credentials are for the SOAR.
   - **Existing CLI or script** — org already has `splunk-cli` or a Python wrapper. Your adapter shells out and parses.
   - **MCP server** — a server the user already has configured in Claude Code.
   - **Bastion / jump host** — they SSH somewhere and run tools there. In that case **the agent runs on the bastion**, not here. Stop, tell them, and exit cleanly.

3. **What data does the system hold that matters for investigations?** Freeform. "auth events", "process execution", "email security", "asset inventory", "identity/role data". You need this for the data-source knowledge doc. It's okay if the answer is vague — you'll refine it after the sample query in Phase 3.

4. **What environment variables hold the credentials?** (Not the values — the variable names. If the user doesn't know yet, tell them you'll print a list at the end and they can set them before re-running Phase 3.)

You do **not** ask for credential values, tokens, passwords, API keys, or endpoint URLs that encode auth material. Those go in env vars or `.env`. If the user tries to paste one, refuse and remind them where it belongs. This is non-negotiable — it's the credential boundary.

#### MCP vs CLI adapter — user preference, not a technical winner

This is closer to spaces-vs-tabs than to a clear architectural call. Both paths work. Both are supported. The right answer depends on what the user already has, what they want to own, and what they find ergonomic. **You are not opinionated here** — you present the trade-off honestly and let the user choose.

Since Claude Code 2.1.7 (Jan 2026), Tool Search lazy-loads MCP tool schemas when they'd exceed ~10% of context, so the old "large MCP servers bloat context" concern is mostly retired. Small servers are frontloaded and cheap; large ones are deferred and loaded on demand. Token cost stopped being a tiebreaker.

Here are the axes that actually differ:

| Axis | MCP server | Generated CLI adapter |
|---|---|---|
| **Token cost** | Small servers: frontloaded, cheap. Large servers: lazy-loaded via Tool Search, ~3k tokens per query that touches the server. | Stateless. Zero context cost when idle. Per-invocation output sized by your formatter. |
| **Customization** | Whatever the server author decided — output shape, error messages, pagination, retry. You don't control it. | Full control. You pick field projection, salt wrapping, aggregation, error text, exit codes. |
| **Effort upfront** | If a maintained server already exists and the user has it configured: ~0 code. | Write + test a Python CLI per system. |
| **Effort ongoing** | Upstream version bumps, bug reports against someone else's codebase. | Local iteration, fully under the user's control. |
| **Quality** | Depends on the server author. Vendor-official ≠ weekend project. | Depends on Claude's synthesis at generation time, tested immediately in Phase 3. |
| **Ownership** | Consumer relationship. Forking is possible but awkward. | You own the code. |
| **Aesthetic** | Config-driven, declarative. Appeals to people who like "less code is better code". | Imperative, visible. Appeals to people who like reading the source they depend on. |

Walk the user through these questions and present both options fairly:

1. **Is there a maintained MCP server for this system?** (Vendor-official, a well-known community server, or an internal one.) If no MCP server exists and the user doesn't want to write one: CLI adapter, jump to Phase 2.
2. **Do they already have the MCP server configured in Claude Code?** If yes, the MCP path is essentially free to try. If they'd need to stand up a new server just for this: effort parity with writing a CLI.
3. **Do they need custom output shape, field projection, salt wrapping, or investigation-specific post-processing?** If yes, MCP gives them whatever the upstream author decided; CLI gives them control.
4. **Do they prefer owning the source vs consuming an upstream?** This is where aesthetic and team culture come in. Ask, don't assume.

Present both options, explain the trade-off in one or two sentences the user can act on, and let them pick. Do not steer. If they've integrated other systems via `/connect` already and they liked the pattern, they'll probably want to stay consistent — but confirm, don't decide for them.

Claude Code's MCP config lives in `.mcp.json` (project scope) or `~/.claude.json` (user scope). You don't write to those files — that's user-managed configuration. Your job for the MCP path is to note in the data-source doc that the system is reached via MCP `<server-name>` and list the specific tool names the investigation loop should use (e.g., `mcp__splunk__query_spl`, `mcp__splunk__get_health`). Lead templates and future `/investigate` runs reference those tool names directly.

### Phase 2: Generate the adapter

Skip this phase if the user chose the MCP path above — jump to Phase 4.

Read the contract once:

```bash
cat schemas/adapter_contract.py
```

#### Pick the contract shape

The contract has two shapes. Pick based on the system:

- **`AdapterContract`** (query-shaped) — the common case. SIEMs, EDRs, log stores, anything with a native query language and time-bounded results. Subcommands: `health-check`, `query <native_query>`. The query string passes through unmodified.
- **`LookupContract`** (lookup-shaped) — CMDBs, asset DBs, identity/HR systems, threat intel enrichment. The upstream is fundamentally keyed by identifier (`GET /assets/{id}`), not by query DSL. Subcommands: `health-check`, `lookup <key_field> <key_value>`.

If you're unsure, pick `AdapterContract`. Most systems fit it, and forcing a lookup-shaped API into it is usually cleaner than the reverse.

#### Key constraints you're binding yourself to

- The subcommands and exit codes are spelled out in `schemas/adapter_contract.py`. Follow them exactly.
- **Pass-through native query language.** Splunk adapter takes SPL, Elastic takes KQL, Wazuh takes Lucene. No abstraction, no translation. The agent already knows these languages from training; a translation layer is perpetual bug surface.
- **Credentials from env vars only.** Non-secret config (endpoint, index, retention defaults) from `knowledge/environment/systems/{system}/config.env`. Secrets are injected by the shell. See "Where secrets live" below.
- On missing config or missing secret env vars, print a specific hint pointing to the fix and exit 2.
- On import failure (missing `opensearch-py`, `splunk-sdk`, etc.), print the setup command (`bash scripts/tools/{system}/setup.sh`) and exit 2.
- If `--run-dir` is passed, read the salt from `{run_dir}/meta.json` and wrap output in `<run-{salt}-{system}-data>…</run-{salt}-{system}-data>`. Untrusted-data defense.
- **Examples in `--help` are load-bearing.** If you put an example query or field name in a subcommand's help text, runtime agents will pattern-match against it. Use *real* field names the user confirmed, not generic placeholders. (This was measured, not assumed — see `design.md` §5.)

#### Language, dependencies, packaging

**Python is the language.** Security tooling, SIEM SDKs, and glue code are overwhelmingly Python in this space, so adapter generation targets Python 3.11+. (Rust/Go/TypeScript all exist in the ecosystem, but the vendor SDK surface is Python-first, and mixing runtimes inside one plugin is more trouble than it's worth.) Don't generate adapters in other languages.

Use stdlib (`urllib.request`, `json`, `ssl`, `argparse`) as the first choice. Reach for a vendor SDK only when the API genuinely needs one (SigV4 signing, streaming protocols, proprietary auth flows). A 300-line stdlib adapter is almost always better than pulling in a 50-dependency SDK.

When external deps ARE needed, generate a per-integration venv:

```
scripts/tools/{system}/requirements.txt    — pinned deps (use >= floors, not ==)
scripts/tools/{system}/setup.sh            — uv-first, venv fallback
```

`setup.sh` follows this pattern (identical to `scripts/siem/setup.sh`, the existing Wazuh example):

```bash
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
REQ_FILE="$SCRIPT_DIR/requirements.txt"

if command -v uv >/dev/null 2>&1; then
    uv venv "$VENV_DIR" -q
    uv pip install -q -p "$VENV_DIR/bin/python3" -r "$REQ_FILE"
else
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/python3" -m pip install -q -r "$REQ_FILE"
fi
echo "Done. Activate with: source $VENV_DIR/bin/activate"
```

`uv` is preferred when present (fast, reproducible). Plain `venv + pip` is the fallback so the script works on systems without uv. **Never install system-wide.** The adapter's shebang or invocation always goes through its own venv.

**Reference example:** `scripts/siem/wazuh_cli.py` + `scripts/siem/setup.sh` — one working adapter that ships with the plugin as a CI/test target. Wazuh is not the default SIEM and is not assumed to be installed by real users; it's there because the devcontainer runs a Wazuh stack and it gives the plugin something to integration-test against. The wazuh_cli.py itself predates this contract and uses a flag-based CLI shape (`--query`, `--health-check`) rather than subcommands. **Copy the config loading, salt wrapping, and error-handling patterns from it. Do not copy the argparse shape** — new adapters use subcommands per the contract.

#### When in doubt, fetch the docs

**Use WebFetch against the vendor's current API docs** whenever you're unsure about API shape, field names, auth flow, or pagination semantics. Your training knowledge is a starting point, not the source of truth. A 10-second doc check now beats a broken adapter later. Prefer official docs over third-party blog posts; prefer the vendor's current version over archived copies.

### Phase 3: Test end-to-end

Two tests, in order. Do not skip either.

#### 3.1 Health check

```bash
python3 scripts/tools/{system}_cli.py health-check
```

- Exit 0, prints `connected`: proceed.
- Exit 1 with a connection error: diagnose the error class and guide the user through a fix.
  - "connection refused" / DNS failure → network path issue (VPN? firewall? endpoint URL?)
  - "401 Unauthorized" → credential issue (env vars set? right user? token expired?)
  - "timeout" → endpoint reachable but slow; check with curl
  - "certificate verify failed" → SSL issue; ask about CA cert, don't silently disable verification
- Iterate on the adapter or config until health check is green. Don't proceed with a red health check.

#### 3.2 Sample query

Pick the simplest possible query in the system's native language — "return any 5 recent events, no filter." Run it with a small limit:

```bash
python3 scripts/tools/{system}_cli.py query '<simple_query>' --limit 5
```

Show the output to the user and ask: **do these results look right?** This is the "friction-free" check — if the raw results are legible and the field names match what they expect, the agent will be able to consume them. If the output is garbled, truncated, or missing fields the user calls out, iterate on the adapter.

If the sample query returns zero events, that's not necessarily a failure — the query might just be too narrow. **Widen the time window** (e.g., from 1h to 24h, or 24h to 7d) or relax a filter clause. *Do not remove the time filter entirely* — an unbounded query against a production SIEM can return huge result sets, time out, or hit cost/rate limits. Widen, don't drop. After widening, confirm with the user whether the system actually has any data in the broader range.

#### 3.3 Optional: field-model usability probe

Skip this if you're confident in the field names and the `--help` examples are drawn from real org data. Run it when you're scaffolding a system you have limited schema knowledge of, or when the vendor's docs diverge from what the user says their deployment actually contains.

**What it targets.** An empirical trial we ran (documented in `design.md` §5) showed that CLI *shape* (positional vs `--flag`, subcommands vs no subcommands) is legible to fresh-context agents — all three shapes we tested produced syntactically correct commands on the first try. The friction Claude hits at runtime is **field-model** friction: which sourcetype name, which field spelling, which enum values, whether `action=failure` or `status=failed`. This is what the probe should check.

**How.** Spawn a short-lived Haiku subagent with a clean context. Hand it *only* the `--help` output for `query` plus the first draft of `field-notes.md`. Give it a concrete, realistic task like *"find the 5 most recent failed SSH logins on host `web-01` in the last hour"*. Ask for the exact shell command and a short note on what ambiguities it had to guess about. Examine the output: if Haiku had to guess field names that are not in the docs or the help examples, the field-notes are too thin — fill them in before committing. If Haiku reaches for field names that are *wrong* (hallucinations from training priors), call that out explicitly in field-notes as "don't use X, use Y".

**Note.** The probe is evidence, not a verdict. You decide whether a mismatch is worth fixing vs documenting. See `${CLAUDE_SKILL_DIR}/design.md` §5 for the full finding and why we pivoted the probe away from `--help` shape and toward field model.

### Phase 4: Scaffold environment knowledge

The adapter runs. Now make the agent able to use it without friction. The investigate loop reads environment knowledge to resolve "this lead needs auth events" to "query Splunk like this." If that chain is broken, the adapter is useless — the agent won't find it.

Scaffold the following files. Each is lean at first; the team fills them in over time as they use the system.

#### Per-system directory

`knowledge/environment/systems/{system}/` — create if missing.

- **`config.env.template`** — **tracked in git.** The canonical list of non-secret config keys the adapter reads (endpoint, index, retention days, SSL verify). Each key is commented with what it means and an example value. *Secrets are never in this file and never will be.* Include a header: `# Copy this file to config.env and fill in values for your deployment.`
- **`config.env`** — **not tracked in git.** Local copy of the template with the deployment-specific values the user gave you in Phase 1. Each deployment has a different copy. Init.sh already adds the `config.env` pattern to `.gitignore`; if it didn't, add it now. *Do not commit a filled-in config.env, even if it "only" contains an endpoint URL* — deployment details are sensitive.
- **`field-notes.md`** — frontmatter `tags: [{system}, fields, gotchas]`, then two sections: "Fields you'll reach for" (names, types, what they mean, which enum values are valid) and "Known quirks" (non-obvious semantics, surprising nulls, field-splits across event types, hallucinations to avoid). Start small. Leave a `TODO: fill in as the team learns` at the bottom. This is the single most load-bearing file for runtime agent quality — invest here.
- **`SKILL.md`** — frontmatter `name: {system}`, `description: {system} implementation knowledge for this org`. Body: how to invoke the CLI (at least one complete real example), common query patterns if you discovered any, a pointer to `field-notes.md`. Reference any supporting docs you create.

#### Where secrets actually live

The three-layer pattern, with what's tracked in git and what isn't:

| File | Contents | Git |
|---|---|---|
| `knowledge/environment/systems/{system}/config.env.template` | Non-secret keys with example values and comments | ✓ tracked |
| `knowledge/environment/systems/{system}/config.env` | Deployment-specific non-secret values (endpoint, index name) | ✗ gitignored |
| `.env` at the repo root (or shell environment) | Secrets only — tokens, passwords, API keys | ✗ gitignored |

The adapter's `load_config()` reads `config.env` for non-secrets and `os.environ` for secrets. Environment variables override `config.env` entries, which is how CI and per-run overrides work.

The `.env` file pattern is convention, not enforcement — users can substitute shell export, direnv, a vault integration, or whatever their org's secret management looks like. Your job is to tell them which env var names the adapter expects (you do this in Phase 1 question 4, and reinforce it in the Phase 5 summary) and to ensure `.env` is in `.gitignore`. The init script already adds it. If a user brings their own secret management, they're responsible for getting the env vars into the adapter process — don't try to solve their secret layer for them.

#### Data-source doc

`knowledge/environment/data-sources/{data_type}.md` — the data-sources layout is organized by data type (auth-events, process-events, network-events, etc.), not per system. Read what's already there:

```bash
ls knowledge/environment/data-sources/
```

For each data type the system covers (from Phase 1, question 3), **append** a section to the matching file noting that this system is a source, with:

- Access: `scripts/tools/{system}_cli.py` (or MCP tool names, if MCP-direct)
- Query language: SPL / KQL / Lucene / native
- Retention: what the user told you
- Coverage notes: which subset of the data type this system holds (e.g., "CrowdStrike covers process events on endpoints, not servers")

If no matching file exists yet for a data type the system covers, create one. Use an existing file as the template.

#### What you do NOT scaffold

- **Signature knowledge.** `/connect` does not touch `knowledge/signatures/`. That's `/author`'s job.
- **Lead templates.** Lead templates encode investigative methodology ("characterize the source IP, then cross-reference with asset DB"), which comes from investigation experience, not API documentation. If the team wants starter lead templates for the new system, they run `/author` after.
- **Permissions.** Adapter access is implicit via `Bash(python3 scripts/tools/{system}_cli.py *)`. Per-signature permissions live in `config/signatures/{id}/permissions.yaml` and are edited by `/author`.

### Phase 5: Re-run preflight and commit

```bash
python3 scripts/preflight.py
```

The new system must show green. If it doesn't, go back to the phase that surfaced the gap.

Stage and commit:

```bash
git status
git diff
git checkout -b connect/{system}
git add scripts/tools/{system}_cli.py \
        scripts/tools/{system}/ \
        knowledge/environment/systems/{system}/ \
        knowledge/environment/data-sources/
# commit with a clear message, but DO NOT push, DO NOT merge
```

**You do not merge.** The human review gate is the trust boundary for generated code. Present a summary to the user:

- Files created / modified (with relative paths)
- Health check result
- Sample query result (one line of output)
- Environment variables the user must have set
- Open items / TODOs left in the scaffolded knowledge

Tell the user: "Review the diff and merge when ready." Then stop.

Walk through `${CLAUDE_SKILL_DIR}/checklist.md` now. If any item is unchecked, surface it in the summary.

## Ground rules

These exist to keep the skill in its lane, not to block a legitimate request. When you hit one that conflicts with what the user is actually trying to do, read the tier carefully: hard limits are non-negotiable and protect safety properties; defaults are the right move for ~90% of connections and should be treated as the path of least resistance, but can be overridden *deliberately* and *transparently* when the user has a genuine reason.

### Hard limits (non-negotiable)

- **Never handle credentials.** Tokens, passwords, API keys, pasted cURL commands containing auth headers — all forbidden. If the user tries to share one, stop and remind them where it belongs (env var or vault). Repeat if necessary. This is the single most important property of the whole flow.
- **Never edit other skills' territory.** No writes to `knowledge/signatures/`, `config/signatures/`, `hooks/`, `schemas/`, `skills/` (other than reading `schemas/adapter_contract.py`). Those belong to `/author` or the plugin maintainers. If the task genuinely requires touching them, stop and tell the user to run the appropriate skill or open a PR by hand.
- **Fail loud on ambiguity.** Never silently substitute a default, a placeholder, or a guessed value for something the user didn't confirm. Surface the ambiguity and ask.

### Defaults (right for most connections, overrideable with cause)

- **Pass-through native queries.** The adapter takes SPL / KQL / Lucene / etc. unmodified. Override only if the upstream genuinely has no query language (lookup-shaped systems → use `LookupContract` instead) or has a quirk that makes pass-through lossy. Document any override in `field-notes.md`.
- **One system per invocation.** If the user mentions three systems during the interview, take notes on the others and suggest re-running `/connect` for each. Override if the three systems are truly co-located (e.g., the same vendor's SIEM + EDR sharing an auth flow) and separating them would duplicate most of the work.
- **Adapter at `scripts/tools/{system}_cli.py`.** This is where the investigation loop and preflight look for adapters. Override only if the user has an existing directory structure you're integrating into, and in that case add a symlink or a note in preflight's discovery path.
- **Python.** See Phase 2. Override means opening a conversation about why, not picking another language silently.
- **No lead templates or signature knowledge.** Those come from investigation experience and live under `knowledge/signatures/` owned by `/author`. If the user wants starter lead templates for a well-known system, suggest running `/author` afterwards — don't build them here.
- **Don't rewrite the wazuh example.** `scripts/siem/wazuh_cli.py` is the plugin's reference/test example. Its eventual migration to subcommand argparse is a separate PR. Note a divergence if you see it; do not fix it.
- **Adapter updates are a deliberate re-run.** If `{system}_cli.py` already exists when `/connect {system}` is invoked, stop and confirm the user wants to update before touching it.
- **Consult `/handbook` on demand.** When you need KB layout, file shapes, or runtime rules, invoke `/handbook` rather than re-deriving them.

### When a request falls outside both

Sometimes the user is legitimately integrating something weird — a homegrown tool with no API, an org-specific shell pipeline, a legacy log scraper that shells out to `ssh host 'journalctl ...'`. That's fine. The skill exists to help them. Generate what's needed, surface the divergence explicitly, and let the human review gate catch anything you got wrong. The hard limits still apply; everything else is negotiable.
