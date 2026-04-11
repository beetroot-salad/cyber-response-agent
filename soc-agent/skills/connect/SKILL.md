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

The design rationale is in `${CLAUDE_SKILL_DIR}/design.md`. Read it if you need to ground a decision about the adapter contract, the MCP coexistence rule, or why you don't ask for credentials.

Before acting: walk through `${CLAUDE_SKILL_DIR}/checklist.md` at the end, before calling the connection done.

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

#### MCP coexistence

If they say "it's behind an MCP server," ask how many tools the server exposes and how often they'll query it:

| Tools | Frequency | Recommendation |
|---|---|---|
| <5 | frequent | Use MCP directly. No CLI. You generate env-knowledge docs only and note the MCP tool names so `/investigate` lead templates can reference them. |
| >10 | rare | Wrap specific MCP tools in a CLI. Avoids loading a large tool schema into the investigate context on every run. |
| anything else | — | Surface the trade-off to the user and let them decide. |

Claude Code loads MCP servers via its own config, not the plugin. You don't write MCP config here. You note in the data-source doc that the system is reached via MCP and which tools to call.

### Phase 2: Generate the adapter

Skip this phase if the user chose "MCP direct" above — jump to Phase 4.

Read the contract once:

```bash
cat schemas/adapter_contract.py
```

Key constraints you're binding yourself to:

- Two argparse subcommands: `health-check` and `query`.
- `query` accepts `<native_query>` as a positional argument plus `--start`, `--end`, `--limit`, `--raw`, `--run-dir`.
- `health-check` exit codes: 0 = connected, 1 = connection/auth failure.
- `query` exit codes: 0 = executed, 1 = query failed, 2 = connection/auth failure.
- **Pass-through native query language.** Splunk adapter takes SPL, Elastic takes KQL, Wazuh takes Lucene. No abstraction, no translation.
- **Credentials from env vars only.** Non-secret config (endpoint, index, defaults) from `knowledge/environment/systems/{system}/config.env`. Secrets are injected by the shell.
- On missing config or missing secret env vars, print a specific hint pointing to the fix and exit 2.
- On import failure (missing `opensearch-py`, `splunk-sdk`, etc.), print the setup command (`bash scripts/tools/{system}/setup.sh`) and exit 2.
- If `--run-dir` is passed, read the salt from `{run_dir}/meta.json` and wrap output in `<run-{salt}-{system}-data>…</run-{salt}-{system}-data>`. Untrusted-data defense.

**Reference implementation:** `scripts/siem/wazuh_cli.py` is the closest working example. It's flag-based rather than subcommand-based (predates the contract) — *mimic the config loading, salt wrapping, and error-handling patterns, not the argparse shape*.

Write the adapter to `scripts/tools/{system}_cli.py`. Use stdlib `urllib.request` where possible — keep the dep footprint small. If the system really needs a vendor SDK (`splunk-sdk`, `elasticsearch`, `opensearch-py`, etc.), also generate:

```
scripts/tools/{system}/requirements.txt    — pinned deps
scripts/tools/{system}/setup.sh            — creates .venv, pip install
```

Model the setup.sh after `scripts/siem/setup.sh`. Per-integration venv; no system-wide pip installs.

When in doubt about API shape, field names, or auth flow, **use WebFetch against the vendor's current API docs**. Your training knowledge is a starting point, not the source of truth. A 10-second doc check now beats a broken adapter later.

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

If the sample query returns zero events, that's not necessarily a failure — the query might just be too narrow. Try a broader one (e.g., drop the time filter) and confirm with the user whether the system actually has any data.

#### 3.3 Optional: usability probe

Skip unless the adapter's interface is unusual. If the adapter has non-default subcommands, idiosyncratic flags, or an inherited CLI shape from an org tool, it's worth checking that a fresh-context agent can drive it from `--help` alone. Spawn a short-lived Haiku subagent, hand it the output of `python3 scripts/tools/{system}_cli.py query --help` (plus `health-check --help`), and a concrete goal like *"return 5 authentication events for user `alice` from the last hour"*. Ask it to emit the command line it would run. If the command matches the adapter's real shape, you're done. If it mismatches, either fix the adapter to match the instinct or document the divergence prominently in `field-notes.md` — whichever is easier to maintain.

The probe is evidence, not a verdict. You decide whether a mismatch is worth fixing. See `${CLAUDE_SKILL_DIR}/design.md` §5 for the reasoning.

### Phase 4: Scaffold environment knowledge

The adapter runs. Now make the agent able to use it without friction. The investigate loop reads environment knowledge to resolve "this lead needs auth events" to "query Splunk like this." If that chain is broken, the adapter is useless — the agent won't find it.

Scaffold the following files. Each is lean at first; the team fills them in over time as they use the system.

#### Per-system directory

`knowledge/environment/systems/{system}/` — create if missing.

- **`config.env.template`** — non-secret config keys (endpoint, index, retention days, SSL verify). Include comments. Secrets are NOT in this file and never will be. Include a one-line header `# Copy to config.env and fill in.`
- **`config.env`** — the actual non-secret values the user gave you in Phase 1. Add to `.gitignore` if it contains anything deployment-specific.
- **`field-notes.md`** — frontmatter `tags: [{system}, fields, gotchas]`, then two sections: "Fields you'll reach for" (names, types, what they mean) and "Known quirks" (non-obvious semantics, surprising nulls, field-splits across event types). Start small. Leave a `TODO: fill in as the team learns` at the bottom.
- **`SKILL.md`** — frontmatter `name: {system}`, `description: {system} implementation knowledge for this org`. Body: how to invoke the CLI (examples), common query patterns if you discovered any, a pointer to `field-notes.md`. Reference any supporting docs you create.

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

- **Never handle credentials.** Tokens, passwords, API keys, pasted cURL commands that contain auth — all forbidden. If the user tries to share one, stop and remind them where it belongs. Repeat if necessary.
- **Pass-through native queries.** No translation layer in the adapter. The agent speaks SPL, KQL, Lucene. Don't wrap those in a custom DSL.
- **Fail loud on ambiguity.** Same rule as the rest of the plugin: if an endpoint, auth mechanism, or field name is unclear, surface it. Never guess a config value silently.
- **Don't scaffold beyond this system.** You are connecting *one* system. If during the interview the user mentions three others, take notes and tell them to run `/connect` again after this one lands.
- **Don't rewrite `wazuh_cli.py`.** It predates the contract and is mid-migration. Flag the divergence if you notice it, but do not touch it. That's a separate PR.
- **Adapter updates are a deliberate re-run.** If the user runs `/connect {system}` and `{system}_cli.py` already exists, confirm they want to update before overwriting.
- **Consult `/handbook` on demand.** When you need to check KB layout, file shapes, or runtime rules, invoke `/handbook`. Do not re-derive them.
- **No code outside `scripts/tools/` and `knowledge/environment/`.** You don't touch `hooks/`, `schemas/`, `skills/`, or anything else. If the task requires that, stop and tell the user.
