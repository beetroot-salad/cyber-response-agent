# `/connect` — Design Rationale

**Version:** 0.1 | **Date:** April 2026 | **Status:** Shipped (MVP)

Why `/connect` is shaped the way it is. The **what** and **how** live in `SKILL.md`; this file captures the decisions behind those choices so future edits don't accidentally unwind them. The full system-level design is in `docs/design-v3-init-and-connect.md`; this file is the skill-level view.

---

## 1. Problem statement

Connecting a new security system today means:

- Hand-writing a CLI script (`wazuh_cli.py` is 468 lines).
- Creating `config.env.template`, `config.env`, field docs, data-source docs by hand.
- Reading the design docs to understand the adapter contract and the 4-layer knowledge model.
- Configuring credentials outside the agent's scope.
- Wiring the new system into the lead templates the investigation loop consults.

That's a multi-hour task gated on reading several design docs, and it's the first thing a new user has to do before they can run a single investigation. It's the single largest source of friction in adopting the agent.

`/connect` exists to shrink this to "answer four questions, verify a sample query, commit." Generated code is not self-service — the user still reviews the diff before merging — but the grunt work disappears.

---

## 2. Design principles

1. **Handbook is the library; `/connect` is the editor.** Same rule `/author` follows. When the skill needs to know where things live or how the investigation loop consumes environment knowledge, it invokes `/handbook` rather than duplicating content. Keeps both skills honest as the KB layout evolves.
2. **Adapter-only scope.** `/connect` edits `scripts/tools/` and `knowledge/environment/`. Never `hooks/`, `schemas/`, or `skills/`. Never signature knowledge. Signature onboarding is `/author`'s job.
3. **Never touch credentials.** The adapter is the credential boundary. The skill tells the user which env vars to set; it never asks for values and refuses if offered. This is non-negotiable — it's the single most important safety property of the whole setup.
4. **Pass-through native query languages.** The adapter takes SPL, KQL, Lucene as-is. No abstraction. The agent already knows these languages from training, and a translation layer would be a perpetual source of bugs and lost expressive power.
5. **Per-system CLIs.** No unified `siem_cli.py`. Different systems have different capabilities, auth flows, and failure modes that a unified interface would mask or flatten.
6. **Generate from scratch, not from templates.** We deliberately do *not* ship a template library for popular vendors. See §4.
7. **Human review gate.** `/connect` creates a branch and stages files. It does not merge and does not push without explicit user direction. Generated code does not go live without a human reading the diff.
8. **One system per invocation.** Scope creep is the enemy of a clean review diff. If the user wants to connect three systems, they run the skill three times.
9. **Fail loud on ambiguity.** Same rule as the rest of the plugin.

---

## 3. Adapter contract

Two operations: `health-check` and `query`. Everything else — field enumeration, aggregation, schema normalization, data freshness — the agent does in Python after getting raw results. See `schemas/adapter_contract.py` for the authoritative spec and `docs/design-v3-init-and-connect.md` §3 for the reasoning on each excluded capability.

The contract is deliberately tiny because every capability we bake into it has to work across every possible system. Two is the minimum; two is also what the investigation loop actually requires.

### The `wazuh_cli.py` discrepancy

`scripts/siem/wazuh_cli.py` is the reference implementation but predates the contract. It uses flags (`--health-check`, `--query`) rather than argparse subcommands. `/connect` generates the **subcommand** shape for new adapters. The wazuh_cli.py migration to `scripts/tools/wazuh_cli.py` with subcommand argparse is tracked as a follow-up — it's a path change that ripples into hooks, env-knowledge docs, and lead templates, and it deserves its own review.

For now: `preflight.py` handles both shapes. When it finds an adapter in `scripts/tools/`, it runs `health-check`. When it finds one in the legacy `scripts/siem/`, it runs `--health-check`. No user-facing friction.

---

## 4. The "no template library" decision

The tempting path is to ship pre-written adapters for Splunk, Elastic, CrowdStrike, Microsoft Defender — maybe twenty files, 300 lines each, under `skills/connect/templates/{vendor}/`. First-run experience is faster because Claude just copies and adjusts.

We rejected this. Three reasons:

1. **Drift.** A pre-built adapter that tests green today rots silently against vendor API changes. The failure mode is a dormant adapter nobody notices until an investigation needs it. Fresh generation anchors to Claude's current training knowledge at connect time — at least as fresh as the model version, and the skill tests it immediately after generation.
2. **Same failure mode, earlier detection.** If Claude's memory of the Splunk API is wrong in Phase 2, Phase 3's health check surfaces it right there, and the skill iterates. If a vendored template is wrong, the same health check surfaces it — but after shipping a misleading "starter." Net: the failure mode is identical, but generation catches it at connect time instead of during onboarding.
3. **Maintenance cost.** A template library is CI infrastructure, version pinning, a vendor test matrix, and a PR queue for every vendor API change. It's a real ongoing cost for a marginal onboarding speedup.

A template library can be added later as a purely additive change — the `/connect` flow is the same whether Claude synthesizes from training or from a template. Ship the lean version; revisit when we have data on how often synthesis fails.

---

## 5. Validation: what "successful connection" means

Two checks, named in `SKILL.md` Phase 3:

1. **The adapter connects and queries.** `health-check` returns exit 0. A sample query returns reasonable output. This is the machine-side check.
2. **The agent can use the adapter without friction.** The environment knowledge exists — at minimum a per-system directory with field documentation, and a data-source doc noting this system as a source for the relevant data type. The adapter's interface is legible to a fresh-context agent reading only `--help`.

`preflight.py` enforces the first deterministically. The second is where the interesting design question lives.

### Two axes of friction-free

There are two broadly orthogonal ways to reduce agent friction on a generated adapter:

**Axis A — intrinsic legibility.** Make the interface predictable through convention, not instruction. Thin wrappers. Pass-through native query language. Consistent subcommand names across every adapter (`health-check`, `query`) so the agent's prior from one adapter transfers to the next. Argparse's free `--help` on every subcommand. Tight, concrete examples in the system's `SKILL.md`. All of this leans on the agent's training priors about Unix CLIs: if the interface looks like what a competent SRE would write, the agent will reach for the right flag on the first try.

Caveat the user correctly flags: runs are stateless. A consistency win across adapters benefits humans maintaining the plugin more than it benefits any single investigation run, because run N doesn't remember run N−1. The indirect path where it *does* benefit runtime is via the environment-knowledge SKILL.md files the agent reads at run startup — if those follow the same template, the agent gets consistency at read time even without cross-run memory.

MVP commits to Axis A. It's the baseline every adapter must hit. The contract (`schemas/adapter_contract.py`) pins the subcommand names. The checklist demands stdlib-first, native-language pass-through, hint-bearing error messages. No extra runtime cost, no extra Claude calls.

**Axis B — empirical verification.** Before committing the adapter, spawn a fresh-context Haiku subagent, hand it only the adapter's `--help` output and a goal ("return the last 5 authentication events from user `alice`"), and ask it to produce the command line it would run. Compare to what the adapter actually accepts. If the probe reaches for `--query "..."` and the adapter wants `query "..."` (positional subcommand), or if the probe reaches for `--limit=5` and the adapter wants `-n 5`, you've mechanically detected a friction point that convention alone didn't catch.

This is the analogue of `/author`'s reconstruction probe: evidence, not a verdict. A probe mismatch is a signal to fix the adapter *or* to document the quirk prominently in `field-notes.md` so future runs see it in context. It closes the loop on "friction-free agent use" from a human-review concern to a mechanically measurable one.

Axis B is **not** in MVP. Reasons:

- It adds a subagent spawn to every `/connect` run. Cost is small but non-zero, and the skill is meant to feel lightweight.
- It's unnecessary overhead for plain-vanilla adapters that follow the contract. The interesting cases are the ones with unusual subcommand shapes (e.g., a CMDB that uses `lookup` instead of `query`, or a vendor CLI with idiosyncratic flags).
- We want to see real synthesis failures before designing the probe — building it speculatively risks over-fitting.

The checklist in `checklist.md` names the probe as an **optional belt-and-suspenders step** rather than a required one. Use it when the adapter's interface diverges from the default shape. Skip it when the adapter is a straightforward health-check + query. When we have data on how often synthesis-only adapters fail friction-free review, revisit: if the answer is "more than rarely," promote the probe to a required Phase 3.3 step.

### Known gap

No automated replay test that proves "this adapter, called from the investigation loop with a realistic lead, returns results the agent can act on." That would require spawning a mini-investigation against sample data. Parked — probably a follow-up once we have multiple connected systems to compare.

---

## 6. Network and credential realities

Enterprise security systems are rarely reachable with a direct API call from an analyst's laptop. The five patterns in §2 of `docs/design-v3-init-and-connect.md` — direct API, SOAR, existing CLI, MCP, bastion — cover the bulk of real deployments.

The interview in Phase 1 asks explicitly which pattern applies because it fundamentally changes what gets generated:

| Pattern | Generated artifact |
|---|---|
| Direct API | `{system}_cli.py` with an HTTP client |
| SOAR | `{system}_cli.py` that calls the SOAR API, not the target system directly |
| Existing CLI | `{system}_cli.py` that shells out to the existing tool and parses output |
| MCP (few tools) | No CLI — env knowledge docs referencing MCP tool names |
| MCP (many tools) | `{system}_cli.py` that calls specific MCP tools, to keep context small |
| Bastion | **Stop.** The agent runs on the bastion, not the laptop. Exit cleanly. |

Credential handling is always the same regardless of pattern: env vars hold secrets, `config.env` holds non-secrets, the adapter loads both and fails loud if either is missing. The skill never sees raw secrets at any point in the flow. This matters because an LLM context is not an auditable credential store — every other design question can shift, but this one cannot.

### Why we don't handle VPN / proxy / bastion setup

Those are organizational concerns that predate the agent. If the analyst can't reach their SIEM from their laptop, `/connect` can't fix that — it can only diagnose the symptom (connection refused, 401, timeout) and point them at the class of problem. The skill is a compiler and tester, not a network admin.

---

## 7. Model and cost

Main agent: **Sonnet 4.6**, pinned in `SKILL.md` frontmatter. No probes, no subagents.

Rationale:

- `/connect` is a code-generation task (an adapter CLI) plus interactive decision-making (interview, error diagnosis). Sonnet is comfortably strong enough for both. `/author`'s experience shows Sonnet handles comparable work reliably.
- Opus is a 5× cost jump for judgment improvements on a task that's mostly structured. The one place Opus would matter — reasoning about unusual enterprise access topologies — is something we can handle by extending the interview, not by upgrading the model.
- WebFetch is in `allowed-tools`: when Claude's memory of a vendor API is uncertain, fetching the current docs is the right move. Much higher leverage than upgrading the model.

Override via `SOC_AGENT_CONNECT_MODEL` env var is possible if needed later, but not wired up in MVP.

---

## 8. What `/connect` deliberately doesn't do

| Non-goal | Why | Alternative |
|---|---|---|
| Lead templates for the new system | Lead templates encode investigative methodology, which comes from investigation experience, not API docs | `/author` adds lead templates after the team uses the system |
| Signature onboarding | That's `/author`'s job; they require historical investigation data | Run `/author` after `/connect` |
| Network / VPN setup | Organizational, predates the agent | The user configures their own network path |
| Credential storage | Credentials live in env vars or vault; the skill never touches them | `.env`, shell export, vault integration — user's choice |
| Template library for popular vendors | Drift + maintenance cost > marginal onboarding speedup | Generate fresh each time; revisit if synthesis fails often |
| CI wiring | Local-first; CI is additive later | User adds a pipeline when they have a remote |
| Auto-merge | Human review gate is the trust boundary | User reviews the diff and merges |

---

## 9. Open questions

Parked for follow-up:

1. **Adapter testing beyond health-check.** Generated adapters should have contract-compliance tests (does `query --raw` emit valid JSON? does `--run-dir` wrap output with the right salt?). This can be a single parameterized test under `tests/` that iterates over every file in `scripts/tools/`. Not MVP.

2. **Re-connect / update flow.** Re-running `/connect splunk` when `splunk_cli.py` already exists should detect the existing adapter and offer update/diff/keep/replace. MVP confirms with the user but doesn't do a structured merge — if the user has hand-edited the adapter, a regenerate would clobber those edits. Needs a real UX before shipping.

3. **Config file format.** `config.env` is shell-sourceable key=value. Works for flat config; doesn't support lists or nesting. If adapter config grows (e.g., multi-instance Splunk with per-instance index mappings), consider TOML or a sidecar JSON file. Stay with env-style for now.

4. **Non-query systems.** CMDB lookups, threat intel enrichment endpoints, IAM role queries — these don't cleanly fit `query(native_query)`. Options: a separate `LookupContract` ABC with `lookup(identifier)`, or ad-hoc scripts that don't implement the contract. MVP is ad-hoc; formalize if a pattern emerges.

5. **Instance naming.** `/connect splunk` assumes one Splunk instance. Multi-instance (prod + audit + dev) needs a suffix convention (`splunk_prod`, `splunk_audit`). Interview could ask for an instance tag. Not MVP.

6. **Re-using existing MCP servers.** When a user says "I have Wazuh MCP already configured," the skill currently notes the tool names in env docs but doesn't verify the MCP server is actually loaded in the user's Claude Code config. A preflight check that enumerates currently-loaded MCP tools would be useful. Needs a Claude Code API we don't have yet.

---

## 10. Relationship to other skills

| Skill | Relationship |
|---|---|
| `/handbook` | Source of truth for KB layout and runtime rules. `/connect` invokes it on demand; does not duplicate. |
| `/author` | Sibling. Owns signature knowledge. `/connect` writes data-source docs that signatures reference via leads; `/author` writes the signature knowledge that consumes them. Neither touches the other's territory. |
| `/investigate` | Consumer of `/connect`'s output. Investigation loop calls the adapter CLIs and reads the environment knowledge docs scaffolded here. `/connect` never invokes `/investigate`. |
