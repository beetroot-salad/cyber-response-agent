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

`scripts/siem/wazuh_cli.py` is a reference example, not the default SIEM and not a shipping utility. It exists because the devcontainer runs a Wazuh stack, which gives the plugin something to integration-test against and a concrete working adapter to point at. It is not assumed to be relevant to any real user — no one's plugin installation is "connected to Wazuh" out of the box.

The example predates this contract and uses a flag-based CLI shape (`--query`, `--health-check`) rather than argparse subcommands. `/connect` generates the **subcommand** shape for new adapters. A migration of the wazuh example to `scripts/tools/wazuh_cli.py` with subcommand argparse is plausible but not scheduled — it's a path change that ripples into hooks, env-knowledge docs, and lead templates, and it deserves its own review. For now the example stays where it is and serves as a read-only reference.

`preflight.py` handles both shapes on discovery: adapters under `scripts/tools/` are invoked with `health-check` as a subcommand; adapters under `scripts/siem/` are invoked with `--health-check` as a flag. This keeps the example working without forcing the migration.

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
2. **There is enough environment knowledge for `/author` to build on later.** A per-system directory exists with a lean `field-notes.md`, a `SKILL.md` with at least one real CLI example, and a short data-source entry. Not a comprehensive reference — enough for post-mortem to grow.

`preflight.py` enforces the first deterministically. The second is where the interesting design question lives.

### Connect-time scaffold vs post-mortem growth

The environment knowledge `/connect` produces is deliberately thin. The runtime reader for the investigation loop is `knowledge/common-investigation/leads/{lead}/templates/{vendor}.md` — a per-lead, per-vendor query template plus field mapping that the agent consults at query time. Those lead templates are written by `/author` after real investigation experience reveals which leads are worth formalizing and what the actual field semantics are for this deployment. They are not written at connect time.

That split is load-bearing. Writing lead templates upfront would be:

- **Unbounded.** Which leads for this vendor? Which shape? Which fields? The answers depend on which signatures your team investigates, which environments the system covers, and which post-mortem findings surface — none of which are known at connect time.
- **Speculative.** API docs tell you what the system *can* return, not which queries actually characterize the alerts you'll see. The difference between those two is exactly what post-mortem extracts.
- **Unmaintainable.** Pre-written templates rot. Templates grounded in real investigations get refreshed whenever an investigation reveals drift.

So the lifecycle is:

1. **`/connect` (this skill).** Adapter + lean `field-notes.md` + short data-source entry + `SKILL.md` with one CLI example. Captures what Claude can spot during the connection session — obvious gotchas, vendor-specific aliases, the minimum the investigation loop needs to *find* the system. Friction on the first investigations is expected and accepted.

2. **`/investigate` (existing skill).** Runs against the system. Hits friction on query composition the first few times — Claude composes queries on the fly from whatever field knowledge exists plus its training priors. Some guesses are right; some are wrong. That's the input signal for the next step.

3. **`/author` post-mortem (existing skill).** Reads the investigation run, identifies where Claude got field names wrong or reached for the wrong enum, and bakes those findings into `field-notes.md` and into new/updated lead templates under `knowledge/common-investigation/leads/{lead}/templates/{vendor}.md`. Each post-mortem run compounds on the last.

By investigation N (for small N — maybe 5–10), the system has lead templates grounded in real data and a `field-notes.md` that covers the actually-encountered gotchas. That's the steady-state quality bar. `/connect` doesn't try to hit it upfront because it can't — the required information isn't available at connect time.

Practical consequence: **lean is correct at connect time, not a shortcut.** A three-bullet `field-notes.md` that captures the one vendor-specific field alias you noticed is a better MVP than a twenty-bullet reference you're guessing at. The guesses become noise; the observed gotcha stays useful.

### Two axes of friction-free

There are two broadly orthogonal ways to reduce agent friction on a generated adapter:

**Axis A — intrinsic legibility.** Make the interface predictable through convention, not instruction. Thin wrappers. Pass-through native query language. Consistent subcommand names across every adapter (`health-check`, `query`) so the agent's prior from one adapter transfers to the next. Argparse's free `--help` on every subcommand. Tight, concrete examples in the system's `SKILL.md`.

Runs are stateless, so a consistency win across adapters benefits humans maintaining the plugin more than it benefits any single investigation run. The indirect path where it *does* benefit runtime is via the environment-knowledge SKILL.md files the agent reads at run startup — if those follow the same template, the agent gets consistency at read time even without cross-run memory.

MVP commits to Axis A. It's the baseline every adapter must hit. The contract (`schemas/adapter_contract.py`) pins the subcommand names. The checklist demands stdlib-first, native-language pass-through, hint-bearing error messages. No extra runtime cost, no extra Claude calls.

**Axis B — empirical verification via Haiku probe.** Before committing the adapter, spawn a fresh-context Haiku subagent, hand it a realistic task (e.g., *"find the 5 most recent failed SSH logins on host web-01 in the last hour"*), and inspect what command it emits and what ambiguities it calls out. The probe is evidence, not a verdict — the main agent reads the output and decides whether a mismatch means "fix the adapter" or "fill in the docs".

The original framing of this probe — draft in the previous version of this design — was that it would target the adapter's `--help` output, to catch cases where CLI shape (positional vs `--flag`, subcommand vs no subcommand) confused fresh-context agents. We ran the experiment.

### What the probe measured

Three Haiku trials in parallel, each with isolated context, each given a different CLI shape of the same Splunk adapter:

| Trial | Shape exposed | Result |
|---|---|---|
| 1 | `query "<spl>" --start ... --end ... --limit N` (subcommand + positional query, flag metadata) | Syntactically correct command on the first try. |
| 2 | `query --query "<spl>" --start ... --end ... --limit N` (subcommand + `--query` flag) | Syntactically correct command on the first try. |
| 3 | `--query "<spl>" --window 1h --limit N` (flag-based, no subcommand — the current `wazuh_cli.py` shape) | Syntactically correct command on the first try. |

Zero CLI-shape confusion across all three shapes. Haiku correctly read argparse `--help` output and produced a valid invocation regardless of whether the query was positional or a flag, and regardless of whether there was a subcommand layer.

What *did* produce uncertainty, in every trial: **field model**. Which sourcetype name (`linux_secure` vs `sshd` vs `ssh`). Which field for "failure" (`action=failure` vs `status=failed`). Whether to include `index=main`. Whether to assume newest-first ordering. One trial reached for `--window 1h` because that convenience flag existed in its `--help`; the others computed ISO timestamps because `--window` wasn't present. That's a design hint about what convenience flags to expose, not a CLI-shape problem.

**Implication: the probe was targeted at the wrong layer.** CLI shape is not where runtime friction lives. Field semantics is. The probe should target `field-notes.md` and the `--help` *examples* — because those examples are load-bearing: Haiku pattern-matched against whatever example the help text showed, and if the example is wrong, the generated command inherits the wrongness.

### What the probe should target, revised

Axis B lives, but pivots:

- **No longer probe CLI shape.** All three shapes pass. Using convention + argparse `--help` is sufficient.
- **Probe field-model fidelity instead.** Hand Haiku the `query --help` output plus the draft `field-notes.md`, give it a realistic task, and inspect the ambiguities it surfaces. If Haiku has to guess at sourcetype names, field spellings, or enum values that should be documented, `field-notes.md` is too thin — expand it before committing.
- **Check the `--help` examples.** If Haiku pattern-matches on an example in `--help` that uses generic placeholder field names, the adapter's examples need real deployment-specific values. "Examples in help are load-bearing" is a design principle now, not a hypothesis.
- **Optional convenience-flag review.** If the task would be much easier with a `--window 1h` shortcut than with `--start`/`--end` arithmetic, consider adding it. Not required, but a cheap win.

This is the version that ships in `checklist.md` as optional-but-useful and in `SKILL.md` Phase 3.3. Promote to required when we have evidence that synthesis-only adapters produce silently thin field-notes often enough to warrant the cost.

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
| MCP | No CLI, or a CLI that wraps specific MCP tools. Which path depends on user preference — see §3 MCP vs CLI. |
| Bastion | **Stop.** The agent runs on the bastion, not the laptop. Exit cleanly. |

Credential handling is always the same regardless of pattern:

- `config.env.template` (tracked in git) — the canonical list of non-secret keys.
- `config.env` (gitignored) — the deployment's actual non-secret values.
- `.env` or shell environment (gitignored) — secrets only.

The adapter loads both and fails loud if either is missing. The skill never sees raw secrets at any point in the flow. This matters because an LLM context is not an auditable credential store — every other design question can shift, but this one cannot.

The `.env` file pattern is convention, not enforcement. Users bring their own secret management — shell export, direnv, vault integration, Kubernetes secrets, whatever. The adapter's only requirement is that the expected env var names are set in its process environment by the time it runs. How that happens is out of scope.

### Why we don't handle VPN / proxy / bastion setup

Those are organizational concerns that predate the agent. If the analyst can't reach their SIEM from their laptop, `/connect` can't fix that — it can only diagnose the symptom (connection refused, 401, timeout) and point them at the class of problem. The skill is a compiler and tester, not a network admin.

---

## 7. Model and cost

Main agent: **Sonnet 4.6**, pinned in `SKILL.md` frontmatter. Axis B probe (optional): Haiku, dispatched via Task.

Rationale:

- `/connect` is a code-generation task (an adapter CLI) plus interactive decision-making (interview, error diagnosis). Sonnet is comfortably strong enough for both. `/author`'s experience shows Sonnet handles comparable work reliably.
- Opus is a 5× cost jump for judgment improvements on a task that's mostly structured. The one place Opus would matter — reasoning about unusual enterprise access topologies — is something we can handle by extending the interview, not by upgrading the model.
- The Haiku field-model probe is a quick one-shot question ("here's the docs, here's a task, what would you run and what are you unsure about?"). No chain-of-thought, no multi-turn. Haiku is fast enough to keep Phase 3 feeling interactive.

Override via `SOC_AGENT_CONNECT_MODEL` env var is possible if needed later, but not wired up in MVP.

## 7a. WebFetch and prompt injection

WebFetch is deliberately **not** in the skill's `allowed-tools` list.

The skill needs to fetch vendor API docs during Phase 2 when Claude's memory is uncertain. Granting blanket `WebFetch` permission would pre-approve every fetch, and an LLM fetching attacker-controlled content is a textbook prompt-injection vector — a malicious page can carry instructions that alter agent behavior mid-flow. For a security-adjacent tool like `/connect`, that's unacceptable blast radius.

Claude Code's permission model treats `allowed-tools` as a grant, not a restriction: tools not listed are still *callable*, they just fall through to the user's permission settings and typically prompt interactively. That's exactly the fallback we want. Every WebFetch call becomes a one-second user decision with the URL visible — cheap friction in exchange for eliminating blind fetches.

### What we considered and rejected

- **Per-domain allowlist in `allowed-tools`.** Claude Code supports `WebFetch(domain:example.com)` but not wildcard or path restrictions. We'd need to pre-enumerate every vendor's documentation host (docs.splunk.com, www.elastic.co/guide, learn.microsoft.com, docs.crowdstrike.com, …), which is unmaintainable at scale and still doesn't cover first-party custom systems.
- **A PreToolUse hook that validates domains at runtime.** Technically viable — the hook could hold a regex allowlist and block anything else. We're not building it in this PR because it's a separate piece of infrastructure with its own design questions (where does the allowlist live? can the user override? how do hooks compose with other plugins?) and because per-invocation user approval already achieves the safety goal without new code.
- **Static project-scoped `settings.json` with `deny: ["WebFetch"]` as a baseline.** This could belong in the plugin's docs as a recommended hardening step for teams that want an extra belt. Not enforced by the skill itself.

### What the user sees

Every WebFetch call from `/connect` prompts them with the URL and a short reason ("fetching Splunk query API v2 docs to verify field names"). One-second approval for the legitimate path; one-second deny for anything unexpected. Users who trust a specific vendor domain globally can pre-authorize it in their own `settings.json` — that's opt-in hardening, not something the skill assumes.

---

## 8. What `/connect` deliberately doesn't do

| Non-goal | Why | Alternative |
|---|---|---|
| Lead templates for the new system | Unbounded (which leads?), speculative (which queries actually characterize real alerts?), unmaintainable (pre-written templates rot) — see §5 "Connect-time scaffold vs post-mortem growth" | `/author` writes lead templates post-mortem from investigation runs |
| Comprehensive field reference | Connect-time guesses become noise; post-mortem records real gotchas | `field-notes.md` grows via `/author` post-mortem |
| Signature onboarding | That's `/author`'s job; signatures require historical investigation data | Run `/author` after `/connect` |
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
