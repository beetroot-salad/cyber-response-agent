# `connect` — design rationale

**Version:** 0.2 | **Status:** ported to `defender/` (PoC) | June 2026

Why connect is shaped the way it is. The **what** and **how** are in
`SKILL.md`; this file captures the decisions so future edits don't
unwind them. This skill is a port of the v3 soc-agent `/connect`; the
v3 system-level design is preserved at the repo root in
`docs/design-v3-init-and-connect.md`. Where v3 assumed a
plugin with a preflight script, an adapter-contract ABC, and `/author`
post-mortem, defender has a runtime loop, a shim layer, and an offline
learning loop — so the port keeps v3's principles and re-grounds its
mechanics. Section 9 records what changed and why.

---

## 1. Problem statement

Onboarding a system of record into defender by hand means: writing an
adapter CLI that matches the existing ones, dropping a `bin/` shim,
splitting per-system knowledge into a Visibility surface and an
Execution surface in the right shapes, writing a non-secret `config.env`,
and seeding a couple of query templates — across five+ files, gated on
reading `system-skill-shape.md`, `state-surface-adapters.md`,
`bin/README.md`, and `queries/SCHEMA.md` first. connect shrinks that to
"answer four questions, verify a sample query, review the diff." The
generated code is not self-service — the human reviews the diff before
merging — but the grunt work and the doc-reading disappear.

---

## 2. Design principles

1. **The docs are the library; connect is the editor.** When the skill
   needs to know a file shape or a runtime rule, it reads the owning doc
   (`system-skill-shape.md`, `state-surface-adapters.md`,
   `queries/SCHEMA.md`, `bin/README.md`) rather than duplicating it.
   Keeps the skill honest as the layout evolves.
2. **Adapter-only scope.** connect writes the adapter, its shim, the
   per-system skill, the config, and a couple of seed templates. Never
   `hooks/`, `learning/`, `lessons/`, the runtime `SKILL.md`, or another
   system's files.
3. **Never touch credentials.** The adapter is the credential boundary.
   The skill names the env vars; it never asks for values and refuses if
   offered. Non-negotiable — an LLM context is not an auditable
   credential store.
4. **Pass-through native query languages.** A query source takes its
   native query unmodified; a lookup source keys on an identifier. No
   abstraction layer. The agent already knows these languages, and a
   translation layer is a perpetual source of bugs and lost expressivity.
5. **Per-system CLIs.** No unified `siem_cli.py`. Different systems have
   different capabilities, auth flows, and failure modes a unified
   interface would flatten — and a per-system CLI matches the per-system
   SKILL split.
6. **Generate from scratch, not from a template library.** See §4.
7. **Human review gate.** connect branches and stages; it does not merge
   or push. Generated code does not go live without a human reading the
   diff.
8. **One system per invocation.** Scope creep is the enemy of a clean
   review diff.
9. **Fail loud on ambiguity.** Same rule as the rest of defender.

---

## 3. The adapter contract

There is no ABC. The contract is the convention the existing adapters
follow, and the reference is two concrete shapes rather than a base
class:

- **`elastic_cli.py`** — credentialed, direct HTTP. Resolves its own
  connection and secrets; a query source with a native query language.
- **`_stub_transport.py`-based stubs** (`cmdb_cli.py`, `identity_cli.py`,
  …) — HTTP over `docker --context soc-playground exec <host> curl`. A
  shared transport helper keeps them thin; mostly lookup sources keyed by
  identifier.

Both expose `health-check` plus one subcommand per verb, emit a stable
`--raw` JSON envelope, and use exit codes `0` / `1` / `2` (plus `64` for
usage errors — bad flag, unknown subcommand, missing arg — emitted free
by the shared `AdapterArgumentParser` in `_stub_transport.py`). The contract
is deliberately tiny because every capability baked into it has to work
across every system. Health-check tells the runtime the source is
reachable; the verbs return raw results the agent post-processes. Field
enumeration, aggregation, and normalization are the agent's job in
Python, not the adapter's.

Two things the v3 adapter did that defender's does **not**:

- **No `--run-dir` salt wrapping.** v3 adapters wrapped output in
  per-run untrusted-data delimiters themselves. In defender that is the
  runtime's job — `hooks/tag_tool_results.py` salts adapter output
  post-hoc — so the adapter emits clean output and stays
  deployment-agnostic.
- **No self-managed capture.** The gather subagent runs every adapter
  call wrapped in `defender-record-query`, which persists the `--raw`
  payload by-ref to `gather_raw/{lead_id}/{seq}.json` and appends a row
  to the queries table. The adapter neither redirects stdout nor names
  files. This is why the `--raw` envelope must stay stable: drift breaks
  the queries table and replay.

---

## 4. The shim + auto-gating decision

Every adapter gets a `bin/defender-{system}` shim. The reason is the
harness allowlist: it matches a Bash command on its first token and
re-gates each part of a compound command, so a path/module/`cd &&` form
produces a different leading token every time and an unattended
`claude -p` run trips "requires approval" on legitimate calls (issue
#261). The shim collapses every form to one allowlisted token
(`Bash(defender-* *)`).

The shim is also the **registration mechanism**. `hooks/_cmd_segments.py`
defines `adapter_shims()` as every `defender-*` shim minus
`NON_ADAPTER_SHIMS`, and all three runtime gate hooks
(`approve_shim_invocations.py`, `block_main_loop_raw_access.py`,
`block_unwrapped_adapter_calls.py`) read that one list. So dropping a
shim in `bin/` gates the new adapter everywhere — clamped out of the
main loop, forced through `defender-record-query` inside gather — with
no per-hook edit and no allowlist edit. This is why connect's "register
the adapter" step is just "drop the shim," and why the v3 `preflight.py`
+ explicit per-CLI permission entries are gone: the shim layer
subsumes both.

---

## 5. The Visibility / Execution split

Per-system knowledge is two files, by audience:

- **`SKILL.md` (Visibility surface)** — what the system can and cannot
  answer here and how to read its output. Read by the orchestrating
  defender (routing), the offline author, and the actor-reviewer judge.
- **`execution.md` (Execution)** — adapter CLI shape, flags, query
  syntax, connectivity, exit codes. Read **only** by the gather subagent
  at dispatch.

The split is load-bearing, not cosmetic. A one-file "named sections"
layout leaked the adapter's credential/tunnel variables into the
orchestrator's context, where it groped for them instead of dispatching
gather (issue #261). The orchestrator loads `SKILL.md` to *route* but
never queries a source; putting execution detail in a sibling file the
orchestrator never reads removes the trigger structurally rather than
with a "don't read this" note. connect must respect this: connectivity
and credential detail go in `execution.md`, never the Visibility surface.

---

## 6. The "no template library" decision

The tempting path is to ship pre-written adapters for Splunk, Elastic,
CrowdStrike under `skills/connect/templates/{vendor}/`. Rejected, for
three reasons:

1. **Drift.** A pre-built adapter that tests green today rots silently
   against vendor API changes; the failure mode is a dormant adapter
   nobody notices until a run needs it. Fresh generation anchors to the
   model's current training and is tested immediately in Phase 3.
2. **Same failure mode, earlier detection.** If the model's memory of
   an API is wrong, Phase 3's health check surfaces it at connect time —
   versus a vendored template surfacing it after shipping a misleading
   starter.
3. **Maintenance cost.** A template library is CI, version pinning, and
   a per-vendor PR queue, for a marginal onboarding speedup.

The same logic extends to the **query catalog**. connect seeds only the
two or three templates the maintainer is certain of; it does not
pre-build a catalog from API docs. The catalog grows post-merge: the
offline lead-author (`learning/lead_author.py`) mints `_draft/{verb}.md`
templates from real gather runs and curates them. Writing templates from
API docs upfront is unbounded (which measurements matter for this
vendor?) and speculative (which queries actually characterize the alerts
you'll see?) — exactly what the post-merge flow extracts and a docs-read
cannot.

---

## 7. MCP vs CLI

Both work; both are supported. **Defender's existing systems are all CLI
adapters — v2 chose CLI for simplicity.** A CLI gives one stable shim
token, a stdlib transport, full control over the `--raw` envelope the
gather capture depends on, and consistency across the directory (the
gather subagent's prior from one adapter transfers to the next). MCP
wins on upfront effort when a maintained server is already configured,
and on not-owning-the-code.

The defender-specific axis the v3 design didn't have: **capture**. The
queries table and `gather_raw/` are fed by the adapter's `--raw`
envelope flowing through `defender-record-query`. MCP output is tagged
for injection safety by the runtime but does not flow through that
capture path, so an MCP system is thinner in the offline learning loop.
That's a real cost to weigh, not a disqualifier. connect surfaces the
trade-off and lets the maintainer decide; it does not steer.

---

## 8. The Haiku field-model probe

An optional Phase 3 check. Its history: the v3 probe targeted the
adapter's `--help` *CLI shape*, to catch cases where positional-vs-flag
or subcommand-vs-not confused fresh-context agents. The experiment (three
Haiku trials, three CLI shapes of the same adapter) found **zero**
CLI-shape confusion — Haiku read argparse `--help` correctly every time.
What produced uncertainty in every trial was the **field model**: which
sourcetype, which field means "failure", whether to assume newest-first.

So the probe pivoted, and the port keeps the pivoted version: probe
field-model fidelity, not CLI shape. The fit is even cleaner in defender
than in v3 — the runtime gather subagent *is* Haiku, so probing with
Haiku tests the exact consumer of `execution.md` and the Visibility
surface. Ambiguities Haiku surfaces are gaps in those surfaces; fill the
obvious ones, leave the subtle ones for post-merge. The probe produces
evidence, not a verdict.

---

## 9. Validation, and what changed from v3

A successful connection is two checks:

1. **The adapter connects and queries.** `health-check` exits `0`; a
   sample query returns legible output. The machine-side check.
2. **There is enough per-system knowledge to dispatch and route.** A
   `skills/{system}/` dir with a Visibility `SKILL.md`, an
   `execution.md`, a non-secret `config.env`, and a couple of seed
   templates. Lean, not comprehensive.

The headline difference from the v3 design: **there is no
`preflight.py`.** v3 enforced check (1) with an aggregate preflight
script that walked every adapter. Defender has no such script — each
adapter's `health-check` is the unit, and the shim/gate-hook layer
replaces the "is this wired in?" half of preflight. Whether defender
eventually wants an aggregate health roll-up is an open question (§11),
but connect does not assume one and does not write one.

Other v3 mechanics the port drops, because the machinery doesn't exist
in defender:

| v3 concept | Why dropped |
|---|---|
| `schemas/adapter_contract.py` ABC | Contract is convention + two reference adapters, not a base class |
| `scripts/preflight.py`, Phase 0/5 preflight | Replaced by per-adapter `health-check` + shim auto-gating |
| `schemas.py` / `AlertSchema` per system | No alert-schema mechanism in defender; alerts arrive as fixtures |
| `data-sources/{type}.md` registry | Coverage lives in the per-system Visibility surface |
| `ActionContract` / act-mode / `config/actions.yaml` | No act-mode in defender; `ticket` is read-only |
| `/author`, `/investigate`, `/handbook` slash commands | Replaced by the learning loop, `run.py`, and `skills/handbook/` |

---

## 10. Network, credentials, and why we don't do VPN/bastion

The access patterns (HTTP-over-`docker exec`, direct API, existing CLI,
MCP, bastion) fundamentally change what gets generated, which is why the
interview asks. Credential handling is the same regardless of pattern:
non-secret config in `config.env` (tracked when it holds no secrets,
gitignored per the `wazuh` precedent when it would encode a sensitive
deployment), secrets in env vars only. The adapter loads both and fails
loud if either is missing; the skill never sees a raw secret.

We don't handle VPN/proxy/bastion setup. Those are organizational
concerns that predate the agent. If the maintainer can't reach the
system, connect can only diagnose the symptom (connection refused, 401,
timeout) and name the class of problem. The skill is a compiler and
tester, not a network admin.

---

## 11. WebFetch and prompt injection

WebFetch is deliberately not pre-approved for the skill. connect needs
to fetch vendor docs when the model's memory is uncertain, but an LLM
fetching attacker-controlled content is a textbook prompt-injection
vector, and blanket approval would pre-authorize every fetch. Leaving it
unlisted means each call falls through to the maintainer's permission
settings and prompts interactively with the URL visible — cheap friction
for the legitimate path, no blind fetches. A per-domain allowlist was
considered and rejected (unmaintainable across vendors, no coverage for
first-party systems).

---

## 12. Model and cost

connect is a maintainer skill invoked in a normal session, so — unlike
v3, which pinned the skill to Sonnet in frontmatter — it carries no
`model:` pin: it runs on whatever model the maintainer's session uses,
and a pin would be ignored for an in-conversation Skill anyway. The
field-model probe (§8) is the one place a specific model matters, and it
deliberately uses Haiku via `Task` to match the runtime gather subagent.

---

## 13. Relationship to other surfaces

| Surface | Relationship |
|---|---|
| `defender/docs/` + `skills/handbook/` | Source of truth for file shapes and runtime rules. connect reads them on demand; does not duplicate. |
| Offline lead-author (`learning/lead_author.py`) | Grows the query catalog connect seeds, from real runs. connect writes a couple of templates; the lead-author writes the rest. |
| Learning loop (`learning/author.py`, lessons) | Sibling, post-merge. Writes `lessons/`; connect never does. |
| Runtime loop (`run.py` → `defender/SKILL.md`) | Consumer of connect's output. The investigation loop dispatches the adapter and reads the per-system skill. connect never invokes it. |

---

## 14. Open questions

1. **Adapter contract-compliance tests.** Generated adapters should have
   a generic test (does `--raw` emit valid JSON? does `health-check`
   exit `0`/`2` correctly?), parameterized over every file in
   `scripts/tools/`. Not built yet.
2. **Re-connect / update flow.** Re-running connect on an existing
   adapter should offer update/diff/keep/replace; today it only confirms
   before touching (Phase 0). A regenerate would clobber hand edits —
   needs a real UX.
3. **Aggregate health roll-up.** Defender dropped v3's `preflight.py`.
   If "is the whole environment reachable?" becomes a recurring question,
   a script that walks every `bin/defender-*` `health-check` is the
   natural shape. Deferred until a case demands it.
4. **Config format.** `config.env` is flat key=value. If adapter config
   grows (multi-instance, per-instance index maps), consider a sidecar
   JSON file rather than stretching env-style.
5. **Instance naming.** connect assumes one instance per system.
   Multi-instance (prod + audit) needs a suffix convention
   (`splunk_prod`). Not handled yet.
6. **Verifying a configured MCP server.** For the MCP path, connect notes
   tool names but can't verify the server is actually loaded in the
   maintainer's config — needs an API defender doesn't have.
