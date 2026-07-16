# Lead-author — learning from failed executions (2026-06-26)

Companion to `defender/docs/lead-author-refinement.md`,
`defender/learning/lead_author.{md,py}`, and the connect skill
(`defender/skills/connect/`). Captures the decision to feed agent-fixable
execution failures back into each system's `execution.md` — the file the
gather subagent reads at dispatch — so a labelled mistake is *prevented*
on its next occurrence, distinct from template curation.

Status: **decision, not yet implemented.** When this doc and the code
disagree, the code wins.

## Premise

**A failed execution is the clearest pitfall signal we get.** It's a
labelled mistake with the intent attached (the lead's `goal` /
`what_to_summarize`) and the system's own diagnosis attached (the stderr
digest). `lead_author.md:91` already calls `payload_status: error` the
strongest fold signal. The whole feature is just making sure the loop
*acts* on that signal instead of dropping it.

## Problem

`record_query` tags every non-zero exit as `payload_status="error"` with
the stderr digest, and `extract()` keeps error rows. But the failures we
most want — a malformed ES|QL pipe, `index:windows` instead of
`index=windows`, a mistyped param — never reach the curator. Two filters
drop them first:

- **Untagged verb → no draft.** A bad pipe runs as
  `query(system="elastic", verb="esql", params={"query": "<bad>"})` with no
  `query_id`, so the row's `query_id` collapses to `elastic.esql` — whose suffix
  IS the recorded verb. `draft_synthesis._draft_candidate_segments` reads a
  suffix-equals-verb id as an untagged call and `synthesize_drafts` skips it — no
  draft minted (the coined-id rule that replaced the old `_NON_CANDIDATE_VERBS`
  set).
- **Unresolved query_id → WARN-and-drop.** With no template and no draft,
  `build_handoff` drops the invocation.

So an `error` invocation only survives when it rode an *already-cataloged*
template. Fresh mistakes fall through — and minting `elastic.esql` from
one is exactly the junk catch-all the verb filter exists to prevent.
There is no template to attach the lesson to.

## Decision

Split **template failures** from **general failures**, routing each to a
home the right reader actually consults.

- **Template failure** (error on a `query_id` that resolves to a catalog
  template): unchanged — folds into that template's `## Pitfalls` (works
  today).
- **General failure** (agent-fixable error on an unresolved/non-candidate
  `query_id`): instead of WARN-and-drop, fold into the system's
  **`execution.md` `## Common pitfalls`** section. The purpose is
  *prevention*, not retrieval — so the entry must be read *before* the
  next attempt, not grepped on demand by an agent that already suspects
  the problem. A general failure is, by definition, a query gather
  *coined* (no template fit; `skills/gather/SKILL.md:46`); that coin
  branch is the one place the mistake is made, so gather Reads
  `execution.md` before coining a no-template query and sees the pitfall
  on the exact path that produced it. One terse entry per pitfall (the
  mistake + the fix), co-located in the relevant existing section (an
  index gotcha under index selection, a pipe gotcha under the ES|QL
  surface) so consulting that surface surfaces it.
- **Infra failure**: ignored. Never a learning candidate, or the agent
  "learns" not to query a system that was merely down.

### The one load-bearing split: agent-fixable vs infra

Excluding infra is the only distinction that *must* be structural, and
the adapter exit codes already draw it — the shared exit taxonomy
(`scripts/adapters/faults.py`, imported by every adapter's `VERBS`
functions): `0` ok · `1` query rejected · `2` unreachable /
misconfigured · `64` bad invocation. The circuit breaker already treats
`{2,124}` as infra and tolerates `{1,64}` (`circuit_breaker.py`), so the
bucket is just *the codes the breaker already forgives*.

**Carry a derived `error_class`, not the raw exit code.** Derive it once,
at the single capture point (`record_query`), into the queries-table row
— `infra` for `{2,124}`, `agent-fixable` otherwise — and have
`ExecutedLead` / `build_handoff` key on *that*, never on exit-code
integers. `ExecutedLead` currently drops `exit_code` entirely
(`lead_author.py:235-249`); it should carry `error_class` instead. This
keeps the cosmetic numbers out of the downstream switch and makes the
feature transport-agnostic (see below).

**The query-vs-usage tag (exit 1 vs 64) is cosmetic.** Code `64` is one
narrow case (CLI misuse); code `1` is many (bad syntax, unknown field,
404, …). The curator reads the stderr digest and infers the mistake class
from context — we don't switch behaviour on it. So the digest carries it;
the structure does not. No need to surface ES's `error.type` or mint a
syntax-specific exit code — that granularity buys nothing the digest
doesn't already give the author.

## Transport boundary

**The implementation reads only the queries/leads tables and is agnostic
to what populated them.** Its entire input surface is two fields off a
queries row — `error_class` (`infra` vs `agent-fixable`) and `query_id`
(resolves to a template or not) — plus the joined lead's `goal`. It never
asks "is this a CLI?", never reads an exit code, a shim name, or anything
transport-shaped.

Transport semantics terminate at **the table writer**. The single capture
point that writes a row (`record_query` today) is the only component that
knows about exit codes; it collapses them into the derived `error_class`
before the row lands. Everything downstream — `ExecutedLead`,
`build_handoff`, the curator — sees only the table.

This is a property of the *contract*, not of the current data. Today CLI
is the only writer, so in practice the feature only ever sees
CLI-sourced failures: MCP is a peer connect path whose calls produce no
queries-table row at all (`decisions.md:57-63`, `mcp.md:33-40`), so MCP
failures simply don't appear until something writes them. The design
doesn't try to close that gap — it just refuses to bake in an assumption
that would *prevent* closing it. When an MCP capture path populates the
same tables with the same `error_class`, the feature inherits it with
zero changes, because it was never transport-aware to begin with. (The
circuit breaker is already "transport-agnostic by design … when adapters
move to MCP servers the same record/trip/kill logic applies" —
`circuit_breaker.py`.)

And the taxonomy stays out of this feature entirely: every connected CLI
inherits the exit codes from the one shared adapter module ("one shared
module per tree, never two" — `cli-adapter.md:38-42`), so a new source
follows the convention for free and the writer — not the consumer — owns
the mapping into `error_class`.

## Resolved design forks

- **Reader = the gather subagent**, not the main agent. Bad ES|QL is
  written during gather; the gather subagent doesn't read the PLAN-time
  lessons corpus. It *does* read `defender/skills/{system}/execution.md`
  → fold the pitfalls there rather than mint a separate `pitfalls.md`.
  No new file type, no grep step, no shim: the corpus rides a file
  already on the dispatch read path. The one required change is the read
  *gate* — today `execution.md` is read "only if you need the index list
  or CLI flags" (`skills/gather/SKILL.md:35`); make it unconditional on
  the coin-a-query branch, where general failures originate. Cost moves
  from grep-precision to context size — entries are read in full, not
  matched — so the growth control below is load-bearing, not optional.
- **Curator = a new *mode* of the lead author**, fed by the
  general-failures bucket, reusing the serial `--author-drain` +
  branch/PR plumbing. Split into its own author later only if the prompt
  gets too dense.
- **Growth control:** reuse the lead author's existing anti-duplication
  bias, and keep entries to one line (mistake + fix). No forward-check —
  these aren't disposition-affecting. Because `execution.md` is read in
  full (not grepped) on the coin branch, a bloated or duplicate-ridden
  pitfalls section is a standing context tax, not just grep noise; the
  curator must prune as aggressively as it appends.

## Staging

1. **Validate the signal.** Derive `error_class` in `record_query`; carry
   it into `ExecutedLead`; in `build_handoff`, stop dropping unresolved
   `agent-fixable` error invocations — collect them into a logged
   general-failures bucket (query/goal/stderr-digest). Ship nothing
   user-facing; measure volume + quality across real runs before building
   the curator.
2. The lead-author curation mode that folds general failures into each
   system's `execution.md` `## Common pitfalls`. No new file type and no
   grep shim — the section rides a file the gather subagent already reads.
3. Make the `execution.md` read unconditional on the coin-a-query branch
   (`skills/gather/SKILL.md:35` → drop the "only if" gate when no template
   fits), so a freshly-folded pitfall is actually read before the next
   coin. This is the one-line change that turns the corpus from written to
   *read*.
