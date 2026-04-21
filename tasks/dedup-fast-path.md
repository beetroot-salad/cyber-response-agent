---
title: Re-introduce the CONTEXTUALIZE→CONCLUDE dedup fast-path
status: backlog
groups: orchestrator, product-design
---

## What

The CONTEXTUALIZE handler used to route directly to CONCLUDE when the
ticket-context subagent returned a `dedup_candidate` (a prior ticket from the
same entity tuple in a recent lookback window). The intent: when the same
alert re-fires, reuse the prior investigation's disposition instead of
investigating from scratch.

The path was retired after run #43 (2026-04-21) — see the run's driver.log and
the cost-baseline row in `.claude/skills/testrun/SKILL.md`. The retirement
change drops the `if dedup: return Phase.CONCLUDE` branch in
`handlers/contextualize.py:_route()` and the `dedup → "screen"` mapping in
`handlers/conclude.py:_select_routing_source()`. The ticket-context subagent
still emits `dedup_candidate`; the CONTEXTUALIZE handler payload still carries
`dedup_matched_ticket_id` as telemetry only.

## Why retired

Run #43 hit a 300s timeout in the `conclude` subagent on the dedup path. Root
cause was a broken prompt contract, not the subagent model or timeout:

- The CONTEXTUALIZE→CONCLUDE dedup path dispatches the `conclude` subagent
  with `routing_source=screen` as a stand-in for a real dedup mode.
- The subagent's instructions (`agents/conclude.md`) for
  `routing_source=screen` say "extract `matched_pattern`, `matched_archetype`,
  `matched_ticket_id` from the SCREEN subagent result in investigation.md."
- In the dedup path, no SCREEN ran — investigation.md has only CONTEXTUALIZE.
- The subagent improvised: it hallucinated a SCREEN outcome from the
  archetype-scan output, never consulted the dedup precedent file, and
  produced `matched_archetype: null` / `disposition: inconclusive` after
  ~5 minutes of reasoning — the opposite of what dedup reuse should produce.

So the fast-path's actual behavior was wrong even before the timeout killed
it. A 300s bump would have surfaced `disposition: inconclusive` on what
should have been an instant precedent-reuse.

Secondary reason: cron-fired monitoring probes produce ~20 prior 5710 alerts
in ~3.5h on the playground, so every scenario-A run hit the dedup path and
failed — blocking orchestrator evaluation on the signature.

## Design questions to answer before re-introducing

1. **Mechanical vs subagent.** When a dedup candidate is found, the handler
   can:
   - (a) Read `archetypes/<name>/<dedup_id>.json` directly and copy the prior
     disposition / confidence / matched_archetype / trust_anchors_consulted
     into report.md frontmatter + a one-sentence summary. No subagent call.
   - (b) Dispatch a dedicated subagent branch (`routing_source=dedup`) whose
     prompt says "here is the prior precedent; reuse its disposition" and
     cites the dedup target in the trace. Slower but allows Tier-2 judge
     coverage.
   Lean mechanical (a) unless there's a quality reason to keep a judge loop
   on the reuse path.
2. **Ticket-context cadence.** How wide should the lookback be? The current
   subagent returns any prior 5710 from the same (srcip, srcuser) — that
   catches burst repeats but also catches cron probes an analyst hasn't
   resolved. Dedup should match against *resolved* prior tickets with the
   same archetype, not any prior alert.
3. **Precedent file shape.** The prior ticket's JSON under
   `archetypes/<name>/<id>.json` has `disposition`, `confidence`,
   `matched_archetype` — does it also need `trust_anchors_consulted`,
   `trace`, `summary` to fully mechanical-compose a report.md? Check which
   precedent files today carry those fields; the dedup path may need a
   precedent-snapshot schema upgrade.
4. **Archetype-directory resolution.** The dedup candidate's ticket ID is
   emitted without the archetype directory context. The mechanical path
   needs to find `archetypes/*/` that contains `<ticket_id>.json` — either
   by scanning all archetype dirs or by augmenting the ticket-context output
   to include the archetype name.
5. **Invalidation.** If the prior ticket's disposition was `escalated` or
   `inconclusive`, dedup reuse is inappropriate — you'd propagate an
   unresolved disposition. The dedup path should skip unless the precedent
   is `resolved`.
6. **Analyst-visible trace.** The report.md for a dedup-resolved ticket
   should clearly state "this alert was deduped against ticket X" — not hide
   the reuse. Otherwise analysts see a disposition with no visible
   investigation work.

## Testing gaps (part of the infra dependency)

- The Wazuh playground conflates "repeating probe" with "matches prior
  disposition" — the monitoring-host cron fires every ~10 minutes, so prior
  tickets always exist for scenario A, but there's no reliable way to produce
  a "new alert that matches a resolved prior ticket's disposition" fixture.
- Scenario B (bait burst) produces a new shape, so dedup shouldn't fire
  there — but the current ticket-context lookback catches both.
- Need: a way to seed a resolved precedent snapshot into
  `archetypes/<name>/*.json`, trigger a matching alert, and verify the
  handler reads the right file and produces the expected frontmatter. This
  is a harness-level capability that doesn't exist today.

## Re-introduction criteria

Do not re-enable the dedup branch until all of:
- Design decisions 1–6 above are answered (in a design doc or PR
  description).
- A test fixture exists (mechanical or fake-subagent) that exercises the
  dedup path end-to-end without requiring a live Wazuh playground run.
- The `conclude` subagent prompt has an explicit `routing_source=dedup`
  branch (if path (b)) or the handler has a mechanical dedup-compose
  function (if path (a)).
- An eval run on 5710 with a seeded precedent shows dedup reuse
  producing a correct resolved/benign/high outcome in <60s wall clock
  (not a 300s timeout).
