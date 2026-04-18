# Hypothesize subagent — context management probe (v2)

Fresh restart of the hypothesize-subagent extraction pilot. The v1 pilot
lives under `../archive/hypothesize-subagent-pilot-v1/`.

## Goal

Determine what context the HYPOTHESIZE subagent actually needs to produce
a well-formed one-hop hypothesis fork + lead selection. Cheaper context
delivery → smaller window, fewer tokens, faster turnaround.

## Setup

One dummy alert (`fixture/alert.json`) — rule-5710, single attempt, internal
src IP, attempted username `root`. Paired `fixture/investigation.md`
contains CONTEXTUALIZE output (prologue vertices/edges, ticket-context,
archetype scan, ASSESS decision). HYPOTHESIZE is the next phase.

All arms share the same system prompt: the HYPOTHESIZE phase section copied
verbatim from `soc-agent/skills/investigate/SKILL.md` (§HYPOTHESIZE) plus
an instruction to emit the output block and stop. All arms use Sonnet.

Arms differ only in **how much context is pre-loaded vs. fetched by the
subagent**:

| Arm | Delivery | Tools given |
|---|---|---|
| **A — Pointers only** | User message names paths (alert.json, investigation.md, signature knowledge dir). Subagent reads what it decides it needs. | Read |
| **B — Fully inlined** | User message inlines alert JSON, full investigation.md, and all relevant signature knowledge (context.md, playbook.md, all archetype stories). No filesystem access needed. | none |
| **C — Hybrid digest** | User message inlines a compact pre-digest: anchor vertex block, archetype scan YAML (already rendered in investigation.md), playbook hypothesis seeds section only. Pointers for deeper reads if the subagent wants them. | Read |

## Assessment

Manual scoring of each arm's output against:

1. **Well-formed one-hop shape** — each `?hypothesis` names `attached_to_vertex`, proposed edge / parent-vertex classification, 1–2 lean predictions, refutation shape.
2. **Classification coverage** — did the subagent enumerate the plausible upstream parent classifications? (automated / human-authorized / human-unauthorized / adversarial)
3. **Adversarial hypothesis present** — at least one threat hypothesis kept active.
4. **Lead selection quality** — selected lead's outcome actually discriminates across the active hypotheses; dispatch mode (single / composite / primary-deferred) justified.
5. **No umbrellas, no multi-hop narrative** — hypotheses stay lean; refinement deferred.
6. **Pitfalls enumerated** — alert-specific, per-hypothesis.

Plus cost signals: token count (input + output), wall time, number of tool calls.

## Known caveat

Some fixtures and playbooks in the repo still follow the older narrative
hypothesis style. The v2 fixture here is hand-written to match the current
one-hop discipline in `docs/investigation-language.md` §Hypothesis and
SKILL.md §HYPOTHESIZE. Outputs from arms against older fixtures would not be
directly comparable.
