# Phase C′ — dissolve (step 5)

## Topology

- **One dissolve leaf** (Opus, xhigh effort), after the judge and before §7. Inputs: the project's principles document (the profile's `conventions.principles` points to it) plus the design doc's principles section, the intent and design sections, `45-dispositions.md`, `44-probes.md`, `10-brief.md`, `20-demands.md`. Output: `47-dissolve.md`.
- Skipped (recorded in `handoff.deviations`) when the judge reports two or fewer material clusters — there is nothing to group.
- Re-run after an amendment only if the re-judge leaves new material clusters.
- The orchestrator reads the frontier's `## Tensions`, `## Outside the principles`, and `## Remaining forks` in full: they are what §7 relays.

The phase exists because of what the runs measured: the human's most consequential rulings came from rejecting a batch of forks and asking "what is the root cause — is there a design call that dissolves these rather than patches them?", and how much of the batch the project's principles actually called for. Each time, most of the batch shared one or two causes, and one design call made the forks disappear. This leaf asks that question first, so the human rules on causes instead of symptoms.

## Charge — the dissolve leaf

You **propose; you never dispose.** Every ruling is the human's. Your output is a better question, not an answer.

Read the principles first and hold them as the yardstick — they are the project's, not this workflow's; apply what they say, and nothing they don't. Then read the material clusters in `45-dispositions.md`.

**1. Find the root causes.** For each material cluster ask *why does this decision exist at all?* — which mechanism, data-model choice, shared location, or tolerance in the design creates it. Group clusters that share a cause. A cause shared by several clusters is a **tension**. Typical shapes: two owners for one path; state living where a less-trusted party can write it; a per-item layout that makes every item a lifecycle; a conversion or migration that must handle the old shape; handling for a condition the principles say not to handle.

**2. Propose the dissolving design call** for each tension: the change to the design that makes the cluster's forks stop being questions — not a pick among their readings. State, per tension:
- the cause, in one sentence, and the clusters it produces;
- the proposed call, and the principle it rests on;
- what it dissolves (cluster ids) and what it changes in the design (mechanisms, data model, obligations narrowed or removed);
- what it costs — what the code must then carry, what it forecloses, any obligation it would drop;
- the reading-by-reading alternative, for a human who keeps the design.

Ground every claim about today's code in the brief, the ledger, or `44-probes.md`; a proposal resting on an unprobed fact lists it as a probe obligation (`route: re-ground`) for the orchestrator to settle before §7. When a cluster has no cause beyond the doc's silence, say so — it stays a fork.

**3. Mark what is outside the principles.** Start from the judge's `outside-principles` flags and add what it missed: list the forks (any grade) that exist only to serve something the principles reject or don't require. Each with the principle it falls outside and what dropping it means (a `rejected:` non-obligation). The human confirms or keeps them in one question.

**4. List what remains** — material clusters no tension dissolves, unchanged from the judge's relay (cluster id and one line each; the judge's fork section carries the detail).

Write each tension for a cold relay to the human: they will read it in an AskUserQuestion option, so lead with the consequence, not the mechanism. Order tensions by how many material clusters each dissolves. Digest: tensions found, clusters dissolved if every proposal were adopted, outside-the-principles count, remaining material count.
