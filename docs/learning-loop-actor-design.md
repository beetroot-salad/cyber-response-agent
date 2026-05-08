# Learning-loop actor — design draft (2026-05-08)

Companion to `docs/actor-reviewer-learning-loop.md` and
`docs/learning-loop-experiments-2026-05-08.md`. Captures the actor-side
decisions taken during design discussion and flags the one open
question that an A/B trial against real fixtures will close.

Status: **draft, visibility A/B resolved 2026-05-08, role-split
reframe 2026-05-08**. The actor runs blind, produces story-only output
(no defender-side discriminator), and the judge derives the
discriminator. Orchestrator contract, output shape, run-dir layout,
and gray-box reveal are all locked.

## Scope

The adversarial actor is one half of the offline learning loop. It
reads a completed defender investigation and produces a malicious
counterfactual *story* — what end-to-end activity, by what actor,
against what target, would have produced this alert. The actor's job
is purely generative red-teaming.

The judge owns everything downstream: deriving the smallest
discriminating observable from the story, grounding it in a deployed
system-of-record, checking whether the lead sequence already covered
it, and emitting the verdict + structured finding.

This separation — **actor simulates the adversary, judge plays the
blue-team evaluator** — is the proper red/blue split. An earlier draft
asked the actor to also name a "breaking evidence" query that would
refute its own story; that conflated roles (purple-teaming) and was
the load-bearing cause of the visibility-aware failure mode in the
2026-05-08 A/B (see §Resolved). The reframe drops that section.

Out of scope here: judge prompt design, lesson-author / PR pipeline,
sampling policy beyond manual selection, actor self-learning.

Out of scope here: judge prompt design, lesson-author / PR pipeline,
sampling policy beyond manual selection, actor self-learning.

## Locked decisions

### One-shot execution

The actor runs once per case. Lead results are not revealed to it.
"Did the story survive evidence?" is computed by the judge from
`(actor_output, actual lead results)`. Two-phase actor self-reflection
is dropped — it costs ~2× per case for a signal the judge already
produces, and the experiments showed no quality lift.

### Loose-structured output — story only, three sections

The actor emits free-text markdown with three named sections:

1. **Attack story** — concrete causal chain. Who, with what access,
   from where, doing what, against what target. Specific actor model,
   technique IDs where applicable, named tooling.
2. **Goal** — what this operation specifically achieves (credential
   theft / lateral movement to system X / exfil of data class Y /
   persistence mechanism Z), not "compromise the host."
3. **Bypass** — why this story would plausibly survive a competent
   investigation: the structural ambiguity in the alert that makes the
   malicious explanation hard to falsify against the benign one. If
   the story is symmetric with a benign one on the alert alone, say so.

No "breaking evidence" section. The actor does not name queries,
fields, observables-to-check, or refutation paths. Those are blue-team
work and belong to the judge.

The headings are the soft contract the judge keys on. Prose inside is
free. Variance inside the prose is treated as a feature (more samples
of distinct attacker reasoning) rather than noise to suppress.

### Judge owns discriminator + verdict

The judge receives `(alert, lead_sequence, actor_story)` plus
deployment knowledge (visibility surface, environment systems) and
produces:

- the smallest discriminating observable that would refute the story,
  grounded in a deployed system-of-record
- whether the lead sequence already covered that observable
- structured `findings.yaml` per the parent-doc schema
- the verdict (reject / merge / revise / observability-finding / …)

Discriminator derivation lives at the judge because it requires both
the deployment surface (which systems are queryable) and the lead
sequence (what was already done). The actor has neither and shouldn't
have either — the visibility-aware A/B arm proved that giving the
actor deployment knowledge collapses its output onto the existing lead
set.

### Skip marker on opt-out

If the actor cannot construct a plausible malicious story, it emits a
single-line skip marker. The orchestrator records the skip in the run
dir, does not invoke the judge, and does not open a PR.

```
runs/{case_id}/learning/actor_skip.txt   # short rationale
```

### Gray-box reveal — raw query + lead name

The actor sees `alert.json` plus the projected lead sequence. Each
entry exposes:
- `position`
- `lead_name` — the defender's name for the dispatch
- `queries[].id` and `queries[].params` — the raw query, verbatim

Synthesized fields (`goal`, `what_to_characterize`) are **not**
projected. The raw query is the source of truth and avoids the
projection layer leaking results through summary phrasing.
`result_ref` is omitted entirely.

The projector is responsible for redaction-by-construction: if a
projected entry cannot be reduced to `(lead_name, queries)` cleanly,
the case is rejected from the learning run rather than asking the
actor to infer leads from prose.

### Memoryless across cases

The actor sees only the current case. No prior accepted findings, no
peer-actor outputs, no judge feedback from earlier runs. This keeps
samples IID for any future actor-learning workstream.

## Orchestrator contract

A thin Python orchestrator owns prompt assembly, actor invocation,
judge invocation, and run-dir writes. The actor itself is a prompt
file, not a script.

```
python defender/learning/run.py \
    --case <run_id> \
    --mode adversarial \
    [--visibility-aware]
```

Steps:
1. Read `runs/{case_id}/` (alert.json, investigation.md, tool_trace.jsonl).
2. Project `lead_sequence.yaml` (see §Gray-box reveal).
3. Assemble actor prompt from the actor file + projected inputs.
4. Invoke actor (one shot). Write `actor_output.md` or `actor_skip.txt`.
5. Invoke judge (skipped on actor_skip). Write `findings.yaml`.
6. Do **not** open PRs. The lesson-author / PR stage is a separate
   command and remains decoupled so the actor↔judge loop can iterate
   without touching git.

Run-dir layout:

```
runs/{case_id}/learning/
  lead_sequence.yaml      # projected, redacted contracts
  actor_input.md          # the exact prompt the actor saw (reproducibility)
  actor_output.md         # free-text with the four sections
  actor_skip.txt          # alternative to actor_output.md
  findings.yaml           # judge output (omitted on skip)
  judge_input.md          # the exact prompt the judge saw
```

`actor_input.md` is stored alongside the output to give a future
actor-learning workstream a `(input, output, judge_output)` trajectory
triple per case without re-running projection.

### File locations

```
defender/learning/
  run.py                  # orchestrator
  actor.md                # actor prompt (sibling to defender/skills/, defender/agents/)
  judge.md                # judge prompt (locked once visibility A/B settles)
  project_lead_sequence.py  # projector
```

Co-locating with the orchestrator (rather than under
`defender/agents/`) keeps the boundary explicit: this is a learning-
loop component, not a defender phase agent.

## Resolved by 2026-05-08 A/B

### Visibility access — actor runs blind

The A/B (4 fixtures × {blind, aware} × N=1, $1.10 total, judge =
`judge_core_v2`, run artifacts in `/tmp/ab-exp/`) decisively favored
the visibility-blind arm:

| fixture | blind verdict | aware verdict |
|---|---|---|
| real-01 (nagios probe) | **observability-finding** (Nagios-config-on-source) | reject (duplicate of l-001) |
| real-02 (zabbix burst)  | **revise → playbook** (Zabbix item-config check) | reject (duplicate of l-001) |
| real-03 (falco shell)   | reject (duplicate of l-003) | reject (duplicate of l-003) |
| synth-01-ssh (T1550.001) | **revise → playbook** (device-presence reformulation) | reject (verbatim duplicate of l-002) |

**Blind: 3 actionable findings** (2 playbook reformulations + 1
systems-tree onboarding finding) across 4 fixtures.
**Aware: 0 actionable findings** — every aware run produced a
breaking-evidence query that exactly duplicated an existing lead.

### Reframe driven by the A/B

The original A/B was framed as "should the actor see the deployment
surface so its breaking-evidence query is feasible?" Both failure
modes — aware-collapses-to-duplicate, blind-proposes-infeasible — are
downstream of the actor having a §4 *breaking evidence* section at all.

Asking the attacker to name the query that would refute their own
story forces them to reason as a defender. With deployment knowledge,
the actor picks queries that look exactly like the ones the defender
already runs (duplicates). Without deployment knowledge, the actor
picks queries against systems that don't exist (infeasible). Neither
is the right output for a red-team simulator.

The fix is to drop §4 from the actor entirely. Actor outputs an
attack story; judge derives the discriminator. The visibility surface
moves to the **judge**, where it grounds the derivation in deployed
systems. This rebalances the two roles correctly:

- Actor: red team. Tells you what attack could have produced this.
- Judge: blue-team evaluator. Tells you whether the lead set covers
  the smallest test that would catch it.

The 2026-05-08 A/B result still stands as "actor doesn't see
deployment surface," but the *reason* shifts: the actor doesn't pick
queries at all, so the question is moot at the actor stage. A
follow-up A/B (deferred) tests visibility access at the **judge**.

### Reframe validation re-run

Same fixtures, story-only actor (`defender/learning/actor.md`) + judge
that derives the discriminator (`defender/learning/judge.md`,
internally `judge_v3`). Cost $0.76 across 4 actor + 4 judge calls
(run dir `/tmp/ab-exp2/`).

| fixture | v1 blind (old actor + judge_v2) | v2 reframe (story-only + judge_v3) |
|---|---|---|
| real-01 | observability-finding (deploy Nagios FIM on .10) | **merge — lead-quality** (drop `host=` filter on l-001) |
| real-02 | revise → playbook (Zabbix item-config DB) | observability-finding (proc parentage on .10) |
| real-03 | reject (duplicate of l-003) | reject (duplicate of l-003) |
| synth-01-ssh | revise → playbook (device-presence reformulation) | **merge — lead-set** (ITSM ticket-integrity lead) |

Yield preserved (3/4 actionable in both). Verdict quality up: 2 clean
`merge` verdicts in v2 vs 0 in v1 blind. Two qualitative wins:

- **real-01**: judge_v3 derived a better discriminator than the v1
  actor proposed. With no actor query to anchor on, judge looked at
  the story and noticed l-001 already covers the right axis but is
  over-constrained (`host=target-endpoint` blocks fleet-wide
  probe-breadth measurement). One-parameter playbook edit beats v1's
  "deploy new instrumentation" finding.
- **synth-01-ssh**: judge_v3 derived ITSM ticket-integrity audit as the
  discriminator — directly targeting the cover-up mechanism the
  actor's bypass section spotlighted (INC-8821 as misdirection). v1
  went after device-presence reformulation; v2 is more responsive to
  what the story actually claimed.

One regression: real-02 went from playbook-actionable (v1: Zabbix-DB
item-config check) to observability-finding (v2: proc parentage on
the monitoring host, no deployed substitute). Possible causes: judge
under-reaches for non-obvious deployed substitutes; or v1's
reformulation was speculative grounding the new judge correctly
declines. N=1 — undecidable. Worth keeping a watch on as more
fixtures land.

**Reframe accepted.** Actor prompt at `defender/learning/actor.md`
(three sections, no §4). Judge prompt at `defender/learning/judge.md`
(derives discriminator). Both ready for the orchestrator stage.

## Future work pointers

- **Judge prompt revision.** `judge_core_v2` was designed against a
  4-section actor that emitted §4 breaking-evidence. Under the
  reframe the judge no longer receives §4 and must derive the
  discriminator itself. Needs a new prompt revision (call it `judge_v3`)
  that takes `(alert, lead_sequence, story)` and produces
  discriminator + classification + verdict.
- **Visibility-at-the-judge A/B.** Re-run the A/B variable at the
  judge stage: does the judge produce better-grounded reformulations
  with `defender/skills/{system}/` Visibility surface excerpts in its
  prompt? Hypothesis: yes — the surface is a deployment grounding tool
  by design, and the judge's job *is* deployment grounding.
- **Actor learning.** The trajectory triple stored per case
  (`actor_input.md`, `actor_output.md`, `findings.yaml`) is the natural
  RL training surface. Memoryless execution and orchestrator-owned
  prompt assembly preserve sample IID-ness.
- **Multi-trial policy.** Variance is a feature — N>1 produces
  additional independent samples rather than redundant
  re-confirmations. Policy choice (always N=1 vs occasional N=2)
  belongs to the sampling layer, not the actor.
- **Lesson-author / PR pipeline.** Separate command, separate doc.
- **Benign-defender mode.** Out of scope for this draft; same
  orchestrator shell will host it once the adversarial path lands.
