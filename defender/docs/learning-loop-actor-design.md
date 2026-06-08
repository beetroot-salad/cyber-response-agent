# Learning-loop actor — design draft (2026-05-08)

Companion to `defender/docs/learning-loop.md` and
`defender/docs/learning-loop-experiments-2026-05-08.md`. Captures the
actor-side decisions taken during design discussion and flags the one
open question that an A/B trial against real fixtures closed.

Status: **design draft, superseded by landed implementation.** The
actor and judge described here exist today as `defender/learning/actor.md`
and `defender/learning/judge.md`. A telemetry-oracle stage
(`defender/learning/oracle.md`) was inserted between them, and a
forward-check gate (`defender/learning/verify_forward.md`) sits
downstream of the judge — neither stage existed in this draft. When
this doc and the code disagree, the code wins. Kept for the
visibility-A/B and role-split reasoning.

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

Synthesized fields (`goal`, `what_to_summarize`) are **not**
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
  actor_output.md         # free-text: three sections (story / goal / bypass), or a single SKIP line
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

### Encounter-first / bidirectional reframe

A second round of review on the gap-detection judge surfaced four
overlapping concerns: (a) the prompt was unidirectional (find playbook
gaps), losing the actor-side signal when the investigation refuted the
story; (b) discriminator-first ordering biased toward `lead-set`
findings and crowded out `analyze-discipline` and `lead-quality` gaps;
(c) emitting a `proposed playbook edit` conflated the judge with the
author; (d) the structured trailer locked enums at N=4 cases.

The judge prompt was rewritten as a bidirectional **encounter
evaluator**:

- §1 Encounter analysis — claim-by-claim, what the lead set
  established about each load-bearing claim in the story.
- §2 Verdict — one of `actor-wins | defender-wins | both-lose |
  observability-gap` (competition outcome, not gap-or-not).
- §3 Lessons — structured prose claims with side ∈ {defender, actor,
  environment} and type ∈ {lead-set, lead-quality, analyze-discipline,
  detection-confirmed, observability}. Multiple lessons per encounter.
  Lessons are **claims**, not edits — placement is the author stage.
- §4 Confidence.

The structured trailer was dropped: enums are provisional, will
emerge from corpus observation, and an author-stage parser can extract
fields from prose when needed.

### Encounter-first re-run (4 fixtures, N=1, $0.81)

| fixture | verdict | lesson sides |
|---|---|---|
| real-01 | **defender-wins** | 2× actor (l-001 cadence, l-002 fleet-scope refuted) + 1× defender (no asset-registry check) |
| real-02 | **actor-wins**     | 2× defender (l-002 lead-quality, no asset-registry) + 1× actor (l-002 caught fleet-sweep) |
| real-03 | **actor-wins**     | 3× defender (no docker-exec disambiguation, no orchestration-integrity, analyze-discipline on probe-authorization) |
| synth-01-ssh | **actor-wins** | 4× defender (key provenance, l-001 query-scope-vs-stated-goal, ITSM, primary-device concurrent-session) |

**Yield jump: 11 lessons across 4 fixtures**, vs 3 actionable findings
in v1/v2. `defender-wins` shows up as a real outcome (real-01) with
explicit detection-confirmed actor-side lessons — the actor-learning
channel now has a signal that earlier versions collapsed to `reject`.
Encounter-first ordering caught precise lead-quality gaps the
discriminator-first prompt missed (synth-01-ssh's l-001 query-scope
vs stated-goal mismatch). Run dir `/tmp/ab-exp3/`.

**Reframe accepted.** Actor prompt at `defender/learning/actor.md`
(three sections, projected lead_sequence input). Judge prompt at
`defender/learning/judge.md` (encounter-first, bidirectional, lessons
not edits). Projector at `defender/learning/project_lead_sequence.py`.
Ready for the orchestrator stage.

### N=3 variance check (4 fixtures × 3 trials, $2.35)

| fixture | t1 | t2 | t3 |
|---|---|---|---|
| real-01 | actor-wins | actor-wins | actor-wins |
| real-02 | **defender-wins** | actor-wins | actor-wins |
| real-03 | actor-wins | **defender-wins** | actor-wins |
| synth-01-ssh | actor-wins | actor-wins | actor-wins |

36 lessons across 12 trials. Three findings:

1. **Verdict is per-trial, not per-fixture.** Different trials commit
   to different load-bearing claims (real-02 trial 1 = horizontal
   sweep, caught by l-002 → defender-wins; trials 2+3 = host-identity
   exploitation, not caught → actor-wins). Verdict tracks the
   encounter, not the alert. real-01's N=1 defender-wins was a sample,
   not a fixture property.
2. **Lesson cores converge across trials; framings vary.** Every
   real-01 trial hits "source-host identity verification on .10"
   and "ANALYZE inference from behavioral pattern to legitimacy" with
   three different phrasings. Every real-02 trial hits "no
   asset-registry / source-IP-identity-registration check." Strong
   empirical support for the author-stage dedup design: lessons are
   dedupable as claims, not as edits.
3. **N>1 expands coverage on ambiguous fixtures.** synth-01-ssh
   surfaced 9 distinct gaps across 3 trials spanning persistence,
   device identity, ITSM corroboration, primary-device silence,
   ticket-timing correlation. Clear fixtures (real-01, real-02)
   plateau by N=2 on lesson types. Sampling implication: ambiguous
   fixtures justify N>1; clear fixtures plateau quickly.

`defender-wins` rate held: N=1 = 1/4 (25%), N=3 = 2/12 (17%).
Most actor stories survive some aspect of a typical investigation.

### Load-bearing lessons survive the verdict

The most important finding from the N=3 sweep: each fixture has a
structural defender gap that *every* trial hits, regardless of which
verdict that trial produced. Concretely, all 3 trials of each real-*
fixture surfaced the same load-bearing defender lesson:

| fixture | load-bearing gap | t1 | t2 | t3 |
|---|---|---|---|---|
| real-01 | source-host identity verification on .10 | actor-wins ✓ | actor-wins ✓ | actor-wins ✓ |
| real-02 | no asset-registry / CMDB / source-IP-identity check | **def-wins** ✓ | actor-wins ✓ | actor-wins ✓ |
| real-03 | no lead covers orchestration-layer / docker-exec-API integrity | actor-wins ✓ | **def-wins** ✓ | actor-wins ✓ |

The defender-wins trials (real-02 t1, real-03 t2) emitted the
structural defender lesson *alongside* the actor-side
`detection-confirmed` lessons. real-03 t2 produced 4 lessons total:
2× actor (l-001 baseline + l-003 sshd characterization caught the
supply-chain artifact) + 1× defender (orchestration-layer lesson) +
1× defender (analyze-discipline on ORIENT not following up on the
`EXE_WRITABLE` flag).

Two implications:

1. **The judge is not verdict-gated on defender lessons.** A
   defender-wins encounter still produces defender-side lessons when
   the actor's load-bearing claim points at a real gap, even if that
   trial's tactical detail (sweep volume, supply-chain artifact, etc.)
   was caught by the existing leads. The lesson stream is robust to
   actor tactical noise.
2. **Cross-trial dedup is well-defined.** Three trials produce three
   different prose framings of "no source-host identity check"; they
   map cleanly to one lesson with three evidence refs. Strong
   empirical case for the separate author stage owning dedup.

The actor's degrees of freedom (which CVE, which contractor model,
which sweep volume) do not propagate up to the structural-gap layer.
The alert's surface bounds the load-bearing claim; the lessons
converge there even when the actor diverges everywhere else.

## 2026-05-09 — judge schema rev (v3)

The encounter-first judge (v2) produced two structural frictions when
re-run on a live e2e (one Falco rule-100001 alert + one rule-5710
monitoring-probe alert):

- The four-way verdict (`actor-wins | defender-wins | both-lose |
  observability-gap`) hid the most useful output on the 100001 case.
  The defender refuted the *story-level frame* (a 7-day identical
  baseline killed the "fresh first-exec" narrative) but the
  *mechanism-level claim* (Docker socket exec leaves no invoker
  telemetry) survived independently. v2 returned `defender-wins` and
  buried the surviving mechanism as a secondary lesson under a
  side-channel rule. The headline fact — that a tighter actor variant
  mirroring the established command and cadence would slip past the
  same investigation — read as a footnote.
- The §3 lessons block carried a typed `claim:` + `evidence:` pair
  per entry plus its own confidence note plus the §4 verdict-level
  confidence paragraph. Three places to look for whether a finding
  was load-bearing; in practice the judge mostly used §4 and left the
  per-finding fields redundant. There was also no explicit cap, so
  borderline lessons that the judge itself flagged as moderate-
  confidence in §4 still landed in §3.

### v3 changes

The output is now five sections:

1. **Outcome** — replaces verdict. Vocabulary is descriptive of what
   happened to the *story*, not symmetric "who wins": `caught`,
   `survived`, `incoherent`, `undecidable`. The headline can carry
   nuance directly (e.g. "story-level frame caught, mechanism-level
   claim survived") because the field is single-valued by design but
   the rationale paragraph is allowed to state that the picture is
   mixed and which aspects fell on which side.
2. **Encounter analysis** — unchanged in role; aspect-by-aspect walk
   that grounds the findings.
3. **Defender findings (max 3, load-bearing only)** — asymmetric with
   §4. Single NL `finding:` field with quotes embedded inline (claim
   + evidence collapsed). Cap forces prioritization. Outcome→finding
   rules permit residual gaps under `caught` — that license proved
   load-bearing on the e2e re-run, where the rule-5710 case produced
   a `caught` outcome with a still-meaningful lead-set finding about
   a tighter actor variant.
4. **Actor observations (max 2, optional)** — strategy-level notes
   on actor mispredictions, framing choices that crumbled, or
   discarded classes. Asymmetric on purpose: defender findings route
   to the corpus-edit author stage; actor observations are
   observations-only until the actor-learning loop materializes. The
   field name avoids implying a downstream consumer that doesn't
   exist yet.
5. **Confidence** — one paragraph that is allowed to call out
   divergent confidence across findings inline ("high on outcome,
   moderate on the lead-quality finding because…"). Per-finding
   confidence fields are explicitly out — the judge's tendency to
   spread confidence into one paragraph despite the per-finding
   field being available was the empirical signal.

### Motivating result

The same 100001 actor story produced two judges:

| schema | outcome | findings | net |
|---|---|---|---|
| v2  | `defender-wins` | 1 actor (baseline) + 1 defender (residual) | residual gap buried |
| v3  | `survived` | lead-set + observability + detection-confirmed (3) | residual gap is the headline |

On 5710, the same actor story produced:

| schema | outcome | findings |
|---|---|---|
| v2  | `actor-wins` | 3 defender (lead-set ×2 + analyze-discipline) |
| v3  | `caught` | detection-confirmed + lead-set + lead-quality (3) |

The 5710 verdict swing was independent of the schema change — v3's
encounter analysis engaged with a `l-002` observation ("zabbix +
healthcheck within seconds of each other") that v2 had read as
ambiguous and v3 read as structurally inconsistent with the actor's
single-username story. Both reads are defensible; the schema does not
force one. What the schema *did* force was that v3's `caught` outcome
still surfaced a residual lead-set gap (no source-host lead — load-
bearing against a tighter single-username variant), which v2's
`actor-wins` would have made the headline but v2's `defender-wins`
would have buried.

### Locked decisions in v3

- Asymmetric field names (`defender_findings` vs `actor_observations`)
  reflect the asymmetric downstream pipeline; they are not a
  symmetry violation to be resolved later.
- Cap is 2–3 findings, with explicit "skip lesser findings even if
  you spot them" instruction. Empirically the judge stayed at 3 on
  both e2e cases; whether the cap is too generous becomes a
  measurement question once we have more cases.
- Single bottom-level confidence paragraph; per-finding confidence
  fields are not added back without empirical evidence that they
  carry distinct signal.
- Outcome vocabulary is `caught | survived | incoherent | undecidable`.
  `partially_caught` was considered and rejected — the rationale
  paragraph already carries the nuance, and adding a fifth value
  would push the judge to commit to a label that the prose was
  already handling more flexibly.

Lock target unchanged from v2: the prompt iterates until cross-case
variance on a small N is contained and lessons survive ablation;
v3 is the current incumbent against which any future change is
measured.

## Future work pointers
- **Visibility-at-the-judge A/B.** Re-run the A/B variable at the
  judge stage: does the judge produce better-grounded discriminators
  with `defender/skills/{system}/` Visibility surface excerpts in its
  prompt? Hypothesis: yes — the surface is a deployment grounding tool
  by design, and the judge's job *is* deployment grounding. Until this
  A/B runs, `defender/learning/judge.md` treats absence-from-investigation
  as `deployment-unknown`, not `not-deployed`, to avoid prematurely
  routing real lead-set findings to instrumentation backlog.
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
