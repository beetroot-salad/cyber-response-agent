# Investigation Review and Learning Loop

## Status

**Implementation cache; code wins on conflict.** The loop described
here exists under `defender/learning/` as orchestrator (`loop.py`) →
actor (`actor.md`) → telemetry oracle (`footprint.md` → `_oracle_router.py`) → judge
(`judge.md`) → author (`author.md`/`author.py`) with a per-lesson
forward-check gate (`verify_forward.{md,py}`) → lessons corpus
(`defender/lessons/*.md`). This doc is not the source of truth, but it
should track the implementation closely enough that a reader can
orient without reopening every file.

This document describes an **offline learning mechanism** that mines completed
investigations for reusable lessons and writes them into
`defender/lessons/*.md`. The current implementation commits lesson edits
locally; PR wrapping and CI review remain design/deferred work. The loop is
not a real-time guard.

The live investigation path is unchanged: a single investigator. A same-context
self-evaluation loop is described below as a future enhancement, not as a
current runtime stage.

The previous version of this doc bundled live review and cross-case learning
together and proposed a heavyweight schema (multi-axis subjective rewards,
canonical taxonomy, anti-scope fields, addendum library, retrieval algorithm).
That scope was wrong for where we are. This version replaces it with a much
lighter artifact pipeline and a checked-in lessons corpus.

## Inspirations

The defender + learning-loop architecture is closer in spirit to
classical ML training regimes than to "an LLM agent with a better
prompt." It helps to read the components through that lens — both
because the analogies suggest concrete techniques to import, and
because they flag known failure modes early.

**Reinforcement learning.** The runtime defender is the *policy*. Its
trajectory through ORIENT → PLAN → GATHER → ANALYZE → REPORT is an
*episode*. The judge's outcome (`caught | survived | undecidable | ...`)
is a sparse, per-episode *reward signal* — and like all sparse rewards,
it's hard to credit-assign back to the specific decision that earned it.
The lessons corpus is a low-bandwidth *policy update*: instead of
gradient steps on weights, we get curated text injected at PLAN time.
Things to borrow from RL practice:

- *Reward shaping over outcome-only rewards.* The judge's findings are
  intermediate signal — "this lead set missed authorization
  context" — that we credit-assign by hand into a lesson. Without it,
  we'd be trying to learn from `caught/survived` alone, which is
  exactly the regime RL practitioners avoid when they can.
- *Off-policy replay.* The actor + telemetry oracle let us evaluate
  counterfactuals against a completed run without re-executing the
  defender. Each real run amortizes into many synthetic adversarial
  evaluations.
- *Distribution shift.* Lessons authored from yesterday's cases bias
  the policy on today's cases. The same drift pathology that haunts
  offline-RL haunts us — keep an eye on whether lessons that helped
  on past fixtures hurt on new ones, and prefer a held-out eval set
  the curator has never seen.
- *Reward hacking.* If the judge's outcome rubric has a loophole, the
  defender will find it. The forward-check gate
  (`verify_forward.{md,py}`) is the structural answer for promotion:
  a candidate lesson has to keep the source case on its ground-truth
  disposition before it is committed. The judge's prompt is part of
  the reward function and should be audited as such.

**Evolutionary / population-based methods.** The lessons corpus is a
*population* of candidate behaviors. Authoring a new lesson is
*mutation*; the curator's merge / supersede / skip decisions are
*selection*. The defender at runtime samples from this population
(reads the lesson bodies whose descriptions look relevant). Things
to borrow:

- *Diversity matters.* A monoculture of similar lessons covers one
  failure mode well and misses the rest. The curator's job is partly
  diversity preservation — supersede when a new lesson genuinely
  obsoletes an old one, otherwise keep both.
- *Niching by relevance description.* Lessons compete for PLAN-time
  attention. The frontmatter `description` is the niche tag — the
  defender only reads the body if the description fires on the
  current alert shape. This makes the corpus scale sublinearly with
  size, but only if descriptions are crisp.
- *Fitness ≠ proxy fitness.* The proxy fitness we optimize is "judge
  outcome on synthetic adversarial cases." True fitness is "triage
  quality on real production alerts." Periodically sanity-check that
  the proxy still tracks.

**Self-play and curriculum.** The actor is adversarial against the
defender's *prior* runs. As the defender improves (lessons accumulate),
the actor's job gets harder — the surviving stories have to slip
through tighter lead sets. This is a form of *autocurriculum*. The
risk: if the actor gets stuck producing the same shape of attack, the
defender overfits to that shape. Watch for actor-story diversity.

**Where the analogy breaks.** We are not running gradient descent.
There is no continuous parameter space, no smooth loss surface, no
guarantee that "more lessons" monotonically improves anything. The
update mechanism is text edits curated by an LLM, with all the
discontinuity that implies. Expect non-monotonic improvement and
budget for regression-detection accordingly.

## References

- Sutton & Barto, *Reinforcement Learning: An Introduction* — for the
  policy / reward / credit-assignment vocabulary used above.
- Lehman & Stanley, *Abandoning Objectives: Evolution Through the
  Search for Novelty Alone* — the diversity-preservation argument.
- Silver et al., self-play in AlphaGo / AlphaZero — actor-vs-prior-defender
  is a coarse cousin of self-play.
- Sculley et al., *Hidden Technical Debt in Machine Learning Systems* —
  for the failure modes of feedback loops in production ML; many
  apply once a lesson corpus starts feeding back into the runtime.

## Purpose

Improve investigation **correctness and efficiency** by sampling a
counterfactual adversarial actor against completed cases and converting
judge findings into compact pitfall lessons.

The implemented mode is **gray-box adversarial-defender**: could a competent
adversary have survived this exact lead sequence, and what defender pitfall did
that encounter expose? Benign-defender review and live self-evaluation remain
future enhancements.

## Design Principles

1. **Offline only.** No live latency cost. No production gating.
2. **One encounter outcome.** The judge emits one outcome keyword
   (`caught | survived | undecidable | incoherent | skip-passthrough`) plus
   a small set of grounded findings. There is no additive scoring model.
3. **Concrete observables only.** A lesson must name a specific field,
   artifact, system-of-record query, or analysis discipline failure. Abstract
   advice is rejected by the author or forward-check gate.
4. **Git history as the audit trail.** The author edits only
   `defender/lessons/*.md`, commits those edits, and rotates the queue
   atomically. PR review can wrap that flow later, but it is not in the
   current scripts.
5. **No addendum library, no retrieval engine, no taxonomy.** The lesson
   corpus is flat markdown. Runtime retrieval is the defender PLAN step:
   enumerate frontmatter and read bodies whose descriptions look relevant.

## Loop Shape

```text
Completed run dir
(alert.json + investigation.md + report.md + lead_sequence.yaml + gather_raw/)
        │
        ▼
defender/learning/loop.py <run_dir>
        │
        ├── normalize disposition from report.md
        ├── project actor_input.yaml
        ├── actor_story.md (or SKIP)
        ├── projected_telemetry.yaml from telemetry oracle
        ├── judge_findings.yaml from judge
        ├── persist under defender/learning/runs/<run_id>/
        └── append queueable findings to defender/learning/_pending/findings.jsonl
                       │
                       ▼
defender/learning/author.py (when threshold is reached)
        │
        ├── lock + clean-scope + idempotency + ground-truth gates
        ├── new/fold/skip lesson edits under defender/lessons/
        ├── verify_forward.py per candidate edit
        └── commit lesson edits + rotate queue / hold findings
```

## Adversarial-Defender Mode

### Goal

The adversary's objective is to pass as benign through the actual lead
sequence the investigator pursued. The defender's objective is for the lead
sequence to break the adversary's story.

### Implemented Variant

Only **gray-box: query-only reveal** is implemented. The actor sees
`alert.json` plus the ordered lead projection containing only
`position` and `queries[].id` / `queries[].params`. It does not see lead
descriptions, result references, or investigation results. It emits either a
plain-markdown attack story (`Attack story`, `Goal`, `Bypass`) or a single
`SKIP:` line.

The actor does **not** self-reflect after results are revealed. The telemetry
oracle translates the actor story into per-lead projected events, and the judge
does the projected-vs-actual comparison. Direct-review and black-box variants
remain design ideas, not current code paths.

### Lead set projection

The "lead set" is the ordered set of defender→gather dispatches used in
the investigation, not a loose prose summary of what the investigator did.
Each entry pairs the free-form lead description the defender sent gather
(goal + what to characterize) with the **queries** gather actually ran.
The cross-case join key is `(query.id, query.params)` — not a lead slug.
The defender does not pick from a slugged lead catalog; gather picks (or
authors) a query template per dispatch, and the template id is what makes
a lead addressable across cases.

The source run materializes that ordered contract as:

```yaml
case_id: <run id>
alert_ref: alert.json
entries:
  - position: 0
    lead_description:
      goal: <defender's measurement contract>
      what_to_summarize:
        - <dimension the gather result must characterize>
    queries:
      - id: <system-prefixed kebab, e.g. wazuh.auth-events>
        params: {<param>: <bound value>}
    result_ref: <gather_raw/{position}.json>
```

`defender/scripts/project_lead_sequence.py` is the canonical projector. It
parses `:L findings` rows from `investigation.md`, requires `system` and
`template` cells, derives `queries[].id` as `{system}.{template}` (or
`ad-hoc`), parses bound params from the `query` and `window` cells, and writes
`lead_sequence.yaml` back into the source run dir. If a
`gather_raw/{position}.lead.json` sidecar exists, its `goal` and
`what_to_summarize` fill `lead_description`; otherwise the projector falls
back to the `:L` row name and an empty dimension list.

The schema allows multiple `queries[]` entries per lead position, but the
current projector emits one query per parsed `:L` row. Templates authored
during a run are written back to the per-system catalog
(`defender/skills/gather/queries/{system}/`), so the catalog grows organically
with usage; early near-duplicates are accepted and normalized downstream when
patterns stabilize.

For gray-box adversarial runs, the actor sees `alert.json` plus an
**answer-and-intent-redacted** projection of the lead sequence:

```yaml
case_id: <run id>
alert_ref: alert.json
entries:
  - position: 0
    queries:
      - id: wazuh.auth-events
        params: {srcip: 172.22.0.10, window: 7d}
```

This projection is emitted as
`defender/learning/runs/<run_id>/actor_input.yaml`. It discards
`lead_description` and `result_ref` at projection time. If the dispatch
contract cannot be projected cleanly, the learning run is rejected rather than
asking the actor to infer the lead set from prose.

### Artifact Schemas

The current implementation uses three model-authored artifacts, not a single
`adversarial_run` record.

**Actor output** (`actor_story.md`) is plain markdown with exactly three
numbered sections (`Attack story`, `Goal`, `Bypass`) or a single `SKIP:` line.

**Oracle** is two-stage — generation and coverage-matching are decoupled so
the matching can be deterministic:

- **Stage A — footprint** (`footprint.md`, LLM). Sees only the alert + actor
  story (no leads), and enumerates the events the activity writes into telemetry,
  each with its *true native attributes* (`data_source`, `host`, `container_id`,
  `source_ip`, `rule`, `when`, …). With no leads in view there is no per-lead
  generation pressure, so nothing to overload.
- **Stage B — router** (`_oracle_router.py`, deterministic). Places each
  footprint event under the lead positions whose query it satisfies, by plain
  containment over each query's structured `filters` block (`index`, `window`,
  locator `predicates`). No query-language parsing: the filters are recovered
  upstream (`scripts/lead_filters.py`) from the template that produced each query,
  so routing is vendor-neutral.

**Oracle output** (`projected_telemetry.yaml`) is a single YAML document:

```yaml
projections:
  - position: 0
    events:
      - {data_source: "logs-falco.alerts", container_id: "ffbff…", rule: "…", when: "…"}
  - position: 1
    events: []
uncovered:                 # footprint events no lead's filter caught — the
  - {data_source: "logs-system.syslog", note: "authorized_keys write"}   # mechanical coverage-gap signal
unrouted_leads:            # positions with no structured filter (ad-hoc / un-promoted
  - {position: 2, queries: [{id: elastic.some-coined-id, params: {…}}]}  # template); judge assesses from raw query
```

Placement is by containment, so an out-of-envelope event (a sidecar's *different*
container id) lands in `uncovered`, never overloaded into the nearest lead. The
judge reads `uncovered` as a `lead-set` / `no-lead-exists` survival signal, modulo
the `unrouted_leads` it must check by hand.

**Judge output** (`judge_findings.yaml`) is a single YAML document:

```yaml
outcome: |
  caught | survived | undecidable | incoherent | skip-passthrough
  <short rationale>
encounter_analysis: |
  <lead-by-lead projected-vs-actual analysis>
defender_findings:
  - type: lead-set | lead-quality | analyze-discipline | observability | detection-confirmed
    subject: <specific lead position, no-lead gap, or system path>
    finding: |
      <grounded finding>
    citations:
      - {source: investigation | actor | alert | projected_telemetry, quote: "<verbatim span>"}
actor_observations:
  - type: misprediction | framing-choice | discarded-class
    subject: <story aspect>
    observation: |
      <optional actor-side note>
confidence: |
  <short confidence note>
```

`actor_observations` is optional and is not queued into the defender lesson
corpus today. `detection-confirmed` findings are retained in
`judge_findings.yaml` but filtered out of `_pending/findings.jsonl` as
audit-only. Queueable finding types are `lead-set`, `lead-quality`,
`analyze-discipline`, and `observability`.

## Lesson Delivery

### Pipeline

1. **Run** — `defender/learning/loop.py <run_dir>` handles one completed case.
   It persists artifacts under `defender/learning/runs/<run_id>/` and appends
   queueable judge findings as JSONL to
   `defender/learning/_pending/findings.jsonl`.
2. **Threshold** — when pending count reaches `LEARNING_AUTHOR_THRESHOLD`
   (default 5), `loop.py` calls `author.run_batch()`. `author.py` can also be
   run directly.
3. **Pre-flight** — `author.py` takes `_pending/.lock`, requires
   `defender/lessons/` to be git-clean, filters already-authored findings via
   lesson `source_finding_ids`, and holds findings whose source disposition is
   not `benign` (currently `inconclusive` or missing ground truth).
4. **Author agent** — `author.md` receives the remaining findings, enumerates
   existing `defender/lessons/*.md`, and decides `new`, `fold`, or `skip`.
   Lesson files are flat markdown with frontmatter: `name`, `description`,
   `source_finding_ids`, `created_at`.
5. **Forward-check** — after each new or folded lesson edit, the author runs
   `verify_forward.py <lesson_path> <run_id>`. `GOOD` keeps the edit; `BAD`
   reverts it and leaves the finding held for later review.
6. **Commit + post-flight** — the author commits lesson edits if any survived.
   `author.py` verifies that the claimed `commit_sha` is HEAD, that HEAD
   touches only `defender/lessons/*.md`, and that the lessons dir is clean.
   Then it atomically rotates `_pending/findings.jsonl`, appends consumed
   findings to `_pending/consumed.jsonl`, and logs no-commit held/skip batches
   to `_pending/held_report.log`.

### Why Lessons, Not an Addendum Library

- Git history is the audit trail. No separate `runs/_lessons/lessons.yaml` to
  maintain.
- Lessons land in the same `defender/lessons/` corpus the runtime investigator
  already reads at PLAN time. No retrieval service, no prompt projection, no
  sidecar taxonomy.
- A future PR wrapper can review the committed lesson diff and add CI replay
  before merge, but the current local transaction is intentionally smaller.

### Citation requirement

Each judge finding carries `citations`, each a `{source, quote}` pair with
`source ∈ {investigation, actor, alert, projected_telemetry}`. The author can
rewrite the lesson for future use, but should not invent evidence. The durable
lesson-to-source link is the `source_finding_ids` frontmatter list plus the
consumed queue record.

## Sampling Policy

There is no scheduler or sampling layer today. The API is manual:
`defender/learning/loop.py <run_dir>`.

Current disposition behavior:

- The disposition selects which direction(s) run through actor/oracle/judge:
  `benign` → adversarial only (FN hunt), `malicious` → benign only (FP hunt),
  `inconclusive` → both. (`_loop_orchestrate.py` `_directions_for`, gating on
  `ADVERSARIAL_DISPOSITIONS` / `BENIGN_DISPOSITIONS` in `_loop_config.py`.)
- Author promotion only proceeds for findings whose source disposition is
  `benign`; `inconclusive` findings are held as no-ground-truth because the
  forward-check gate needs a ground-truth disposition.

The older counter-disposition/random-bucket policy remains a future sampling
design, not current behavior.

## Run Artifacts

```text
defender/learning/runs/{run_id}/
  alert.json                  # copied from source run
  report.md                   # copied from source run
  investigation.md            # copied from source run
  lead_sequence.yaml          # copied after projection
  actor_input.yaml            # redacted actor-facing lead sequence
  actor_story.md              # actor markdown or SKIP line
  projected_telemetry.yaml    # oracle output, absent on actor SKIP
  projected_telemetry.raw.txt # optional raw fenced/bad oracle output
  judge_findings.yaml         # judge output, absent on actor SKIP
  judge_findings.raw.txt      # optional raw fenced/bad judge output
  source_refs.yaml            # source paths, normalized_disposition, alert_rule_key

defender/learning/_pending/
  findings.jsonl              # queueable findings
  consumed.jsonl              # consumed committed/idempotent/skipped findings
  held_report.log             # no-commit held/skip summaries

defender/lessons/
  *.md                        # committed pitfall lessons read at PLAN time
```

The source run dir also contains or receives `lead_sequence.yaml`; the loop
copies canonical artifacts into `defender/learning/runs/<run_id>/`.

## MVP

Implemented:

1. Lead-sequence projection from defender run artifacts.
2. Gray-box adversarial actor.
3. Telemetry oracle with schema-only exemplar redaction.
4. Judge output validation and queueable finding extraction.
5. Pending JSONL queue, consumed queue, held-report surface.
6. Lesson author with clean-scope/idempotency/ground-truth gates.
7. Per-lesson forward-check gate before commit.
8. Flat `defender/lessons/*.md` corpus and PLAN-time retrieval contract.

Deferred:

1. Benign-defender mode and live self-evaluation / self-review loop.
2. Scheduling and statistical sampling policy.
3. PR wrapper and automatic CI gating.
4. Holdout replay / inverse-failure measurement.
5. Actor-side learning corpus.

## Evaluation

- **Queue yield**: findings appended per run, by `outcome` and finding `type`.
- **Detection-confirmed audit rate**: caught encounters that produced
  audit-only `detection-confirmed` findings but no queued lesson.
- **Citation validity**: fraction of finding `citations` whose quotes resolve
  to the claimed artifact and support the finding.
- **Forward-check pass rate**: candidate lesson edits marked `GOOD` vs `BAD`
  by `verify_forward.py`, with manual review of BAD holds.
- **Author disposition**: committed vs folded vs skipped vs held-forward-bad vs
  held-no-ground-truth.
- **Inverse failure (deferred)**: replay merged lesson commits against a
  held-out fixture set; measure correct-disposition runs that the lesson would
  have made worse.

## Future Enhancements

### Benign-defender mode

Benign-defender remains a useful design idea but is **not implemented**. There
is no benign actor prompt, no `benign_run` schema, and no current sampling
path that routes malicious cases to a benign-mode reviewer.

The mental model:

> The defender calls the operator (or the service-account owner). The operator
> answers, then washes them: "you could have verified this yourself by doing
> XYZ." XYZ is a concrete query against a system of record.

If built, this mode should name a query against an actual system of record
present in the environment. "The operator would have told you" without a
system query should remain rejected as post-hoc rationalization. The useful
reward signal is whether the minimum resolving query was already present in
the lead set, and if so whether it appeared early enough to avoid unnecessary
work.

### Live self-evaluation loop

The live investigator may eventually run a same-context self-review before
commit that asks: "what counter-disposition story explains the same
observations, and is there one cheap missing check?" This is separate from the
offline learning loop. Offline learning should continue to run against the
investigation as it actually happened, regardless of whether live
self-evaluation fired.

Keep this future loop small: it should surface a missing check or force an
escalation when the case is underdetermined, not become a second full
investigator or a source of post-hoc rationalization.

### Learning actor (true co-evolution)

Today's autocurriculum is **one-sided**: the defender accumulates
lessons and improves; the actor is a fixed prompt. Over time, this
biases the corpus toward defending against whatever attack shapes the
current actor prompt happens to generate well. Failure modes the
actor doesn't think to write — novel pivots, environment-specific
abuse paths, attack chains the prompt under-samples — never enter the
training signal.

A **learning actor** mirrors the defender's improvement mechanism on
the adversarial side: a corpus of attack-pattern lessons (or
exemplars) the actor reads when generating counterfactual stories,
authored from cases where the actor *failed* to slip past the
defender's lead set or where the judge marked the story `incoherent`.

Sketch of the loop, symmetric to the defender's:

- **Signal source.** Cases where the actor's story was `caught` by
  the defender's existing leads, *or* cases the actor `SKIP`-ed when
  in fact a competent adversary could have produced a survivable
  story (the latter requires a separate "missed-skip" detector —
  potentially the judge itself, given the run + the SKIP rationale).
- **Curator.** A counterpart to `author.py` that folds these into
  attack-pattern lessons under (e.g.) `defender/learning/actor_lessons/`.
- **Retrieval.** The actor enumerates lesson frontmatter at
  story-generation time, same shape as the defender's PLAN-time
  retrieval; loads bodies whose description fires on the alert
  surface.
- **Diversity guard.** Critical here — a monoculture of attack
  patterns is exactly the failure mode this enhancement is supposed
  to fix. The curator must enforce niching across (TTP, target
  surface, pivot mechanism), and the eval harness should track
  actor-story diversity as a first-class metric.

This gets us closer to genuine self-play: each side's lessons make
the other side's job harder, and the curriculum advances on its own.
Caveats from the RL/evo literature apply double — co-evolution is
notoriously prone to **cycling** (defender learns to beat actor v3,
actor v4 rediscovers v1's tricks), to **arms-race drift** away from
realistic alerts, and to **Red Queen dynamics** where both sides get
more capable on synthetic cases without either gaining on real ones.
Mitigations to design in from day one:

- Hold a fixed set of historical actor stories as a regression suite;
  the live actor must continue to surface them, not just the ones
  the live curator currently rewards.
- Periodically re-run the defender against a *frozen* prior actor to
  detect overfitting to the current one.
- Anchor on real production alerts as ground truth — the proxy
  fitness ("can our actor beat our defender") must continue to track
  true fitness ("does our defender triage real cases correctly").

**Prerequisite.** Don't build this until the one-sided loop is
demonstrably moving the needle on real cases. A learning actor adds
a second moving part to a system whose first moving part isn't yet
proven; debugging compound feedback loops is much harder than
debugging one. Ship the defender-side learning, validate it, then
revisit.

## Open Questions

- Where does shared knowledge live when a lesson recurs across signatures?
  The current answer is still a flat `defender/lessons/` file that broadens
  its `description`; if that becomes too coarse, do we add tags or subdirs?
- Should the lesson-author agent see prior accepted lesson commits as exemplars? If
  yes, how to avoid drift toward a single editing style.
- For benign mode, how strict should "system of record actually queryable"
  be enforced? Hard-fail in the schema, or accept and flag in held metadata /
  future PR wrapper metadata?
