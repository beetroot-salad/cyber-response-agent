# Learning-loop experiments — 2026-05-08 session notes

Companion to `docs/actor-reviewer-learning-loop.md`. Captures the experiments
that drove the v4 environment surface and the architectural reframes that
emerged. Written so a fresh-context session can pick up without rebuilding
the reasoning.

## What was run

Three consecutive experiment loops, ~$3 total spend, ~24 LLM calls.

| Phase | Spend | Trials | Fixtures |
|---|---|---|---|
| Actor exposure 1 (alert-only) | $0.70 | 7 (real ×3, synth ×4) | real-01/02/03 + synth-01/02 |
| Actor exposure 2 (alert + leads, results redacted) | $0.80 | 8 | real-01/02/03 + synth-01-ssh (pilot-02) |
| Judge v1 (5-section prompt, single fixture, N=3) | $0.45 | 3 | synth-01-ssh exp-2 trial-1 |
| Judge v2 (tightened prompt, same input, N=3) | $0.45 | 3 | same |
| Judge v2 on real fixture (N=3) | $0.45 | 3 | real-02 exp-2 trial-1 |

All actor + judge runs landed in `/tmp/actor-exp/`. Pilot-02 defender run on
the synthetic SSH-bastion fixture lives at `/tmp/defender-runs/pilot-02/`
(out-of-tree, gitignored under `defender/run-transcripts/`).

## Empirical insights

### 1. Exposure 2 (gray-box, leads visible) materially beat exposure 1

The synth-01-ssh fixture is tagged with ground-truth `Agent-forwarding
(T1550.001)` as "the real cheap-pivot the defender's 'key exfil is
expensive' argument misses." On this fixture:

- Exposure 1 (alert-only): 0/2 trials surfaced T1550.001. Both went for
  stolen-key + post-config-diff scenarios.
- Exposure 2 (leads visible, results redacted): 2/2 trials independently
  named T1550.001 and proposed the right discriminating query (inbound
  SSH chain at the pivot host).

Mechanism: with the lead sequence visible, the actor identifies what is
*not* probed and reasons backward to "what attack lives in this gap?"
Agent forwarding is the attack class that lives in the gap where the
source's auth state is unverified. Alert-only context has a
domain-knowledge ceiling that exposure 2 broke.

### 2. Actor variance lives in the narrative, not the lesson

Across N=2 trials per fixture at exposure 1+2:

- Different attack stories → same breaking-evidence query, when the alert
  admits multiple plausible attacks.
- Same attack story → same breaking-evidence query, when one attack
  class dominates.

The lesson layer (the breaking-evidence section) is the most stable
output. It's also the most cleanly extractable — every run produced a
`(system, query_template, params, expected_resolution)` tuple. This
shape was emergent, not designed.

### 3. Variance dropped sharply at exposure 2

Trials within a fixture became near-identical at exposure 2. Implication:
N=1 may suffice in production, with N=2 reserved for novel signature
classes.

### 4. Negative-result trust

Real-03 (falco shell) had a discriminating defender lead set. The actor
at exposure 2 reached the defender's same conclusion rather than
fabricating gaps. The "actor hallucinates to look productive" failure
mode did not appear in 23 actor runs.

### 5. Judge variance was a prompt-design problem, not a model problem

Judge v1 produced a 3-way verdict split (reject / merge / revise) on
identical input. The factual analysis converged across all three trials;
the verdicts diverged on a single inferential step (would Wazuh likely
cover a Building-7 wifi endpoint?).

Judge v2 — same model, same trials, same input — collapsed to full
verdict convergence after two prompt fixes:
- Added an `observability-gap` classification (the missing category)
- Split feasibility from decisiveness (the under-specified axis)

This shifts the architectural question from "judges are unreliable, use
N=5 voting" to "tighter prompts buy you single-trial reliability for
many cases." Multi-trial voting can be reserved for low-internal-
consistency cases, not used as the default.

### 6. Judge produces multiple findings per call

Judge v2 trial 3 on real-02 surfaced a separate analyze-discipline
critique (the defender rationalized a 5-username set as confirming a
probe hypothesis when it should have been flagged as anomalous) that
the *actor* never raised. The judge isn't just verifying actor claims;
it's actively extracting additional findings from the investigation
during verification. Schema needs to support 1-N findings per call,
not single verdicts.

### 7. The reformulation pressure converted the judge into a lesson-extractor

Judge v2's §4 was designed as a query-fix mechanism ("if the actor's
query is broken, propose a fix"). In practice it functioned as the
primary lesson-extraction step. All three v2 trials on real-02 produced
deployable reformulations using `host_query` instead of the actor's
infeasible Zabbix-API query. The judge collapses one downstream stage
when it emits a fixed-up query, not just a verdict.

## Architectural reframes during the session

### A. "Paranoia" is the wrong axis

Initial framing: classify findings as paranoia / duplicate / real-gap.

Reframe (driven by the image-tampering critique example): "paranoid"
imports a single-org risk posture into what should be an environment-
aware control evaluation. Real questions:

- What control would close this finding?
- Is that control deployed, deployable, or accepted-as-residual?

The AI-era posture argument: defenders absorb investigation cost,
attackers absorb attack-construction cost. Pushes the right default
toward "surface and consider," not "filter as paranoid."

### B. Judge scaffolds the lesson; it doesn't gate it

Initial framing: actor produces finding → judge votes merge/revise/reject
→ author writes PR. Gate-shaped pipeline.

Reframe: the judge's job is to extract the load-bearing question from
the actor's free-text creative output, verify whether the investigation
answered it, and emit a structured lesson candidate. Verdict labels
become routing metadata, not gates. The actor's job is to produce
attack scenarios that imply concrete checks; if the breaking-evidence
section is lazy, the judge's job is to sharpen it, not score it down.

### C. Two output channels, not one

- **Playbook lessons**: route to playbook PR (or covered-by-control,
  observability-finding, etc.).
- **Actor feedback**: signal back to the actor for self-learning ("your
  query was infeasible — next time check deployed-systems first").

These are distinct. The same judge call produces both.

### D. "Environment.md" duplicates the directory tree

Initial framing: a single `environment.md` summarizing deployed tools /
controls / residuals.

Reframe: the production tree at `soc-agent/knowledge/environment/`
already encodes most of this with the right taxonomy:

| Subtree | Authoritative or cache? |
|---|---|
| `systems/` | Authoritative — deployed tools and how to dispatch |
| `operations/` | Authoritative — trust anchors, "is this sanctioned" |
| `data-sources/` | Index — derives from systems/ |
| `context/` | **Cache** — explicitly framed as fallback |
| `fleet/` | Niche — corpus-derived |

A flat `environment.md` would duplicate the tree's index function.

### E. Most "environment context" is cache

Driven by the user's framing: "172.0.0.10 is a monitoring host" is cache
of past observations; "finance team works late" is cache of `team=finance
| timechart earliest=-30d`; trust anchors are cache of past tickets and
slack. Caches go stale silently. The right architecture is *store the
derivation, cache the result with a freshness timestamp, re-derive
when stale*. This is a separate workstream (the future self-learning
loop) from the actor-reviewer experiment.

### F. v4 is visibility-only

Final scope: the experimental `defender/` architecture owns its own
minimal env surface, scoped to *only* what a human writes fresh on
deploying a new system. Per-system SKILL.md, four fields
(available_queries, gaps, read_guidance, when_to_use). Sibling dir to
`defender/skills/`. No operations/, no context/, no fleet/. Test for
inclusion: would we know this immediately on system deploy? Yes → v4.
Only after the corpus catches up → cache loop.

## Tradeoffs identified

### Actor input shape (raw vs summary vs load-bearing question)

Decision: keep raw actor response as judge input, add explicit
instruction to focus on §4 (breaking-evidence) as the load-bearing
claim. Pre-extraction adds a stage with cost and no clear win at this
scale. Story-level cues sometimes carry weight (Trial 3's
analyze-discipline catch came partly from how the actor framed the
bypass).

### Memory / retrieval shape (open)

Considered:

- **By file path** (current `actor-reviewer-learning-loop.md`): playbook
  is the lesson store. Fails at scale; every signature accretes.
- **By invlang structural key** (`(signature, hypothesis, query.id)`):
  deterministic, debuggable, low overhead. The breaking-evidence
  query already produces these tuples natively. Most plausible bet.
- **By embedding similarity**: powerful but opaque; needs a decision
  about what to embed against. Defer.
- **By skill-style trigger**: agent decides when to consult its own
  training. Probably wrong for this surface.

Decision: deferred. The empirical evidence so far points toward
invlang-keyed retrieval but no end-to-end test exists yet.

### Environment knowledge as cache vs primary

The split between "deployed tools" (primary) and "behavioral
classifications" (cache) maps cleanly onto the existing
`systems/` vs `context/` split in production. v4 honors this split by
including only the primary side. Cache surface deferred to the future
self-learning loop with its own input (corpus of past investigations
+ tickets + slack).

### Single-trial judge vs multi-trial vote

After v2's variance collapse, single-trial looks viable for many cases.
Multi-trial voting becomes targeted ("when judge's internal sections
disagree, run N=3 and arbitrate"), not the default. Cost shift: from
~$0.45/finding (3-trial vote) toward ~$0.15/finding (single judge with
internal-consistency check). Validate as the loop scales.

## Open questions deferred

1. **End-to-end retrieval pattern.** Invlang-keyed lesson files are the
   leading candidate but unvalidated. Need a small experiment where a
   live investigation loads matching lessons.
2. **Bloat mitigation.** Author-side ideas surfaced (batched author
   every N findings; golden-set replay; dedup against last X edits at
   the same key). Not implemented.
3. **Actor self-learning channel.** Distinct from playbook PRs. Where
   does feedback live? How does the actor consume it next run?
4. **Environment knowledge cache loop.** Mining `context/`-shaped
   classifications and trust-anchor caches from corpus. Separate input
   pipeline from actor-reviewer.
5. **Inverse-failure replay.** Doc's deferred §Evaluation bullet. Without
   it, accepted lessons could quietly regress on unrelated fixtures.
6. **Gather-side learning loop.** Different surface (per-dispatch query
   templates, not per-case investigations). Pilot-02's srcip-binding
   fix is the model. Not part of actor-reviewer scope.

## Direct insights that drove the v4 design

- Per-system SKILL.md, four fields, sibling to `defender/skills/`:
  user's explicit call after walking through the production tree.
- v4 boundary excludes operations/ context/ fleet content: user's
  reframe — those are derivable cache, populated by a future cache
  loop, not primary docs.
- Judge needs the visibility surface to route findings between
  {dispatchable, deployable-but-not-deployed, true observability gap,
  fixture artifact}: empirically established on real-02-exp2-t1, where
  v2 judge collapsed all four into one infeasibility flag.
- Cache-of-derivations framing is load-bearing: classifications,
  trust anchors, control-coverage facts are all derived from corpus
  and become stale silently. Storing them as primary facts creates
  the bloat trap LLMs walk into. v4 stays clean by refusing to
  accept any field that could plausibly be cache.
