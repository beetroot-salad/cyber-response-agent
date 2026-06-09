---
date: 2026-05-29
branch: defender-v2-env
status: complete (Tier-2 validation deferred)
---

# V2 Noise FP — Lesson Candidates + Authoring Mechanisms

This experiment investigates a single false-positive case observed when
running defender v2 against a benign noise alert in the live playground,
and characterizes (a) which corrective lesson formulations fix the
disposition and (b) which offline-learning authoring mechanisms produce
those lessons.

## Context

**Baseline run** (the FP under investigation):
`/tmp/defender-runs-v2/20260527T150928Z-v2-noise-alert-suspicious-network-tool/`

A Falco alert fired on `nc -z -w1 db-1 22` inside container
`d8fb0192a17f` (uid=1003, no TTY, EXE_LOWER_LAYER). Ground truth: this
is the documented `monitoring-port-probe` baseline-catalog noise pattern
running as `svc.monitoring`, intentionally tuned to fire the
`v2-falco-suspicious-network-tool` rule. Correct disposition: `benign /
high`.

Defender disposition'd `malicious / confidence: medium`. The
investigation built an "attack campaign" narrative around 369 companion
alerts in the broader window — without ever dispatching a lead against
the identity stub or CMDB that would have grounded `svc.monitoring` as
an authorized monitoring service. The legitimacy contract `ac1`
collapsed to `indeterminate → escalate` because the agent pre-judged
that the anchor system "couldn't help".

The two distinct sub-failures identified from the baseline run's
thinking blocks:

1. **Identity discriminator abandoned** — the agent's own loop-1
   thinking explicitly named `uid=1003` as the correct discriminator
   then dismissed the lookup on an assumed tool-input-shape limit
   (event 314: *"the identity tool works with hostnames like web-1 or
   db-1, not container IDs or uids"*).
2. **Volume-as-evidence collapse** — loop-2 PLAN encoded a one-way
   prediction ("companion attack alerts ... would confirm an active
   campaign"). No peer hypothesis whose predictions are satisfied by
   the same observation (mass-identical probes across containers from
   a single monitoring identity).

## Structural fixes applied (pre-experiment)

Committed on `defender-v2-env` (commit `7e12667`):

- Split per-system SKILLs (`identity`, `cmdb`) — moved `## Execution`
  sections to sibling `execution.md` files. Defender reads only
  `SKILL.md` (visibility surface); gather reads both. The split keeps
  tool input-shape claims out of the defender's reading scope, so the
  agent can't pre-judge gather's capability based on knowledge it
  shouldn't have had.
- Added discipline principle to `defender/SKILL.md` about not
  pre-judging unowned-tool input shapes.
- Updated `gather/SKILL.md` to Read both files on dispatch.

This fix is the new baseline. All experiment runs were against this
post-fix codebase.

## Stage A — Lesson candidate sweep

Four candidate lessons authored, each targeting a different upstream
failure point. Each was injected via its own git worktree
(`/workspace/.claude/worktrees/lesson-test-L{1..4}/`) with a single
lesson at `defender/lessons/lesson.md`. Same alert, same code, same
model (Sonnet 4.6).

### Lesson candidates

| ID | Name | Targets |
|---|---|---|
| **L1** | `high-volume-identical-alerts-imply-systemic-origin` | `:H` formation in loop 2: scaffold a systemic-routine peer hypothesis before volume signal lands |
| **L2** | `legitimacy-contract-requires-dispatch-not-assumption` | The `indeterminate→escalate` shortcut — distinguish `unattempted` from `indeterminate` |
| **L3** | `dont-pre-judge-tool-input-shapes` | Defender/gather separation (overlaps with the structural-fix discipline rule) |
| **L4** | `companion-alert-volume-needs-baseline-mapping` | Loop-2 lead structure: ground each companion rule in its baseline noise pattern |

### Stage A results

| Trial | Disposition | Confidence | # leads | Notes |
|---|---|---|---|---|
| Baseline (pre-fix) | malicious | medium | 3 | Original FP |
| **L2 trial 1** | **benign** | **high** | 4 | Cleanest path: host-state + CMDB + identity → monitoring-port-probe catalog match |
| L2 trial 2 (repro) | benign | high | 3 | Container resolved to `web-1`, 354 invocations / 30d |
| L2 trial 3 (repro) | benign | high | 4 | Container resolved to `jump-box-1`, 564 invocations / 48h |
| L1 | inconclusive | medium | 3 | ES tunnel dropped mid-run; could not reach volume discriminator |
| L1 rerun | inconclusive | low | 3 | ES tunnel dropped again; gather had `.claire`/`.claude` path typo |
| L3 | inconclusive | medium | 6 | Did dispatch the identity lead but gather bound svc.monitoring to wrong host |
| L4 | benign | medium | 5+ | Correct disposition but 3-candidate container resolution capped confidence |

### Stage A findings

- **L2 is the empirical winner.** 3/3 trials produced `benign / high` with 3-4 leads. Variance only in resolved container name (web-1, web-1-or-web-2, jump-box-1) and lead count — both irrelevant to disposition.
- **L4 also works** but at higher cost (5+ leads vs L2's 3-4) and lower confidence (medium vs high). The lesson directs the agent to ground *every* companion rule against the baseline catalog, which is correct but over-investigates relative to L2's single-anchor-query approach.
- **L1 unscored.** ES tunnel dropped on both attempts (Hetzner VPS appears to time out idle SSH forwards). With ES unreachable the volume discriminator never landed. The lesson framing was not directly testable in this experiment.
- **L3 partial success.** The lesson moved the structural failure (agent dispatched the identity lead) but a gather-side host-binding error (svc.monitoring queried against db-1 instead of web-1/web-2) kept the contract open. Conservative escalation followed. Validates that the SKILL-level discipline rule + L3 framing moves the structural failure, but exposes a separable gather-resolution-chain quality issue.

## Stage B — Authoring mechanism comparison

Six mechanisms tested. Each took the baseline FP run's artifacts as
input and produced one lesson candidate. Same input across mechanisms;
each invoked via `claude -p` with Read/Grep/Glob/ls/cat/wc tools.

### Mechanisms

- **A — self-reflection (no truth)** — single Sonnet pass, agent re-reads its own work with the prior "some structural move was wrong; find it".
- **B1 — debate + arbiter** — defender argues for disposition, prosecutor argues against, arbiter (no truth) distills lesson from winning claims.
- **B2 — reconciliation (no arbiter)** — 2-round defender↔prosecutor exchange with concede/reinforce/refine labels; defender authors lesson if convergence reached.
- **C — external reviewer** — single Sonnet pass, framed as independent reviewer building strongest case the disposition is wrong.
- **D — actor-counterfactual (sketch)** — judge+author phase only. Noise actor's benign story hand-authored (proper actor pipeline not yet built for benign-noise direction); Sonnet compares actor story to defender investigation and authors lesson.
- **E — counterexample probe (no truth)** — single Sonnet pass with explicit directional prior ("disposition class is FP-dominated; treat it as wrong; find why").

### Cost + wall

| Mech | Cost | Wall (sum) | Wall (critical path) |
|---|---|---|---|
| D | $0.21 | 92s | 92s |
| A | $0.38 | 238s | 238s |
| E | $0.42 | 163s | 163s |
| C | $0.50 | 162s | 162s |
| B1 | $3.03 | 717s | 577s |
| B2 | $3.21 | 1,453s | 998s |

### Lesson targets produced

| Mech | Lesson target | Matches L2? |
|---|---|---|
| **D** | Contract dispatch — anchor must have direct lead. Behavioral evidence cannot substitute for an authoritative anchor query. | **Yes — verbatim** |
| A | Scaffold both peer hypotheses when triage question is binary (asymmetric `:H` topology — when triage names "X OR Y", both must be hypotheses with their own predictions) | No |
| C | Single-hypothesis eliminative disposition (refuting benign does not confirm adversarial) | No (same as A) |
| B1 | Scaffold benign **variants** as siblings (watchdog vs startup-check) — collapsing into one hypothesis produces a straw-man prediction | No |
| B2 | Fleet-scoped GATHER cannot establish per-container attribution (invlang edge-authority violation — requires container-filtered follow-up lead) | No |
| E | Unscoped companion sweep + base-rate inversion (same-rule prevalence is the signature of an FP-dominated rule; reading prevalence as campaign evidence is circular) | No |

### Headline finding

**Only the actor-based mechanism (D) reproduced L2.** The five
artifact-only mechanisms (A, B1, B2, C, E) each identified a different
load-bearing structural failure — all real, all upstream — but none
reproduced L2's framing.

**Why:** the artifact-only mechanisms are bounded by what's visible
inside the investigation. They can find structural flaws within the
reasoning (asymmetric topology, eliminative collapse, fleet-attribution
violations, base-rate inversion). But L2's framing — "you should have
queried the identity stub / baseline catalog" — requires knowing that
those external sources exist and answer this question. That knowledge
lives in the deployment's configuration files, not in the investigation
artifacts. The actor-based mechanism is the only one that brings
external truth about the deployment into the loop's scope.

**Cost shape:** D was the cheapest mechanism by a factor of 2-15×. B1
and B2 cost 8× more than A/C/E for no apparent lesson-quality
advantage — they found different targets but not better ones (subject
to Tier-2 validation).

### Implication for the production learning loop

The actor-based mechanism is **necessary, not optional**, for learning
from false-positives. The prior session's task to build the
benign-noise actor (`actor.md` is currently adversarial-only;
`handoff-noise-investigation.md` flagged this as v2 workstream)
remains the highest-leverage piece. Without it, no mechanism in the
loop can produce L2-class lessons from a future FP case.

The other mechanisms (A, B1, B2, C, E) are not wasted — each produced
a real upstream lesson on a distinct failure class. They are
complementary, not competitive: a future loop might run a cheap
artifact-only mechanism (A or E) on every closed case and reserve the
expensive actor-based mechanism (D) for cases where artifact-only
finds nothing or where ground-truth disagreement is high.

## What's still open

### Tier-2 empirical validation (deferred)

The artifact-only lessons (A, B1, B2, C, E) target structural failures
distinct from L2. Each may or may not actually fix the FP when
injected. Concrete prediction issues:

- **A/C** ("scaffold adversary peer hypothesis"): the agent would
  scaffold `?adversary-controlled-execution` with its own predictions.
  Same l-003 evidence would grade adversary `++`. Without ALSO
  consulting identity/CMDB, disposition might still come out malicious.
  Likely insufficient on its own.
- **B1** ("benign variant siblings"): watchdog hypothesis might also
  get refuted (intervals don't cluster near a configured sleep
  period). No legitimacy-anchor consultation. Possibly insufficient.
- **B2** ("per-container attribution / edge authority"): container-
  filtered follow-up lead would return empty for the persistence /
  pivot events, blocking their use as per-vertex evidence. Might
  produce inconclusive but probably not benign-with-high-confidence.
- **E** ("base-rate inversion + container scoping"): combination of
  B2's structural move and an explicit base-rate guard. Might be the
  artifact-only lesson most likely to flip disposition empirically.

Cost: ~$1 × 4 trials × ~25 min wall (concurrent in 2 batches).

### Build the production benign-noise actor

The directional D sketch validated the architectural shape but used a
hand-authored story. A production benign-noise actor would:

- Mirror `defender/learning/actor.md` for the benign direction (story
  is grounded in `playground-v2/hosts/base/baseline/catalog.yaml`,
  not in MITRE ATT&CK).
- Sample baseline patterns the way the adversarial actor samples MITRE
  techniques.
- Use an oracle to synthesize the gather output the defender would see
  under the noise story.
- Judge convergence (does the defender's investigation match the
  story's load-bearing facts?) and author the lesson when divergence
  is significant.

Scaffolding for the symmetric pipeline (`_author_runner.py`,
`replay_actor.py`, `author_actor.md`, `verify_forward_actor.md`)
already exists for the adversarial direction. Estimated effort: ~1-2
days of prompt + pipeline work to mirror it for the benign direction.

## Mechanism F — cross-investigation diff (optional future enhancement)

Not run in this experiment. Worth considering as a future addition to
the mechanism roster.

**Premise:** instead of analyzing one investigation, compare *multiple
defender runs* of the same alert. This experiment already produced 5+
defender runs of the same alert (baseline, L1a/L1b, L2a/b/c, L3, L4).
They disagree on disposition (malicious / inconclusive / benign) and
on which leads were dispatched. Lessons could emerge from where
investigations *diverged* — what move did the benign-disposition runs
make that the malicious-disposition runs didn't?

**Distinct advantage:** invariance vs accident. F is the only
mechanism that can distinguish "this is the agent's structural failure
mode" from "this was an accident of this particular run's lead
choice". Single-run mechanisms (A/B/C/D/E) can't see across-run
variance.

**Plausible shape:** one Sonnet pass per pair of disagreeing
investigations, identifying the load-bearing structural divergence.
Then a synthesis pass distilling lessons from the divergence pattern.

**Estimated cost:** $1-2 (Haiku reading + Sonnet synthesis); requires
multiple defender runs as input, which makes F naturally a post-hoc
mechanism rather than a per-FP mechanism.

**Worth trying when:** the learning loop needs to identify structural
failure modes that aren't tied to specific FPs — e.g., "the agent
collapses benign variants into one hypothesis" is the kind of finding
F could surface from across-run variance even when each individual
investigation looked OK.

## Artifacts

All on `/tmp/` (not persistent across long sessions, but currently
available):

- Baseline FP run: `/tmp/defender-runs-v2/20260527T150928Z-v2-noise-alert-suspicious-network-tool/`
- L1-L4 Stage A trials: `/tmp/defender-runs-L{1,1b,2,2b,2c,3,4}/`
- Stage A lesson candidates: `/tmp/lesson-cards/L{1..4}-*.md`
- Stage B mechanism outputs: `/tmp/stage-b/mechanism-{A,B1,B2,C,D,E}/`
- Per-trial worktrees: `/workspace/.claude/worktrees/lesson-test-L{1..4}/`

To preserve any of these for citation in future writeups, copy into
this directory before the temp paths age out.

## Commits

- Structural fix (split SKILLs + tool-shape discipline): `7e12667` on
  `defender-v2-env`. Local-only branch per CLAUDE.md push guard.

## Related

- Prior session handoff: `/workspace/defender-v2-tree/handoff-noise-investigation.md`
- Production learning-loop docs: `defender/docs/learning-loop.md` (on `main`)
- Adversarial actor (the existing direction): `defender/learning/actor.md`
- Currently-empty benign lesson corpus: `defender/lessons/`
