# Judge discipline — reframe from verdict-adjudicator to lesson-extractor (2026-05-17)

Follow-up to PR #214 (actor over-specificity). The actor fix shipped;
the remaining problem from the same incident run was **judge
discipline**: on `20260516T135250Z-live-5710-alert` the judge ruled
`caught` and cited "actor predicted 1 username, lead returned 3" as
the refutation — over-specificity reasoning applied symmetrically
across the encounter (the actor was told not to over-commit; the
judge was treating extras as contradictions).

This experiment iteratively reshapes the judge prompt and measures
on the same problematic fixture (N=3 per round, same model and
invocation as prod).

## Method

- **Fixture.** `/tmp/defender-runs/20260516T135250Z-live-5710-alert`
  (real live-5710 SSH brute-force run from the prior PR's failure
  case).
- **N=3 reruns** against the existing actor + oracle outputs from
  that run — only `judge.md` changes between rounds. Driver:
  `/tmp/rerun_judge_n3.py`, calls `defender.learning.loop.invoke_judge`
  directly so model (`claude-sonnet-4-6`), prompt-loading, output
  format, and `_run_claude` invocation match prod exactly.
- **Single-variable iteration.** Each round changes one thing; results
  inform the next round.

## Rounds and results

### Round 1 — refutation discipline subsection

Added a "What 'refute' means" subsection under §Outcome explaining
that the story is an existential claim (events would exist), not
exhaustive (these are the only events). Refutation is subset-shaped:
projection absent from actuals = refutes; actuals contain projection
plus extras = consistent; ambient traffic from unrelated entities
doesn't refute.

**Result: 1/3 trials applied the subset rule cleanly.** Trial 0 said
"survived" with correct subset reasoning. Trials 1 and 2 still cited
username breadth as refutation (trial 2 mixed it with a legitimate
temporal-absence refutation).

### Round 2 — mechanism-inversion bullet

Added an explicit "mechanism-inversion is not a refutation" bullet —
"the story's mechanism cannot produce event E" is **not** grounds for
refutation when E is present in the actuals; the story doesn't claim
its mechanism produced everything in the window.

**Result: still 1/3.** Trial 2 cleanly applied the new bullet
("zabbix events present as subset; extras consistent with ambient
monitoring traffic"). Trials 0 and 1 backslid on different attack
vectors:

- Trial 0: argued "extras come from the IP the story claims as actor
  beachhead, so they're attributable to the actor's mechanism" — a
  more sophisticated mechanism-inversion the bullet didn't cover.
- Trial 1: re-asserted "username exclusivity refuted" without
  engaging the new rule.

### Reframe — fixture is OOD, refutation framing is the wrong lever

User reframed: the fixture is OOD (multi-tenant monitoring traffic
from one host is rare in the wild), the judge lacks environment
priors to adjudicate, **both readings are defensible**. The right
question isn't "did the story technically survive" — it's "what are
the sharpest findings/observations for student (defender) and teacher
(actor) capability improvement?"

Structural findings on this encounter (invariant to which reading
wins):
1. Source-IP asset identity is the load-bearing unresolved
   dimension; no lead resolves it.
2. Compromised-monitoring-server attack class is below the
   instrumentation floor.
3. Defender's analyze step monolithically processes l-001 results
   with no per-mechanism decomposition.

### Round 3 — structural shifts

Three coordinated edits:

- **§Outcome.** Allow ambiguity-acknowledging rationale (pick the
  better-supported verdict; name the ambiguity; identify what would
  have disambiguated). Add "Role reminder" framing the judge as
  findings-extractor, not verdict-adjudicator.
- **§Encounter analysis.** Add a required question — "what would have
  disambiguated this encounter?" — to surface the highest-leverage
  structural findings.
- **§Defender findings.** Convert outcome→finding-type rules from
  hard requirements to guidance; add explicit rule that structural
  findings outrank verdict-anchored findings when both are available.

**Result: verdict split unchanged (2 caught / 1 survived), but
findings shape shifted substantially.** All three trials now surfaced
the source-IP asset identity gap and the compromised-monitoring-host
observability gap. The verdict-anchored finding (`detection-confirmed`)
appeared in the two caught trials but no longer crowded out
structural ones.

### Round 4 — full student-teacher reframe

User reframed again: "this is a student-teacher architecture. We want
to extract the highest-value lessons to the student (defender) and
teacher (actor) to improve capabilities over time. Findings/observations
are first-class output; verdict is metadata."

Four coordinated edits:

- **Top of prompt.** Replaced opening paragraph with explicit
  student-teacher framing. "Your output is two streams of lessons …
  the outcome enum is an analytics tag, not the product."
- **§Defender findings.** Further demoted outcome→type coupling.
  "Pick findings purely by teaching value to the defender. Verdict
  shape is irrelevant to this question." Soft observations on
  typical-shape are now post-hoc sanity checks, not selection rules.
- **§Actor observations.** Promoted to symmetric treatment with
  defender findings: max bumped 2→3, citations recommended, expanded
  type definitions (misprediction / framing-choice / discarded-class),
  added selection question ("would the next story expose a real
  defender gap rather than getting caught on incidentals?").
- **Teacher-side disambiguation.** Added "what would have made this
  story sharper?" companion question to the defender-side
  disambiguation question.

**Result: verdict shift 2/3 → 1/3 survived; findings shape fully
decoupled from verdict.** All 9 findings across the 3 trials are
structural (lead-set, lead-quality, analyze-discipline, observability).
No `detection-confirmed` entries — the caught trial emitted three
structural findings, refusing to pad with a hollow capability
finding.

## What the final-round findings look like

Convergent themes across trials (good signal of robust extraction):

| Theme | T0 | T1 | T2 |
|---|---|---|---|
| Source-host visibility | F1 no source-host lead | F1 process/cron on source | F1 enrolled-agent lookup + F3 asset-identity |
| Analyze decomposition | F2 per-username cadence | F3 multi-username as anomaly vs noise | F2 missing 3rd hypothesis |
| Monitoring-infra exfil channel | F3 instrumentation gap | F2 Zabbix DB exfil channel | — |

**Sharpest findings:**

- T2-F1 "no Wazuh enrolled-agent lookup before declaring CMDB-gap" —
  concrete, tactical, hits an exhausted-too-early reasoning gap.
  Names a wazuh-native option that was available without
  integrations.
- T2-F2 "missing third hypothesis covering multi-account monitoring
  initialization" — doesn't just flag the gap; scaffolds the missing
  hypothesis.
- T1-F2 "Zabbix item-history as passive exfiltration channel" —
  connects the story's actual goal to the instrumentation surface.

**Sharpest actor observation:** T1's framing-choice — "omit SSH
probing entirely; DB exfil reaches the goal without generating any
5710 events." A story-class-level redirection, not a tweak to the
current story.

**Mild concern.** Findings converge thematically but use different
anchor/topic phrasing across trials. Author stage will need
thematic dedup to avoid three near-duplicate corpus entries for the
same lesson. Out of scope for this experiment.

## What shipped

`defender/learning/judge.md` — all four rounds of edits:

1. Top-of-prompt student-teacher framing.
2. §Outcome: "What 'refute' means" subsection with subset-shaped
   refutation rules + mechanism-inversion bullet + ambiguity-
   acknowledging rationale guidance + role reminder.
3. §Encounter analysis: "what would have disambiguated this
   encounter?" required question.
4. §Defender findings: outcome→type coupling demoted to soft
   post-hoc sanity checks; teaching-value-only selection rule.
5. §Actor observations: symmetric treatment with defender findings
   (max 3, citations, type definitions, selection question,
   teacher-side disambiguation companion).

## What was learned

- **Refutation discipline alone (rounds 1-2) was the wrong lever.**
  Hit a 1/3 ceiling because the fixture is genuinely ambiguous; no
  amount of rule-tightening collapses the ambiguity.
- **The fixture is a useful OOD stress test, not a defect.** Real
  environments don't ship multi-tenant monitoring on one host; the
  judge lacks training-distribution priors. Picking a verdict isn't
  the work — extracting the structural lessons that *would have
  disambiguated* is.
- **Findings-first, verdict-as-metadata** is the framing the prompt
  should have started from. The student-teacher framing makes the
  judge's job concrete: produce two streams of grounded lessons,
  the verdict tags them for downstream filtering.
- **Symmetric treatment of actor observations matters.** Previously
  treated as a short optional notes section; under student-teacher
  framing, actor lessons are equally first-class — the future
  actor-side learning loop will need them at the same grounding
  caliber as defender findings.

## Deferred

- **Author-stage thematic dedup.** Across-trial dedup of structurally
  identical findings under different phrasings. Track separately.
- **Verdict reliability on borderline encounters.** The reframe
  deliberately accepts split verdicts on ambiguous fixtures. If
  downstream routing logic ever depends on verdict for more than
  audit/queueable filtering, may need a `verdict_ambiguity` sidecar
  or marginal-tier qualifier.
- **Pushing the misprediction axis deeper.** Actor `misprediction`
  observations across trials all restate the ambient-traffic point
  in different voices. A "prefer the deepest misprediction"
  selection nudge could push trial-2-style "model the host's
  baseline" lessons up over surface-level ambient-pattern
  restatements. Low priority.
