# Validation pass — setup & design decisions (1 run per arm)

Goal: **direction signals**, not a tuned verdict. Prompts are first-draft. One trial per arm
over the frozen benign falco fixture; artifacts left for review.

## Fixture (frozen disposition A, held fixed across arms)
`fixtures/falco-net-tool-live/` — defender run `falco-nettool-s1`, disposition **benign / high**.
A single `nc -z -w1 jump-box-1 22` falco net-tool alert; defender grounded it to scanner-1 /
svc.monitoring automation against a 9,189-event/7-day baseline. The benign basin rests on
"established automation by an authorized service account" applied to *port-scan-shaped* activity —
the scripted⇒benign dual the judge's likelihood-ratio check targets.

## Arms (each run once; mechanism: actor → oracle → judge, fully offline)
- **arm0-baseline** — current `defender/learning/actor.md` (unchanged), blind, live corpus. The
  regression anchor / existing pipeline.
- **armA-reframe** — `variants/actor.md.reframed`: para 2 reframed to the *defeat-the-analysis*
  objective ("the strongest attack is the one the defender's own analysis would dispose benign"),
  framed as a contextual human-vs-automation benign-cause judgment. Blind, live corpus.
- **armB-whitebox** — `variants/actor.md.reframed-whitebox`: same reframe + a sixth input,
  `gather_summary` (the per-lead telemetry actuals), inlined into the actor's user prompt.

Single variable isolated **arm0→armA** = the reframed objective. **armA→armB** = white-box actuals.

## Decisions worth your eye
1. **Corpus retirement deferred (intentional).** The plan's S2 retires the human-mimicry pattern
   lesson `ssh-brute-force-timing-mimicry`. The actor retrieves tradecraft by running
   `lessons_actor_index.py` over the *live* `defender/lessons-actor/`, so an `add_dir` swap would not
   control retrieval — and that lesson is **sshd-tagged, not retrieval-relevant to a falco net-tool
   alert**, so retiring it is inert for this fixture. armA therefore isolates the reframed objective
   alone. (For the sshd anchor, where the lesson IS retrieval-relevant, retirement is implemented in
   `run_arms_sshd.py` by temporarily moving the lesson out of the live corpus during the actor call and
   git-restoring it after — see `results/validation-arms-sshd.md`.) Corpus classification: 14 env-facts
   (`mutable:true`, kept) vs 13 pattern lessons (`mutable:false`); only the one is human-mimicry.
2. **Falco-relevant tradecraft already points at automation-matching.** `single-probe-anomaly-against-
   existing-cadence` and `nc-cmdline-destination-as-primary-discriminator` already tell the actor to
   blend into the established monitoring cadence — which, unlike the sshd case, is a *winnable* basin.
   So the reframe's lift may be smaller on the falco anchor than it would be on sshd. Note this when
   reading the arm0 vs armA stories.
3. **White-box source differs from the plan.** The plan extracts gather-Task `tool_result` summaries
   from `tool_trace.jsonl`. This run executed gather **inline** (0 Task dispatches, no per-lead Task
   summaries), so `gather_summary.md` is assembled from the frozen payloads + the captured
   `gather_summary.json` (l-004) with its `assessment`/disposition block **stripped** — per-lead
   telemetry actuals only. Faithful to armB's intent (real telemetry, no disposition leak); the
   sourcing mechanism is the difference.
4. **Seed pinned across arms.** `_actor_seed` is pinned to a constant so archetype (`internal`/
   `external`) + the sampled 12-technique MITRE menu are identical for all three arms — differences
   are attributable to the intervention, not the seed draw. (Production varies the seed per trial for
   the N=6 distribution; held fixed here for a clean 1-each comparison.)

## Artifacts per arm (`runs/<arm>/`)
`actor_story.md`, `actor_trace.jsonl`, `actor_archetype.txt`, `actor_menu.txt`,
`projected_telemetry.yaml` (oracle), `judge_findings.yaml` + `comparison/` (judge), and
`runs/results.json` (per-arm status + judge outcome). Outcomes appended below after the run.
