# Actor objective: defeat-the-analysis vs mimic-telemetry, blind vs white-box (#276)

## Question

**Engineering** — Does reframing the adversarial actor's objective from "look benign / mimic the
observed telemetry" to "produce telemetry the defender's *analysis A* would dispose benign (land in
A's benign basin)" move the actor off the unwinnable human-mimicry frame for scripted-benign alert
classes and onto stories that actually exercise the defender's `scripted ⇒ benign` false-negative —
and how much of that the **blind** actor (env-lessons substrate only) can reach versus a **white-box**
actor (reads a **summary** of the lead actuals), whose delta measures env-lessons substrate sufficiency.

Anchor case: **`v2-falco-suspicious-network-tool`** (re-anchored from `v2-sshd-success-after-failures`
— see `results/s1-notes.md`). The sshd class does **not** dispose benign in the current environment
(3 runs: malicious / inconclusive / malicious; its only generator uses an internal source the defender
escalates on via groundability + user-anomaly, and no loopback generator exists). The falco net-tool
class disposes **benign / high** on a single `nc -z -w1 <host> 22` health probe from `svc.monitoring`
(frozen fixture below) while being *port-scan-shaped* (8 hosts × 5 ports) — the same scripted⇒benign
dual the experiment targets, in a class where the env corpus already grounds the case. Judge side
already handles the dual — the likelihood-ratio check at `judge.md:113-117` names the dual-consistent
observable verbatim ("treats scripted cadence … as evidence *for* benign, when that's exactly what the
malicious mechanism also produces"), shipped in #275. This experiment is the **actor-side complement**:
get the actor to write the story (recon/exfil mimicking the monitoring-probe pattern) that triggers that
check.

## Variants

Note on bundling: the three cells are **not** a clean single-variable ablation, and intentionally so.
Baseline→ArmA bundles two changes — objective reframe (`actor.md`) **and** corpus retirement — because
they are not independently coherent: a reframed objective with the old human-mimicry lessons still in
the corpus would be re-steered to the dead end on retrieval, so leaving them in is not a meaningful
control. Treat {reframed objective + retired corpus} as one logical "reframe" intervention. The single
clean variable isolated between **ArmA and ArmB is gather access**. Baseline is the regression anchor.

### baseline (regression) — current actor, blind
- `actor.md`: unchanged (text below, para 2).
- corpus: unchanged — `ssh-brute-force-timing-mimicry` and the other human-mimicry pattern lessons present.
- invocation: `invoke_actor` unchanged — `add_dir=[LESSONS_ACTOR_DIR, LESSONS_ENVIRONMENT_DIR]`, no `gather_raw`.

Current `actor.md` para 2 (the objective being reframed):
```
**What makes a story strong.** The strongest attack is not the most sophisticated — it is the one
whose every individual artifact is indistinguishable from authorized activity, so that the malice
lives only in the *sequence and intent*, not in any single anomalous event. Prefer an operation that
reuses this deployment's real identities, hosts, trust paths, and cadences over one that introduces a
novel host, account, tool, or destination. …
```

### armA — reframed objective + retired corpus, BLIND
- `actor.md` para 2 reframed (diff ≤30 lines) — **alert-agnostic**, framed as a contextual judgment
  (no per-class hints baked into the prompt):
```diff
-**What makes a story strong.** The strongest attack is not the most sophisticated — it is the one
-whose every individual artifact is indistinguishable from authorized activity, so that the malice
-lives only in the *sequence and intent*, not in any single anomalous event.
+**What makes a story strong.** The strongest attack is the one the defender's own *analysis* would
+dispose benign — one whose telemetry the defender's benign-supporting reasoning cannot separate from
+authorized activity, so the malice lives only in the *sequence and intent*. The benign baseline you
+match is a contextual judgment, not a default: some legitimate activity is a routine *human* action
+(interactive, irregularly paced, a real session); other legitimate activity is a *script or automated
+job* (machine-paced, uniform, non-interactive, no persistence). Read the alert and the deployment to
+infer which kind of benign cause this signal fires on, and match *that*. Adopting a human-error frame
+where the routine cause is automation — or the reverse — is a refutation waiting to happen, not
+stealth.
```
- corpus: human-mimicry pattern lessons **git-retired** (one-time manual reset — `ssh-brute-force-timing-mimicry`
  and any folded successors; `sshd-success-session-and-cadence-detection`, a true defender-capability
  env-fact, is **kept**). Exact retire set finalized in setup step S2.
- invocation: blind, unchanged `add_dir`.

### armB — reframed objective + retired corpus, WHITE-BOX (gather **summary**, not raw)
- `actor.md`: same reframe as armA, plus a clause: it is given a **summary of what each lead actually
  returned** (the deployment's real telemetry for this case) and should ground its projected telemetry
  against that summary rather than guessing.
- corpus: same retired set as armA.
- **Decided refinement:** the actor reads the **gather summary, not the raw `gather_raw/` dump.** The
  summary is a real, already-captured artifact. Engine = `run.py` (`claude -p`, CC subscription — no
  first-party key needed). `run.py` runs with `--output-format stream-json` and writes the **full**
  transcript to `{run_dir}/tool_trace.jsonl` (content intact — note this is the *opposite* of the
  PydanticAI engine, where `tool_trace.jsonl` is a content-stripped projection; under `run.py` it is
  the raw stream). Gather is a **Task subagent** (`skills/gather/SKILL.md`) that "returns a tight
  summary"; that summary lands in the main stream as the gather **Task `tool_result`**.
- **Build step:** parse `tool_trace.jsonl`, pull the **gather Task `tool_result` blocks** (the per-lead
  summaries the defender reasoned over) → render `gather_summary.md` (one section per lead, summary
  text only). This is the actual telemetry the defender saw, not a re-synthesis.
- **Contamination guard (load-bearing, structurally satisfied by the filter):** take *only* the gather
  Task `tool_result` blocks. The main agent's own assistant text — its analysis, synthesis, and
  disposition (A's answer) — and the `report.md`/`investigation.md` it writes are excluded by
  construction. So `gather_summary.md` carries summarized telemetry X with **no disposition leakage**.
  (If the actor read A's conclusion it would just invert it instead of constructing Y, destroying what
  the arm measures.)
- **Noted leak (inherent to white-box, acceptable):** gather summaries are shaped by the defender's
  `goal` / `what_to_summarize`, which `actor_view` deliberately redacts (`lead_repository.py:28`). The
  summary partially reveals what the defender chose to extract — that's the point of the arm, not a bug.
- invocation: `invoke_actor` stages `gather_summary.md` and adds it to `add_dir` (no `jq`/`grep` over
  raw needed). `actor_input` queries-only projection is **retained** alongside — the summary adds the
  actuals, it does not replace the contract. Gated behind `ACTOR_WHITEBOX=1` so the production path is
  untouched.
```diff
 # _loop_subagents.py  invoke_actor(...)   [ACTOR_WHITEBOX=1 only]
-        settings_path=ACTOR_SETTINGS,
-        add_dir=[LESSONS_ACTOR_DIR, LESSONS_ENVIRONMENT_DIR],
+        settings_path=ACTOR_SETTINGS,
+        add_dir=[LESSONS_ACTOR_DIR, LESSONS_ENVIRONMENT_DIR, learning_run_dir / "gather_summary.md"],
```

## Fixtures

- `fixtures/falco-net-tool-live/` — **frozen full defender run** `falco-nettool-s1` (live stack,
  `run.py`, claude-sonnet-4-6, `--no-learn`). Disposition **benign / high**. Contains `alert.json`
  (a single `nc -z -w1 jump-box-1 22` falco net-tool alert, uid 1001 / `container.name=<NA>`),
  `gather_raw/` (l-004..l-007 + payloads), `report.md`, `investigation.md`, `executed_queries.jsonl`,
  `gather_summary.{md,json}` (the armB white-box source — built from the gather payloads, not from the
  raw stream, since this run gathered inline), `cadence_analysis.txt`, `lessons_loaded.jsonl`,
  `meta.json`, `budget.json`. (`tool_trace.jsonl`, the raw stream-json transcript, is **not committed** —
  heavy and regenerable; replay needs only the tables + `gather_raw/` + `report/investigation`.)
  This is the frozen disposition A + actuals X that all three cells probe.
  **Load-bearing (satisfied):** disposition is benign, so the likelihood-ratio check can arm; the benign
  reasoning rests on "established baseline automation by an authorized service account" applied to
  port-scan-shaped activity (8 hosts × 5 ports, 9,189-event 7-day baseline) — the dual-consistent
  observable the actor must exploit. Full rationale + the abandoned sshd attempts in `results/s1-notes.md`.

- ~~`fixtures/sshd-live-run/`~~ — abandoned anchor (kept: `alert.json` only). sshd does not dispose
  benign here; see `results/s1-notes.md`.

Single fixture is sufficient: the question is class-specific (scripted-benign disposition logic), and
one faithful instance of the class exercises the variable. Breadth across alert classes is a later
generalization question, not this one.

## Trials

Mechanism per trial (actor varies; A held fixed from the frozen fixture):
`replay_actor` (actor stage on the frozen `gather_raw`) → `invoke_oracle` → judge (`run_judge`) →
`author_actor` (lessons). Reuses existing loop functions; `eval_secondary.py` already chains
actor-replay → oracle → judge at HEAD and is the closest existing harness to fork.

- **Validation:** 1 trial per cell (3 total). Confirm: replay wires the frozen `gather_raw`; the
  reframed `actor.md` loads; armB actually reads `gather_summary.md` (check `actor_trace.jsonl`), and
  the summary contains no disposition/narrative leakage from `investigation.md`/`report.md`;
  the judge arms the likelihood-ratio check on the benign disposition. Inspect all three stories + the
  judge findings by hand before scaling.
- **Scale-up:** N=6 per cell (18 trials). Actor seed varies per trial (`_actor_seed`), so this
  characterizes the *distribution* of story shapes each cell produces, not a point estimate. Mid-run
  analysis at 2/cell (6 trials, ~33%): if armA already collapses to SKIP/incoherent, or baseline and
  armA are indistinguishable, stop and rethink the reframe before spending the rest.
- **Analysis script:** `experiments/actor-basin-276/analyze.py` (written before scale-up). Reads each
  trial's `actor_story.md` + `judge_findings.yaml` + authored lesson diff; emits the metrics below.

## Decision criteria

Metrics (per-trial, then per-cell mean with n shown):
- **basin-landing rate** — story is a scripted / no-persistence (or otherwise A-benign) variant, NOT
  human-paced mimicry. (The behavioral target of the reframe.)
- **judge-FN-naming rate** — judge emits the `analyze-discipline` likelihood-ratio finding naming the
  scripted⇒benign dual-consistency.
- **outcome mix** — caught / survived / incoherent / skip.
- **lesson quality** (qualitative) — does `author_actor` produce a clean reframed pattern lesson, or a
  muddle? are armB's lessons *realizable* by a blind attacker, or do they depend on having read logs?

Calls:
- **Reframe adopted (armA over baseline)** if basin-landing rate and judge-FN-naming rate rise
  materially over baseline *without* inflating incoherent/skip. This is the #276 fix; if it lands, the
  retired corpus + reframed `actor.md` ship.
- **Reframe rejected / baseline retained** if armA collapses to SKIP/incoherent, or its story shape is
  indistinguishable from baseline (reframe inert).
- **White-box (armB) pursued as a production change** only if it surfaces basin-landing stories / FNs
  armA misses AND those lessons survive the realizability filter. If armB's wins are all
  unrealizable-by-a-blind-actor, keep the actor **blind in production** and use white-box only as an
  offline *ceiling oracle* to audit env-lessons substrate gaps (armB−armA delta = substrate deficiency
  to encode into `lessons-environment`).

## Setup (pre-trial, in order)

- **S1. ✅ DONE** (re-anchored to `v2-falco-suspicious-network-tool`). Live-stack run `falco-nettool-s1`
  via `run.py` (claude-sonnet-4-6, `--no-learn`) → **benign / high**; full artifacts incl.
  `tool_trace.jsonl` frozen to `fixtures/falco-net-tool-live/`. sshd anchor abandoned (never disposes
  benign here — 3 invalid runs). Full record: `results/s1-notes.md`.
- **S2.** Finalize + `git rm` the human-mimicry pattern lesson set (manual reset; tooling retire-path
  deferred). Record removed files in `results/retired-lessons.md` with rationale.
- **S3.** Author the two `actor.md` variants under `variants/`; wire the `ACTOR_WHITEBOX` flag in
  `invoke_actor`.
- **S4.** Write `analyze.py`. Then validation pass (3 trials).

## Layout
```
experiments/actor-basin-276/
  plan.md
  variants/        actor.md.baseline, actor.md.reframed, invoke_actor.whitebox.diff
  fixtures/        sshd-live-run/   (frozen full defender run — S1)
  runs/            <cell>/<trial>/  (actor_story.md, judge_findings.yaml, authored-lesson.diff, traces)
  analyze.py
  results/         retired-lessons.md, midrun.md, final.md
```
```
