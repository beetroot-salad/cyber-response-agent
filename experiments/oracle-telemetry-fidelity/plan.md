# Oracle telemetry fidelity — sanity check against real playground-v2 telemetry

**Date:** 2026-07-25
**Status:** plan (pre-trial)

## Question

**Engineering.** Is the oracle's per-lead telemetry projection *directionally right* — does the
delta it predicts for a story that really happened match the delta that story actually wrote to
the telemetry the defender's leads read?

Scope discipline: this is a **sanity check, not a calibration**. The output is "the oracle is / is
not completely off" over 2–3 data sources, not a per-field accuracy table or a prompt change.

### Why this is measurable at all

In production the oracle is *counterfactual*: the actor's story never happened, so there is no
actual telemetry to compare against. This experiment removes that obstacle by substituting a
**true** story — the ground truth of an attack we actually fired — for the invented one. Every
other input is unchanged, so a divergence is oracle translation error and cannot be story error.

## Deviation from the standard template

The skill's variant structure (`current` vs `proposed`, one variable) does not apply: there is no
prompt change under test. The two arms being compared are not two configs but
**oracle prediction vs. observed reality**, with the production oracle held fixed as the only
"variant". The regression-validator role the `current` arm normally plays is filled by running the
**unmodified production path** (`invoke_oracle` → `ORACLE_PROMPT`, `ORACLE_MODEL`,
`ORACLE_EFFORT`) — if this experiment needed a patched oracle to run, that would itself be a
finding.

## Arms

### A — oracle prediction (production path, unmodified)

```
invoke_oracle(run_dir, ground_truth_story.md, learning_run_dir,
              oracle_fn=_run_oracle_pydantic)
```

Input shape is byte-for-byte the production shape, per `build_lead_user_prompt`:
`{actor_story, lead{lead_id, what_to_summarize, queries[id, params]}, sample_event}` — including
`sanitize_wtc` timestamp stripping and the `_scrub_skeleton` value-scrubbed sample. The oracle
gets its shape reference (the scrubbed sample event) exactly as it does in production, so its
output is shape-comparable to actuals by construction.

The only substitution: `actor_story` is the ground-truth narrative of the attack we fired,
rendered in the actor's own output format (§0 selected techniques / §1 attack story / §2 bypass)
so the story slot's shape is also unchanged.

### B — actual telemetry (observed)

The same leads' queries as executed live by the defender run: `executed_queries.jsonl` +
`gather_raw/{lead_id}/{seq}.json`. This is the attack-window observation `A`.

## The baseline problem, and how B is made comparable to A

The oracle emits a **signed diff over the baseline**; the actuals are `baseline + delta`. A
mechanical diff of the two is therefore invalid. To recover the observed delta we re-run each
lead's queries verbatim over a **control window** containing no attack, and compare.

- `elastic query` verb → shift the `start` / `end` params.
- `elastic esql` verb → rewrite the ISO-8601 literals inside the `query` body (windows are inlined
  in ES|QL text, not separate params).
- state/lookup systems (`cmdb`, `identity`, `host-state`, `change-mgmt`) → no time axis; these are
  the `0` category by construction and are re-run unshifted as a control on stability.

**Two control windows**, because neither alone is trustworthy:

| Control | Window | Why |
|---|---|---|
| `C1` same-day | attack window shifted back far enough to clear boot settle | same environment state, same day; but the env booted 2026-07-25T07:34Z, so the first ~10 min are boot transient (agent enrollment, simultaneous container start, sshd restarts) and not representative baseline |
| `C2` −15d | same clock window on 2026-07-10 (a full continuous-run day: 543 workstation sshd successes) | a far larger, settled baseline sample under the same `V2_BASELINE_SEED` schedules; different day is the cost |

Agreement between `C1` and `C2` on a lead's category is the confidence signal. Disagreement is
reported, not averaged away.

## Scoring — in the oracle's own vocabulary, not string equality

The oracle's prompt defines exactly four moves. Score category agreement first:

| Category | Oracle output | Observed (`A` vs control) |
|---|---|---|
| `+ event` | one or more event mappings | `A` carries attack-attributable rows absent from control |
| `+ noise` | `["<standard environment noise>"]` | `A` non-empty, but distinguishing fields indistinguishable from control |
| `− noise` | `["<suppressed: …>"]` | control non-empty, `A` empty — stream went dark |
| `0` | `[]` | `A` and control both empty, or the query has no event stream (state/lookup) |

Then, for leads where both sides are `+ event`, a **field-grounding** check on the entities the
prediction commits to (`host.name`, `user.name`, `source.ip`, `event.outcome`, `process.name`):

- concrete predicted value == observed value → `match`
- concrete predicted value != observed value → `wrong` (the expensive error)
- `<angle-placeholder>` → `unknown`, scored separately and **never** counted as `wrong`; the prompt
  mandates placeholders for values the story does not state, so penalizing them would penalize
  compliance.

### Known limitation, stated up front

Most `elastic` templates are **aggregate ES|QL** (`STATS accepted=…, failed=… BY …`) — they return
aggregate rows, not documents, while the oracle predicts *events*. For those leads a document-level
diff is meaningless. They are scored one level up: does the observed count delta (attack rows
present / absent, and in the predicted direction) agree with what the predicted event set implies?
That is a judgment call, so aggregate leads are labelled `aggregate` in the results and reported
separately from `doc-returning` leads rather than pooled into one number.

## Fixtures

Generated by this experiment, not reused — a live run is the point.

- **Attack:** `playground-v2/attacks/catalog.yaml` → `cross-tier-ssh-probe`, seed 42 (the scenario
  paired with the existing `defender/fixtures/v2-cross-tier-ssh-pivot` alert, so its rule and
  investigation shape are known-good). `runs/<id>/meta.json` is the ground-truth source: exact
  commands, per-step rc, second-precision start/end.
  - Trigger dependency: rule `v2-cross-tier-ssh-pivot` is an EQL **sequence** whose first leg is a
    successful sshd on `office-ws-*`/`dev-ws-*` — produced by *baseline*, not by the attack (which
    dispatches via `docker exec`). So the attack must be fired within `maxspan=15m` of a baseline
    workstation login. Fire-when-observed, do not inject the login: injecting it would put activity
    in the environment that the ground-truth story would then have to cover.
  - Fallback if the sequence will not close: `ssh-brute-force-canary` → `v2-sshd-failed-auth-burst`,
    a self-contained threshold rule the attack triggers alone.
- **Alert:** pulled from `.internal.alerts-security.alerts-default-*` after the rule fires.
- **Defender run:** `python3 defender/run.py <alert.json> --no-learn` — supplies the leads in
  production shape and the actual telemetry in one artifact.
- **Data sources:** target 2–3. Expected: `elastic` sshd-auth (event stream, should be `+ event`),
  `elastic` zeek-connection **or** falco (second event stream), plus one state source
  (`cmdb` / `host-state`) which should be `0`. Category diversity comes free from the lead mix;
  `− noise` will likely be unexercised by this attack and that gap will be stated, not hidden.

## Trials

Validation: **1** — one attack, one defender run, one oracle pass over all its leads. Each lead is
an independent observation, so a single run yields ~5–8 scored data points.

Scale-up: **none planned.** The stated goal is a sanity check. If the validation pass shows the
oracle is badly off, the next step is diagnosis (a second run to separate run-specific noise from
systematic error), not a scaled N — so N is deliberately left unset rather than promised.

Analysis script written before scoring: `analyze.py`. Because a single pass is <10 trials the
mid-run-analysis rule does not bind, but `analyze.py` is still written before the oracle is
invoked, so the metrics cannot be chosen after seeing the predictions.

## Decision criteria

The subject is the oracle's fidelity, so the criteria are about what we conclude, not which arm ships:

- **Oracle judged sound (not off):** category agreement on ≥ 3 of the ~5–8 leads including the
  primary `+ event` lead (the sshd auth stream the alert fired on), **and** zero `wrong` concrete
  field values on the `+ event` leads. Placeholders and `unknown` do not count against this.
- **Oracle judged materially off:** either the primary `+ event` lead is missed (predicted `0` /
  `+ noise` when the attack demonstrably wrote a distinguishable event), or any `− noise`
  suppression is predicted where the actual stream is alive (the prompt calls this out as turning
  ordinary silence into a false detection), or ≥ 2 `wrong` concrete field values.
- **Inconclusive:** `C1` and `C2` disagree on the category of the primary lead — the baseline
  recovery, not the oracle, is then the thing under suspicion, and the finding is about the method.

## Layout

```
experiments/oracle-telemetry-fidelity/
  plan.md                    # this file
  fixtures/
    alert.json               # the alert the rule produced
    attack-meta.json         # copy of the runner manifest (ground truth)
    ground_truth_story.md    # the true story, in actor output format
  runs/                      # defender run dir copy + oracle projection + control-window results
  analyze.py                 # scoring: category agreement + field grounding
  results/
    findings.md
```
