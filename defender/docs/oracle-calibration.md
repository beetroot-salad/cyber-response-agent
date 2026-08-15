# Oracle calibration — the evaluation procedure

How to measure whether the telemetry **oracle** is right, and what to do with the
answer. Issue #693. The suite it produces lives at `defender/evals/oracle_golden/`;
that directory's README is the **format reference** (file layout, tools, current
coverage). This document is the **procedure**: the steps, the checks each step
must pass, and the failure each check exists to prevent.

## Why the oracle is measured at all

The learning loop substitutes *actor story → oracle projection* for executing an
attack (`learning-loop.md`). That is the right safety trade, and it makes oracle
error a first-order source of **false learning**:

- under-projection manufactures an apparent **evasion** (the defender "missed"
  telemetry that would have existed);
- over-projection manufactures an apparent **catch** (the defender "found"
  telemetry the activity never wrote);
- confusing the four result classes changes the judge's conclusion outright.

So the oracle is treated as a learned simulator that must be calibrated against
activity that **actually happened** — never against an imagined counterfactual,
and never against the source investigation's ordinary telemetry, which is a
different world.

## What is being scored

One **case** binds four things: the ground-truth story, the oracle-visible input
(what_to_summarize + queries + sample), the hidden observed telemetry, and the
control-window baseline. The oracle sees only the first two; the last two are the
scoring target. The split is enforced at the file level (`oracle_visible/` vs
`hidden/`), because a discipline that depends on remembering is not a boundary.

Every lead is labelled with one of the oracle's own four classes — the **signed
diff over baseline** the lead's queries physically surface:

| class | the activity… |
|---|---|
| `+event` | writes an event these queries surface that is distinguishable from baseline |
| `+noise` | lights these queries, but only with baseline-shaped events — net delta 0 |
| `-noise` | removes the baseline stream these queries read — it goes dark |
| `0` | never touches these queries (wrong system/window/filter, or a state lookup) |

**The label is envelope truth, not intent.** It comes from what the queries
return, not from what the lead was *for*. A lead's stated purpose is recorded
(`intent_note`) to *explain* a divergence, never to excuse one.

### The rule that keeps the suite a measurement

> **A label may be corrected from the environment. Never from the projection.**

Labels *can* legitimately be revised after a projection has been seen — the
2026-07-25 re-evaluation revised three of six results, and every revision came
from re-measuring the environment (control windows under each lead's own
predicate, query filters against the mutated story) rather than from what the
model emitted. That distinction is the whole difference between a suite that
measures the oracle and one that quietly converges on agreeing with it.

Operationally: a class change is accompanied by a control re-measurement or a
generator re-run, never by an edit. `label.py` is the mechanical form of the same
rule — the projection is not one of its inputs, so it *cannot* be fitted to one.

## Dev and held-out

The oracle is a prompt, and the prompt is the thing under test. There are two
leakage paths and only the first is obvious:

- **Prompt fitting.** Any change to `oracle/prompt.md` motivated by a case in the
  suite is fitted to that case. With one pool, the suite stops being a
  measurement the moment it becomes a target.
- **Label fitting.** Covered by the rule above.

`manifest.yaml` carries `split: dev | held-out`.

- **Split at CASE level, never lead level.** Leads inside a case share a story and
  an envelope and are not independent.
- **A derived case inherits its base's assignment.** mut-001 and neg-001 reuse
  case-001's envelopes byte-for-byte; putting one on the other side would put one
  capture on both sides. Pinned by `validate_cases.py`.
- **The six seed cases are all `dev`, and held-out is forward-only.** They were
  visible while the prompt was being iterated, so calling them held-out now would
  be a fiction. Retro-splitting four captures would also leave 1–2 environments
  per side and burn the singleton classes.
- **Held-out is assigned by the generator, before the first replay** — a
  `generate_case.py --split` flag, not a human promise made after seeing a score.

**What is enforced, and what is not.** A held-out result is written once per
(case, tag) into the append-only `held_out_ledger.yaml` with the sha256 of its
score artifact, so a rewritten result, a deleted one, or a second run kept under
the same tag are all detected. To record a new oracle version, add a **new tag**;
never re-run an existing one for a better number.

What is **not** enforced, stated plainly rather than implied: nothing stops a
prompt author reading a held-out case. The case tree is readable by anything with
repo access, and unlike the defender's held-out nets (`run_common.is_held_out_alert_copy`)
there is no process boundary here to attach a guard to. That is a review
obligation, and this document is where it is written down rather than a
construction the code provides.

## Units — what `n` actually is

An interval computed over leads overstates the suite, because leads inside a case
are not independent: 27 of the suite's 36 leads are case-001's nine envelopes
shown three times. The reporter therefore computes at **`n = n_units`**, where a
unit is **(activity family × host pair)**.

Seeds and re-runs **pool** within a unit — ten seeds of one scenario against one
host pair are ten runs of one story shape, not ten trials. `runner.py
--target/--user` is what moves the unit; `--seed` is not. This is a deliberately
conservative full-within-unit-correlation assumption, held until there is enough
data to estimate the real intra-unit correlation.

The consequence worth internalizing: **automation raises the capture count
cheaply and does not raise the unit count.** That is why the unit had to be fixed
before recruitment started rather than after.

`n_environments` is reported alongside: two cases captured from one restored
snapshot are one environment however different their stories.

### Sizing — where the resolver's `N` comes from

`N` is *derived* from the interval width the policy needs, not chosen
(`stats.py:required_n`). For a **≥ 0.90 lower bound at 95% confidence**:

| observed rate | units needed |
|---|---|
| 1.00 (perfect) | 35 |
| 0.97 | 69 |
| 0.95 | 127 |
| below 0.90 | unreachable — the bound converges to the rate |

Below a floor of three units the reporter prints `insufficient` rather than a
number: Wilson on one unit spans [0.21, 1.00], and printing that next to a point
estimate invites the point estimate to be read.

## A. Capture an observed case (needs the environment)

> **Only against `playground-v2`.** `build_case.py` performs no scrubbing —
> every observed payload is committed verbatim under `hidden/`. Correct for a
> synthetic stack and only for one.

1. **Lever up.** `infra/bin/up.sh` restores the latest lever-down snapshot. It
   needs local Terraform state and `terraform.tfvars`, both gitignored — a fresh
   workspace has neither, and the script will fail at `terraform apply`. The
   equivalent without state:

   ```bash
   hcloud server create --name soc-playground --type ccx33 --location nbg1 \
       --image <latest lever-down snapshot id> --ssh-key <your key> \
       --firewall soc-playground-edge
   infra/bin/update-ssh-config.sh <ip>          # docker context rides this alias
   ```

   The firewall pins SSH to a `/32` allow-list; add yours and remove it after.
   Then install detection rules: `python3 playground-v2/scripts/install_detection_rules.py`.

   **That installer needs the CONTAINER's password, not `/workspace/.env`'s.** The two
   differ on a restored snapshot, and the installer talks to Kibana from outside, so it
   fails every rule with HTTP 401 while `infra/bin/es.sh` keeps working — es.sh execs
   *inside* the container and reads `$ELASTIC_PASSWORD` there. Take the same value:

   ```bash
   V2_ELASTIC_PASSWORD=$(ssh soc-playground 'docker exec elasticsearch printenv ELASTIC_PASSWORD') \
       python3 playground-v2/scripts/install_detection_rules.py
   ```

   **Then wait for recovery before measuring anything.** A restore replays ~430 shards,
   and a partially recovered index returns fewer rows — which reads as a quiet baseline,
   the exact error the suite exists to catch. Green never arrives on a single node
   (replicas cannot be assigned), so the condition is `unassigned_primary_shards: 0` with
   nothing initializing, not `status: green`.

2. **Fire a real operation.**

   ```bash
   python3 playground-v2/attacks/runner.py list
   python3 playground-v2/attacks/runner.py run <scenario> --seed 42
   ```

   The per-run record under `playground-v2/attacks/runs/<run-id>/meta.json` —
   resolved source/target/identity, every command, every timestamp — **is the
   ground truth the story must match**. If no catalog scenario covers the
   activity, run it by hand and record the equivalent detail in the manifest;
   note that the case's leads are then `authored`, not captured.

3. **Capture the alert and investigate it.**

   ```bash
   experiments/oracle-telemetry-fidelity/extract_alert.py <rule_id> <since-iso> <out.json>
   python3 defender/run.py <out.json> --run-id <slug> --no-learn
   ```

   The run's leads + queries become the oracle-visible envelope. Prefer this over
   authoring leads: the calibration premise is *the envelope production actually
   issues*.

4. **Write `story.md` from the runner record.** State only what happened — an
   invented step makes the oracle "wrong" for a story reason. State **nothing
   about the evaluation**: no result class, no "a faithful oracle would…", no
   mention of controls or leads. **The story is an oracle input**, and it is the
   one file the hidden/visible split cannot protect.

5. **Measure controls** (below) and write `hidden/controls.yaml`.

   **Pick the offsets by probing the ingest timeline first.** The default 7/14/21 assumes
   the stack was running a week ago, and it often was not: the playground is levered up
   and down, so 2026-07-26's 7-day control lands on 07-19, inside a gap that ran
   07-18..07-24. Measured blind, case-006 came back with 47 dead controls — a third of
   its baseline evidence, gone. A dead window is not an empty baseline, and the judge
   correctly refuses to conclude anything from one, but the evidence is still lost.

   ```bash
   infra/bin/es.sh '/logs-*/_search' -H 'Content-Type: application/json' -d '{
     "size":0, "query":{"range":{"@timestamp":{"gte":"now-32d"}}},
     "aggs":{"per_day":{"date_histogram":{"field":"@timestamp","calendar_interval":"day"}}}}'
   ```

   Then choose whole-week offsets that land on live days — 14,21,28 for a 07-26 capture —
   and pass them through: `generate_case.py --offsets-days 14,21,28`. Whole weeks are not
   optional: the benign generators are schedule-shaped, so an offset that changes the
   weekday is not a control at all.

6. **Assemble and label.**

   ```bash
   python3 defender/evals/oracle_golden/build_case.py \
       <run_dir> <story.md> <controls.yaml> cases/<case-id>     # dir name IS the case id
   ```

   Then author `expected.yaml` and `manifest.yaml` *from* `hidden/`: per-lead
   class, the `fields` a correct projection must commit to, and `observed_fields`
   — ground truth for every other concrete value the capture carries, so
   fabrication in those fields is graded.

### Measuring a control — the step that decides the class

A control answers one question: *would this row be here anyway?* Get it wrong and
the class is wrong, silently.

- **Use the lead's own query predicate.** A control measured on a broader filter
  describes a different envelope. Case-003 recorded "44 auth docs in the control
  window" over *all* dev-ws-1 auth docs while its lead filters
  `event.outcome IS NOT NULL`; under the real predicate the control is **0**, and
  the `-noise` label it justified was wrong.
- **Control the distinguishing field, not the carrier.** Case-002's Falco rule
  fires routinely in the baseline (`config-mgmt-key-rotate` rotates
  `svc.config-mgmt` keys and trips the same rule ~hourly in work hours), so
  zero-count windows on the *rule* prove only that the baseline missed those
  windows. The event is distinguishable by `fd.name`/`user.name`.
- **`+event` requires** the attack window to have the row and **every** control
  to lack it. **`+noise` requires the converse** — the control windows must carry
  the same row, which is what makes the activity indistinguishable.
- **`-noise` requires a baseline to remove.** Confirm the envelope is non-empty
  in the control windows *first*. An envelope that is empty either way is `0`.
- Use shape-matched windows (same clock window on prior comparable days) — the
  Poisson baseline generators are schedule-shaped, so a weekday control for a
  weekend capture is not a control.

## B. Derive a case (no environment needed)

Both kinds reuse a captured case's envelope byte-for-byte and change only the
story, so they carry no `hidden/` — their ground truth is definitional.

- **negative-control** — an unrelated story shown to another case's leads. Truth
  is all-`0`. Catches a projection copied from the query window or salience hint
  rather than caused by the story.
- **mutation** — one causal action or entity altered; the projection must change
  accordingly.

**Re-derive the labels from the mutated story. Do not inherit them.** Read every
query predicate: if the mutation changes an entity that appears in a *filter*,
the lead's **class** changes, not just its field values. mut-001 altered the
source IP while l-004 and l-006 filter on the original — those leads became `0`,
the seed labels kept `+event`, and a correctly-empty projection was scored as two
disagreements and written off as model jitter.

## C. Replay and score

```bash
python3 defender/evals/oracle_golden/replay.py cases/<case-id> [--tag <model>_effort-<e>]
python3 defender/evals/oracle_golden/score.py  cases/<case-id> \
    cases/<case-id>/projections/<tag>.yaml --json cases/<case-id>/scores/<tag>.json
```

`replay.py` drives the production seam (`invoke_oracle_lead` →
`_run_oracle_pydantic`) and reads **only** `oracle_visible/`, so a projection is
production-identical apart from where its inputs came from. `score.py` is pure —
a function of (`expected.yaml`, `projection.yaml`), no clock, no network, no
model — which is what lets `defender/tests/test_oracle_golden_693.py` assert that
every checked-in `scores/*.json` still reproduces from its projection. **Re-run
the scorer over every case after changing `score.py`**, and run that test file
before committing:

```bash
defender/.venv/bin/python -m pytest defender/tests/test_oracle_golden_693.py -q
```

Read the dimensions, never one number:

| dimension | what it means |
|---|---|
| class agreement (by system) | the four-way call, stratified |
| field grounding | `correct` / `wrong` / `unknown` (placeholder) / `missing` on required fields |
| volunteered-value check | is anything the projection *made up* refuted by the capture? |
| `+event` recall / `0` precision | occurrence metrics; `null` (not `0.0`) when unexercised |
| false suppression | `-noise` predicted where the stream was not removed |
| malformed | output outside the oracle's closed grammar |
| lead-set integrity | missing / unlabelled / duplicated leads — **non-zero exit** |

A score with a non-empty `missing_leads` / `unscored_leads` / `duplicate_leads`
is **not a measurement** and must not be read as one.

### Cause codes — naming the failure, not just counting it

Class agreement says *that* a projection was wrong; it never says *why*, and a
prompt change aimed at "the disagreements" is aimed at nothing. Each error a score
artifact reports carries a cause code in a sidecar,
`scores/<tag>.causes.yaml`, keyed by `lead_id`.

**A sidecar, not a field in the score artifact.** `score.py` is pure and its
output is pinned to re-derive from (`expected.yaml`, `projections/<tag>.yaml`); a
cause code is a judgment no pure function can emit. `validate_cases.py` requires
the sidecar to cover **exactly** the leads the score reports an error on — both
directions, so neither a missing cause nor a stale cause for a lead that has since
scored clean survives.

| code | meaning |
|---|---|
| `C-INTENT-SCOPE` | answers the lead's dominant framing rather than the union of its envelope |
| `C-HETERO-UNDER` | the lead's sub-queries disagree; the projection emits one sub-query's class |
| `C-UNDER-PROJECT` | a weaker class than the envelope carries (`+noise` or `0` where it is `+event`), with no heterogeneity or intent-scope explanation |
| `C-SUPPRESS-UNBASELINED` | `-noise` emitted where the envelope's control baseline is zero |
| `C-FABRICATED-VALUE` | a volunteered concrete value the capture refutes, where a placeholder was mandated |
| `C-OVER-PROJECT` | `+event` emitted where the envelope is `0` or `+noise` |
| `C-MALFORMED` | output outside the oracle's closed grammar |
| `C-LABEL-SUSPECT` | suspected label defect — resolvable only by re-measuring the environment |

**The evidence bar.** A cause is treated as real, and may motivate a prompt
change, only at **≥ 5 instances across ≥ 3 distinct units**. Units, not cases:
mut-001 and neg-001 are not independent evidence of anything case-001 already
shows, and neither are two seeds of one scenario. The reporter tallies causes at
unit granularity and marks each `established` or `insufficient`.

**Two standing exemptions, and why they are not special pleading.** The bar
governs taxonomy *claims* — "this is a real failure mode" — not errors the
instrument already grades or defects readable in the specification:

- a defect visible in `prompt.md` itself at n=0 (the suppression rule not
  requiring the stream to plausibly be reporting);
- an error an existing metric already counts (`wrong_concrete_fields`).

Both are dev-motivated and stay dev-motivated: validated on dev, reported on
held-out.

**What the first exercise of that exemption actually showed.** The suppression
defect was fixed in `prompt.md` (the marker now requires the stream to have
plausibly been reporting, not just an explicit blinding action) and every
projection was re-recorded under the tag `glm-5.2_effort-none_prompt-711`. **It
changed nothing** — all 36 leads across all six cases projected identically,
including case-003 `l-001`, the false suppression the change was written for.

Two things follow, and both are worth more than the fix would have been:

- the prompt's silence was **not** the mechanism of that error, so
  `C-SUPPRESS-UNBASELINED` loses its specification-defect exemption and now needs
  ordinary evidence — ≥5 instances across ≥3 units — like any other cause;
- a spec fix that provably regresses nothing across 36 leads is still worth
  keeping, but "we fixed the prompt" is not the same claim as "the oracle
  improved", and only the second would have needed a held-out number.

The change is kept. Its dev evidence is a null result, recorded as one.

**`C-INTENT-SCOPE` and `C-HETERO-UNDER` are currently inseparable.** After
deriving `heterogeneous` mechanically, case-001's heterogeneous leads are
`l-002, l-004, l-006` and its `intent_note` leads are `l-002, l-006` — which are
exactly the two misses. The two hypotheses have the same witness set on the whole
suite; they are one two-lead observation stated twice. Separating them needs
crossed recruitment (a heterogeneous lead with no intent-scoping, and an
intent-scoped homogeneous one). Entries carry `confounded_with` rather than
picking a winner.

## D. Verify before you trust (the re-evaluation pass)

A case is not calibrated because it was captured; it is calibrated because it
survived a check. This pass caught three of six seed results:

1. **Re-measure every control** under the lead's own predicate, against the
   restored capture snapshot.
2. **Re-derive every derived case** from its own story (§B).
3. **Re-read each story** for evaluation vocabulary — the seed negative control
   told the oracle it *was* a negative control and "must therefore return `0` for
   every lead". `test_no_story_states_the_expected_result` now lints this, but a
   leak phrased differently would pass the lint and not the intent.
4. **Check the story against the runner record and the inventory**, not against
   memory of what was run.
5. **Ask what a re-run of the same query would return now.** A ground truth that
   only held at the instant of capture is a claim about that instant, and must
   say so.

## Environment hazards that reach the ground truth

Confirmed against the stack; all three have already corrupted a label or a
number.

- **Re-ingest duplication.** Every lever-up re-ships each host's on-disk logs, so
  a document is re-indexed once per restore and any raw count is multiplied by
  the number of restores since the event. Verified: case-001's attack window
  appears ingested at 07:00, 09:00 *and* 11:00. State counts **per distinct
  ingest**; never grade a count without checking `event.ingested`.
- **IP identity rotates.** Container addresses are assigned in start order, so
  the same address is a different host after a restore — `172.18.0.15` was db-1
  through 2026-07-13 and office-ws-1 from ~07-17. IP-scoped envelopes therefore
  mix hosts, which is why case-001's defender run looked up **db-1**. Label from
  `host.name`; treat historical rows in an IP-scoped payload as unattributed.
- **Stopping a shipper delays telemetry; it does not destroy it.** Killing the
  Elastic Agent stops shipping, but the host keeps writing its log, and the
  backlog arrives with original timestamps once the agent restarts (measured:
  ingested 09:47:04 for events timestamped 09:37–09:44). Only telemetry the agent
  *generates* is permanently lost. A durable `-noise` capture needs a stream of
  that kind, or an action that destroys data at source — clearing the log,
  disabling auditd.

- **A control window can land in a lever-down gap.** The stack is levered up and
  down between snapshots, so a shape-matched window a week back can fall in a
  period when the server did not exist. Every query returns zero rows there, which
  is indistinguishable from "this stream has no baseline" — and reading it that way
  **suppresses real `-noise`**: case-003's 2026-07-18 control is empty only because
  the environment was down between 07-17 and 07-25, while the same query a week
  earlier returns 444 auth documents. `controls.py` liveness-probes each window
  (total ingest across `logs-*`; no live playground-v2 hour is silent, because the
  agents alone emit metricbeat continuously) and marks a dead one `live: false`;
  the labeler ignores it rather than counting it as an empty baseline.

Two more traps that are not the environment's fault:

- A **zero-byte** `hidden/observed/**.json` is an **errored** query, not an empty
  result (`runtime/query_tool.py` writes `""` on non-zero exit). The hidden tree does not
  carry the `payload_status` that says so — check the source run's
  `executed_queries.jsonl`.
- The oracle never receives a **schema exemplar** in this environment:
  `redact_exemplar` needs a `### Raw Sample Events` header that playground-v2's
  JSON payloads never carry, so every sample is the placeholder. The suite is
  faithful to production here — exercising that channel needs a payload-format
  change, not another case.

## E. Gate learning on the result

A **slice** is (system × template × result-class):

- **trusted** — enough calibrated cases with class agreement ≥ threshold, **zero**
  wrong concrete fields, **zero** false suppression, **zero** malformed output on
  that slice;
- **no-update** — below threshold, any of those errors, or unexercised.

Unexercised is the metric being `null`, **not** `0.0` — `score.py` keeps them
distinct precisely so aggregation cannot read "never measured" as "worst
possible".

The downstream contract: the learning loop **must not** apply a positive or
negative lesson-score update when the oracle slice the judgment depended on is
`no-update`. Model-reported confidence is not calibration and must never
substitute for a trusted slice.

**This gate is not wired in yet** (#693 acceptance criterion, open). Until it is,
the loop can apply a lesson update derived from an untrusted slice — today that
includes every `+event` slice with a wrong volunteered value and the single
`-noise` slice, which is both untrusted and effectively unexercised.

## Enforcement — what is pinned, and what is review

Split deliberately in two, because a rule list that mixes the two invites both to
be believed equally.

**Pinned mechanically.** `validate_cases.py` over the case tree (CI runs it), and
the engine tests beside each module:

- every case carries `split`, `unit`, and `capture_environment`;
- a derived case's `split` and `unit` equal its base's;
- a derived case declares an `expectation:`, because the judge never runs on it
  and nothing else would grade it;
- every held-out `scores/<tag>.json` matches its append-only ledger hash, and a
  ledger entry with no score file carries a `retired:` reason;
- no `story.md` carries evaluation vocabulary, and `replay.py` names no `hidden/`
  path in code;
- every observed payload is named for a seq some query in `leads.jsonl` is keyed
  by, so a control cannot baseline a different query's envelope (#882);
- every stored control measures the window its record declares, and the
  accepted-invalid registry (`known_defects.yaml`) still describes the tree it
  waives (#882);
- the reporter refuses to publish an interval below the unit floor, and never
  pools dev with held-out.

Four bullets here used to name machinery the judge redesign removed — `label.py`,
the `scores/<tag>.causes.yaml` sidecar, score reproduction, and an
`audit_labels.py` that is now `audit_judge.py`. A gate list that names checks
nobody runs is worse than a short one: it is read as coverage. `validate_cases.py`'s
own module docstring is the list of record; this mirrors it.

**Review-only, and labelled as such** — no code can check these:

- a `prompt.md` change cites the **dev** case ids that motivated it;
- **a label may be corrected from the environment, never from the projection**;
- a held-out case is not read while the prompt is being edited.

## Generating cases

`generate_case.py` orchestrates the tools that already exist: fire
(`attacks/runner.py`) → capture (`extract_alert.py`) → envelope (`defender/run.py`)
→ story (`story_from_run.py`) → assemble (`build_case.py`) → controls
(`controls.py`) → label (`label.py`). Two properties the hand path could not
guarantee come for free: the story cannot leak the evaluation, because the
renderer's only input is the runner's record; and a control uses the lead's own
predicate, because it *is* the lead's own query with its bounds moved.

Three things worth knowing before running it:

- **Baseline generators stay ON.** `attacks/catalog.yaml` used to advise
  `V2_BASELINE_ENABLED=false`, which is right for capturing an alert fixture and
  wrong for calibration: the oracle's class is a signed diff over baseline, so
  with the generators off `+noise` cannot occur at all and `+event` is easier than
  production.
- **The generator does not predict which rule a cell trips.** It takes whichever
  rule actually fired, preferring one whose alert names the operation's target
  host — because with baseline running, unrelated alerts fire during the capture
  window too, and investigating one of those binds a story to an envelope its
  activity never touched.
- **A cell that trips no rule has no captured envelope.** That is a real outcome,
  not a failure: recruit it with authored leads, recorded as `lead_source: authored`.

### The labeler is itself calibrated (`audit_labels.py`)

When labels come from a program, that program is calibrated against hand-derived
truth before its output is trusted. A labeler bug biases every case the same way,
and no amount of `n` detects a systematic error — unlike human error, which is at
least uncorrelated across cases. The seed six are the audit set, and a divergence
is adjudicated by **re-measurement, never by adjusting the labeler to agree**: a
labeler tuned until it reproduces the hand labels has been fitted to them and
calibrates nothing.

Running that audit is what found four instrument defects, every one an
environment fact rather than a label error: duration-matched control windows too
short to see a sparse baseline; `source.ip` unusable as a row key because
addresses rotate across lever-ups; doc-returning queries keyed on the whole ECS
document, so every one of them graded `+event`; and lever-down gaps read as empty
baselines. The fourth had the labeler about to commit *the same error the suite
exists to catch in the oracle* — inferring suppression from absence.

### Levering up from a fresh workspace

Beyond the missing Terraform state noted in §A.1: the project's `soc-playground-admin`
and `soc-playground-devcontainer` SSH keys and the `soc-playground-edge` firewall
already exist, so `terraform apply` from empty state collides with all three, and
`/workspace/.ssh/devcontainer_ed25519.pub` (a required variable's default path) is
absent in a fresh container. Use the `hcloud server create` path in §A.1, add your
egress IP to the firewall's SSH allow-list, and remove it afterwards.

`defender/run.py` boxes its bash lane in a container, and under
docker-outside-of-Docker the run dir's in-container path is not the host path the
bind mount resolves, so the box cannot start. `DEFENDER_ALLOW_UNSANDBOXED=1` is
the documented local escape hatch (`runtime-sandbox-design.md`); the permission
gate still applies, only the container boundary is dropped.

## What the 2026-07-26 pilot campaign measured

Six stratified cells were fired against a live stack restored from snapshot
`412461512`. Read the per-cell outcomes carefully, because **two of the six
failures were operator error, not environment** — the interesting constraint is
narrower than a first pass suggested:

| cell | outcome |
|---|---|
| `ssh-brute-force-canary --target db-1 --user sre.alice` | fired `v2-sshd-failed-auth-burst` on db-1 → **case-009**, held-out — since **retired** (its story was rendered by a pre-fix `story_from_run.py` that carried the catalog's static description, naming the scenario's *default* target; the ledger entry stays, annotated) |
| `cross-tier-ssh-probe --target db-1` (its default) | fired within 2 min; run aborted on a since-fixed generator bug (a stale run dir) |
| `cross-tier-ssh-probe --target web-2 --user sre.alice` | fired on **web-2**, the intended target; capture then failed for 12 straight polls because its working directory was deleted mid-run |
| `ssh-brute-force-canary --target web-1` | took a **baseline** alert about a different host on its first poll — voided |
| `persistence-authorized-keys --target db-1` | **no rule fired at all** — 20 polls, zero candidates |
| `living-off-the-land --target web-1` | **no rule fired at all** — 20 polls, zero candidates |

So retargeting is **not** broadly undetectable: `ssh-brute-force-canary` fires on
db-1 and `cross-tier-ssh-probe` fires on web-2. What does fail is narrower and
sharper:

> **The two Falco-dependent scenarios — `persistence-authorized-keys` and
> `living-off-the-land` — raised nothing once retargeted off `canary-1`.** The pilot
> read this as the Falco rules being host-scoped. **That diagnosis was wrong** (fixed
> 2026-07-27): the rules are cluster-wide, and both scenarios are *local* — their
> commands act on the host they run on and never interpolate `${target}`, so `--target`
> moved only the runner record while the write still happened on `canary-1`. The runner
> had no way to move *where the commands ran*. `--source` (below) is that knob:
> `persistence-authorized-keys --source db-1` fires `v2-falco-authorized-keys-modification`
> on db-1 — the first time that rule ever fired on a non-canary host (case-014).

Three things for whoever recruits next:

- **A cell that fires no rule has no captured envelope, and that is a real
  outcome.** The generator reports it and exits rather than inventing one; recruit
  such a cell with authored leads and record `lead_source: authored`.
- **The generator will still take an off-target alert if no target alert exists
  yet.** It now *prefers* one naming the operation's target host, which is what
  turned the `--target web-2` cell's alert into the right one — but preference is
  not a requirement, and the `--target web-1` cell shows what happens when it
  polls before its own alert lands. Requiring a target-host match (and waiting for
  it) is the obvious next hardening.
- **A `+noise` cell needs the identity AND the host pair to be baseline.**
  case-009 was aimed at `+noise` by running an attack as a routine SRE account and
  landed as `+event`: `office-ws-1` has `trust_edges_out: []`, so no route from it
  is routine for anyone. case-004's `jump-box-1 → db-1` is the shape that works.

## Status

`defender/evals/oracle_golden/README.md` carries the current coverage table and
per-case results.

**2026-07-28:** `nginx.access`, `keycloak.events` and `squid.access` are now each a scored
observed case (case-016/017/019; README §2026-07-28) — held-out grew 4→6 units, and
**`C-MISSED-DELTA` cleared the establishment bar** (6 instances across 5 units): the oracle
projects a baseline-overview lead empty when its window overlaps the activity, reproduced on
nginx and squid independently. Two capture levers proved necessary and are worth reusing:
force alert *synthesis* (a sentinel `--rule`) so a real Falco `curl`-CONNECT alert cannot
hijack the investigation onto `zeek.http` instead of the intended source, and prune the
over-broad correlate-everything lead before it trips the verdict judge (squid `l-006`,
162 KB) — the same investigation-bounding constraint as item 1.

Open work, in the order it matters:

1. ~~**make the two Falco-dependent scenarios detectable when retargeted**~~ **Done
   2026-07-27** — the runner grew a `--source` flag (the local-scenario retarget knob);
   `persistence-authorized-keys --source db-1` fired the authorized-keys rule on db-1 and
   was captured + scored as case-014, a new held-out Falco unit. A `sudo-escalation-burst`
   scenario retargets the same way. What is *still* open: the verdict judge cannot hold a
   many-query `+event` lead's payload (case-015's postgres capture — see the README
   finding), so bounding the investigation is the next constraint on this family;
2. wire the trust resolver into lesson scoring (the safety criterion);
3. ~~**find out whether the held-out/dev gap is real.**~~ **Provisionally answered
   2026-07-27, and the answer is no.** On one unit held-out read 2/8 active against
   dev's 8/13, which is the number this item was written about. case-008 and
   case-010 — captured 2026-07-26, assigned held-out by the generator before any
   replay, and held unscored until then — took it to three units, where it reads
   **9/17 = 0.53 [0.21, 0.94]** against dev's **0.61**. That gap is about one lead,
   which is the judge's own measured noise floor. case-005 was an outlier, and the
   two cases that show it are the two with **zero** dead control windows against
   its 31%. What is *not* settled is why case-005 is so much worse; and note the
   confound this suite cannot currently separate — see item 9;
4. re-capture `-noise` against a stream with a measured non-zero baseline in its
   own envelope — the class currently rests on one lead whose darkness is partial;
5. routine **benign** observed cases (the suite is malicious-heavy);
6. host-state / identity as `+event` surfaces, and more mutation entities;
7. stratify reports by activity family once enough cases exist to support it;
8. a remedy for `C-SUPPRESS-UNBASELINED` that actually moves a projection — the
   prompt fix did not (see above), so the mechanism is still unknown;
9. **separate story *shape* from split.** Production feeds the oracle the malicious
   actor's three-section prose (`0. Selected techniques` / `1. Attack story` /
   `2. Bypass`, pinned in `malicious_actor/prompt.md`). Only the four seed cases
   are that shape. Every recruited case is a `story_from_run.py` transcript —
   commands and verbatim stdout — which is a deliberate and well-argued trade (a
   renderer structurally cannot leak the evaluation into an oracle input, and
   cannot invent a step) whose **cost was never written down**: the recruited shape
   is off the distribution production actually projects from, and it is the shape
   of every held-out case and every unit added since the seed set. The active band
   splits by shape more than it splits by side:

   | shape | split | active |
   |---|---|---|
   | actor prose | dev | 5/7 = 0.71 |
   | transcript | dev | 5/8 = 0.63 |
   | transcript | held-out | 11/22 = 0.50 |

   Within the transcript shape dev and held-out roughly agree (0.63 / 0.50), which is what
   retired item 3. What remains is a shape effect the suite cannot currently
   measure, because shape is confounded with capture date and nearly with split —
   and every future recruit deepens it (the 2026-07-28 held-out captures are both
   transcript). `n` is 7 against 30, so this is a
   hypothesis. Settle it cheaply and without the stack: hand-render one captured
   operation's story in actor-prose shape and score it against the **same**
   `hidden/` tree. That is not a mutation — the story describes what actually
   fired, so the telemetry is still its ground truth and the pair is judgeable.
   Run the renderer's `EVAL_TELLS` lint over the hand-written story to keep the
   leak protection the renderer was built for.
