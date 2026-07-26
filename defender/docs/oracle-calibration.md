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

## Status

`defender/evals/oracle_golden/README.md` carries the current coverage table and
per-case results. Open work, in the order it matters:

1. wire the trust resolver into lesson scoring (the safety criterion);
2. re-capture `-noise` against a stream with a measured non-zero baseline in its
   own envelope — the class currently rests on one lead whose darkness is partial;
3. routine **benign** observed cases (the suite is malicious-heavy);
4. host-state / identity as `+event` surfaces, and more mutation entities;
5. stratify reports by activity family once enough cases exist to support it.
