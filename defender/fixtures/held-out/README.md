# Held-out alert set

24 alerts with human-applied ground-truth disposition labels — 8 per class
(`benign | malicious | inconclusive`). Used as the primary eval surface for
the actor-learning workstream (see
`defender/docs/learning-loop-actor-learning.md` §Metrics).

Each subdirectory contains:

```
{slug}/
  alert.json          # the alert input — same shape as defender/fixtures/*
  ground_truth.yaml   # disposition + class_axes + rationale, held_out: true
```

`ground_truth.yaml` **never leaves this directory.** `disposition` is an answer
key and a run dir sits inside the agent's readable workspace, so nothing is
copied there and no run records a pointer back to its fixture. Two consequences:

- **Scoring** (`evals/held_out.py`) walks THESE dirs and locates each fixture's
  run by run-id convention — the opposite direction from a scan over run dirs.
  Launch a scored run as:

  ```bash
  python3 defender/run.py defender/fixtures/held-out/<slug>/alert.json \
      --run-id <slug> --no-learn
  ```

- **Contamination** is stopped at the enqueue boundary, not inside the learning
  loop. `run_common.enqueue_learning` refuses any alert under this directory, so
  a held-out run is never handed to the learn worker and no `defender_findings`
  or `actor_observations` from it can reach `defender/learning/_pending/*.jsonl`.
  That check is on the PATH, so it holds even if a label file is missing or
  malformed — and `--no-learn` above makes the intent explicit at the call site.

The learning loop itself has no notion of ground truth at all.

## Class balance

| class | count | sizing rationale |
|---|---|---|
| `benign` | 8 | per-class recall floor 70% |
| `malicious` | 8 | per-class recall floor 90% — 8/8 required at 90% |
| `inconclusive` | 8 | per-class recall floor 70% |

Per `defender/docs/learning-loop-actor-learning.md` §Ship criteria: with 8
per class and a 90% malicious-recall floor, **any** malicious miss is a
ship-blocker. This is intended.

## Synthesis caveat

This is a **bootstrap** held-out set: alerts are hand-authored synthetic
shapes inspired by real signatures (Wazuh rules 5710/550/553/554/5715,
Falco container-shell/reverse-shell, Sysmon LSASS-access patterns, etc.)
plus a one-paragraph rationale per case. They are *not* drawn from a
production alert stream.

The labels are deliberate teaching cases — each one isolates a single
load-bearing discriminator (e.g. source-host identity, file location +
ownership, command shape, timing relative to package activity). They are
designed so a competent investigator with normal SIEM access could
disposition each one correctly.

Replace with real labeled production alerts when available; the file
layout and `ground_truth.yaml` schema are the contract that downstream
harnesses depend on.

## Schema

```yaml
held_out: true              # marker — selects the fixture into the eval set
disposition: benign | malicious | inconclusive
class_axes:                 # optional taxonomy hints — not consumed by the loop
  vendor: wazuh | falco | suricata | sysmon | bind | modsecurity | auditd
  rule_class: <short slug>  # free-form, for stratified reporting
rationale: |                # what makes this label the right call —
  <one paragraph>           # the human reviewer's note, not consumed by code
```

## Running the baseline

```bash
# Investigate every held-out alert through the runtime defender:
for f in defender/fixtures/held-out/*/alert.json; do
  python3 defender/run.py "$f"
done

# Score correctness against ground truth:
python3 defender/evals/held_out.py /tmp/defender-runs
```

`held_out.py` reports aggregate accuracy plus per-class recall and
flags runs that crashed / produced no parseable `report.md` as **wrong**
against the ground-truth class (see the failure-accounting rule in
§Metrics of the design doc).
