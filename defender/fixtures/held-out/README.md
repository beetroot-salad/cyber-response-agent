# Held-out alert set

**This set is currently EMPTY.** It held 24 hand-authored Wazuh-format alerts
(8 per class); those were retired when the Wazuh-shaped fixtures were dropped
in favour of the v2 Elastic alert schema, and no Elastic-format replacements
have been authored yet. Until they are, the primary metric has no denominator:
`evals/held_out.py` runs and reports `no held-out fixtures found`.

The layout, the schema and the contamination nets below are all still live —
this file documents the contract a replacement set must satisfy, and its
presence is what keeps the directory (and so the harness's directory walk)
intact. Alerts with human-applied ground-truth disposition labels, 8 per class
(`benign | malicious | inconclusive`), are the primary eval surface for the
actor-learning workstream (see
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

- **Contamination** is stopped at the two entrances to learning, and both checks
  are label-free:

  - `run_common.enqueue_learning` refuses any alert **under this directory**, so a
    held-out run is never handed to the learn worker. A PATH check — it holds even
    if a label file is missing or malformed. `--no-learn` above makes the same
    intent explicit at the call site.
  - `loop.py <run_dir>` (the direct LEARN entrypoint) is handed a run dir and never
    sees the fixture path, so it asks by **content** instead: `run_one` refuses when
    the run dir's `alert.json` is byte-identical to a held-out fixture's
    (`run_common.is_held_out_alert_copy`). The alert is a verbatim copy, so its
    digest is the one surviving link back to the fixture.

  Neither opens a `ground_truth.yaml`. The learning loop still has no notion of
  ground truth — only of which inputs are eval members.

Because the eval matches a run to its fixture by run-dir NAME, keep the fixture
slugs anchored: a run dir claims a slug only when the slug is the whole name, a
prefix, or a suffix at a `-` boundary (`evals/held_out.index_runs`).

## Class balance

Target for a replacement set (the retired Wazuh set met it):

| class | count | sizing rationale |
|---|---|---|
| `benign` | 8 | per-class recall floor 70% |
| `malicious` | 8 | per-class recall floor 90% — 8/8 required at 90% |
| `inconclusive` | 8 | per-class recall floor 70% |

Per `defender/docs/learning-loop-actor-learning.md` §Ship criteria: with 8
per class and a 90% malicious-recall floor, **any** malicious miss is a
ship-blocker. This is intended.

## Synthesis caveat

The retired set was a **bootstrap** one: hand-authored synthetic shapes in the
Wazuh alert format, inspired by real signatures (Wazuh rules
5710/550/553/554/5715, Falco container-shell/reverse-shell, Sysmon
LSASS-access patterns, etc.) plus a one-paragraph rationale per case. They were
*not* drawn from a production alert stream — and their `agent`/`data.srcip`
vocabulary and synthetic `172.22.0.x` addressing had no counterpart in the v2
Elastic index, which is why retiring them cost less than it appears.

Its labels were deliberate teaching cases — each isolating a single
load-bearing discriminator (e.g. source-host identity, file location +
ownership, command shape, timing relative to package activity), designed so a
competent investigator with normal SIEM access could disposition each one
correctly. Keep that property in a replacement set.

Prefer real labeled production alerts; failing that, author v2 Elastic-shaped
synthetic ones (see `defender/fixtures/v2-*/alert.json` for the schema). The
file layout and `ground_truth.yaml` schema below are the contract downstream
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
