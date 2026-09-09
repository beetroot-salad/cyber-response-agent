# glm-5.3 vs glm-5.2 — container attribution on a Falco persistence alert

## Question

**Engineering** — does the investigator model account for the container
misattribution seen in `fresh-authkeys-20260909`, or is the failure a property of
the alert's telemetry and the fixture rather than the model?

The source run closed `inconclusive` reasoning about `soc-playground` (the VPS
that runs the Falco agent) as the subject, never resolving `container.id
15a12ab1403f` to `canary-1`, where the persistence write actually happened.

## Variants

One variable: the **investigator** model. Gather stays `kimi-k2.6`; the review
gate stays `kimi-k3`.

### current (regression validator)
```
DEFENDER_MODEL=glm-5.2
```

### proposed
```
DEFENDER_MODEL=fireworks:accounts/fireworks/models/glm-5p3
```

**Set via env, never `--model`.** `resolve_review_model` returns the operator's
raw `--model` when it is non-None, so `--model` moves the investigator *and* the
review gate together — two variables. `DEFENDER_MODEL` is read only by the
investigator builder; the review deliberately does not read it, so its `kimi-k3`
default stays pinned in both arms. `glm-5.3` is not in the Fireworks alias map,
hence the `fireworks:` passthrough to the id the API actually serves.

## Fixtures

- `fixtures/alert.json` — the live `v2-falco-authorized-keys-modification` alert
  captured 2026-09-09T16:19Z, byte-identical to the source run's input.

Shape-current: extracted today from the live cluster through the same projector
the committed v2 fixtures use. Load-bearing: the whole question is whether the
model makes a pivot this alert requires and does not hand over — the alert names
`soc-playground` as `host.name` with `host.containerized: false`, and the
container id survives only in the resolved ancestor.

**Not hermetic.** Runs query the live playground, so baseline generators add
drift between trials. Query windows are anchored on the alert timestamp, not
wall clock, which bounds it — but it is noise both arms share, not noise removed.

## Trials

Validation: 1 per variant (2 runs), confirming the 5.3 passthrough resolves,
the review model stayed `kimi-k3`, and the metrics extract.

Scale-up: **N=5 per arm** (10 runs total). The primary metric is near-binary, so
5/arm resolves the large effect this question is about and not a subtle one.
Roughly 12 min and ~95 tool calls per run — the arms run sequentially against one
playground.

Mid-run analysis after the first 3 trials of the scale-up (~30%), via
`analyze.py`, before committing the rest.

## Metrics

Per trial, extracted by `analyze.py` from the run dir:

| metric | source | why |
|---|---|---|
| `container_resolved` | `canary-1` named in `investigation.md` | primary — did it make the pivot |
| `subject_host` | host named in the `:T conclude` summary | what it thinks it triaged |
| `disposition` | `report.md` frontmatter | outcome |
| `gate_reached` | `review_record.*.json` present | inconclusive bypasses the gate |
| `fixture_tell` | "fake"/"simulation"/"training" in the conclude block | did it shortcut on the fake key material |
| `lessons_loaded` | `lessons_loaded.jsonl` | did the frontier lane fire in both arms |
| `tool_calls` | `budget.json` | cost |

## Decision criteria

- **proposed wins** if ≥4/5 5.3 runs resolve the container to `canary-1` while
  ≤1/5 5.2 runs do — the model accounts for the miss, and 5.3 is worth
  considering as the investigator default.
- **current retained** if the arms are within one trial of each other on
  `container_resolved`. The failure is then not the model's, and the fix belongs
  upstream: the fixture's self-announcing `fake_key ... attacker@elsewhere`
  material, and the absent container→name mapping in the telemetry.
- **inconclusive** if 5.3 resolves the container but both arms still close on the
  fixture tell — an attribution gain that the contaminated fixture masks, and the
  fixture has to be fixed before the model question can be re-asked.

The third outcome is the one I expect to matter most: the source run scored the
adversary hypothesis `--` on the strength of the key material reading as fake,
which no amount of model capability corrects.

## Layout

```
experiments/glm53-container-attribution/
  plan.md
  fixtures/alert.json
  runs/{arm}-{n}/          # run dirs, DEFENDER_RUNS_BASE points here
  analyze.py
  results/
```
