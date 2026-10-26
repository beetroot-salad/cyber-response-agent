# Held-out alert set

**This set is currently EMPTY.** Its earlier members — hand-authored Wazuh-format alerts and the
three Kibana-projected playground examples — are retired: none was captured against the stack the
set is now scored on. Until replacements are captured, the primary metric has no denominator:
`evaluations/held_out.py` reports `no held-out fixtures found`.

The layout, the schema and the contamination nets below are all live — this file documents the
contract the replacement set must satisfy, and its presence keeps the directory (and so the
harness's directory walk) intact. Members are playground alerts with human-applied ground-truth
disposition labels, 8 per class, and are the primary eval surface for the actor-learning
workstream (see `defender/docs/learning-loop-actor-learning.md` §Metrics).

Each subdirectory contains:

```
{slug}/
  alert.json          # the alert input, as the playground tenant's alert mapping reads it
  ground_truth.yaml   # disposition + class_axes + rationale, held_out: true
```

`ground_truth.yaml` **never leaves this directory.** `disposition` is an answer
key and a run dir sits inside the agent's readable workspace, so nothing is
copied there and no run records a pointer back to its fixture. Two consequences:

- **Scoring** (`evaluations/held_out.py`) walks THESE dirs and finds each fixture's
  run through the held-out index — a JSON Lines file you name, kept outside every
  runs and episodes tree, one `{slug, run_id}` row per run — never by a run
  folder's name, which is an opaque UUID (#1187). See §Running the set.

- **Contamination** is stopped at the two entrances to learning, and both checks
  are label-free:

  - `run_common.enqueue_learning` refuses any alert **under this directory**, so a
    held-out run is never handed to the learn worker. A PATH check — it holds even
    if a label file is missing or malformed. `--no-learn` makes the same
    intent explicit at the call site.
  - `loop.py <run_dir>` (the direct LEARN entrypoint) is handed a run dir and never
    sees the fixture path, so it asks by **content** instead: `run_one` refuses when
    the run dir's `alert.json` is byte-identical to a held-out fixture's
    (`run_common.is_held_out_alert_copy`). The alert is a verbatim copy, so its
    digest is the one surviving link back to the fixture.

  Neither opens a `ground_truth.yaml`. The learning loop still has no notion of
  ground truth — only of which inputs are eval members.

The index records each fixture slug separately from the run's opaque UUID. Keep fixture slugs
stable across launches so later scoring can associate their index rows with the same fixtures.

## Labels

A label is any disposition the agent can author: `benign`, `false-positive`, `inconclusive`,
`malicious`. `unresolved` is recorded only by the host when a run ends without a settled finding,
so it is never a right answer. Scoring is exact match, and `held_out.py` refuses the whole set if
any fixture carries a label outside those four, naming each one — a typo must not become a class
of its own.

`benign` and `false-positive` are separate classes and are not interchangeable:

- **`benign`** — the rule detected what it claims to, and that activity is legitimate (a
  config-management key rotation that writes `authorized_keys`; an authorized vulnerability scan
  that trips the port-scan rule).
- **`false-positive`** — the rule fired on behaviour other than what it claims to detect (a
  "cross-tier pivot" stitched together from two unrelated logins; an "off-hours sudo" fire during
  working hours).

Write the rationale against that line. A case where the two readings are genuinely balanced is a
poor teaching case; pick another.

## Class balance

| class | count | per-class recall floor |
|---|---|---|
| `benign` | 8 | 70% |
| `false-positive` | 8 | 70% |
| `inconclusive` | 8 | 70% |
| `malicious` | 8 | 90% — 8/8 required |

Per `defender/docs/learning-loop-actor-learning.md` §Ship criteria: with 8
per class and a 90% malicious-recall floor, **any** malicious miss is a
ship-blocker. This is intended.

## What a member is

Members are alerts captured from the playground (`playground-v2/`) and investigated by the
playground tenant. Keep the teaching-case property: each fixture isolates a single load-bearing
discriminator (source-host identity, actor account, file location, timing against a change
window), so a competent investigator with normal access to the playground's systems could
disposition it correctly — or, for `inconclusive`, could not, because the evidence that would
settle it is genuinely unavailable rather than merely hard to find.

An alert names its incident; the agent investigates it against the live stack. A fixture is
therefore valid only while the telemetry and stub state it depends on are unchanged — capture
the set and score its runs against the same frozen playground.

## Schema

```yaml
held_out: true              # marker — selects the fixture into the eval set
disposition: benign | false-positive | inconclusive | malicious
class_axes:                 # optional taxonomy hints — not consumed by the loop
  source: <telemetry source, e.g. falco | system.auth | postgresql | keycloak>
  rule_class: <short slug>  # free-form, for stratified reporting
rationale: |                # what makes this label the right call —
  <one paragraph>           # the human reviewer's note, not consumed by code
```

## Running the set

Every run names its tenant, and there is no default (#1078). The set is scored against the
playground tenant; `$TENANT_ID` below is its UUID (one-time setup: the repo `README.md` and
`evaluations/README.md`). Pin every run of one index to one knowledge revision `K`, so its
scores are comparable (#1108 P4).

```bash
# Investigate each held-out alert, appending its row to the index F yourself:
for f in evaluations/fixtures/held_out/*/alert.json; do
  slug=$(basename "$(dirname "$f")")
  run_id=$(python3 defender/run.py "$f" --tenant "$TENANT_ID" --no-learn --knowledge-commit K \
           | sed -n '1s/^run_id=//p')
  [ -n "$run_id" ] && printf '{"slug": "%s", "run_id": "%s"}\n' "$slug" "$run_id" >> F
done

# Score correctness against ground truth:
python3 evaluations/held_out.py "$DEFENDER_DATA_ROOT/$TENANT_ID/runs" --index F
```

A run that crashes before announcing its id leaves no row, and the slug's older row (if any) is
scored instead. `held_out.py` reports aggregate accuracy plus per-class recall and counts runs
that crashed or produced no parseable `report.md` as **wrong** against the ground-truth class
(see the failure-accounting rule in §Metrics of the design doc). A confident close whose review
cannot run is recorded `inconclusive`, so a dip in malicious recall can be the review gate rather
than the investigation — open the run before reading it as a reasoning miss.
