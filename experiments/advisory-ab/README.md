# advisory_ab — does PLAN-time Class-8 advisory retrieval help?

Four-arm comparison of the `advisory_recall` Class-8
(`lead_branch_effects`) surface (PR #222), wired into PLAN.

## Questions

1. **Relevance vs cost.** Advisory is plausibly relevant to only some
   cases. Is the cost of firing every time worth it on cases where it
   doesn't help? → **A vs D** answers the upper bound (always-on
   value), **B vs D** and **C vs D** answer whether discretion
   recovers the cost on cases where advisory doesn't bite.
2. **Caller construction.** B (Haiku subagent, NL task) vs C (main
   agent inline Bash). Recall once fired is deterministic — quality
   differences reduce to call-correctness × call-when-needed. Cost is
   the live axis: terse Haiku call vs in-context Sonnet reasoning.

## Arms

| | A | B | C | D |
|---|---|---|---|---|
| Surface | none | Haiku subagent (`defender/skills/advisory`) | main agent inline Bash | main agent inline Bash, **every PLAN turn** |
| Discretion | — | yes — agent picks when | yes — agent picks when | **no** — fires unconditionally each loop |
| Input the caller passes | — | NL goal + frontier (`?h1,?h2`) + `run_dir` | `--signature` + `--frontier` from current `:H` rows | same as C |
| Return | — | rendered Class-8 markdown | rendered Class-8 markdown | rendered Class-8 markdown |
| Per-arm overlay | `arms/a.md` (empty) | `arms/b.md` | `arms/c.md` | `arms/d.md` |

The Class-8 markdown is the same artifact across B/C/D — only call
construction and *when to call* differ. PR #222's
`advisory_recall(classes=("lead_discrimination",))` is the
load-bearing API.

## Comparisons we are buying

- **A vs D** — does always-on advisory move outcomes / lead choice?
  Upper-bound "is the data useful at all".
- **D vs {B, C}** — does agent discretion recover the negative-case
  cost without losing the positive-case value? This is the relevance
  question.
- **B vs C** — for the discretion mode, which caller is cheaper?
  Prior: B (Haiku) lower cost-per-call but framing-overhead may
  balance it; C (Sonnet inline) higher cost-per-call but no
  duplication of context.

## Cases — synthetic fixtures

Test alerts are **synthetic** — modeled on the patterns in real
`/tmp/defender-runs` 5710 cases but with net-new entity values so the
test alerts are not in the corpus. No exclusion plumbing needed.

Each fixture lives under `fixtures/<id>/`:
- `alert.json` — the input defender receives at ORIENT
- `ground_truth.yaml` — hand-labeled disposition + relevance prediction
  + rationale
- `README.md` — short story + construction notes

**Pilot (v1):** 1 positive + 1 negative, both rule-5710 (the signature
with the richest corpus support):
- `POS-1` — undocumented source `172.22.0.42` + uncommon-but-plausible
  username `apt-mirror`. Two competing explanations equally plausible
  from the alert content alone; the discriminator beyond CMDB+IAM is
  `wazuh-auth-pattern` (cadence). Advisory should surface it. Gold:
  `inconclusive`.
- `NEG-1` — exact replay of the recurring `172.22.0.10` + `nagios`
  pattern. CMDB+IAM resolves cleanly on loop 1 from first principles.
  Advisory has nothing marginal to add; arm D pays the cost overhead.
  Gold: `malicious`.

**Next pass** (after pilot signal): expand to rule-100001 and
rule-100110 variants per the original ask.

### A note on gather behavior

Defender's gather subagent hits live CLIs (playground CMDB jq, IAM
jq, Wazuh CLI, host-query). CMDB and IAM are stub registries against
`/workspace/playground/{cmdb,iam}/*.json` — both fixtures resolve
faithfully against the real registry data. The Wazuh side will
return empty for synthetic source IPs (the alerts aren't in the
index). That's accepted noise for the pilot; the load-bearing
metrics (lead choice, cost, loops) are unaffected. If gather-noise
contaminates outcome too much in the pilot results, we layer in
seeded Wazuh data in v2.

## Metrics

Output per run goes to `results/<timestamp>/<arm>-<case>.json`.

**Outcome:**
- `disposition_match` — matches `cases.json.gold` (bool)
- `disposition_observed` — what defender wrote in `report.md`
- `leads_count` — `len(lead_sequence.yaml.entries)`
- `loops_count` — `:L` rows under PLAN headers in `investigation.md`

**Cost (relative to total investigation cost):**
- `total_cost_usd` — sum from stream-json `result` events
- `total_input_tokens`, `total_output_tokens`
- `wall_clock_seconds`
- `advisory_call_count` — number of times the arm invoked retrieval
- `advisory_cost_share` — advisory tokens / total tokens (the
  load-bearing ratio for the cost question)

**Sanity:**
- `advisory_invocation_rate` — `advisory_call_count` ÷ `loops_count`
  (low on positives = prompt didn't land; very high on negatives = over-trust)

## Sample size

**Pilot:** 24 runs = 2 cases × 4 arms × **N=3 trials** to absorb
within-arm variance. Trials are necessary here because a single
defender run is stochastic on lead choice and loop count, and the
pilot only has 2 cases — without trials, single-run noise dominates
arm-level signal.

Scale up the case count (next pass: 100001 + 100110 fixtures) before
scaling trials further.

## Running

```bash
# Pilot (full matrix, N=3 trials):
python3 defender/learning/eval/advisory_ab/run.py --all --trials 3

# Single run:
python3 defender/learning/eval/advisory_ab/run.py --arm b --case POS-1 --trial 1

# Aggregate:
python3 defender/learning/eval/advisory_ab/score.py defender/learning/eval/advisory_ab/results/<timestamp>/
```

## What we are NOT measuring in v1

- Anchoring violations (the block already says "precedent only";
  raw-log eyeball catches the loud cases).
- Class 5 / Class 6 usefulness — Class 6 is sparse per PR #222, and
  Class 5 is the trace surface, not the discrimination surface that
  drives lead choice. Add later if needed.
- Class-misuse rate for C (track via `tool_trace.jsonl` but don't gate).
