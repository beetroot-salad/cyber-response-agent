# TOON vs columnar JSON — kimi-k2.6 (gather)

## Question

**Engineering.** Does encoding an ES|QL payload as TOON instead of the current columnar JSON
reduce `kimi-k2.6`'s input tokens *without* degrading its ability to read a cell out of that
payload?

This is #834's ask 4 ("establish the accuracy oracle before the cost one") asked of the model that
actually reads these payloads. `DEFAULT_GATHER_MODEL = "kimi-k2.6"` (`runtime/driver.py:74`) —
gather is the role ES|QL payloads land in. All published TOON benchmarks measure GPT and Claude
tiers; none measures Kimi, and none uses a columnar baseline.

## Variants

One variable: **the serialization of the payload in the model's context**. Same payload content,
same question, same prompt scaffold in both arms.

### current (regression validator)

Production path, unmodified:

```python
from defender.scripts.adapters.elastic_adapter import esql_payload
from defender.scripts.gather_tools.payload_view import render
view = render(json.dumps(esql_payload(query, resp)), payload_rel, run_dir)
```

Emits the wire's columnar shape — `columns` once, `values` as bare arrays (#834/#842).

### proposed

Identical payload, serialized TOON via `toons` (Rust-backed, spec-compliant — see Encoder note):

```python
import toons
view = toons.dumps(esql_payload(query, resp))
```

```
values[2]{cmd,u}:
  "a\nb --x",root
  ls,bob
```

### Encoder note — not incidental

Four PyPI TOON packages were probed against §7.1/§9.3 on our own hazards:

| package | verdict |
|---|---|
| `toons` 0.7.0 (Rust) | **spec-compliant** — `null` literal, `"a\nb --x"` escaped, `"42"`/`"07"` quoted, `"a,b"` quoted, multi-valued falls back to list form |
| `toon-format` 0.1.0 | stub — `NotImplementedError` on encode |
| `py-toon-format` 0.1.0 | **unsafe** — emits a *literal* newline inside a row, forging a row from an attacker-controlled `cmdline`; leaves `"42"`/`"07"` unquoted |
| `toon-python` | will not install (unsatisfiable) |

`toons` is the only viable arm. The row-forgery hazard #834 recorded is not a property of the
format (§7.1 requires the escape) but *is* a live property of one published implementation.

## Fixtures

Drawn from the 1,014 recorded payloads under `/tmp/defender-runs/*/gather_raw/*/*.json` — the same
corpus #834 measured. Census reproduced: **551 ES|QL, 423 dict-row, 0 columnar** (pre-#842
recordings; re-shaped through `esql_payload` so both arms are shape-current).

TOON tabular eligibility on those 423, measured through `toons`:

- **412 (97.4%) tabular-eligible**
- 11 (2.6%) fall back to list form — all 152 multi-valued cells live here
- 0 non-uniform key sets

**Scope restriction.** Fixtures are drawn only from payloads that pass **whole** under the 8 KB
ceiling (`passthrough_max_bytes()`), where `render` returns verbatim. Over-ceiling payloads would
confound encoding with truncation policy — `payload_view.walk` is a JSON structural walk with no
TOON equivalent, and building one is a separate change. Recorded as a limitation, not measured.

Stratified sample of 40, deliberately including:

- `fixtures/wide-single-row.json` — the `row_count: 1`, 1,657-column payload (#842's `_fit_cells` case)
- `fixtures/null-heavy.json` — a payload from the 17%-null population
- `fixtures/newline-cmdline.json` — a `cmdline`/`message` cell carrying a literal newline (the escaping probe)
- `fixtures/agg-narrow.json` — a `STATS … BY` aggregation, 2–9 columns, many rows (TOON's best case)
- 36 more sampled across the row-count/column-count distribution

## Trials

**Mechanical ground-truth oracle — no LLM judge.** Each question is generated *from* the payload,
so the answer is computed, not adjudicated:

1. **cell lookup** — "what is `<col C>` in the row where `<col K>` is `<value V>`?" — this is the
   misbinding probe; a slipped column produces a wrong, checkable answer
2. **arity** — "how many rows are in this payload?"
3. **extremum** — "which `<col K>` has the largest `<numeric col C>`?"

Scoring is exact string/numeric match against the computed answer.

Validation: 1 trial per variant per fixture (4 seed fixtures × 3 questions × 2 arms = 24 calls).
Scale-up: **N = 40 fixtures × 3 questions × 2 arms = 240 calls**, temperature 0.
Mid-run analysis at **30%** (72 calls) via `analyze.py`; continue, abort, or adjust there.

Input tokens are read from the Fireworks response `usage.prompt_tokens` — the real tokenizer, not
the offline proxy #834's −32.5% came from.

Analysis script: `experiments/toon-vs-columnar-kimi/analyze.py`, written before scale-up.

## Decision criteria

- **proposed wins if** input tokens fall **≥10%** versus columnar on the same fixtures **and**
  cell-lookup accuracy is not worse — Wilson lower bound on (TOON − columnar) ≥ −2pp.
- **current retained if** cell-lookup accuracy drops more than 2pp, **or** the token saving is
  <10%. #842 already took the large, safe share (−23.3% of the original baseline); a single-digit
  remainder does not justify a non-JSON view, the N2 disk/view split, and a second encoder in the
  path.
- **Either way**, the eligibility census (97.4%) and the encoder audit above are reportable
  findings for #834 independent of the outcome.

## Layout

```
experiments/toon-vs-columnar-kimi/
  plan.md
  variants/      # render_current.py, render_toon.py
  fixtures/      # sampled payloads + generated Q/A ground truth
  runs/          # per-trial JSON
  analyze.py
  results/       # midrun.md, final.md
```
