# Result — TOON does not clear the bar. Current columnar retained.

`kimi-k2.6` (Fireworks), 40 fixtures × 100 questions × 2 arms = **200 trials**, temperature 0,
all valid (no length exclusions). Fixtures are real recorded ES|QL payloads pushed through the
production `esql_payload` → `render` path.

## Cost — the deciding number

| metric | current (columnar) | TOON | delta |
|---|---|---|---|
| **input tokens** (real Kimi tokenizer) | 94,065 | 87,755 | **−6.7%** |
| view bytes | 207,403 | 187,738 | −9.5% |

**Below the ≥10% threshold the plan set, so `current` is retained.**

This also corrects #834's recorded figure. The issue's design comment measured columnar 416,571 →
TOON 366,210 tokens, i.e. **−12.1%** for TOON over columnar, using an offline proxy tokenizer.
Measured against the real tokenizer of the model that actually reads these payloads, the edge is
**−6.7%** — the proxy overstated it by roughly 1.8×.

## Accuracy — no detectable difference, and no power to detect one

| kind | n | current | TOON |
|---|---|---|---|
| cell lookup (misbinding probe) | 40 | 100% | 100% |
| arity | 40 | 100% | 100% |
| extremum | 20 | 100% | 100% |

Zero misbinding in either arm. **This is a ceiling effect, not a strong result**: both arms scored
100/100, so these questions cannot discriminate between the encodings. The honest reading is "no
degradation detected on retrieval tasks this easy," not "no degradation." Discriminating power
would need harder questions — multi-hop, or the wide payloads excluded below.

## What the run establishes independently of the verdict

1. **TOON's table needs the dicts #842 deleted.** SPEC §9.3 requires an array of *objects*;
   production `values` is array-of-arrays, so the TOON arm must re-zip into dicts as encoder
   input for TOON to re-flatten them into `values[N]{cols}:`. Transient and view-only — disk
   stays JSON (N2) — but it means adopting TOON re-materializes what #834 removed, one layer up.

2. **Tabular eligibility is not a blocker**: 412/423 (97.4%) of dict-row ES|QL payloads encode
   tabular; the 11 that fall back to list form hold all 152 multi-valued cells. My §9.3 concern
   was real but small.

3. **The Python TOON ecosystem is hazardous.** Of four PyPI packages: `toons` 0.7.0 (Rust) is
   spec-compliant; `toon-format` 0.1.0 is a stub; `toon-python` will not install; and
   **`py-toon-format` 0.1.0 emits a literal newline inside a row**, forging a row from an
   attacker-controlled `cmdline`, and leaves numeric-looking strings unquoted. The row-forgery
   hazard #834 recorded is *not* a property of the format (§7.1 mandates the escape) but is a
   live property of a published implementation.

## Limitations — stated, not folded in

- **Over-ceiling payloads unmeasured.** Fixtures are restricted to payloads passing whole under
  8 KB, where `render` is verbatim; 14 tabular payloads over the ceiling (widest 504 cols /
  1 row / 30,836 B) are excluded. `payload_view.walk` has no TOON equivalent, so including them
  would confound encoding with truncation policy. The over-ceiling win is unknown.
- **Fixture pool skews to TOON's best case**: 2–9 columns, 2–103 rows — the aggregation class.
  Wide payloads are all over-ceiling and excluded. A favorable sample still returned −6.7%.
- **Reading only.** Nothing here measures the model *generating* TOON.
- **One model, one provider.** `glm-5.2` (the investigator role) is untested; it reads reports,
  not raw payloads, so it is lower-value but not zero.

## Harness defect found and fixed mid-run

`kimi-k2.6` is a reasoning model: `reasoning_content` bills against `max_tokens` before any
`content` is emitted. At `max_tokens=64` every trial returned empty with `finish_reason=length`
and scored 0% in **both** arms — caught by the validation pass, which is what it is for. At 2048 a
single TOON trial still flaked empty; re-running the identical call at the same budget answered
correctly, so reasoning length varies run-to-run even at temperature 0. Final run uses 4096 and
records `finish_reason`, and `analyze.py` excludes length-capped trials as *invalid* rather than
scoring them wrong — otherwise the encoding is charged for a harness cap.
