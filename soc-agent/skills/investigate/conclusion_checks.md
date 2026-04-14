# CONCLUDE Self-Check

Read before writing `## CONCLUDE` to `investigation.md`. Answer every question that applies to your status. Write your answers to `{run_dir}/conclusion_checks.json` using the schema at the bottom of this file. Each citation is a line range from `investigation.md` plus a short **VERBATIM** token that must appear within those lines — copy-paste directly from the log, character for character (backticks, punctuation, whitespace). Do not retype or paraphrase.

If a question reveals that you shouldn't be concluding yet, return to HYPOTHESIZE.

---

## Questions — status: resolved

### `adversarial_refuted`

Name the adversarial hypothesis you maintained (the "what if this is a real threat" one) and the lead that produced `--` evidence against it.

A `--` grade means the observation **directly contradicts a core prediction** of the hypothesis. "Looks unlikely", "outweighed by other evidence", and "deprioritized" are not `--`. If you cannot identify such an observation, your adversarial hypothesis was not refuted — return to HYPOTHESIZE or escalate rather than resolving.

**Answer shape:** name the hypothesis, the lead, the core prediction, the refuting observation. Cite both the GATHER observation and the ANALYZE grade line.

### `plus_plus_refutation_attempt`

For the hypothesis you graded `++`, name one check you ran that **would** have refuted it if the result had come back differently, and cite where it ran.

`++` represents confidence backed by a **failed attempt to falsify**, not consistent evidence alone. If every lead you ran for the `++` hypothesis was confirmatory with no refutation path, the maximum honest grade is `+` — return to HYPOTHESIZE.

**Answer shape:** name the check, state the result that would have refuted the hypothesis, cite the GATHER block where it ran.

### `authoritative_vs_circumstantial`

Name the trust anchor your `++` grade rests on and cite where it was consulted. A trust anchor is a named entry in an archetype's `required_anchors`, a precedent ticket ID inside the matched archetype, or a system of record (registry, change ticket, policy source) explicitly authorized for this signature.

If your `++` rests only on circumstantial consistency (pattern match, timing, naming) with no named anchor, downgrade to `+` and either find an authoritative anchor or escalate. "Do not promote circumstantial to authoritative."

**Answer shape:** name the anchor (anchor name, ticket ID, or system of record), cite the GATHER/ANALYZE line where it was consulted, state the result.

### `dangling_evidence`

Every significant observation in the investigation log must be consistent with your confirmed hypothesis. Cite the ANALYZE block where coverage was reviewed.

If any observation is unexplained or contradictory, you cannot resolve — return to HYPOTHESIZE to expand the hypothesis space, or escalate. There is no "list exceptions" path here: dangling evidence is a stop condition, not a footnote.

**Answer shape:** cite the ANALYZE block that confirms full coverage.

### `archetype_shape_match`

Two parts:

1. **Matched archetype coverage.** Does the matched archetype's story describe every notable feature of this alert? Cite the archetype feature you compared against. If features don't fit, escalate as a novel variant — do not force-close.

2. **Adversarial archetype distinguished.** Name the adversarial archetype closest in shape to this alert (the one a real threat would most plausibly hide inside) and cite the feature that distinguishes it from the matched archetype. If no feature distinguishes them, the matched archetype isn't load-bearing — escalate.

**Answer shape:** matched archetype name + coverage citation, adversarial archetype name + distinguishing feature citation.

---

## Questions — status: escalated

### `dangling_evidence`

Same question as for resolved status. Even escalated reports benefit from explicit coverage review — the "What We Don't Know" section should account for any observation your best hypothesis doesn't explain.

### `escalation_rationale`

Name the specific uncertainty that prevents resolution. "Two live hypotheses that the evidence cannot discriminate" is a valid rationale; "felt unsure" is not. Cite the ANALYZE block where the undecidable state was recorded.

**Answer shape:** name the uncertainty, cite the ANALYZE block.

---

## Output schema

Write to `{run_dir}/conclusion_checks.json`:

```json
{
  "status": "resolved",
  "checks": [
    {
      "question_id": "adversarial_refuted",
      "answer": "The ?brute-force hypothesis was refuted: it predicted >50 attempts but only 1 was observed.",
      "citations": [
        {"lines": "62", "contains": "1 authentication attempt from 10.0.1.50"},
        {"lines": "78-82", "contains": "weight: \"--\""}
      ]
    },
    {
      "question_id": "plus_plus_refutation_attempt",
      "answer": "...",
      "citations": [
        {"lines": "95-100", "contains": "..."}
      ]
    }
  ]
}
```

Rules:

- `status` is `resolved` or `escalated`.
- `checks` contains one entry per required question for that status. Missing or extra question IDs are rejected.
- Each citation is an object with two fields:
  - `lines` — either a single line `"64"` or an inclusive range `"62-68"`. 1-indexed, matches what the `Read` tool shows.
  - `contains` — a short **VERBATIM** substring that must appear within the cited line range. Copy-paste character for character; do not retype or paraphrase. 2–10 words is usually enough.
- Empty citation lists, empty `contains` strings, or out-of-bounds line ranges are rejected.
- Write this file **before** writing `## CONCLUDE` to `investigation.md`.
