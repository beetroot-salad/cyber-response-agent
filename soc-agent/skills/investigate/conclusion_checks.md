# CONCLUDE Self-Check

Read before writing `## CONCLUDE` to `investigation.md`. Answer every question that applies to your status. Write your answers to `{run_dir}/conclusion_checks.json` using the schema at the bottom of this file.

A PostToolUse hook validates the file when you write `## CONCLUDE`. The hook checks:

- Every required question for your status is answered.
- Every citation you give appears as a verbatim substring in `investigation.md`.

The hook does **not** judge whether your answers are correct. It does verify that your citations point at real content. Fabricated citations fail the gate and block the CONCLUDE write. Write honest answers — if a question reveals that you shouldn't be concluding yet, return to HYPOTHESIZE.

Citations are verbatim substrings from `investigation.md`. Copy a distinctive chunk directly — a few words including the specific value, lead name, or grade are usually enough for a unique match.

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

Is the `++` grade backed by **authoritative** evidence (a named trust anchor confirming, a registry entry, an operator in a change ticket, a direct policy source), or by **circumstantial** consistency (pattern match, timing, naming)?

Circumstantial `++` is the failure mode the skill names explicitly: "Do not promote circumstantial to authoritative." If your `++` rests on circumstantial evidence, downgrade to `+` and either find an authoritative anchor or escalate.

**Answer shape:** classify the evidence (authoritative or circumstantial), cite the anchor consultation or the circumstantial observation, state whether the grade is justified.

### `dangling_evidence`

Does your confirmed hypothesis explain **every** significant observation in the investigation log? List any observation that doesn't fit and explain why it doesn't invalidate the verdict. If none, state so and cite the ANALYZE block where coverage was reviewed.

Dangling evidence is a strong signal the hypothesis space is incomplete — the most common failure mode is a `++` hypothesis that explains the main event but not surrounding observations the investigation surfaced.

**Answer shape:** list unexplained observations (or "none") with citations.

### `archetype_shape_match`

Does the matched archetype's story describe every notable feature of this alert, or only the major ones? List any feature the archetype doesn't cover and explain why it doesn't invalidate the match.

The archetype catalog is a pattern-recognition cache, not the source of truth. Forcing an alert into the closest archetype when the evidence has features the archetype doesn't describe is the failure mode the skill explicitly names. If features don't fit, escalate as a novel variant rather than force-close.

**Answer shape:** list non-matching features (or "full match") and cite the archetype feature you're comparing against.

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
        "1 authentication attempt from 10.0.1.50",
        "?brute-force:\n    weight: \"--\""
      ]
    },
    {
      "question_id": "plus_plus_refutation_attempt",
      "answer": "...",
      "citations": ["..."]
    }
  ]
}
```

Rules:

- `status` is `resolved` or `escalated`.
- `checks` contains one entry per required question for that status. Missing or extra question IDs are rejected.
- Every citation string must be a substring present somewhere in `investigation.md` at the moment you write `## CONCLUDE`. Plain substring match — copy distinctive chunks directly from the log.
- Empty or whitespace-only citations are rejected.
- Write this file **before** writing `## CONCLUDE` to `investigation.md`. The hook fires on the CONCLUDE header write and rejects it if this file is missing.
