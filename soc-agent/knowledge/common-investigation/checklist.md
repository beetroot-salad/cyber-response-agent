# Investigation Checklist

Read this at CONTEXTUALIZE. Verify every item before CONCLUDE.

This is your self-check — not a rigid schema, but a guide to ensure your investigation is complete and your report will pass validation.

---

## During Investigation

### Hypotheses
- [ ] At least two hypotheses formed (from playbook + your own)
- [ ] At least one **adversarial hypothesis** (represents a real threat) maintained until explicitly refuted with `--` evidence
- [ ] Each hypothesis has a clear, testable profile (what you'd expect to see if true)

### Leads
- [ ] Each lead has a **prediction block** — what each hypothesis predicts you'll observe
- [ ] Each lead has a **raw observation** — what you actually found (specific: IPs, counts, usernames)
- [ ] Each lead has a **structured assessment** — `++/+/-/--` weight per hypothesis with reasoning
- [ ] Leads chosen for **diagnostic value** — they discriminate between hypotheses, not just confirm one

### Evidence Quality
- [ ] Observations are **specific** — "10.0.1.50" not "internal IP", "47 attempts" not "many"
- [ ] No assumptions stated as facts — if you didn't query it, you don't know it
- [ ] Failed queries noted and alternatives attempted
- [ ] Time windows explicitly stated for each query

---

## Before CONCLUDE

### Resolution (status=resolved)
- [ ] Exactly one hypothesis has `++` support
- [ ] **All** adversarial hypotheses have `--` refutation with explicit reasoning
- [ ] A matching precedent exists in `precedents/` — you've verified the file is there
- [ ] `matched_precedent` field points to the actual filename
- [ ] `leads_pursued` count meets minimum for the signature severity (low:1, medium:2, high:3, critical:4)
- [ ] Confidence is `high`

### Escalation (status=escalated)
- [ ] Clear explanation of why you can't resolve — what's uncertain or threatening
- [ ] "What We Know" section has concrete evidence gathered
- [ ] "What We Don't Know" section identifies the gaps
- [ ] "Suggested Next Steps" gives the analyst actionable direction
- [ ] `leads_pursued` still meets the minimum even for escalations

### Report Structure
- [ ] YAML frontmatter between `---` delimiters at start of report.md
- [ ] All required fields present: `ticket_id`, `signature_id`, `status`, `disposition`, `confidence`, `matched_precedent`, `leads_pursued`
- [ ] `status` is `resolved` or `escalated` (not "closed", "open", etc.)
- [ ] `disposition` is `benign`, `false_positive`, `true_positive`, or `inconclusive`
- [ ] `confidence` is `high`, `medium`, or `low`
- [ ] `trace` line summarizes the full investigation path

### Investigation Log
- [ ] `investigation.md` has phase headers: `## CONTEXTUALIZE`, `## HYPOTHESIZE`, `## GATHER`, `## ANALYZE`
- [ ] Each phase has the structured format from the investigator instructions
- [ ] ANALYZE phases have YAML assessment blocks

---

## Common Mistakes

- **Confirming without refuting:** Finding evidence for your preferred hypothesis is not enough. You must also show why the adversarial hypothesis is wrong.
- **Resolving without precedent:** `status=resolved` requires `matched_precedent` pointing to a real file. If no precedent matches, escalate.
- **Skipping leads:** Don't conclude after one lead unless it conclusively discriminates all hypotheses. Most investigations need 2-3 leads.
- **Vague observations:** "The IP appears internal" — did you check? What range? Be specific.
- **Forgetting state transitions:** Every phase change needs a `write_state.py` call. Missing one breaks the audit trail.
