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

**Hypothesis discipline — the primary check.** An investigation resolves because
its reasoning converges, not because a pattern matches. Even when an archetype
cleanly matches, these items must hold:

- [ ] Exactly one hypothesis has `++` support
- [ ] **All** adversarial hypotheses have `--` refutation with explicit reasoning
- [ ] The confirmed hypothesis explains every significant observation in the investigation log (no dangling evidence)
- [ ] `leads_pursued` count meets minimum for the signature severity (low:1, medium:2, high:3, critical:4)
- [ ] Confidence is `high`

**Archetype match + grounding — required for auto-close.** Resolution via
`status=resolved` additionally requires an archetype match with its grounding
leg satisfied. This is the fast-path short-circuit on top of hypothesis
discipline, not a replacement for it. If no archetype matches, the hypothesis
work above still runs — but the outcome is escalation, not auto-close.

- [ ] `matched_archetype` names a real directory under `knowledge/signatures/{sig}/archetypes/` — you've verified `story.md` + `trust-anchors.md` are there and parse
- [ ] The matched archetype's story actually fits the observed evidence (not just the nearest plausible archetype; see the COMPLETENESS discipline in the Common Mistakes section below)
- [ ] **Grounding leg satisfied** — at least one of:
  - [ ] Every entry in the archetype's `required_anchors` appears in `trust_anchors_consulted` with `result: confirmed` and a concrete citation
  - [ ] `matched_ticket_id` names a precedent snapshot inside the same archetype directory, whose `captured_at` is within `precedent_max_age_days`, and whose `temporal: true` anchor entries have been re-confirmed against live anchors
- [ ] If the archetype declares no `required_anchors`, `matched_ticket_id` is set (mandatory for anchor-less archetypes)

### Escalation (status=escalated)
- [ ] Clear explanation of why you can't resolve — what's uncertain or threatening
- [ ] "What We Know" section has concrete evidence gathered
- [ ] "What We Don't Know" section identifies the gaps
- [ ] "Suggested Next Steps" gives the analyst actionable direction
- [ ] `leads_pursued` still meets the minimum even for escalations

### Report Structure
- [ ] YAML frontmatter between `---` delimiters at start of report.md
- [ ] All required fields present: `ticket_id`, `signature_id`, `status`, `disposition`, `confidence`, `leads_pursued` (plus `matched_archetype` and optionally `matched_ticket_id` + `trust_anchors_consulted` for resolved reports)
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
- **Forcing an alert into the closest archetype:** The archetype catalog is a pattern-recognition cache, not the source of truth. If the evidence has features the matched archetype's story doesn't describe, that's a sign the archetype isn't the right fit — escalate as a novel variant rather than force-closing under a close-but-wrong archetype. Tier 2's COMPLETENESS criterion catches this.
- **Skipping sibling archetypes:** When multiple archetypes under the same signature share primitives, resolving to one without running the discriminating lead that would have refuted the other(s) is incomplete. The archetype `story.md` files document the discriminating boundaries ("what takes an alert *out* of this archetype") — read them.
- **Resolving without grounding:** `status=resolved` requires BOTH a `matched_archetype` AND grounding (required anchors confirmed, OR a `matched_ticket_id` citation). An archetype match without grounding is not enough; a ticket citation without a matching archetype is not enough.
- **Stale temporal grounding:** A cached precedent's `anchors_at_time` entries marked `temporal: true` are historical facts that may no longer be true — on-call windows rotate, change tickets close, deploy runs roll back. The current investigation must re-confirm them against live anchors before the precedent's grounding transfers.
- **Skipping leads:** Don't conclude after one lead unless it conclusively discriminates all hypotheses. Most investigations need 2-3 leads.
- **Vague observations:** "The IP appears internal" — did you check? What range? Be specific.
- **Forgetting state transitions:** Every phase change needs a `## PHASE` section header in `investigation.md`. The `infer_state.py` hook validates transitions automatically — if you skip a phase or write headers out of order, the write will be rejected.
