---
signature_id: SIGNATURE-ID
last_updated: YYYY-MM-DD
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: SIGNATURE-ID

## Hypothesis Catalog

### ?hypothesis-1
Description of the first candidate explanation.

**Typical profile:** Key indicators that characterize this hypothesis.

### ?hypothesis-2
Description of the second candidate explanation (must include at least one adversarial hypothesis).

**Typical profile:** Key indicators.

---

## Lead List

### lead-name-1
**Query:** What to search for.

> **Tip:** Reference common knowledge inline with `@import:name` — e.g., `@import:lesson-name`. The resolver loads referenced files from `knowledge/common/lessons/` automatically at skill load time.

**Discriminates:** Which hypotheses this lead helps distinguish.

| Hypothesis | Prediction |
|------------|------------|
| ?hypothesis-1 | Expected observation if hypothesis-1 is true |
| ?hypothesis-2 | Expected observation if hypothesis-2 is true |

---

## Screen

<!-- Optional but recommended. Define fast-path patterns for common resolutions.
     The screen subagent checks these before the full investigation loop.
     Only include patterns with unambiguous mechanical indicators.
     For high/critical severity signatures, screen leads must meet MIN_LEADS_BY_SEVERITY. -->

| Pattern | Indicators | Leads | Action | Precedent |
|---------|-----------|-------|--------|-----------|
| {pattern} | {indicator-1, indicator-2, ...} | {lead-1, lead-2} | {disposition} | {precedent.json} |

<!-- Remove this section entirely if no clear fast-path patterns exist. -->

---

## Start With

Recommend which lead to pursue first and why.

---

## Auto-Close Criteria

All must be true:
1. Exactly one hypothesis remains with `++` support
2. All adversarial hypotheses have `--` refutation
3. A matching precedent exists
4. No escalation triggers present
5. Confidence is high

## Escalation Criteria

Escalate immediately if ANY:
- [Condition 1]
- [Condition 2]

## Scope

Define the investigation boundary.
