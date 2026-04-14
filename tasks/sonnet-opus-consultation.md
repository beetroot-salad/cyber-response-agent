---
title: Runtime Opus→Sonnet consultation design (two call-points)
status: backlog
groups: sonnet, cost
---

Belt-and-suspenders: keep knowledge-maturation investment as primary defense, add narrow runtime Opus consultation at 1–2 high-leverage points as a backstop.

**Consultation point 1 — HYPOTHESIZE → GATHER boundary (query construction + hypothesis completeness)**
Input: {alert, active_hypotheses, selected_lead, lead_definition}
Opus returns: {minimum_discriminating_fields_to_query, flagged_bundled_hypotheses, missing_mechanism_variants}
This blocks the GATHER dispatch until Opus approves the query shape.

**Consultation point 2 — ANALYZE → CONCLUDE boundary (only when adversarial is being refuted on circumstantial evidence)**
Hook-level gate: "does the ANALYZE assessment assign -- to the adversarial hypothesis based on anything other than an authoritative query result?" If yes → consult Opus before CONCLUDE. Gate catches "coherent confabulation" without always-on consultation cost.

**What Opus contributes**: field schema awareness for SIEM queries; mechanism-variant enumeration (splitting bundled hypotheses); environment-knowledge integration.

**Not included**: a CONCLUDE-side consultation that duplicates Tier 2 judge work.

Defer implementation to migration session. Design-only here.
