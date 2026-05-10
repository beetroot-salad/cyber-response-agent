# Retrieval Needs — A.4 Walk Annotation

## Headline

The A.4 walk reveals that v2.2's queryable surface is adequate for the coarse retrieval questions (what hypotheses were instantiated, what was the disposition, which leads ran in which loop) but fails specifically where retrieval matters most in a poor-scaffolding case: the partial-prediction-match cap, the partial-authority anchor ceiling, and the severity-ceiling termination mechanism are each load-bearing reasoning facts that land entirely in prose strings. A future agent with no playbook scaffold and a similar alert — shared-role IAM session, first-ever PII bucket access, human-attributed interactive session, no change ticket — could retrieve this case by hypothesis set shape and disposition, but could not extract the three structural lessons that would actually change its reasoning: that the partial human-presence confirmation is insufficient for `++` without authorization context, that instance-integrity anchors are partial-authority for full-layer compromise questions, and that the out-of-band test that would close the case is named in `ceiling_rationale` but not in any queryable field.

---

## The walk in one paragraph

A CloudTrail alert fires on role `data-pipeline-svc` performing 17 ListObjectsV2 calls on a customer-PII bucket (`company-customer-exports`) outside its documented access pattern. Loop 1 eliminates the scheduled-batch hypothesis (no registered job) and scopes the activity to marcus@company.com's interactive SSH session on the instance. Loop 2 confirms marcus MFA'd from his enrolled device, checks instance integrity (clean but partial-authority), finds no concurrent communications, finds no change ticket, and verifies this is marcus's first-ever access to this bucket. ANALYZE: `?ad-hoc-operator-run` caps at `+` (human presence confirmed via MFA+MDM but change-context unmet), `?compromised-instance` caps at `-` (integrity clean but partial-authority), `?compromised-iam-credential` caps at `-`. No adversarial hypothesis reaches `--`. The investigation terminates at severity ceiling, escalated to analyst with a recommendation to contact marcus directly and, if benign, create an archetype for the ad-hoc operator pattern.

---

## Retrieval needs by walk position

### R-1 — At CONTEXTUALIZE, initial hypothesis seeding: "What hypotheses does a prior similar case suggest for an EC2 instance-profile role performing an anomalous S3 list burst?"

**Context:** The agent has the alert in hand: IAM role, EC2 instance-profile session, PII bucket outside documented access, nighttime batch window, no immediate human attribution from the alert payload itself. Before forming hypotheses, a retrieval system could seed the candidate set from prior similar cases.

**Past-investigation queries the agent would want:** "Have we seen a shared service role perform an anomalous list/read on a PII-classified bucket before, with ambiguous attribution, and what hypotheses did that investigation instantiate? What were the initial candidate explanations?"

**v2.2 fields the query would need to match against:** `prologue.vertices[].classification` (to find cases involving `service-session` on a host with a shared IAM role), `prologue.vertices[].attributes.role_sharing_note` (shared role), `prologue.edges[].attributes.api_call` (ListObjects), `prologue.vertices[target].attributes.bucket_classification` (customer-pii), `hypothesize.hypotheses[].name` (what hypotheses were instantiated).

**Indexability:** partial — `hypothesis_index.yaml` (§5's projection) would carry the hypothesis names if the distiller canonicalized the vertex shape. But the vertex shape canonicalization whitelist for `session` type is `{target_host_classification, source_user_classification, privilege_escalation}` — none of which captures `shared_role` or `bucket_classification`. The API call type and bucket sensitivity are in edge and remote-endpoint attributes, not in the canonicalized vertex shape key. The hypothesis set would be found only if a future distiller extends the whitelist.

**If prose-only, what schema change would make it queryable?** Add `role_sharing: bool` and a top-level `scenario_tags: [...]` field (e.g., `["shared-iam-role", "pii-bucket-access", "anomalous-list-burst"]`) that the distiller can index without parsing prose. Alternatively, extend the vertex shape whitelist for `session` to include `role_type: shared|dedicated|automation`.

---

### R-2 — At CONTEXTUALIZE, dead-lead recognition: "Is iam-session-origination-chain known to be attribution-opaque on EC2 instance-profile sessions?"

**Context:** The agent would normally consider tracing the IAM session backward to a human identity via the IAM layer. In this environment, EC2 instance-profile sessions carry no human attribution at the IAM layer — the origination chain terminates at the role attachment. This is an environment fact that, if recorded from a prior run, would silently drop the lead before the agent even considers it.

**Past-investigation queries the agent would want:** "Has iam-session-origination-chain been documented as attribution-opaque on EC2 instance-profile sessions? If so, what was the environment reason, and what alternative leads actually provided human attribution?"

**v2.2 fields the query would need to match against:** `dead_leads_index.yaml` entry for `(iam-session-origination-chain, session:classification=service-session;role_type=instance-profile)`. The companion YAML captures this only in `v-001.concerns[0]` (a prose string).

**Indexability:** prose-only in the companion YAML. The `concerns` field on v-001 says "iam-session-origination-chain lead is attribution-opaque on EC2 instance profiles" but this is a free-form string. The dead-leads projection index would make it queryable if the distiller extracted it — but the companion provides no structured signal for the distiller to extract. The distiller would need to infer "this is a dead-lead note" from the text content, which is unreliable.

**If prose-only, what schema change would make it queryable?** Add a top-level `dead_leads_observed: [{lead_name, vertex_shape, reason}]` block to the companion alongside the `conclude` block, parallel to the distiller's `dead_leads_index.yaml`. This gives the distiller a structured extraction point without requiring prose parsing.

---

### R-3 — At Loop 1, anchor-lookup(job-scheduler): "Have we seen a case where no registered job was found for a service role, but the activity turned out to be a legitimate ad-hoc operator run?"

**Context:** The job-scheduler anchor returned no registered job (l-001), which moved h-001 from null to `-`. This is a significant hypothesis elimination step. A future agent would want to know: in similar cases where job-scheduler returned negative, what was the actual disposition? Did any turn out true positive?

**Past-investigation queries the agent would want:** "Has job-scheduler ever returned no-registered-job for role data-pipeline-svc (or a similar shared-batch role), and what was the ultimate disposition? Were any of those cases true positives?"

**v2.2 fields the query would need to match against:** `l-001.outcome.observations.vertices[v-004].attributes.lookup_result` ("no-registered-job"), `l-001.outcome.observations.vertices[v-004].attributes.registered_jobs_for_role` (empty list), `conclude.disposition`, `conclude.matched_archetype`.

**Indexability:** partial — `lookup_result: "no-registered-job"` is a string enum value in the observation vertex attributes, and `conclude.disposition` is a structured field. A query can match `disposition` cleanly. But `lookup_result` is nested inside `outcome.observations.vertices[].attributes` on a specific anchor-source vertex — not a first-class lead-level field. The fidelity report's recommendation #1 (`trust_anchor_result` structured field) would surface this at the lead level. Currently a retrieval system must traverse: lead → outcome.observations → vertices → filter by classification → read attributes → find lookup_result. That traversal is possible but fragile — it depends on knowing that the anchor result lives in the anchor-source vertex's attributes, not in a dedicated field.

**If prose-only, what schema change would make it queryable?** Implement fidelity report recommendation #1: add `outcome.trust_anchor_result: {anchor_id, result: confirmed|refuted|partial|no-data, structured_fields: {...}}` to trust-mode lead outcomes.

---

### R-4 — At Loop 1, scope(instance, concurrent-ssh): "Have we seen a case where a shared service role's anomalous activity was traced to an interactive SSH session from a named employee, and how did the investigation resolve it?"

**Context:** The SSH session scope (l-002) materialized marcus's active session — a significant finding that both weakens h-001 (scheduled batch unlikely with a human on the instance) and strengthens h-002 (ad-hoc operator run). A future agent seeing a similar pattern would want to know: in prior cases where a service-role anomaly was traced to an SSH session from a human, what proportion were benign vs. true-positive?

**Past-investigation queries the agent would want:** "In investigations where a service-role IAM session's activity was correlated to an interactive SSH session from an employee, what was the disposition distribution? Were any true positives (attacker with stolen credentials using the service role while also SSH-ing)?"

**v2.2 fields the query would need to match against:** `l-002.outcome.observations.vertices[v-005].classification` (ssh-session), `l-002.outcome.observations.vertices[v-005].attributes.authenticated_user` (marcus@company.com — but this is user-specific, not a pattern), `conclude.disposition`, `h-002.weight` (final weight of `?ad-hoc-operator-run`), `h-004.weight` (final weight of `?compromised-iam-credential`).

**Indexability:** structured — `conclude.disposition` and final hypothesis weights are structured fields. The SSH session classification `ssh-session` is a structured classification. A retrieval system could query: "cases where a `service-session` had a correlated `ssh-session` in scope leads and disposition was X." The vertex shape key for `lead_selection_index.yaml` could encode this pattern. However, the correlation between the service-session (v-001) and the ssh-session (v-005) is expressed only through their co-presence in the same investigation — there is no explicit "correlated-with" edge between the IAM session and the SSH session in the prologue or gather.

**If prose-only, what schema change would make it queryable?** Add an explicit `correlated_with: [v-id, ...]` field on session vertices when two sessions on the same host are determined to be temporally correlated during investigation. This would make the IAM-session → SSH-session correlation queryable.

---

### R-5 — At Loop 2, anchor-lookup(vpn-mfa): partial-prediction-match decision on `?ad-hoc-operator-run`: "Have we seen cases where human-presence was confirmed via MFA+MDM but change-context was unmet, and was the + cap correctly applied?"

**Context:** The vpn-mfa anchor confirmed marcus's MFA and device posture (l-004), advancing h-002 to `+`. But p2 (change ticket or comms) was not tested by vpn-mfa. Under rule 6, covering only p1 of {p1, p2, p3} caps the weight at `+` rather than `++`. This is the A.4 case's core tension: the human presence evidence is strong, but the authorization evidence is absent. A future agent in a similar situation would want to know: does partial-prediction-match capping consistently occur in cases like this? Is the `+` cap a reliable signal that the case needs an out-of-band escalation?

**Past-investigation queries the agent would want:** "In cases where `?ad-hoc-operator-run` (or equivalent) capped at `+` due to confirmed human presence but unmet change-context, what did the resolution turn out to be? Were these typically escalated? Did any resolve as true positives?"

**v2.2 fields the query would need to match against:** `h-002.weight` ("+"), `h-002.name` ("?ad-hoc-operator-run"), a signal that the cap was due to partial prediction coverage, `conclude.termination.category` ("severity-ceiling"), `conclude.disposition` ("unclear").

**Indexability:** partial — `h-002.weight` is structured ("+"), and `conclude.termination.category` is structured ("severity-ceiling"). But the *reason* for the `+` cap (partial prediction match, specifically p1 confirmed and p2 unmet) lives in resolution reasoning strings. The pattern "weight is `+` AND termination is `severity-ceiling`" is queryable from structured fields — this combination is itself a meaningful retrieval signal. However, "cap was due to unmet change-context specifically" requires reading the reasoning string on l-008's resolution.

**Schema gap:** v2.2 has no field to express "which specific prediction(s) remained unmet at `+`." The `weight_history` records weight transitions with lead references, but the unmet prediction IDs at the time of the `+` cap are not recorded structurally. A future agent could infer them by comparing the full prediction set against the accumulated `matched_prediction_ids` — but this requires traversal, not a direct field lookup.

**If prose-only, what schema change would make it queryable?** Add `unmet_prediction_ids: [p2]` to the conclude block or to the final resolution that produced the `+` cap. This would make "capped at + because p2 (authorization context) was unmet" directly queryable.

---

### R-6 — At Loop 2, anchor-lookup(ec2-instance-integrity): partial-authority anchor return on `?compromised-instance`: "Has ec2-instance-integrity ever been partial-authority for the 'is this instance compromised at any layer' question, and what does a cap at `-` mean in practice?"

**Context:** The instance-integrity anchor returned clean (l-005), but the cap rationale in the fidelity report's central finding applies: ec2-instance-integrity covers disk/file/IMDSv2 but not in-memory implants or kernel rootkits. This means even a fully clean return cannot advance `?compromised-instance` to `--`. The cap at `-` is correct but non-obvious — the resolution reasoning string explains it, but the structured weight (`-`) does not distinguish "capped at - because evidence weakly refutes" from "capped at - because anchor is partial-authority."

**Past-investigation queries the agent would want:** "In cases where ec2-instance-integrity returned clean and was used as a trust anchor for compromise detection, did the walk proceed to `--` on the compromise hypothesis, or was it always capped at `-`? Is partial-authority consistently the reason for the cap, or does full refutation sometimes happen?"

**v2.2 fields the query would need to match against:** `l-005.concerns[0]` (the partial-authority note — prose string), `l-005.resolutions[0].after` ("-"), `l-005.resolutions[0].severity_of_test` ("moderate"), `l-005.resolutions[0].reasoning` (the partial-authority rationale — prose string), `h-003.weight` ("-").

**Indexability:** prose-only for the partial-authority rationale. The weight `-` and severity `moderate` are structured. But the *reason* the severity was moderate rather than severe — the anchor's partial authority — is in `lead.concerns` (a prose string) and `resolution.reasoning` (a prose string). The fidelity report identified this as a gap: v2.2's authority enum is flat and does not model per-question authority. This walk confirms the gap is load-bearing: a future agent retrieving this case cannot determine from structured fields that the `-` cap was due to partial-authority, not weak evidence.

**If prose-only, what schema change would make it queryable?** The fidelity report's recommendation for `anchor_manifest` per-question authority levels (recommendation #1's extension) is relevant. Add `outcome.authority_for_question: full | partial | not-applicable` to trust-mode lead outcomes, with a `partial_authority_rationale` string. This gives the distiller a structured extraction point for the `anchor_manifest` per-question entry.

---

### R-7 — At ANALYZE, final weight assessment across all hypotheses: "In cases with severity-ceiling termination and `unclear` disposition, what was the distribution of final hypothesis weights?"

**Context:** After all leads run, the final weight state is: h-001 (`?scheduled-batch-run`) at `-`, h-002 (`?ad-hoc-operator-run`) at `+`, h-003 (`?compromised-instance`) at `-`, h-004 (`?compromised-iam-credential`) at `-`. This weight pattern — one benign hypothesis at `+`, three adversarial/alternative hypotheses at `-` — is the signature of a severity-ceiling case. A future agent would want to know: in prior cases with this weight pattern at termination, what was the ultimate resolution after analyst review?

**Past-investigation queries the agent would want:** "In investigations that terminated at severity ceiling with disposition `unclear`, where the most-supported hypothesis was a benign `+` and all adversarial were at `-`, what proportion confirmed benign after analyst follow-up? What follow-up actions closed the case?"

**v2.2 fields the query would need to match against:** `conclude.termination.category` ("severity-ceiling"), `conclude.disposition` ("unclear"), `h-002.weight` ("+"), `h-003.weight` ("-"), `h-004.weight` ("-").

**Indexability:** fully structured — all five of these fields are enums or structured values. A retrieval query on these exact fields is possible without prose parsing. This is one of the places v2.2 performs well: the hypothesis weight distribution at termination is extractable from structured fields. The `lead_selection_index.yaml` projection could record this pattern as a ceiling entry with `max_in_scope_weight: {adversarial: "-"}` as Appendix A.4 describes.

**Schema gap (minor):** The weight at ANALYZE is the final weight, but there is no `final_weight` convenience field on hypotheses. A retrieval system must find the most recent resolution that modified each hypothesis's weight — traversable but not a direct lookup. Adding `hypothesis.final_weight` as a denormalized field in conclude would make this a one-field query.

---

### R-8 — At CONCLUDE, severity-ceiling termination: "What specific out-of-band test would have closed this case, and is that recorded in a queryable way?"

**Context:** The ceiling_rationale names the out-of-band test: "direct confirmation from marcus that the S3 list burst was intentional and authorized." This is the most actionable fact in the entire investigation for a future agent or analyst. A retrieval system that can surface "the previous similar case was closed by direct operator confirmation" would help a future agent understand immediately what escalation path to recommend.

**Past-investigation queries the agent would want:** "In prior cases that terminated at severity ceiling with an out-of-band confirmation requirement, what was the specific confirmation needed? Was it human operator contact, legal-team authorization, or something else? What was the turnaround time?"

**v2.2 fields the query would need to match against:** `conclude.ceiling_rationale` (a prose string naming "out-of-band confirmation from marcus@company.com"), `conclude.termination.category` ("severity-ceiling").

**Indexability:** partial — `termination.category` is structured and queryable. `ceiling_rationale` is a prose string. The specific out-of-band test (contact the human, not "file a ticket" or "wait for a scan") is not expressed in any structured field. A future retrieval system cannot distinguish between "ceiling because operator contact needed" vs. "ceiling because scan tool was unavailable" vs. "ceiling because legal authorization required" without parsing the rationale string.

**If prose-only, what schema change would make it queryable?** Add a structured `ceiling_test: {kind: out-of-band-human-contact | tool-unavailable | legal-authorization | other, subject: <string>}` field to conclude. This would allow retrieval queries like "find cases where ceiling was due to out-of-band-human-contact" — a directly actionable pattern.

---

### R-9 — At CONCLUDE, out-of-band escalation handoff: "What information should the escalation handoff carry for the analyst who will contact marcus?"

**Context:** The investigation terminates at severity ceiling and is escalated. The analyst receiving the escalation needs to know: who to contact (marcus), what to ask (confirm or deny the S3 list burst), what evidence already exists (MFA-confirmed presence, process-tree attribution, no change ticket, first-ever bucket access), and what the disposition would be if confirmed benign vs. confirmed unauthorized. None of this is in structured v2.2 fields — it is in the summary string and in scattered vertex attributes.

**Past-investigation queries the agent would want:** "In prior escalation cases where the ceiling was due to out-of-band human contact, what information did the analyst need to include in the contact message? What was the standard escalation template for this case type?"

**v2.2 fields the query would need to match against:** `conclude.summary` (prose), `conclude.ceiling_rationale` (prose), `h-002.weight` ("+"), `v-008.identifier` ("marcus@company.com"), `v-010.attributes.first_ever_access` (true).

**Indexability:** prose-only for the escalation narrative. `v-010.attributes.first_ever_access` is a queryable boolean. `h-002.weight` is queryable. But the package of information an analyst needs — "this specific person, these specific facts, this specific question to ask" — is not expressible in any v2.2 schema field. The schema has no `escalation_contact` or `analyst_handoff` block.

**If prose-only, what schema change would make it queryable?** Add an `escalation_handoff` block to conclude (triggered when `termination.category` is `severity-ceiling` or `exhaustion-escalation`): `{contacts: [{name, email, role}], open_questions: [{question, why_unanswerable_in_scope}], supporting_facts: [{fact_id, structured_value}]}`. This would make the handoff information retrievable by future similar cases.

---

### R-10 — Cross-loop: "Is there a structured signal distinguishing `?ad-hoc-operator-run` at `+` because of strong partial evidence from `+` because of weak overall evidence?"

**Context:** h-002 ends at `+` with strong evidence for p1 and no evidence for p2. A hypothetical investigation where p1 and p2 were both weakly supported would also end at `+`, but the retrieval value of the two cases is very different: the first (this case) says "MFA+MDM is confirmed, authorization context is missing — escalate for authorization verification"; the second says "weak overall evidence — escalate for more investigation." These require different analyst actions but produce the same structured weight.

**Past-investigation queries the agent would want:** "In cases where h-002 (?ad-hoc-operator-run) was at `+` at termination, was the `+` due to strong partial prediction coverage (human presence confirmed, authorization unmet) or due to weak overall evidence? Which prediction IDs were confirmed vs. unmet?"

**v2.2 fields the query would need to match against:** Per-prediction confirmation status at the time of termination — which prediction IDs were matched across all resolutions on h-002. This requires aggregating `matched_prediction_ids` across all resolutions for h-002: l-004 matched p1, l-008 failed to match p2, l-003's scope evidence supports p3. The aggregation is possible by traversal but not by direct field lookup.

**Indexability:** prose-only at the per-prediction level. Aggregated matched vs. unmet IDs are computable but not stored. A retrieval system cannot answer "which predictions were confirmed at termination?" without replaying all resolutions. See R-5 for the same gap from a different angle.

**If prose-only, what schema change would make it queryable?** Add a `prediction_status_at_termination: [{hypothesis_id, prediction_id, status: confirmed|unmet|not-tested}]` block to conclude. This is derivable from the gather section but is expensive to re-derive; denormalizing it into conclude makes it directly queryable.

---

## Cross-cutting findings

### Fields that ARE structured enough for retrieval

- `conclude.termination.category` — four-enum field; "severity-ceiling" is directly queryable. R-7, R-8.
- `conclude.disposition` — three-enum field; "unclear" is directly queryable. R-7.
- `conclude.matched_archetype` — null is a queryable value; cases with null are retrievable. R-3.
- `hypothesis.weight` (final weight) — enum; the distribution {h-001: -, h-002: +, h-003: -, h-004: -} is reconstructable from structured fields. R-7.
- `hypothesis.name` — string enum; `?ad-hoc-operator-run` is findable by exact-match. R-5.
- `lead.mode` — enum (materialize/scope/trust); trust-mode leads are distinguishable from scope leads. R-3.
- `lead.loop` — integer; loop sequence is extractable. Cross-loop.
- `v-010.attributes.first_ever_access` — boolean; this specific finding is structured and directly queryable. R-9.
- `conclude.confidence` — enum; "medium" is queryable (though coarse).

### Fields that are NOT structured enough

- **`ceiling_rationale`** — prose string naming the specific out-of-band test needed. Corroborates fidelity report finding about `conclude.ceiling_rationale` being prose-only. R-8.
- **`trust_anchor_result`** — The anchor outcomes (job-scheduler: no-registered-job, change-management: no-ticket, ec2-instance-integrity: clean) live in anchor-source vertex attributes as string values, not in a structured field on the lead outcome. Directly corroborates fidelity report recommendation #1. R-3, R-6.
- **`partial-authority rationale`** — Why ec2-instance-integrity caps `?compromised-instance` at `-` not `--` is in `lead.concerns` and `resolution.reasoning` prose. The per-question authority gap is new to this walk vs. the rule-5710 case (where all anchors were either confirmed or refuted, not partial-authority). R-6.
- **`unmet prediction IDs at termination`** — Which specific predictions remained unconfirmed at the `+` cap on h-002 is derivable but not stored. R-5, R-10.
- **`dead-lead signaling`** — The iam-session-origination-chain drop lives in `v-001.concerns` prose. No structured mechanism to tell the distiller "this is a dead-lead observation." R-2.
- **`escalation handoff`** — Who to contact, what to ask, what evidence to provide. Entirely in prose. R-9.
- **`ceiling_test.kind`** — The type of out-of-band test needed (human contact vs. tool gap vs. legal authorization) is not expressed in any structured field. New finding, not in fidelity report. R-8.
- **`correlated-session signal`** — The correlation between the IAM service-session (v-001) and the human SSH session (v-005) is expressed only through co-presence in the investigation, not as a structural edge. R-4.

### Schema additions ranked by retrieval value

**Corroboration of fidelity report candidates, then new additions:**

1. **`outcome.trust_anchor_result` structured field on trust-mode leads** (fidelity report recommendation #1) — This walk adds urgency beyond the rule-5710 case. Three anchors (job-scheduler, ec2-instance-integrity, change-management) each produced distinct result types: refutation (no-registered-job), partial-authority clean, and no-ticket. All three are in vertex attribute prose. A structured `{anchor_id, result: confirmed|refuted|partial|no-data, structured_fields: {...}}` field would unblock R-3, R-6, and partially R-5. **Unlocks: R-3, R-6.** Priority: highest, corroborated with added urgency.

2. **`prediction_status_at_termination` in conclude** (not in fidelity report — new) — This walk reveals that the partial-prediction-match cap (the A.4 case's core feature) produces no queryable signal about *which* predictions were unmet. A `[{hypothesis_id, prediction_id, status}]` denormalized block in conclude would unblock R-5 and R-10. **Unlocks: R-5, R-10.** Priority: high, new finding.

3. **`ceiling_test.kind` structured enum in conclude** (not in fidelity report — new) — The severity-ceiling termination mechanism names an out-of-band test in prose but gives the distiller no structured extraction point. A `ceiling_test: {kind: out-of-band-human-contact|tool-unavailable|legal-authorization|other, subject: string}` field would make "what would close this case?" queryable. **Unlocks: R-8.** Priority: high, new finding.

4. **`mandatory_adversarial: true` on hypothesis** (fidelity report recommendation #3) — This walk corroborates: h-003 and h-004 should be marked mandatory-adversarial (the agent cannot conclude benign while they remain above `--`). Without the flag, a validator cannot enforce this rule mechanically. **Unlocks: validator enforcement of severity-ceiling termination logic.** Priority: medium, corroborated.

5. **`trace: string` in conclude** (fidelity report recommendation #5) — The walk follows a clear path: `anchor-lookup(job-scheduler)→scope(ssh)→scope(process-tree)→anchor-lookup(vpn-mfa)→anchor-lookup(integrity)→scope(comms)→scope(history)→anchor-lookup(change-mgmt)→escalate:ceiling`. This trace is not stored anywhere. For similarity search across investigations, the trace is the highest-density single field. **Unlocks: similarity search.** Priority: medium, corroborated.

6. **`dead_leads_observed` top-level block** (not in fidelity report — new, minor) — The rule-5710 fidelity report described dead leads as implicit (dropped silently from the pool); this walk reveals that the *companion* also has no structured slot for dead-lead observations. Adding `dead_leads_observed: [{lead_name, vertex_shape, reason}]` to the companion would give the distiller a clean extraction point for `dead_leads_index.yaml` updates. **Unlocks: R-2.** Priority: medium, new finding.

7. **`tooling_gaps` structured list in conclude** (fidelity report recommendation #4) — This walk does not have a tooling-gap-driven ceiling (the ceiling is out-of-band-human-contact, not a tool unavailability). Neutral on urgency. Priority: low in this walk, medium in aggregate.

8. **`prediction_mode: any | all` on hypothesis** (fidelity report recommendation #7) — This walk hits the same OR-clause issue: `?ad-hoc-operator-run`'s authorization evidence could come from a change ticket OR from Slack comms (p2 models these as a single conjunction, which misrepresents the disjunction). The fidelity report identified this; this walk corroborates with a concrete example. **Unlocks: accurate rule 6 completeness checking.** Priority: medium, corroborated.

9. **`outcome.authority_for_question: full|partial`** (extends fidelity report recommendation #1) — This walk reveals a gap the rule-5710 case did not exercise: partial-authority anchor returns that are structurally clean but epistemically limited. The per-question authority is a first-class reasoning fact in A.4. A structured field on trust-mode lead outcomes naming the authority level for the specific question answered would unblock R-6. **Unlocks: R-6.** Priority: high, new (extends recommendation #1).

10. **`escalation_handoff` block in conclude** (not in fidelity report — new) — The analyst-facing handoff information is entirely in prose. For escalations driven by out-of-band requirements, a structured handoff block would make the "who to contact, what to ask, what evidence exists" package machine-readable. **Unlocks: R-9.** Priority: medium, new finding.

---

### What the original A.4 description (Appendix A) assumes the schema can do that v2.2 can't

Appendix A.4 describes three distiller contributions at case close:

**`lead_selection_index` with `max_in_scope_weight: {adversarial: -}`** — This is a §5 projection, not a §3 schema field. v2.2 *can* produce a distillation pass for this if:
- `conclude.termination.category` is "severity-ceiling" (structured, extractable)
- All adversarial hypotheses have final weights (structured, extractable)
- The distiller knows which hypotheses are "adversarial" (NOT structured — requires `mandatory_adversarial: true` flag or heuristic inference from hypothesis name)

So: partial distillation is possible (ceiling + weight distribution), but the "adversarial" designation requires a schema addition (fidelity report recommendation #3). Without it, the distiller would need to infer adversarial status from hypothesis names like `?compromised-*`, which is fragile.

**`pitfall_index` with three learned entries** — The three pitfalls Appendix A.4 identifies are:
1. Partial-prediction-match cap (`?ad-hoc-operator-run` at `+` due to unmet change-context)
2. Partial-authority anchor cap (`?compromised-instance` at `-` due to ec2-instance-integrity coverage limits)
3. Pivot-to-out-of-band (`?compromised-iam-credential` requires out-of-band confirmation to resolve)

Of these, pitfall #1 is partially derivable from structured fields (`h-002.weight` = `+` at a severity-ceiling, combined with the full prediction set on h-002). Pitfall #2 requires parsing `lead.concerns` (the partial-authority note). Pitfall #3 requires parsing `ceiling_rationale`. None of the three is fully derivable from structured fields alone. The distiller would need all three schema additions proposed above (prediction_status_at_termination, authority_for_question, ceiling_test.kind) to extract these pitfalls without LLM assistance.

**`anchor_manifest` entry for `ec2-instance-integrity` per-question authority** — This requires `outcome.authority_for_question` (proposed above). Without it, the distiller can add `ec2-instance-integrity` to the anchor_manifest but cannot record the per-question authority note structurally. The note would need to be extracted from `lead.concerns` prose — possible with a Haiku extraction pass, but not a deterministic structural extraction.

**Summary:** v2.2 can produce approximate distillations for all three A.4 contributions, but none is fully mechanical. The ceiling entry in `lead_selection_index` is the closest to structural (requires `mandatory_adversarial` flag). The three pitfall entries all require at least one new structured field or a Haiku extraction pass.

---

## Bottom line

v2.2 is **partially indexable** for a poor-scaffolding investigation — call it partial/yes-with-gaps. The coarse retrieval questions (what was the disposition, what termination category, what hypotheses were active, what was the final weight distribution) are fully answerable from structured fields. This is enough for broad-strokes case retrieval: a future agent can find "prior cases with severity-ceiling termination and unclear disposition" efficiently. But the three structural lessons that make this specific case valuable — the partial-prediction-match cap on `?ad-hoc-operator-run`, the partial-authority ceiling on `?compromised-instance`, and the specific out-of-band test that would close the case — are each in prose strings. The minimum integration story for useful RAG on v2.2 companions is: extract `conclude.termination.category`, `conclude.disposition`, `hypothesis[].name + weight` (final), `conclude.matched_archetype`, and `conclude.ceiling_rationale`; index the first four as structured fields; treat `ceiling_rationale` as a dense prose embedding. The three must-have schema additions to make the A.4 lessons fully retrievable are: (1) `outcome.trust_anchor_result` with `authority_for_question`, (2) `prediction_status_at_termination` in conclude, and (3) `ceiling_test.kind` enum.
