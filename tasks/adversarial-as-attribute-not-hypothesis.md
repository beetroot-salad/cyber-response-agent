---
title: Reframe adversarial hypothesis rule as vertex/edge attribute, not parallel hypothesis
status: done
groups: hypothesize, invlang, validation
---

**Blocker.** The current "maintain at least one adversarial hypothesis until explicitly refuted" rule (SKILL.md §HYPOTHESIZE → Completeness checks, and mirrored in inv-lang §Hypothesis) forces a parallel `?compromise-followup`-style hypothesis alongside mechanism hypotheses. This doubles the frontier without contributing a topology distinction. The mechanism hypotheses already partition the edge/vertex space exhaustively — adversarial-vs-benign is orthogonal to which mechanism is true.

**Cleaner framing.** Legitimacy is an **attribute** of the confirmed parent vertex and its edges, not a separate mechanism:
- Is the entity (the parent process, the operator identity, the CI service account) approved for this action? → trust-anchor lookup on the vertex.
- Is the ancestry chain vouched for? → attribute on the `spawned` / `triggered_by` / `initiated_by` edge.

Under this framing, a confirmed `?runtime-process` parent is equally consistent with an application shelling out during normal work and an attacker with RCE shelling out from the same application. The mechanism is identical; the legitimacy attribute differs. That attribute is resolved by trust-anchors (image-baseline, oncall-schedule, deploy-runs, workload-manifest) after the mechanism is confirmed.

**Concrete proposal — Approach C (hypothesis declares contract, edge carries verdict):**

Legitimacy is fundamentally a property of the (source_vertex, edge, target_vertex, authority) quadruple at time T. The CFO/IT-operator test case makes this explicit: same `read` edge relation, same target storage, different source-identity → different verdict. The edge is the natural carrier of the verdict; the hypothesis is the natural declarer of "which edges' legitimacy is load-bearing for my disposition."

Three-way decomposition of adversariness (replacing the flat "maintain adversarial hypothesis" rule):

- **Mechanism-level** — when upstream parent classifications naturally include an adversarial variant (e.g., `adversary-controlled-process`), enumerate it alongside benign variants. Normal mechanism enumeration; no special rule.
- **Attribute-level (legitimacy)** — when the same mechanism is consistent with benign or adversarial intent depending on authorization (CFO vs IT operator), declare a `legitimacy_contract` on the hypothesis. The contract names the edge(s) whose authority verdict decides the disposition and which anchor resolves them. This is the common case.
- **Future-edge (orthogonal topology)** — when the adversarial discriminator is a separate downstream edge (5710 → 5715 success), retain the hypothesis shape attached to the hypothetical future edge. That's a real topology question, not a legitimacy attribute.

Schema changes (see `docs/investigation-language.md` schema delta — drafted alongside this task):

1. **Hypothesis gains `legitimacy_contract: [...]`** — optional list. Each entry: `{id, edge_ref, anchor_kind, predicate, on_unauthorized, on_indeterminate}`. `edge_ref` is either `proposed` (this hypothesis's own proposed_edge) or a confirmed `e-*` id.
2. **Edge gains `legitimacy: {...}`** — optional block populated when a lead resolves a contract against this edge. Fields: `verdict` (authorized | unauthorized | indeterminate), `anchor_kind`, `anchor_query`, `as_of`, `resolved_by_lead`, `fulfills_contract` (back-reference `h-{id}.lc{n}`).
3. **Append-only preserved via backward traversal.** The hypothesis is written once with its contract and never mutated. When the resolving lead fires, it either (a) creates the proposed edge with an inline `legitimacy` block, or (b) for an already-confirmed edge, writes a legitimacy attribute-update (extends `attribute_updates` to accept `edge: e-{id}` targets, not just vertices). Either way, the edge side points back to the hypothesis — never the reverse.
4. **Predicate is natural-language.** Evaluated by the agent against anchor data. Any AND/OR combination of conditions is permitted — no structured predicate DSL. The agent reads the predicate, queries the anchor, judges.
5. **New validator rules:**
   - `legitimacy_contract.edge_ref` resolves to `proposed` or an existing `e-*`.
   - Every `edge.legitimacy.fulfills_contract` points to an existing hypothesis + contract entry.
   - A confirmed-weight hypothesis (`++`/`+`) with an unfulfilled contract — or any fulfilling edge with `verdict: indeterminate` — caps disposition at `unclear` + `status: escalated`. `benign` requires every contracted edge to carry `verdict: authorized`.
   - Any `verdict: unauthorized` forces `status: escalated` (disposition becomes `true_positive` or `unclear` depending on remaining evidence).
6. **Drop the "maintain adversarial hypothesis until `--`" rule** from SKILL.md §HYPOTHESIZE completeness checks and operating principle #4. Teeth move from hypothesis-bookkeeping to evidence-based structural enforcement via the validator rules above.

**Open questions resolved:**
- Edge-ref rewrite on materialization? — No. Hypothesis stays append-only; the new edge carries `fulfills_contract` backward. Query direction is edge → hypothesis.
- Multi-anchor contracts? — Natural language predicate; any AND/OR combination. LLM evaluates.
- `indeterminate` semantics? — Caps at escalate; structural via validator.
- `fulfills_contract` back-reference explicit or derivable? — Explicit. Enables validator checks without graph traversal.
- Singular vs plural edge verdicts? — Plural (`legitimacy_resolutions: [...]`). Real case is parallel policy layers on one edge (IAM × data-classification × time-of-day), not compromise chains.
- Legitimacy contracts for session-hijack / forgery? — No. Contracts answer policy-authorization questions only. Integrity/forgery questions are mechanism-level — enumerate them as hypotheses on the `authenticated_as` edge (`?normal-authn` vs `?hijacked-session`), discriminated by behavioral observation (impossible travel, device-fingerprint shift, MFA anomaly). Contracts bottom out at the AuthN edge; below that is mechanism.

**Behavioral-consistency prediction (opt-in addition to hypothesis, no schema extension):**

A legitimacy contract resolved `authorized` establishes policy compliance, not integrity. The compromised-credential case (policy says yes, pattern says off) needs a third check. Rather than schematize it, extend the hypothesis-prediction guidance: when baseline data exists, the agent MAY add a single baseline-consistency prediction using the existing `predictions`/`refutation_shape` machinery.

Gates — all three must hold before writing the prediction:
1. Baseline data for the identity is queryable (not a new/rare identity; not a by-design-no-baseline account like break-glass).
2. Prediction is scoped to the alert's entities and window — not a broad anomaly scan. Threat hunting is explicitly out of scope.
3. Outcome is weight-sensitive — if already at `++` or `--` on other evidence, skip it.

Severity cap: baseline-consistency leads default to `moderate` severity (one-step movement, cap at `+`/`-`). Never `severe` — identity patterns drift and "looks consistent" is easy by coincidence. If baseline is unavailable, write the prediction anyway, note in `concerns` that baseline was not queryable, and let the verdict float to `indeterminate`. Do not confabulate baselines.

**Schema changes (finalized):**

1. `hypothesis.legitimacy_contract: [...]` — optional list; per-entry `{id, edge_ref, anchor_kind, predicate, on_unauthorized, on_indeterminate, concerns}`.
2. `edge.legitimacy_resolutions: [...]` — optional plural list; per-entry `{verdict, anchor_kind, anchor_query, as_of, resolved_by_lead, fulfills_contract, concerns}`.
3. `lead.outcome.attribute_updates[].target: v-{id} | e-{id}` — extended from vertex-only to accept edge targets.
4. Validator rules #19–#22 enforcing edge_ref resolution, back-reference resolution, legitimacy-gated disposition, and attribute-update target shape.

**Guidance changes:**

- SKILL.md §HYPOTHESIZE: drop the "parallel adversarial hypothesis" rule; replace with the three-shape decomposition (mechanism / attribute / future-edge) and gates for optional behavioral-consistency predictions.
- SKILL.md operating principle #4: drop "maintain adversarial hypothesis until `--`"; replace with pointer to legitimacy contracts and the policy-vs-integrity boundary.
- docs/investigation-language.md: new §Legitimacy-as-edge-attribute subsection under Philosophy; new `legitimacy_contract`/`legitimacy_resolutions` fields in §Hypothesis and §Edge; validator rules #19–#22; commentary establishing contracts = policy, mechanism = integrity, and contracts bottom out at AuthN.

See `experiments/hypothesize-subagent-v2/schema-delta-legitimacy.md` for the full draft; v2.8 spec being applied inline to `docs/investigation-language.md`.

**Why it's a blocker.** The hypothesize-subagent v2 pilot (April 2026) and the rule-100001 playbook revision both surfaced this: forcing `?compromise-followup` as a seed makes clean mechanism enumeration impossible. Until the rule is reframed, every playbook rewrite either violates the rule (cleaner but non-compliant) or inflates the hypothesis space (compliant but ugly). For the rule-100001 revision we chose the former pragmatically; the validator does not yet enforce the adversarial-hypothesis rule, so there is no immediate break. But the inconsistency is now visible in the seed and will confuse the subagent extraction work.

**Scope of the change.** Touches:
- `soc-agent/skills/investigate/SKILL.md` §HYPOTHESIZE
- `docs/investigation-language.md` §Hypothesis + §Validator rules
- Every playbook's hypothesis seeds (rule-5710 pending rewrite, rule-100001 already written in the cleaner style and should not regress)
- Validator implementation in `soc-agent/scripts/invlang/`

**Downstream dependencies.** Hypothesize subagent pilot v2 is deferred until this is resolved — otherwise scoring hinges on whether an arm pays lip service to the rule, which is noise. See `experiments/hypothesize-subagent-v2/`.