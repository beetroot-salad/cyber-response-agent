# The design and its grounding

Read when drafting, reviewing, or amending a design. Keep the design useful to both the human deciding it and the cold agent turning it into tests. Lead with behavior, models, flows, and trade-offs. Grounding records support those choices; they are not another specification the human must approve.

Scale detail to uncertainty, behavioral coupling, and the consequence of failure. A small settled correction can fit in a few paragraphs. Do not fill empty sections or manufacture alternatives for ceremony.

## Human-facing design

Include these elements where relevant:

- **Problem and intended change.** Who experiences the problem, what the feature adds or fixes, and representative before/after behavior. Distinguish existing behavior from proposed behavior.
- **Scope and intent.** Observable obligations, who relies on each, and what would reveal a violation. Give obligations stable names or IDs for downstream traceability. State deliberate non-obligations and relevant boundaries; do not enumerate every conceivable exclusion. Keep broad promises broad: listing known surfaces does not silently restrict them.
- **Principles and design properties.** Cite the project's principles document (profile `conventions.principles`) and state additions or overrides. Give each new property its rationale, consequences, and relevant limits. Mark proposed properties until adopted. Properties should guide unlisted cases, not merely praise simplicity or reliability. If principles are absent, clarify the consequential preferences with the human; do not invent project policy.
- **Data model and ownership.** Entities and identity, relationships, authoritative owners, stored versus derived facts, important invariants, lifecycle, and migration/compatibility where affected. Include enough to decide the model without prescribing incidental field or helper names.
- **Flows.** How a request or event moves through the system, its boundaries and state transitions, where outcomes become observable, and credible partial-failure/recovery behavior. Discuss retry, cancellation, concurrency, or ordering when they affect a promised property or interact with shared state.
- **Architecture and decisions.** Chosen mechanisms, the obligations they discharge, and the significant alternatives and trade-offs. Explain why a choice fits this scope and the design properties. Remove a mechanism with no justified purpose or expose the missing requirement. Carry user choices and reasoning accurately; separate adopted decisions from agent recommendations.
- **Representative scenarios and boundaries.** Use a few cases to demonstrate how the model and properties determine outcomes. An edge case should reveal or test a rule, not become an isolated requirement by default. Name consequential uncertainty and deferred verification explicitly.

Use diagrams when they clarify a model or flow. Do not replace the design with an implementation checklist, graph schema, test catalog, or reviewer transcript.

For compatibility with existing `write-tests`, retain recognizable **Principles**, **Intent**, and **Design** sections: intent contains the named obligations and explicit non-obligations; design contains models, flows, and mechanisms linked to those obligations. Background facts remain identifiable as background, not accidental requirements. This is design-level typing: distinguish obligations, mechanisms, and background facts. Formal demand kinds, graph addresses, and bindings are derived downstream; these distinctions need no separate demand ledger here.

When access or trust changes, identify the affected assets, authoritative actors, and allowed flows; derive obligations from those boundaries rather than enumerate attacks. When a hot path or fan-out changes, state relevant load/growth assumptions and distinguish performance targets from measured behavior. Use these concerns only where the change warrants them; unsupported guarantees remain unresolved.

## Supporting grounding

Record the repository/base revision and relevant external versions or configuration. Verify factual assumptions that support a design decision, a promised property, or a realistic test boundary. Do not perform a mandatory per-sentence sweep of background prose.

- **Referential:** a symbol, path, flag, branch, or neighboring design exists as described. Read the source and cite it. Read issues/PRs whose designs this one relies on and check for conflicting owners, models, or flows.
- **Behavior:** current code or a dependency behaves a certain way on an input. Execute a focused probe; source inspection or documentation alone does not establish observed behavior.
- **Census:** these are all the relevant callers, writers, surfaces, or execution contexts. Record a reproducible search and its scope/results. Follow process boundaries when relevant. Use symbol-reference tooling when lexical search cannot establish the set; a partial search is not an exhaustive census.
- **Reachability:** a value is constrained, or one actor cannot reach a resource. Try to falsify the claim. Use an executed break-attempt and a positive control showing that the channel works. Failure to find a counterexample is `unrefuted`, not proof.

Probe only in an appropriate environment; unavailable or unsafe-to-execute checks remain unresolved. A refuted assumption requires revising the design or explicitly changing the assumption it depends on. Do not leave contradictory verdicts and expectations in the current revision.

Retain a fenced YAML **`claims:`** block so existing downstream skills can inherit evidence. Each entry has `{id, kind, claim, probe, probe_kind, observed, verdict}`. Preserve IDs across amendments; update observations when the evidence changes. `probe` identifies the source or reproducing command with relevant input and environment, not an assertion that a check happened.

- `kind`: `referential | behavior | census | reachability`.
- `probe_kind`: `executed | read | search`; use the actual instrument. Behavior needs `executed`; a census uses `search`.
- `verdict`: `holds | refuted | unrefuted | unprobed | deferred`. Reachability's ceiling is `unrefuted`. An unexecuted or failed probe never earns `holds`.

```yaml
claims:
  - id: C1
    kind: behavior
    claim: "An identical replay currently creates a second record."
    probe: "<command and input, at the recorded base revision>"
    probe_kind: executed
    observed: "<actual output or evidence location>"
    verdict: holds
```

Include the actual claims block in the issue/document handoff or a durably linked companion that the next worker can access cold. The current write-tests ledger must inherit the block verbatim; local scratch paths alone are not a durable handoff. Avoid making the human read the ledger to understand the design.

## Readiness and amendments

Name the design revision (commit, document revision, or issue-comment permalink), grounding base, and review disposition. Summarize the material corrections and any unresolved verification that could affect contract authoring. A skipped independent review needs a reason. Known design contradictions or unresolved consequential choices block readiness; bounded implementation details do not. An unresolved factual assumption also blocks readiness when its plausible outcomes require different contracts or architecture. Otherwise record the assumption, how it will be checked, and which downstream role owns that verification.

An amendment records:

- The defect or new evidence and the affected design property.
- The chosen patch or dissolving change, trade-offs, and who decided it.
- Changes to obligations, models, flows, architecture, or scope; unchanged commitments remain in force.
- Which grounding, tests, and implementation regions must be rechecked.

Publish a revised current design with a pointer to its predecessor, rather than leave downstream workers to merge contradictory comments. Revalidate affected evidence against the current base. Contract construction may uncover further holes: readiness is a commitment to this candidate design, not a claim of exhaustive completeness.
