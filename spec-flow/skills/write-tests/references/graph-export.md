# Optional graph export

Read only when a caller or repository requires a spec-coverage graph, or when maintaining a historical graph contract. `write-code-from-tests` accepts compact contracts without this export. The graph is a projection of the reviewed contract plus grounded structure, not a prerequisite for constructing tests. It remains subject to the existing machine checks; this adapter preserves their schema.

Read **schema.md** for the artifact language and **rules.md** for rule meanings, claims/citations and the artifact shape. Use current finding routing: facts go to probes, test defects to authors, and consequential design choices to discuss-issue. Do not reconstruct the retired premise/frontier pipeline or automatically escalate every computed finding to a human.

## Export from settled behavior and observed structure

Use the current design, contract map, decisions, claims and reviewed tests. Materialize demands with stable IDs and existing `discharged_by` test pointers, then their bound actors/boundaries/edges/facets and relevant grounded neighbors. Preserve the design's identity/ownership, actual callers and shared-resource readers/writers, execution contexts and relevant input partitions. Use code names where the checkers join by name, and reconcile names/axes before validation.

Do not fabricate certainty to fill formal slots. An `unknown` is routed to a lookup or a consequential design decision. A missing interaction the export reveals may require a new test or design amendment; reconcile it through the normal loop and recheck affected contract assertions. Update the graph after material revisions. A mechanically clean graph cannot certify a coarse or incomplete partition.

The graph artifact includes `base`, `tests`, demands, structure/delta, gate record and claims as defined in rules.md. Set `base` to the actual recorded fork commit and `tests` to the suite path. Carry the handoff fields read by the current implementer/adversary: `forks` with actual resolution and `resolved_by: human | auto`, `deviations`, `deferred`, `nullstub_passes`, `drops`. Empty collections are fine; do not invent forks or historical phases. Each drop has an in-scope disposition or explicit design exclusion; a known defect cannot hide in `deviations`.

## Validate and reconcile

Run the supported toolchain over the export and suite:

```
spec-graph lint <artifact>
spec-graph gate <artifact> --residue
spec-graph binds <artifact>
spec-graph claims <artifact>
spec-graph calls <artifact>
spec-graph nullstub <artifact> --python <project-interpreter>
```

Complete the gate's judgment portions and record all required evaluated rules, fired outcomes, demand discharges, citations and decisions. Then run `spec-graph gate <artifact>` to verify that record. Exit 2 means a check could not look, never clean. Triage null-stub results using review.md; the existence of tool findings must be resolved, not written into a handoff as proof of readiness. Use only existing explicit waivers/exclusions, not newly invented ones to make commands pass.

Reconcile in both directions: each map entry, adopted decision and consequential discovery is represented in demands/tests or its explicit disposition; each normative graph demand follows from the design. When the export changes requirements or tests, an independent reviewer rechecks the affected contract. Do not require another independent agent for purely mechanical serialization corrections.

Before implementation, `spec-graph actors --base <base>` lacks the new production diff. Record the planned context census and implementation-stage actor check in `handoff.deferred`, along with deferred guard-partition checks and unexercised assertion groups. Do not claim they already ran. Probe evidence does not substitute for an enforcing test.

## Commit and handoff

Commit tests plus `spec_graph_<slug>.yaml` at the profile's corpus location; keep scratch state out. The reviewed test contract is authoritative together with the design; discrepancies with the graph block handoff until reconciled. Include design revision, base and tests ref in the issue note. When publishing is authorized, push and verify the remote ref before handing off to write-code-from-tests. Honest and adversarial work must use that same immutable contract.

## Repairs after implementation exists

Follow **contract.md** for the shared repair-ref procedure. Include updated graph bindings and decisions with the reviewed test repairs on the contract-only lineage, retaining the original base. The honest branch incorporates that revision; adversaries fork the revised contract ref, never the implementation tip. Disclose implementation-informed repairs rather than fabricate a new independent tests-first run.
