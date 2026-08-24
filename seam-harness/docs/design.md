# Seam discovery and handoff validation for decomposed dispatch

**Status:** first implementation design. Independent from `defender`. This document consolidates the original design sketch, its review addendum, and the subsequent decision to preserve semantic judgment rather than mechanize it.

## 1. Frame

A decomposition is a claim about a dependency graph that is not directly known. Top-down, a seam claims independence. Bottom-up, a synthesis group claims dependence. Both are hypotheses about the same hidden structure.

There is an operational asymmetry:

- Seam placement is a prior chosen before work supplies evidence.
- Synthesis grouping is a posterior informed by leaf behavior, conflicting assumptions, refusals, surprises, and integration failures.

The harness therefore cuts speculatively but instruments the cut. A bad seam must become evidence rather than being absorbed by a leaf and returned as a locally coherent result. Dispatch is an experiment on problem structure as well as a way to produce work.

## 2. Responses to coupling

When a task resists decomposition, the harness recognizes three responses.

### Condition rather than cut

Identify the small set of global decisions on which the residual work depends, resolve them once, and broadcast them. Examples include an outline, schema, architecture, invariant, or frozen interface. These cutset decisions deserve disproportionate attention because an error in them propagates globally while most leaf errors remain local.

### Change basis

Separability depends on coordinates. Sections of an essay may be strongly coupled while research, argument, counterexample, and editing passes may be less coupled. A useful interface is a coordinate change: it carries the smallest sufficient account of the rest of the system that lets a leaf act correctly.

### Do not cut

Some cores remain irreducibly coupled. The harness must make doing the coupled core whole a successful planning outcome, not a planner failure. A system that rewards leaf count will manufacture false seams.

Overlap is load-bearing. A shared invariant can legitimately appear in multiple dossiers. The objective is not disjoint minimality; it is to expose the smallest thing neighboring leaves must agree about and ensure it is present wherever it is needed.

## 3. Granularity

Triviality is not the stopping rule. Cutting more finely can move all difficulty into inference-heavy joins while leaving every leaf apparently easy.

Useful stopping signals are:

- **Referent exhaustion:** another cut would leave a child grounded only in sibling outputs or an imagined future solution.
- **Join mechanics:** finer decomposition is safer when synthesis is supported by schemas, tests, types, execution, or another external oracle. When the join is itself a large inference, additional cuts may reduce reliability.
- **Irreducible context:** large or uneven dossiers can signal a coupled core, though dossier size is only a risk indicator—not a literal estimator of graph treewidth.
- **Oracle quality:** code often regenerates referents at multiple levels, but types and tests can still underspecify behavior. Domain, dependency shape, model capacity, and available ground jointly set safe depth.

## 4. Dispatch and verification

The recipient of a lossy handoff cannot know what was omitted. A dropped constraint arrives as freedom, not as a visible gap. Self-verification is therefore weak unless an external oracle supplies the check.

This does not require all verification to remain at the root. It requires the verifier to retain evidence from upstream of the handoff. The implementation uses three complementary positions:

1. An edge-level seam critic compares proposed dossiers and contracts with the upstream task.
2. Independent auditors inspect frozen leaf products using probes the leaves never received.
3. A root-level interpretation pass compares accounts end to end before the topology is revealed.

Verification may be deployed recursively by upstream or independent observers; it must not be delegated solely to the recipient whose missing information is in question.

Reliability decomposition and throughput decomposition remain distinct. Reliability work aggregates independent observations and is comparatively depth-tolerant, though correlated priors and adjudication still limit it. Throughput work composes products and therefore multiplies integration surfaces.

## 5. Planning shape

Planning iterates in time at the root, then fans out once in space.

The root loop converges on global decisions, the decomposition basis, contracts, dossiers, referents, and join strategy. A seam critic tries to find referent failures and unowned invariants. Only a plan judged ready is dispatched. Leaves cannot renegotiate shared decisions independently; they can report evidence that causes the orchestrator to reopen the relevant design scope.

The root is expensive because cutset mistakes propagate. Leaves may use cheaper models when their dossiers are grounded and their joins are mechanical.

## 6. The questioner

The questioner is independent of the proposed decomposition. It sees the stable task frame—task statement, product intent, numbered demands, and probes of the real system—but not the proposed cut. Showing it the topology would bias it toward asking about the seams already imagined.

The questioner is reliability-decomposed into lenses such as:

- adversarial and counterexample seeking;
- environment and execution context;
- failure semantics;
- invariant hunting;
- artifact- or call-graph-derived inspection.

Each lens produces hypotheses, not merely test items. A probe carries:

- an outcome-level question;
- the failure story that motivates it;
- why the property matters independently of process;
- evidence that could resolve it;
- observations that would change the questioner's belief.

Reports remain separate. Synthesis must preserve minority reports and disagreements rather than flattening them into a deduplicated union.

## 7. Discovery probes and held-out probes

A question is not a passive measurement if it is shown to the worker. It can reveal an omitted constraint, repair a dossier, or induce coordination among leaves.

The harness therefore distinguishes:

- **Discovery probes**, which may be shown to the planner during root convergence. If promoted, their implications become explicit contracts or demands.
- **Held-out audit probes**, which remain hidden from the planner and leaves until outputs are frozen.

The parent supplies a baseline account before seeing the decomposition. This is a prior hypothesis, not a checksum: it may be wrong, and a later divergence may represent learning. Auditors answer held-out probes from frozen dossiers, results, evidence, and available artifacts. They do not give the implementing leaf a chance to rewrite its result in response.

## 8. Judgment-preserving interpretation

The harness does not predeclare that every leaf must answer a probe identically. Producer and consumer answers may be complementary; two different local projections may both be correct. Defining all compatibility relations before observing the work would amount to constructing a second decomposition with the same possible blind spots.

Instead, interpretation is staged.

### Independent elicitation

Questioners, the baseline, leaves, and auditors provide substantive accounts. Their output contracts require evidence, assumptions, surprises, and counterfactual observations, but leave the semantic account open.

### Blind interpretation

An interpreter receives anonymized baseline and audit accounts without contracts, leaf roles, or topology. It identifies distinct world models, tensions, correlated assumptions, apparent refusals, and missing evidence. It is explicitly forbidden from diagnosing which seam failed because it cannot yet see the seam.

### Topology-aware diagnosis

A diagnostician then receives the cut, contracts, dossiers, frozen work, and blind interpretation. It considers competing causal explanations, including legitimate projection, learning, handoff loss, an unstated shared invariant, and interface failure. It must state disconfirming evidence and the smallest observation that would separate plausible explanations.

### Adversarial adjudication

One advocate argues that observed divergences are benign or reflect learning; another argues that they demonstrate coupling or loss. The adjudicator sees both cases and recommends continuation, evidence gathering, scoped amendment, recomposition, or doing the coupled core whole.

The structure makes contrasting evidence available. It does not pretend the resulting judgment is mechanical.

## 9. Interface findings and re-entry

Every leaf result contains an `interface_findings` list. An empty list is a positive assertion that the leaf observed no suspected mismatch; it is not omitted silence. Findings are narratives supported by evidence and include the smallest suspected scope.

A leaf does not directly halt the entire run. The finding becomes evidence for diagnosis and adjudication. This avoids both completion-trained absorption and frivolous global stalls.

The first implementation records, but does not automatically execute, re-entry. A sound re-entry mechanism needs:

- contract ancestry and versions;
- a record of which leaf result used which versions;
- propagation of staleness to dependent outputs;
- bounded retries and escalation;
- preservation of the old run as evidence rather than overwriting history.

## 10. Demand identity and overlap

Natural-language demand union is not mechanical. Whole-task demands receive stable identifiers. Identity is used only for bookkeeping:

- each demand has one accountable owner;
- it may create several implementing or consuming obligations;
- it may have several verification witnesses;
- shared invariants may appear in multiple dossiers and contracts.

This distinguishes accountability from implementation and permits the overlap necessary for sound joins.

## 11. Mechanical substrate versus epistemic layer

The mechanical substrate is intentionally thin. It handles:

- Pydantic validation at role boundaries;
- visibility-specific context construction;
- immutable stage records;
- artifact and record digests;
- a hash-linked event manifest;
- IDs, contract versions, and affected scope;
- usage and latency telemetry where the model provider supplies it.

It does not determine semantic compatibility, score truth, or collapse disagreement into a scalar. The epistemic layer remains agentic and evidence-driven.

## 12. Execution-context census

The execution-context census remains a root-pinned global pass over the flattened work. Some invariants exist only in the joint relationship among code, environment, configuration, and call graph; they may be absent from every leaf marginal. Question diversity does not replace this pass.

The current implementation represents the environmental lens and keeps room for artifact-derived tools. Direct call-graph and runtime probing are future domain adapters.

## 13. Falsifiable evaluation

The harness should be evaluated by ablation against:

- a single frontier-model run;
- ordinary decomposed dispatch;
- dispatch plus explicit interface findings;
- plus seam criticism;
- plus held-out audit probes;
- the full blind-interpretation and adversarial-adjudication workflow;
- doing the suspected coupled core whole.

Primary outcomes are end-to-end correctness at matched cost and latency. Secondary measures include whether divergence predicts integration failure, false-finding rate, rework after amendment, planning dossier skew, and detection lead time. Adaptive instrumentation needs some randomized activation or its selection effects will obscure whether it pays for itself.

## 14. Open questions

1. Does the full questioner/audit cycle outperform doing the coupled core whole?
2. Where does the leaf-competence-to-join-competence boundary fall by model and domain?
3. Do independent lenses and mechanical evidence sources sufficiently reduce correlated omissions?
4. When may held-out probes be amended, and how should late probes be distinguished from genuinely blind ones?
5. What prices interface findings and bounds re-entry without suppressing the channel?
6. How much mid-tree coupling escapes root vocabulary, and which domain adapters regenerate useful vocabulary safely?
7. How much does the instrument change behavior even when probes are held out from leaves but shown to planners?

## 15. Intake frame as compiled intermediate representation

The structured task frame is an internal dispatch and audit representation, not the preferred language in which people must describe work. Natural requests, explicit conversational decisions, and source materials enter through a source envelope. A dedicated intake agent proposes the frame without seeing or inventing a decomposition.

The compiled frame never replaces its source. The run preserves both plus derivation links that distinguish explicit claims from inference and defaults. Independent questioners see the source envelope alongside the frame, so intake loss is observable instead of becoming a shared blind spot. Downstream planners and leaves continue to receive narrower typed contexts.

Intake may return `ready`, `needs_clarification`, or `exploratory`. The latter states are successful framing outcomes: they prevent premature acceptance criteria from laundering uncertainty into a dispatchable shape. Normal execution stops on them unless an operator explicitly chooses to run the unresolved experiment. Direct spec authoring remains an expert interface for reproducibility and programmatic callers.

## 16. Legacy diagnostic boundary

The legacy `run` path is a programmatically orchestrated Pydantic AI application. It uses structured outputs for role contracts and application-controlled handoffs for visibility. It does not use model-controlled delegation, because the central experiment depends on preventing roles from acquiring contexts they should not see.

The workflow is intentionally inspectable. Every stage result is preserved independently so a human can reject the adjudicator's account, reconstruct what each role knew, and run later evaluations against the original evidence.


## 17. Recursive context compiler

Version 0.3 adds `solve` as a separate productive path. A node may solve locally, request exact evidence, preserve an irreducibly coupled core, or expand into independent research children. Siblings run concurrently and parent synthesis waits for all child evidence packets. The runtime owns topology, budgets, source visibility, canonical identities, and provenance; agents retain semantic judgment. One root finalizer writes from the assembled evidence rather than asking leaves to draft disconnected parts.

The root, synthesis, and finalization tiers default to Kimi K3. Descendant planning and frontier research default to a smaller Fireworks model. The natural request remains in the evidence catalog beside the intake-generated frame. A read-only workspace adapter supplies a content-addressed file index and exact per-node dossiers. The detailed contracts, operations, evaluation matrix, and current non-mutation boundary are in `recursive-solver.md`.


## 18. Adaptive posterior amendment

The implemented default now removes the full-tree planner from productive `solve`. A controller queries the current immutable question/answer snapshot and chooses only one bounded next action. This is not continuous replanning of a fixed decomposition: investigation produces measurements, posterior synthesis may create new vocabulary and raise new first-class questions, and the next action is allowed to reshape the inquiry. The fixed recursive compiler remains available as an explicit comparator.

This amendment sharpens the model/runtime boundary in §11. The runtime should not fight a language model by trying to encode semantic research judgment as routing rules. It enforces identities, visibility, frozen waves, budgets, source bounds, experiment permissions, and append-only commits. The model uses semantic understanding to formulate searches, recognize analogies and disagreement, decide which retrieved material matters, propose sparse links, and notice when a result changes the question. Typed contracts describe actions and evidence, not the ontology of the solution.

The shared substrate is pull-based. A role receives a compact state digest and can search first-class questions, search answers within or across threads, open exact entries, traverse typed neighbors, and retrieve bounded source excerpts. The full graph and source corpus remain hidden tool state. Exact bounded tool results are journaled so post-mortem analysis does not depend on a later workspace state.

Adaptive actions form a dependency DAG through the graph entries they read and write; they do not inherit fixed planner/researcher descendants. Investigator, synthesizer, controller, and finalizer are runtime capabilities selected by the current evidence state, not a prior claim that every problem has those branches. Synthesis is a legitimate posterior operation but never automatically terminal. See `adaptive-harness.md` for contracts, permissions, CLI controls, and audit records.


## 19. Recursive participant and forum-post amendment

The settled productive architecture removes the remaining cognitive distinction
between controller and synthesizer. Every work-bearing node is one persistent
participant: it queries its forum snapshot, publishes a current synthesis, and
chooses a bounded next action. Delegated nodes receive the same contract and may
recursively delegate, verify, integrate descendants, or finish. The only
separate controller is deterministic runtime code for scheduling, identity,
permissions, budgets, and audit. The finalizer remains separate only as a
presentation boundary.

Adaptive model output is now a natural `KnowledgePost`, not an
`EvidenceDraft`. The post body carries the answer. A single per-question
`responds_to` edge consolidates `answers` and `partially_answers` through
the effects `resolves`, `advances`, and `no_claim`. The design explicitly
does not collapse operational failure or structural coupling into that enum:
provider and execution outcomes remain journal records, while coupling is a
scoped seam signal that becomes a first-class question for the nearest
ancestor. Important unresolved issues likewise become questions rather than
fields in a packet.

The runtime records the full read set mechanically. A post declares only sparse
semantic dependencies such as `derived_from`, `supports`, or
`contradicts`, and may declare one only for an answer actually retrieved in
that call. This preserves the useful distinction between information available
to a participant and information it says its synthesis used without requiring
claim-by-claim epistemic atomization.

Verification is an action available to the same participant. It publishes the
proposition as a question, links the exact answers or artifacts under test, and
returns the bounded executable observation as another answer. The participant
then interprets whether the observation supports or contradicts its synthesis.
It may write checker code through an explicitly permissioned adapter or
delegate checker construction to another participant; there is no fixed
verifier role. Details and exact Pydantic contracts are in
`adaptive-harness.md`.

## 20. Stateful transcript amendment

Every participant turn was a cold `agent.run`: a fresh user prompt carrying
the whole dossier, no `message_history`. A participant therefore had no
memory of its own previous turns except the graph, so on each synthesis turn
it re-pulled its own earlier posts through forum tools. Measured on the last
real run: 57% of everything the root retrieved was its own prior output; the
run authored exactly one `derived_from` link; output tokens were 72% of cost
($15/M vs $0.30/M cached input on Kimi K3, 1,040k window). The
memorandum-as-memory design saves cheap input and spends expensive output.

Decision: a participant keeps its pydantic-ai message history across its
turns. Its first turn still receives the full dossier; every later turn opens
with a compact turn dossier of only what changed, and, after a delegate wave
or a verify action, that wave's results pushed in full — the pushed answer
IDs count as disclosed, so a `derived_from` link to one needs no redundant
re-retrieval. Retrieval stays available but is no longer the main channel.
Because a kept conversation grows without bound, a node's transcript is
pruned deterministically once its estimated size exceeds a budget, oldest
content first, and never inside a protected recent-turn window; every prune
is journaled as a `PrunedEvent`. The output token cap is raised accordingly
(`262144`, from `32000`) since a synthesis turn no longer needs to spend
output tokens re-deriving what it already said. Transcripts are journaled
after every turn and restored on checkpoint resume, so a resumed node
continues its conversation rather than starting cold. See
`adaptive-harness.md`, "Participant transcripts", for the contracts, pruning
rules, and audit records.

## 21. Adversarial verification amendment (design only, not yet implemented)

The recursive shape settled in §19–§20 — a persistent participant that
decomposes when its mandate is not locally solvable, delegates, and is
re-invoked to synthesize — is kept. This amendment settles how verification
works inside that shape. It is recorded ahead of implementation.

The evidence it answers. In the completed runs: the one executed checker was
recorded as "failed; exit_code=1" because the model's own test script crashed
on an index bug *after* every mathematical check in it had passed — a broken
verifier and a refuted claim were indistinguishable. The single best moment
of any run was adversarial: an independent context rejected the controller's
invalid mod-3 argument. The single worst error was synthesis drift: a
correct leaf claim of "at least" was strengthened to "exactly" in the final
memorandum, and no stage was positioned to notice. And the seam attestation
that §13-era packets made mandatory (`boundary_finding`: explicit none or
mismatch) survives only as the optional `seam_signal`, which zero of six
posts in the last real run used.

### Seams are stated through verification criteria

A parent discovers a seam by writing the child's acceptance condition first:
if it cannot state what "done" means for a fragment, the fragment is not a
seam. Verifiability shapes the *statement* of a subtask; it must not select
*which* work is done — the decomposition is still judged by coverage of the
parent's own mandate, which the parent must be able to account for. (The
`acceptance_condition` field already exists on every delegation; this
amendment gives it consumers.)

### Verification is evidence, never a gate

Verification produces observations the parent weighs; it is not a mechanical
precondition for synthesis. Verdicts are three-valued — supported, refuted,
verifier-broken — and a verifier's own failure (crash, timeout, invalid
harness) is always verifier-broken, never refutation. A failing verdict
triggers a bounded retry loop that ends in escalation: the work, the verdict,
and the disagreement go to the parent, which judges. Verification effort
scales with how load-bearing a claim is, and that ranking is the parent's
semantic judgment, not a rule.

### The verifier writes code when code can decide

A verifier prefers an executable check (the audited checker adapters) and
falls back to semantic review when the claim is not mechanically decidable.
The check is derived from the acceptance condition, not from the worker's
own account of its proof — a shared wrong assumption must not be able to
grade itself. Where the adversarial pattern below is in force, the opposing
side authors the check.

### Disputed and load-bearing claims are argued, not re-reviewed

For a claim the parent marks load-bearing, or wherever two answers conflict,
the pattern is two sides before a judge: a proponent defends the claim, an
opponent attacks it (authoring counterexample searches and checks), and a
judge *compares* the two cases rather than generating its own. Comparison is
discriminative and cheap; generation is expensive — the judge can be a
smaller model than the parties. The parent is the default judge; an
independent judge is required only when the parent is itself a party, i.e.
for its own synthesis. Debates are anchored in executable evidence wherever
possible so they converge on truth rather than persuasiveness.

### The child's return attests its seam

The optional `seam_signal` becomes a mandatory fit attestation on a child's
final post: met, partial, or mismatch against the delegated acceptance
condition, with an account. A mismatch is first-class and rides the pushed
wave-result channel (§20), so the parent cannot fail to see it. This
restores the handoff validation the original questioner design required and
the current contract quietly made optional.

### Synthesis is checked by a cold reading

After the root synthesizes its final artifact, a cold participant — no
transcript, no run history — answers the run's original first-class
questions from the artifact alone. A judge compares those cold answers
against the canonical graph answers; any deviation (a strengthened modality,
a dropped condition, a conjecture presented as theorem) is a first-class
finding pushed to the root, which must repair the artifact or justify the
difference. This is the conservation check implemented with machinery the
harness already has — questions, answers, and comparison — rather than a
claim-diff ontology, and it simultaneously tests that the artifact is
self-contained enough for a reader without the run's history.

### Principle

Generation is expensive and fallible; comparison against independently
produced evidence is cheap and strong. The harness's job is to manufacture
cheap comparisons: code output against claim, opponent against proponent,
cold reading against the graph, child return against its acceptance
condition. Nothing in this amendment adds a new ontology; each mechanism is
a new consumer of objects the forum already holds.
