# Recursive context compiler

`solve --execution recursive` is the fixed-tree comparison architecture. The default `solve` path is now the feedback-driven executor documented in `adaptive-harness.md`; the older `run` path remains the high-instrumentation seam experiment.

## What recurses

Every node receives a bounded dossier and chooses one disposition:

- `solve`: the current context makes the work locally decidable;
- `expand`: independent evidence questions can run as children;
- `needs_evidence`: exact source IDs or workspace paths are required before the
  cut can be judged;
- `irreducibly_coupled`: the inference should stay in one stronger context.

Expansion is evidence-oriented. Children investigate facts, failure modes,
interfaces, or analytical angles. They do not draft slices of the final output.
Every expansion supplies a parent synthesis contract, and a child must state why
it does not depend on a sibling's future result. Shared sources and separator
facts may deliberately appear in several dossiers.

The runtime—not a model—assigns canonical node and claim IDs, reserves the node
budget, validates source paths, schedules siblings, and records provenance.
Independent siblings run concurrently. Their parent runs only after all of them
finish. A sequential stage therefore cannot masquerade as a parallel sibling,
which is the defect exposed by the first essay experiment.

## Evidence packets

Frontier researchers return claims labeled `observed`, `inferred`, or
`hypothesis`. Observed claims require a citation or a derivation from child
claims. Citations use original material IDs, referent IDs, or content-addressed
workspace paths. Packets also preserve counterevidence, assumptions, unresolved
questions, boundary findings, and the next useful observation.

Synthesizers must name the canonical child claim IDs behind each parent claim.
The finalizer receives the assembled root packet and writes the requested
deliverable once. This is a context compiler: tree work exists to improve the
data and decisions available to the final act, not to multiply prose authors.

## Shared question/answer knowledge graph

Questions and answers are separate first-class objects, not a single forum post
type and not an answer table keyed by one question. Whole-task demands and node
objectives become durable questions; every completed evidence packet becomes an
answer. The graph permits many answers per question and one answer to address
many questions. This matters because disagreement, partial coverage, and reuse
are properties of the mapping, not exceptions to a one-to-one schema.

The typed relation families are:

| Source | Target | Relations |
| --- | --- | --- |
| answer | question | `answers`, `partially_answers`, `raises` |
| question | question | `refines`, `depends_on`, `duplicates` |
| answer | answer | `derived_from`, `supports`, `contradicts`, `supersedes`, `duplicates` |

The runtime writes links it can know structurally: child question to parent and
demand questions, packet answer to its node, conservative partial coverage of
assigned demands, parent answer to child answers, and an unresolved
observation to a raised question. Models may add up to eight sparse semantic-link proposals with rationales. They
can use
`self` for the answer under construction or exact IDs from their frozen board.
The runtime, not the model, resolves `self`, checks endpoint existence and type,
enforces visibility, and journals accepted links with `origin=agent`; invalid or
replay-stale proposals are retained as explicit rejection records. Graph
position never counts as evidence.

Visibility is round-based. All questions for a sibling wave are published
before dispatch, and each sibling receives the same content-addressed snapshot.
Sibling answers become visible only to the parent synthesis after the entire
wave completes. This gives agents shared memory without making results depend on
which concurrent request happened to finish first. Questions, answers, and
links are individually recorded under `05-knowledge-questions`,
`06-knowledge-answers`, and `07-knowledge-links`; each final result contains the
indexed board and its digest.

The recursive comparator board is run-local and delivered as a bounded snapshot, not a
cross-run database. It also has no semantic retrieval index yet. Persisting it
across tasks requires provenance-aware deduplication, access control, source
expiry, and retrieval that returns a question neighborhood rather than the whole
graph. Those are deliberately not smuggled into this in-run communication MVP.

## Who creates the structured input

People normally submit a natural request. The intake agent compiles it into a
reviewable task frame containing product intent, stable constraints, and
numbered whole-task demands. That frame is an intermediate representation for
routing, coverage, and replay; it is not a claim that every task is naturally a
schema.

The natural request, explicit decisions, and source materials remain alongside
the frame. `solve` adds them to its source catalog, so a planner can recover
nuance from the original wording rather than inheriting every intake
interpretation. Intake can refuse to freeze exploratory or consequentially
ambiguous work. Direct JSON specs exist for benchmarks and programmatic callers,
not as the expected human interface.

## Models and budgets

The default Fireworks allocation is:

- Kimi K3 for the root planner, all parent synthesizers, and the finalizer;
- DeepSeek V4 Flash 0731 for descendant planners and frontier researchers.

All four model slots can be overridden. Depth, node count, fanout, concurrency,
evidence-retrieval rounds, workspace bytes, and output tokens are bounded by
`RecursivePolicy`. Reaching a boundary does not truncate a subtree silently: the
current node is solved in the stronger synthesis tier and records its stop
reason. The planner may also choose `solve` at the root, so small or tightly
coupled tasks do not pay for a manufactured tree.

## Read-only workspace dossiers

`--workspace` snapshots UTF-8 files at run start, excluding version-control,
cache, dependency, run, and output directories. The index exposes relative
paths, sizes, and SHA-256 digests. A planner may request exact paths; only their
snapshotted contents enter that node's dossier. Symlinks, binary files, and
oversized files are excluded, and total limits fail explicitly rather than
silently sampling a repository.

This adapter does not execute tests, inspect a live call graph, apply patches,
or mutate the source tree. Those are the next important domain adapters. For now
the final technical artifact is text, such as a unified diff, which an evaluator
must apply and test separately.

## Running it

```bash
export FIREWORKS_API_KEY="..."
PYTHONPATH=src python -m seam_harness solve tasks/my-task.json \
  --workspace path/to/source \
  --output outputs/result.txt \
  --runs-dir runs
```

Useful overrides include `--research-model`, `--synthesis-model`,
`--final-model`, `--max-depth`, `--max-nodes`, `--max-children`,
`--max-concurrency`, `--planner-max-tokens`, `--research-max-tokens`,
`--synthesis-max-tokens`, and `--final-max-tokens`. The four execution tiers also
accept `--root-thinking`, `--research-thinking`, `--synthesis-thinking`, and
`--final-thinking`. These are provider requests, not guarantees; use recorded
reasoning tokens and output behavior to verify what a model actually honored.

`--require-root-expansion` is an experimental control: it forces one root
research fanout even when the planner would normally keep the task whole. It is
useful for decomposition ablations, not the safe default. `--replay-run` accepts
a verified recursive run with the identical task spec and reuses every completed
node plan and evidence packet, including intermediate plans below the root. A
completed plan remains replayable even when its subtree did not finish. Replayed
artifacts retain their original digests and source-run path in the new journal,
so a failed join can be retried with a different synthesis model without paying
for completed planning and leaf work again.

## Communication and deterministic adapters

Nodes do not hold an unbounded sibling chat. Communication is staged: a parallel
wave returns typed findings and boundary conflicts; the parent may freeze a small
shared separator note or contract for a later wave. This preserves concurrency
and makes new coupling visible without creating conversational cycles or allowing
one confident leaf to contaminate every sibling.

When a subproblem has an exact executable oracle, prefer a deterministic domain
adapter whose output is a content-addressed certificate. Agents should explain,
audit, and synthesize that certificate; they should not spend a parent join
recomputing it from unreliable leaf prose. `unit_fraction_certificate.py` is a
small example: it turns the final two denominators into a finite divisor-factor
certificate. This does not make semantic synthesis mechanical. Conflicting
claims still remain typed and visible, and a partial root packet must not be
silently promoted to ground truth.

## Benchmark observation: exact unit fractions

The four-term unit-fraction benchmark exposed three distinct failure modes. A
single high-thinking Kimi K3 call failed to return an accepted artifact after a
long generation. In the ungrounded recursive run, cheap leaves returned bad
counts and the Kimi join attempted to recompute the whole problem, exhausting
its structured-output budget. With an exact certificate in the workspace,
parallel leaves became useful, but one small-model synthesis still repeated a
bad feasible-range claim; the disagreement remained recorded as `partial`, and
the final pass corrected it against the certificate. The lesson is not simply
"decompose more": cache evidence, route models by role, make exact joins
mechanical where possible, and retain conflicts through finalization.

## Benchmark observation: corpus-bounded knowledge-substrate memo

A harder research run used seven full papers with deliberately conflicting
evidence on multi-agent debate, conformity, argumentation semantics, and CRDTs.
The forced recursive condition reached 20 nodes at depth 3: 14 frontier research
calls, six parent syntheses, and one root finalizer. It produced a 1,551-word
architecture decision memo within the requested 1,400--1,800-word range and
cited all seven corpus files with PDF-page markers. The run-local board
contained 43 questions, 20 answers, and 257 links. Eighteen questions had
multiple answers; the eight unanswered questions were all explicit
`next_observation` questions raised by completed packets rather than silently
dropped gaps. Audit inputs confirm frozen-wave behavior: every sibling group
shared one board digest with zero sibling answers, while each parent synthesis
saw its completed child answers.

The same run is a negative result on efficiency. Wall time was 7m13s for 41
model calls and 43 provider requests. Provider usage was 2,051,640 input tokens
and 96,325 output tokens. Full paper text was resent to a node planner and then
its researcher, and sometimes again to descendants; the finalizer received both
the root packet and a full 43-question board. Fireworks reported almost no cache
reads outside two planning requests. The graph and concurrency worked, but the
context compiler did not compile context aggressively enough. The next
optimization target is therefore content-addressed source excerpts and cached
evidence packets, plus question-neighborhood retrieval and compact board views;
not more nodes.

Every call records its validated dossier before provider invocation and its
typed output or error, model, latency, and provider-reported usage. The run also
records the workspace index hash, node plans, enrichment rounds, evidence
packets, effective stop reasons, topology, root packet, final artifact, and a
hash-linked manifest. `inspect` verifies the record chain. The chain is local
and tamper-evident, not externally signed.

## Evaluation

Use `examples/idempotency_service` for the first decomposable benchmark. Compare
small-single, small-recursive, frontier-single, and frontier-root/small-leaf
conditions at matched task and source snapshots. End-to-end hidden tests are the
primary outcome; node count, depth, token usage, and wall time only explain it.

The current scripted test proves that sibling research overlaps and parent
synthesis waits, but it does not establish model quality. A real benchmark run
and ablation remain necessary.

