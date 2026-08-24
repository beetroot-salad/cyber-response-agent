# Recursive participant harness

The default `solve` path is a feedback-driven question-and-answer graph whose
shape is discovered during execution. The fixed recursive solver remains
available as `--execution recursive` for comparison and replay.

## One cognitive role, one deterministic runtime

The harness no longer has separate controller, investigator, and synthesizer
agents. Every work-bearing node is a participant with the same tools, prompt,
and output contract. A participant:

1. owns a question or mandate;
2. queries the forum and bounded source material;
3. publishes its current answer or finding;
4. chooses whether to delegate, verify, continue, or finish;
5. is invoked again after descendants or verification results arrive.

It is a controller when choosing the next experiment and a synthesizer when
revising its answer. Those are activities, not hard-coded roles. A delegated
participant can recursively perform the same loop, so the realized topology can
match the problem instead of a planner's prior.

The separate runtime is deterministic code, not another reasoning role. It owns
IDs, immutable call snapshots, budgets, concurrency, graph commits, executable
permissions, journal records, and provider-failure handling. It does not decide
what an answer means.

Root turns use the root model tier. A fresh descendant uses the research tier;
if that descendant delegates and is later re-invoked to integrate results, the
same participant contract can use the synthesis tier. This is capability and
cost routing, not a change of semantic role.

## The participant turn

A `ParticipantTurn` contains an optional `KnowledgePost` and one bounded next
action:

```text
ParticipantTurn
  account
  contribution: KnowledgePost | null
  action: delegate | verify | continue | finish
```

The participant can therefore synthesize and dispatch in the same turn.
`continue` is allowed only with a material post; it cannot be used as an empty
planning loop.

A `delegate` action publishes all child questions before dispatch and gives
every peer in the wave the same initial snapshot. Each child is a full
participant and may recurse until the depth, action, or work-item budget binds.
The parent waits for the wave and is then re-invoked against the posterior
forum. Later turns may use newly committed forum knowledge; the frozen initial
wave prevents a nominally independent sibling from depending on arrival order.

## Knowledge posts: natural content, small graph metadata

The model does not return nested claims labeled observed, inferred, hypothesis,
complete, partial, blocked, or coupled. It returns a natural answer body plus
the small amount of structure needed to reuse and audit it:

```text
KnowledgePost
  body

  responds_to:
    - question_id
      effect: resolves | advances | no_claim
      scope_or_reason

  new_questions
  links
  seam_signal | null
```

The response effect is per question. One post may resolve a bounded child
question while merely advancing the root question. `no_claim` is an explicit
epistemic refusal: the participant is saying the available context does not
justify an answer. It is not used for timeouts, provider errors, malformed
outputs, or execution failures; those remain operational journal events and
leave the forum question unanswered.

There is no global post status because the old values mixed different
dimensions:

- answer coverage belongs on each question-response edge;
- provider and runtime outcomes belong in the run journal;
- structural coupling belongs in a seam signal.

Important unresolved issues are new first-class questions rather than strings in
an `unresolved` field. Inputs actually used are `derived_from`, `supports`,
`contradicts`, `supersedes`, or `duplicates` links from the new answer. A link
targets only an answer retrieved in the same call; the post schema offers no
other relation and no other target, so a question is reached through
`responds_to` and the runtime writes `raises`, `refines`, and `depends_on`.
The runtime independently records the complete set of question, answer, source,
and artifact IDs disclosed by tools. Thus the audit distinguishes what the
participant could read from what it says it used.

A seam signal records the finding, affected questions, smallest suspected
scope, consequence if absorbed, and optional contract identity. The runtime
turns it into a forum question, journals it separately, and assigns handling to
the nearest ancestor scope. It is not converted into a global stall.

## The knowledge forum

Questions and answers are independently addressable, many-to-many objects.
Adaptive answers use one `responds_to` relation whose `response_effect`
contains `resolves`, `advances`, or `no_claim`. The fixed recursive
comparator's legacy `answers` and `partially_answers` relations remain
readable but are not emitted by new adaptive participants.

Other typed relations support:

- question refinement, dependence, and duplication;
- answer derivation, support, contradiction, supersession, and duplication;
- answers that raise new questions;
- verification questions that depend on the exact answers or artifacts tested.

No model receives the full graph in its dossier. It receives a digest, counts, a
small focus list, recent action summaries, and exact selected IDs where needed.
It can pull from one immutable call snapshot with tools to search questions,
search answers, open entries and threads, traverse neighbors, search bounded
source excerpts, and read bounded source ranges.

A post may declare an answer dependency only after retrieving that answer in
the same call. This is not treated as evidence that the dependency is correct;
it prevents a model from claiming to have synthesized an answer it never read.
Every query body, arguments, result IDs, snapshot digest, and result digest is
journaled.

## Verification is a forum action

Verification is a capability of every participant, not a fixed verifier role.
The participant with the current synthesis chooses the proposition, targets,
adapter, arguments, and discriminating acceptance condition. The runtime
publishes a verification question, links it to the exact target entries, runs
the registered adapter, stores the result as a content-addressed source, and
publishes the observation as a normal answer.

The runtime does not automatically call a successful process “support.” On the
next turn the participant interprets the observation and may publish
`supports` or `contradicts` links. This keeps semantic judgment with the
model while preserving the executable record.

Adapters are permissioned:

- `text_statistics` is deterministic and enabled by default;
- `pytest` executes existing workspace code and is opt-in;
- `python_checker` executes bounded model-authored Python and is opt-in.

Enable executable checks explicitly:

```bash
PYTHONPATH=src python -m seam_harness solve tasks/my-task.json \
  --workspace path/to/source \
  --enable-experiment-adapter pytest \
  --enable-experiment-adapter python_checker
```

`python_checker` receives no inherited environment secrets, has bounded code,
arguments, time, and captured output, and is fully journaled. It is not a
security sandbox: enabling it authorizes model-authored code execution in the
harness environment.

## Finalization

A participant may finish only by selecting an answer authored for its own
mandate; `self` names the contribution from the current turn. This prevents a
parent from forwarding a child result without performing its own synthesis. At
the root, every numbered whole-task demand must also have a `resolves` response
or appear explicitly in the finish action's unresolved-question IDs; coverage
remains an identity check rather than a model judgment hidden in prose.

The finalizer is a presentation boundary, not a controller. It queries the
selected forum answers and returns:

```text
AdaptiveFinalArtifact
  content
  format
  selected_answer_ids
  unresolved_question_ids
  limitations
```

The runtime owns the canonical answer and unresolved-question IDs. The finalizer
must not strengthen scope, modality, quantifiers, or certainty beyond the
selected answers.

## Participant transcripts

A participant keeps its own pydantic-ai message history across every turn it
takes, instead of a fresh `agent.run` per turn carrying the whole dossier
again. `AdaptiveHarness` owns one `TranscriptStore` (a `ParticipantTranscript`
per node ID): its messages, the index into `messages` where each turn's new
messages begin (`turn_offsets`), and a record of anything pruned away.

A node's first turn still receives the full dossier exactly as before. Every
later turn instead opens with a *turn dossier* holding only the per-turn
fields (`step`, `remaining_steps`, `remaining_work_items`, `remaining_depth`,
`knowledge_summary`, forum activity since this node's own previous turn, its
`participant_feedback`, `selected_answer_ids`, and any pushed wave results).
The stable fields — task, product intent, demands, constraints, stable
context, assignment, workspace index, and available experiments — are not
repeated in the prompt; they are already in the kept conversation, and still
fully present on `deps` for tool use and in the `01-call-inputs` journal
record. Rejected attempts inside one turn (validation retries) share that
turn's transcript, so a later attempt sees the earlier rejected attempt plus
the runtime's feedback rather than starting over.

**Pushed wave results.** After a delegate wave or a verify action returns,
the parent's next turn is handed each descendant's latest answer body, or
its verification result, truncated the same way source excerpts are
bounded. The pushed answer IDs count as disclosed, exactly like a retrieved
query result, so a `derived_from` link to a pushed answer passes the "must
retrieve first" validation without a redundant re-retrieval. This is the main
channel now; ad hoc forum retrieval remains available for anything not
already pushed.

**Pruning.** A transcript is pruned once its estimated size exceeds
`--transcript-token-budget` (default 400,000; `estimated_tokens` sums
`len(str(content or args))` across every part and divides by 4). The most
recent `--transcript-keep-recent-turns` turns (default 2) of a node are never
touched. Pruning is deterministic and ordered: remove thinking, stub tool
results (never the output tool's own acknowledgement, never a tool call's
own arguments), stub assistant text, and only then drop whole turns from the
oldest forward, never the transcript's first turn. Every edit is recorded as
a `PrunedEvent`; a part already stubbed is never re-stubbed. Each prune of a
node's transcript changes the cached prefix an inference provider would
otherwise reuse for that node's calls exactly once — a fact worth knowing
when reasoning about cost, not a correctness concern.

**Journal and resume.** After every turn of a node, the harness writes a
`13-transcripts` record with the transcript's message count, estimated size,
turn offsets, pruned events, and the messages themselves (JSON-loadable via
`pydantic_ai.messages.ModelMessagesTypeAdapter`). On checkpoint resume, the
latest `13-transcripts` record per node (by sequence) is restored into the
new run's `TranscriptStore`, and a `restored-{node}` marker records the
source; a resumed node then continues its kept conversation instead of
starting cold. `--no-push-wave-results` disables the push (retrieval-only,
matching prior behavior); `push_wave_results` defaults on.

## Running with Fireworks

Kimi K3 is the default root, synthesis-tier, and final model. The research tier
defaults to DeepSeek V4 Flash so cheap recursive context assembly can be
measured. To use Kimi K3 everywhere:

```bash
export FIREWORKS_API_KEY="..."
PYTHONPATH=src python -m seam_harness solve tasks/my-task.json \
  --research-model fireworks:accounts/fireworks/models/kimi-k3 \
  --output outputs/result.md \
  --runs-dir runs
```

Relevant bounds are `--max-adaptive-steps` across all participant turns,
`--max-nodes` across delegates and verifications, `--max-depth`,
`--max-adaptive-wave`, `--max-concurrency`,
`--adaptive-request-limit`, and `--max-experiment-seconds`. Transcript memory
is bounded by `--transcript-token-budget` and `--transcript-keep-recent-turns`;
`--no-push-wave-results` turns off pushing a completed wave's results into the
next turn.

Adaptive checkpoint resume verifies the complete ancestor journal chain,
imports questions, answers, posts, legacy packets, links, the transitive
action lineage, and each node's latest participant transcript, then
re-invokes the root participant against the recovered posterior. Proposed or
failed future actions are never replayed.

## Audit and post-mortem

Every run writes an append-only, hash-linked journal containing:

- the task, policy, workspace index, and source digests;
- every public participant and finalizer dossier;
- all query arguments, bounded result bodies, returned IDs, and digests;
- participant turns and rejected invalid turns;
- natural knowledge posts with complete read sets;
- questions, answers, response effects, semantic links, and link rejections;
- seam signals and their nearest handler scope;
- verification requests, executable inputs, stdout, stderr, exit status, time,
  and result digest;
- operational child or adapter failures without fabricated epistemic answers;
- action records with actor identity and depth, before/after snapshot digests,
  explicit reads and writes, spawned work, call IDs, timing, and provider usage.

Run:

```bash
PYTHONPATH=src python -m seam_harness inspect runs/<run-id>
PYTHONPATH=src python -m seam_harness postmortem runs/<run-id> --format json
```

The deterministic post-mortem reconstructs the recursive participant action
DAG, actual maximum depth, post read sets, retrieval behavior, verification
results, seam signals, operational failures, response effects, and final answer
lineage. It does not ask another model to narrate the record.

## Current limits

The forum is run-local and lexical rather than a persistent semantic index.
Runtime validation catches identity, visibility, budget, and permission errors,
not poor judgment. A participant can author a bad checker or misinterpret a
correct result; independent checks remain valuable for high-impact claims.
Parallel peers share a frozen first snapshot but can encounter other committed
forum knowledge on later turns. The final product is text and the harness does
not yet apply patches. Most importantly, the system cannot manufacture external
ground where no executable artifact or referent exists.
