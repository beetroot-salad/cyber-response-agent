# How contract-first works, and why

This is the design behind the plugin: where it comes from, what each stage is for, the reasoning, and where it falls short.
The [README](../README.md) covers install and use; the skills hold the working instructions.

## Not a new idea

Writing the tests first and treating them as the agreement between intent and code is old practice.
The plugin borrows from:

- **Test-driven development**: tests written before the code they check.
- **Acceptance-test-driven development, BDD and specification by example**: concrete, executable
  examples agreed up front stand in for a written specification.
- **Mutation testing**: deliberately wrong versions of the code check whether the tests notice. The
  attackers here are hand-written, intent-aware mutants.
- **Extreme Programming's spike**: throwaway code written to learn, not to keep.

The name overlaps with two unrelated ideas: Bertrand Meyer's _design by contract_ (pre- and
post-conditions inside the code) and _contract-first APIs_ (writing the OpenAPI schema before the
service). Neither is what this plugin does.

What's specific here is that the authors, implementers and reviewers are agents. Left to itself, an
agent decides what an issue means, writes code to that reading, then writes tests that pass on that
code, so nothing ever disagrees. The plugin puts disagreement back: a human settles the intent,
tests pin it before code exists, and each later stage is set up to doubt the one before.

## Why a design and tests, and no independent spec

Two artifacts carry the intent, and each holds what the other can't:

- **The design** holds the why: scope and non-goals, data models and types, flows, the architecture chosen and
  the trade-offs behind it. Tests can't express a rationale or a deliberate omission.
- **The tests** hold the what, in a form that can fail. A sentence in a document can't stop wrong
  code from shipping. The tests are the spec.

The working assumption is that a written spec in between isn't needed. A natural-language spec exists so that people can
coordinate on detail too fine for the design and too early for code. Agents don't need that layer:
given the intent, they can turn it straight into tests, and the tests then serve as the spec,
exact where prose would leave room for two readings. The design can stay compact and lean on
shared context. That cuts both ways: whatever it leaves implicit still has to be settled, and here
that happens when the tests are written and reviewed, not in more prose. It hasn't been measured against a
version with a spec.

The tests are committed **alone, before any implementation**, as a fixed reference. That makes the
order provable from git history rather than from an agent's account, and it stops the code stage
from quietly bending a test to fit what it wrote. When code and tests disagree, that's a finding to
route, never a licence to edit the test.

## The pipeline

```mermaid
flowchart LR
    I[Issue] --> D[discuss-issue<br/>design]
    D --> T[write-tests<br/>contract]
    T --> C[write-code-from-tests<br/>code + attacks]
    C --> R{Last review}
    R -->|full| F[finalize]
    R -->|light| CR["/code-review"]
    F --> M[Human merge]
    CR --> M
    C -. contract holes .-> T
    C -. design defects .-> D
    T -. design defects .-> D
    F -. escaped bug shapes .-> K[(Attack deck)]
    K -. replayed .-> C
```

| Stage                      | Produces                                                                                      | The human decides                                 |
| -------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| discuss-issue              | A design: behavior, scope, data models, flows, architecture, with probed facts and a code map; or a split into several issues | What to promise, how to split, and the consequential trade-offs |
| write-tests                | A committed test contract and a map of which test enforces which promise                      | Only design amendments the tests expose           |
| write-code-from-tests      | Code that passes the contract, attacked by wrong variants; a PR                               | Only design amendments the code exposes           |
| finalize or `/code-review` | A reviewed, re-greened PR; follow-up issues; new attack-deck entries                          | Whether to merge                                  |

## Sketch and spike: finding the better way before it's expensive

A familiar moment: halfway through building something one way, you see how it should have
been built. Usually that moment arrives after the expensive work is done, and then you either
rewrite or live with the first way.

write-tests arranges for that moment to come early and cheap. A thin **sketch** writes one test per
important promise, which forces each design choice into concrete setup and expected results, where
gaps show. A **spike** then implements the core flows for real, against the sketch, and logs every
guess, workaround and place where the design fought the existing code. The spike's code is thrown
away and never shown to later workers; only what it learned travels. A fresh reader checks the
design against both, and the design is corrected before the thorough tests are written, while
changing course costs a few files instead of a suite.

## Reading for fidelity, running for discrimination

A contract can fail in two ways, and each needs a different check:

- **Fidelity:** does the suite demand the right behavior, nothing invented and nothing narrowed?
  That's a question about meaning, so a fresh reviewer _reads_ it, without the author's reasoning.
- **Discrimination:** does the suite reject wrong code? Reading can't answer that. Suites that
  readers had cleared still passed five to nineteen deliberately wrong implementations.

Discrimination is tested by running. Once the honest implementation passes, two or three
attackers, each focused on one risk area, try to keep the suite green with wrong variants of that
code. Starting from working code is cheaper than each attacker building its own, and each exploit
becomes a patch that the repaired test must be shown to catch.

Exploits aren't repaired one by one. An attacker can always find one more spelling, encoding or
exception type, and a test per instance invites the next one: past runs went to seven repair rounds
that way. So a fresh triage reader first drops findings that can't arise in deployment or that no
honest implementer would write, then groups the rest by the design choice that made them possible.
Each family gets one verdict: dissolve it with a design change, accept it as a recorded trade-off,
close it with one test over the whole class, or fix the code. Another round runs only when a
recheck finds a new family.

```mermaid
flowchart TD
    H[Honest code passes the contract] --> A[Attackers write wrong variants]
    A --> Q{Suite still green?}
    Q -->|no| N[Suite caught it]
    Q -->|yes| X[Exploits found]
    X --> T[Triage: drop irrelevant,<br/>group into families]
    T --> D[Dissolve:<br/>design amendment]
    T --> K[Accept:<br/>recorded trade-off]
    T --> C[Close: one test<br/>over the family]
    T --> B[Code bug:<br/>fix the code]
    C --> E{Test fails on every<br/>exploit in the family,<br/>passes on honest code?}
    E -->|no| C
    E -->|yes| R{Recheck finds<br/>a new family?}
    R -->|yes| T
    R -->|no| S[Done]
```

## Where findings go

Every stage can find a problem that belongs to an earlier one. Findings are grouped by cause first,
since one model or flow change often dissolves several, then routed by kind:

| Finding                                                      | Goes to                                                                                 |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| A factual question                                           | A probe. The human doesn't decide what existing code does                               |
| Code is wrong under the settled design                       | Fixed in the code stage                                                                 |
| A test omits, misstates or fails to enforce settled behavior | write-tests' repair author                                                              |
| An existing test goes red because it pins replaced behavior  | write-tests' stale-test repair: update, retire, or route as a design gap                 |
| The design is wrong or leaves a consequential choice open    | discuss-issue's amendment, put to the human as "this is a bug; here are the trade-offs" |

Human attention goes to consequential design choices, never to one question per edge case.

## Why each stage starts cold

Every stage runs as a fresh session that never saw the previous one. GitHub is the only channel:
the issue, its comments, the branch and the PR. That makes any stage resumable after a crash,
inspectable by a person, and runnable headless as one command per stage.

## Rules state goals; applications are a cache

Every rule, in a skill or in a design, states its goal and the principle behind it, never the list
of cases it covers. How a rule applies to one context is recorded separately, as a cache. For a
design, the context is an input, surface or deployment. For a skill, it is the harness, the model
generation, the project's toolchain, or what past runs found. Each skill file ends with a `Cache`
section, and a project keeps its own entries in `.claude/contract-first-cache.md`; a design keeps
its cache at the end of the design doc. Every entry is one line naming the rule it applies and the
context it assumes, so one grep finds every application of a rule, or everything that assumed a
given model family. Humans maintain the skills' caches. The project cache is kept by one independent
agent running the `maintain-cache` skill, dispatched at the end of write-tests' and write-code-from-tests' review steps: it adds facts the run had to
work out, removes entries the run contradicted, and consolidates similar entries across the file,
so the cache stays a short list of general facts instead of a log of instances. It is the file's
only writer, and its changes reach the human with the PR.

A list written as the rule invites work that handles exactly the list: an implementation that
handles the listed members, a test per listed value, an attacker who finds the next member. A
rule stated as its goal decides cases nobody listed. The cache keeps the concrete detail cheap to
reach, and it is easy to recompute when its context changes, for example when a new model family
changes which model suits a role. When an entry and its rule disagree, the rule wins. The attack
deck is the same idea at project scope: a cache of exploit shapes that have worked here.

## Why finalize reads cold

write-tests writes its hand-off note for the implementer, and the implementer reads it. finalize
deliberately doesn't. A reviewer who has read the argument for each choice tends to agree with it,
because the argument is right there. finalize reads the code, the diff and the tests. It does read
the earlier _review_ trail, but checks who wrote each comment, since on a public repo anyone can
comment and finalize holds a push credential.

## Two nets for what escapes

When a bug ships green, finalize traces it back, through a subagent that reads the records it
skipped, to the stage where the defense should have held. The result goes to one of two places:

- **The attack deck** gets the exploit's _shape_, when the design stated the intent and the suite
  passed anyway. Attackers replay the deck on every future contract.
- **The human** gets process findings: which stage missed, and what rule or check might stop it.
  One PR is one data point, so the human weighs it against others before changing the pipeline.

A deck entry that restates a test-writing rule, or a process finding that's really "replay this
exploit", makes the two nets miss the same things, so they stay separate. The deck belongs to each
project, at `.claude/contract-first-attacks.md`; the plugin defines only its format.

## Choosing a lane

The full pipeline is for new or changed promises. Most changes don't need it, and you pick the lane;
skills don't route themselves.

```mermaid
flowchart TD
    S[A change] --> Q1{Does it add or change<br/>what the system promises?}
    Q1 -->|yes| P[discuss-issue → write-tests →<br/>write-code-from-tests → review]
    Q1 -->|no| Q2{Does code disagree with<br/>intent that's already settled?}
    Q2 -->|"yes, and you can state it in a sentence"| PF[proven-fix:<br/>red test first, smallest fix, mutants]
    Q2 -->|no| Q3{Does only structure change?}
    Q3 -->|yes| RF[refactor:<br/>existing suite unchanged, lint against regressions]
    Q3 -->|"unsure, or two readings of intent"| P
```

The lighter lanes hand back rather than decide: they have nowhere to record a design decision.

## Limitations

- **Tests pin only what someone thought to assert.** Intent the design never stated is never
  enforced, and the attackers deliberately attack only stated intent. A green suite is evidence
  about its assertions, not proof of correct code.
- **Attacks sample; they don't prove.** An attacker that finds nothing has missed its samples, not
  shown the suite is tight.
- **The checkers share blind spots.** Authors, reviewers and attackers are usually the same family of
  model. Reading cold removes shared context, not shared habits of thought, so they can all miss the
  same kind of bug. The attack deck and the human at the merge are the main counterweights.
- **Some properties don't fit in tests.** Performance, usability, the quality of prose or prompts,
  and security beyond the cases someone enumerated get little from this pipeline.
- **The design is the ceiling.** A wrong design gets faithfully enforced. The pipeline asks the human
  for consequential choices; it can't make them well on the human's behalf.
- **It costs a lot.** A full run dispatches many agents and takes hours of wall time. That's why the
  lighter lanes exist, and choosing the lane is on you.
- **It's only as good as the test harness.** Without real seams to inject fakes and observe effects,
  tests check less than they appear to.
- **Tests-first history is pinned.** The contract commit must precede the code, so the branch can't
  be freely rebased; long-lived branches get awkward.
- **It's tuned on one project.** The skills and the numbers in this document come from running it
  on one Python codebase. Expect to adjust them elsewhere.

## Keeping agent work cheap

Most of the cost is agents re-reading what they already read, so the skills spend on fewer steps
with smaller histories. Facts about the code are gathered once into a shared code map; each worker
still works out on its own what must hold. Workers outline a file before reading it and read only
the parts they need. Every dispatch names its model and effort: Opus where judgment carries the
result (design check, fidelity review), Sonnet where the design is settled and the work is
expanding it (thorough authoring, spikes, attackers).
