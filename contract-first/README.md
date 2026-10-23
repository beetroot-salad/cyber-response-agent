# contract-first

A design-and-tests pipeline from GitHub issue to merged PR, as a Claude Code plugin.

The design records intended behavior, scope, data models, flows, architecture and trade-offs.
**The tests are the executable contract between that design and code.** Write them before
implementation and review their fidelity, then implement against them and let adversarial
implementers vary that code to look for intent violations the tests permit. Findings can improve the
design, the contract or the code; group them by cause before patching or choosing a dissolving change.

Coverage records are agent scaffolding. `write-tests` starts with a compact map and scales
investigation/review to uncertainty, coupling and failure consequences. `write-code-from-tests` consumes that compact contract directly. There is no separate formal
spec artifact: the design records requirements and the tests enforce them. A green suite does
not prove complete intent.

```
issue → discuss-issue → write-tests → write-code-from-tests → code review → merge
             ↑              ↑                  │
             └──────────────┴── findings ───────┘
```

The implementation stage works against an immutable tests ref. Once its honest implementation is green, attackers try wrong variants of it, and the holes they find return to `write-tests` as contract repairs. `finalize` remains the plugin's existing post-implementation review stage.
`write-code-with-no-spec` is retained for old runs.

## Choosing a lane

You choose the lane; skills don't route themselves. The full pipeline is built for new behavior and is too heavy for most fixes. Ask what the change does to what the system promises:

| The change | Lane | What guards it |
|---|---|---|
| Adds or changes a promise: new behavior, a changed flow or model, a new surface | `discuss-issue` → `write-tests` → `write-code-from-tests` | A committed, reviewed and attacked test contract |
| Code disagrees with intent that is already settled (a bug) | `proven-fix` | A test written red first, plus mutants of the fix's lines |
| Structure changes, behavior doesn't (a refactor) | `refactor` | The existing suite, unchanged; a lint when a removed pattern could return |

Soft guardrails, which the lighter lanes also enforce:

- **If you can't state the intended behavior in a sentence, it isn't a bug fix.** Two reasonable readings of the intent is a design question.
- **A refactor that needs an assertion changed is a behavior change.** The refactor skill stops there and asks.
- **Lighter lanes hand back rather than decide.** When proven-fix or refactor hits a design question, it stops and says so, and you re-route to `discuss-issue`. Neither has anywhere to record a decision.
- **Size isn't the test.** A one-line change to what a refusal says is a promise change. A thousand-line move with no behavior change is a refactor.

Human attention goes to consequential design choices: behavior, scope, models, flows,
architecture and trade-offs. Agents resolve technical details determined by those decisions.
Tests and code may expose design defects; `discuss-issue` handles their amendments. Independent
contract/code review and executed probes provide evidence without making the human adjudicate
every edge case. The merge remains human-approved.

## The skills

| Skill | What it does |
|---|---|
| `/contract-first:discuss-issue` | Opens with only the problem and open questions, then grounds and reviews a design covering behavior, scope, data models, flows, and architecture. Groups findings into fixes or dissolving design choices; hands off a human-facing intent+design doc with supporting probed claims. Also handles design amendments discovered by tests or code. |
| `/contract-first:write-tests` | Sketches the contract and spikes a throwaway implementation to settle the design, authors thorough tests with Sonnet, reviews fidelity with Opus, and iterates through patches or design amendments. Commits tests before implementation with a compact coverage/review record. Known blockers prevent a ready handoff. |
| `/contract-first:write-code-from-tests` | Implements against the committed contract, then has two or three lensed Sonnet attackers try to keep it green with wrong variants of that code. Reconciles findings, completes deferred verification, ships and repairs CI. |
| `/contract-first:proven-fix` | Fixes a bug against settled intent: the test is written red first, then the smallest fix, then up to five hand-written mutants of the fix's deciding lines. Sonnet. |
| `/contract-first:refactor` | Restructures without behavior change; tests change only mechanically, and a lint is added when a removed pattern could return. Sonnet. |
| `/contract-first:write-code-with-no-spec` | Legacy combined lane for existing runs; new small changes use write-tests then write-code-from-tests. |
| `/contract-first:finalize` | Meets the shipped PR **cold**: applies every fix it's confident in, files the rest, feeds process findings back to the human, and re-greens the PR. |
| `/contract-first:ship` | Branch, commit, push, open a PR. Used by the phases above; useful on its own. |
| `/contract-first:handoff` | Writes the terse note that lets a cold session resume the work. |
| `/contract-first:init` | Writes the project profile. Run once per repo. |
| `/contract-first:symbol-refs` | Resolves a Python symbol's cross-file references / definitions via Pyrefly — the resolved sibling of grep and the Explore agent. Used by `discuss-issue`'s census; useful on its own. |

Each stage is a **cold start**: a fresh session that never saw the previous one. GitHub is the only
channel between them — the issue, its comments, the branch, the PR. That constraint is what makes
the pipeline resumable and inspectable, and it is why `write-tests` ends by posting a handoff note.

### The one rule about who reads what

`write-tests` writes its handoff note **for the implementer**. `write-code-from-tests` reads it.
**`finalize` deliberately does not.**

A reviewer who has read the rationale behind every decision will confirm those decisions — the
argument is right there, already made, and agreeing is cheap. `finalize`'s entire value is that it
is the one reader who hasn't been told what to think. It reads the code, the diff, and the tests;
it does not go looking for the design's defence of a choice it finds questionable. (It *does* read
the prior **review** trail — follow-up issues, earlier PR comments — which is review output, not
spec rationale.)

## Install

**Once per clone**, from the repo root:

```bash
claude plugin marketplace add ./
claude plugin install contract-first@contract-first-local --scope project
```

That writes `enabledPlugins` into `.claude/settings.json` (committed), so every session in this repo
has the skills. A teammate cloning fresh runs the same two commands — the marketplace path is
machine-local, so it can't be committed for them.

**Programmatic callers (an orchestrator, CI) should skip the install entirely** and load the plugin
hermetically — no marketplace, no global state, nothing to bootstrap:

```bash
claude --plugin-dir /path/to/contract-first -p "/contract-first:write-tests 559"
```

## The project profile

The method is portable; a project's gate is not. Everything repo-specific lives in **one file** —
`.claude/contract-first.json` — and nowhere else in the plugin:

- `gate` — the exact test + lint + type commands CI runs, the CI config that is the source of truth,
  and the traps that make a green local run a lie.
- `tests` — where tests live, the existing fake/replay harness to build on, and how fakes are meant
  to enter the code (what the project's CI forbids).
- `sourceRoots` — source directories and standalone entrypoints used by repository code censuses.
- `codeGraph` — optional Python source-reference lookup configuration for `symbol-refs`;
  it does not model feature requirements.
- `conventions` — the default branch, the **danger lens** (what kind of hostile reality this system
  faces; `write-tests` selects focused review where relevant), and a pointer to the project's **principles** document (what every fork
  is judged against — the project owns it; asked of the owner, never guessed).

`/contract-first:init` derives it from the repo and then *runs* what it wrote — a profile that has never
been executed is a guess.

## Invoking it

In a session, type the skill: `/contract-first:write-tests 559`.

Headless, put the skill in the prompt string — `claude -p` will not decide to invoke a skill on its
own, so a prose instruction ("use the write-tests skill…") leaves it to the model's discretion:

```bash
claude -p "/contract-first:write-tests 559"          # deterministic
claude -p "Run the write-tests skill for #559"  # a suggestion the model may ignore
```

This is the contract an orchestrator codes against: **one command per stage, the issue number as the
argument.** The stage owns its whole job — including watching CI — and reports one outcome, so the
thing driving it can stay dumb.

## Requirements

`git` and the `gh` CLI (authenticated). The optional Python suite checks (`spec-graph calls`
and `spec-graph nullstub`) use the tests directly and need Python with PyYAML; the bundled
command discovers an interpreter or falls back to `uv run --with pyyaml python`.

The requirements graph is retired from the pipeline. Existing committed graphs and their
checkers remain available for historical investigation; the graph-maintenance CI gate is retired and its project configuration is archived under `docs/archive/`. new work does not create, read, or maintain
them. Historical graph documentation lives under `scripts/spec_graph/references/`.
