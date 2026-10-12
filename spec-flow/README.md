# spec-flow

A design-and-tests pipeline from GitHub issue to merged PR, as a Claude Code plugin.

The design records intended behavior, scope, data models, flows, architecture and trade-offs.
**The tests are the executable contract between that design and code.** Write them before
implementation, independently review their fidelity and discrimination, then implement against
them while an adversary looks for intent violations the tests permit. Findings can improve the
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

The implementation stage dispatches honest workers and contract adversaries against the same
immutable tests ref. `finalize` remains the plugin's existing post-implementation review stage.
`write-code-from-spec` is a compatibility entry; `write-code-with-no-spec` is retained for old runs.
Small changes use the same pipeline with fewer workers and targeted review.

Human attention goes to consequential design choices: behavior, scope, models, flows,
architecture and trade-offs. Agents resolve technical details determined by those decisions.
Tests and code may expose design defects; `discuss-issue` handles their amendments. Independent
contract/code review and executed probes provide evidence without making the human adjudicate
every edge case. The merge remains human-approved.

## The skills

| Skill | What it does |
|---|---|
| `/spec-flow:discuss-issue` | Opens with only the problem and open questions, then grounds and reviews a design covering behavior, scope, data models, flows, and architecture. Groups findings into fixes or dissolving design choices; hands off a human-facing intent+design doc with supporting probed claims. Also handles design amendments discovered by tests or code. |
| `/spec-flow:write-tests` | Authors contract tests early, independently reviews fidelity and discrimination, and iterates through patches or design amendments. Commits tests before implementation with a compact coverage/review record. Known blockers prevent a ready handoff. |
| `/spec-flow:write-code-from-tests` | Dispatches honest implementers and test-breaking adversaries from the same committed contract. Reconciles findings, completes deferred verification, ships and repairs CI. |
| `/spec-flow:write-code-from-spec` | Compatibility entry delegating to write-code-from-tests for older invocations and historical resumes. |
| `/spec-flow:write-code-with-no-spec` | Legacy combined lane for existing runs; new small changes use write-tests then write-code-from-tests. |
| `/spec-flow:finalize` | Meets the shipped PR **cold**: applies every fix it's confident in, files the rest, feeds process findings back to the human, and re-greens the PR. |
| `/spec-flow:ship` | Branch, commit, push, open a PR. Used by the phases above; useful on its own. |
| `/spec-flow:handoff` | Writes the terse note that lets a cold session resume the work. |
| `/spec-flow:init` | Writes the project profile. Run once per repo. |
| `/spec-flow:symbol-refs` | Resolves a Python symbol's cross-file references / definitions via Pyrefly — the resolved sibling of grep and the Explore agent. Used by `discuss-issue`'s census; useful on its own. |

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
claude plugin install spec-flow@spec-flow-local --scope project
```

That writes `enabledPlugins` into `.claude/settings.json` (committed), so every session in this repo
has the skills. A teammate cloning fresh runs the same two commands — the marketplace path is
machine-local, so it can't be committed for them.

**Programmatic callers (an orchestrator, CI) should skip the install entirely** and load the plugin
hermetically — no marketplace, no global state, nothing to bootstrap:

```bash
claude --plugin-dir /path/to/spec-flow -p "/spec-flow:write-tests 559"
```

## The project profile

The method is portable; a project's gate is not. Everything repo-specific lives in **one file** —
`.claude/spec-flow.json` — and nowhere else in the plugin:

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

`/spec-flow:init` derives it from the repo and then *runs* what it wrote — a profile that has never
been executed is a guess.

## Invoking it

In a session, type the skill: `/spec-flow:write-tests 559`.

Headless, put the skill in the prompt string — `claude -p` will not decide to invoke a skill on its
own, so a prose instruction ("use the write-tests skill…") leaves it to the model's discretion:

```bash
claude -p "/spec-flow:write-tests 559"          # deterministic
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
checkers remain available for historical investigation; the graph-maintenance CI gate is retired and its project configuration is archived beside the tooling. new work does not create, read, or maintain
them. Historical graph documentation lives under `scripts/spec_graph/references/`.
