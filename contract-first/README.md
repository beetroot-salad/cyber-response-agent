# contract-first

A design-and-tests pipeline from GitHub issue to merged PR, as a Claude Code plugin.

The design records intended behavior, scope, data models, flows, architecture and trade-offs.
**The tests are the executable contract between that design and code.** They are written before
implementation and reviewed for fidelity. Then the code is written against them, and attackers try
deliberately wrong variants of that code to find intent violations the tests let through. Findings
can improve the design, the contract or the code; they are grouped by cause before anything is
patched. A green suite still does not prove complete intent.

```
issue → discuss-issue → write-tests → write-code-from-tests → finalize or /code-review → human merge
             ↑              ↑                  │
             └──────────────┴──── findings ────┘
```

## Choosing a lane

You choose the lane; skills don't route themselves. The full pipeline is built for new behavior
and is too heavy for most fixes. Ask what the change does to what the system promises:

| The change | Lane | What guards it |
|---|---|---|
| Adds or changes a promise: new behavior, a changed flow or model, a new surface | `discuss-issue` → `write-tests` → `write-code-from-tests` → `finalize` or `/code-review` | A committed, reviewed and attacked test contract |
| Code disagrees with intent that is already settled (a bug) | `proven-fix` | A test written red first, plus mutants of the fix's lines |
| Structure changes, behavior doesn't (a refactor) | `refactor` | The existing suite, unchanged; a lint when a removed pattern could return |

Soft guardrails, which the lighter lanes also enforce:

- **If you can't state the intended behavior in a sentence, it isn't a bug fix.** Two reasonable readings of the intent is a design question.
- **A refactor that needs an assertion changed is a behavior change.** The refactor skill stops there and asks.
- **Lighter lanes hand back rather than decide.** When proven-fix or refactor hits a design question, it stops and says so, and you re-route to `discuss-issue`. Neither has anywhere to record a decision.
- **Size isn't the test.** A one-line change to what a refusal says is a promise change. A thousand-line move with no behavior change is a refactor.

The last review is either `finalize` or Claude Code's built-in `/code-review`. `finalize` also
traces escaped bugs back to the stage that missed them and feeds the attack deck; `/code-review`
is the lighter pass.

Human attention goes to consequential design choices. Agents resolve the technical details those
choices determine, and the merge stays human-approved. For why the pipeline is built this way,
with diagrams, see [docs/design.md](docs/design.md).

## The skills

| Skill | What it does |
|---|---|
| `/contract-first:discuss-issue` | Opens with only the problem and open questions, then grounds and reviews a design covering behavior, scope, data models, flows and architecture. Hands off an intent+design doc with probed claims. Also handles design amendments that tests or code expose. |
| `/contract-first:write-tests` | Sketches the contract, spikes a throwaway implementation to settle the design, authors tests with Sonnet and reviews their fidelity with Opus. Commits the tests before any implementation, with a compact coverage and review record. |
| `/contract-first:write-code-from-tests` | Implements against the committed contract, then has two or three Sonnet attackers try to keep it green with wrong variants of that code. Reconciles findings, ships, and repairs CI. |
| `/contract-first:finalize` | Reviews the shipped PR **cold**, fixes or files what it finds, traces escaped bugs back to the stage that should have caught them, and re-greens the PR. |
| `/contract-first:proven-fix` | Fixes a bug against settled intent: a test written red first, the smallest fix, then up to five hand-written mutants of the fix's deciding lines. |
| `/contract-first:refactor` | Restructures without behavior change; tests change only mechanically, and a lint is added when a removed pattern could return. |
| `/contract-first:ship` | Branch, commit, push, open a PR. Used by the stages above; useful on its own. |
| `/contract-first:guide` | Answers which lane fits a change, where a run stands and what comes next, and why the pipeline works as it does. Runs only when you type it. |
| `/contract-first:handoff` | Writes the terse note that lets a cold session resume the work. |
| `/contract-first:symbol-refs` | Resolves a symbol's cross-file references or definitions through Claude Code's `LSP` tool, checked against grep, where grep alone would also match comments and unrelated same-name symbols. |

Each stage is a **cold start**: a fresh session that never saw the previous one. GitHub is the only
channel between them — the issue, its comments, the branch, the PR. That is what makes the pipeline
resumable and inspectable, and why `write-tests` ends by posting a handoff note.

### Who reads what

`write-tests` writes its handoff note **for the implementer**, and `write-code-from-tests` reads it.
**`finalize` deliberately does not.** A reviewer who has read the argument for every decision tends
to agree with it; finalize's value is being the one reader who hasn't been told what to think. It
reads the code, the diff and the tests, plus the prior review trail (earlier review comments and
follow-up issues).

## What the plugin reads from your project

The method is portable; a project's gate is not. The skills take repo-specific facts from what the
repo already keeps for any agent:

- **CLAUDE.md files** — how to run tests, the traps that make a green local run a lie, the test
  harness to build on, and a pointer to the project's **principles** document (what every design
  fork is judged against; the project owns it, and it is asked of the owner, never guessed).
- **The CI config** — the source of truth for what the gate runs. When it and CLAUDE.md disagree,
  believe CI and fix CLAUDE.md.
- **Language-server config** — whatever the project's language server needs to resolve imports
  (for Python's Pyright, `extraPaths` under `[tool.pyright]`), so `symbol-refs` gets real answers.
- **The attack deck** (`.claude/contract-first-attacks.md`) — the project's own record of exploit
  shapes that carried real bugs past its suites. `finalize` creates it on the first such escape and
  appends to it after that; the attackers replay it on every new contract. A project without one
  just has nothing to replay yet.

## Install

From the repo that holds the plugin, once per clone:

```bash
claude plugin marketplace add ./
claude plugin install contract-first@contract-first-local --scope project
```

That writes `enabledPlugins` into `.claude/settings.json`, so every session in the repo has the
skills. A teammate cloning fresh runs the same two commands: the marketplace path is machine-local.

While editing the skills, or from an orchestrator or CI, load the plugin straight from its folder
instead; edits take effect in the next session:

```bash
claude --plugin-dir /path/to/contract-first -p "/contract-first:write-tests 559"
```

## Invoking it

In a session, type the skill: `/contract-first:write-tests 559`.

Headless, put the skill in the prompt string. `claude -p` will not decide to invoke a skill on its
own, so a prose instruction leaves it to the model's discretion:

```bash
claude -p "/contract-first:write-tests 559"     # deterministic
claude -p "Run the write-tests skill for #559"  # a suggestion the model may ignore
```

This is the contract an orchestrator codes against: **one command per stage, the issue number as the
argument.** The stage owns its whole job, including watching CI, and reports one outcome.

## Requirements

`git` and the `gh` CLI (authenticated). `symbol-refs` works best with a code-intelligence plugin
for the project's language (for example `pyright-lsp` or `typescript-lsp` from Anthropic's
marketplace) and falls back to grep without one. For Python projects, two optional suite checks
(`spec-graph calls` and `spec-graph nullstub`) need `python3` or the interpreter named in
`SPEC_GRAPH_PYTHON`.

## License

MIT — see `LICENSE`.
