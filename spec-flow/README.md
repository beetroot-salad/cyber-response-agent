# spec-flow

A spec-first pipeline from GitHub issue to merged PR, as a Claude Code plugin.

The idea it is built on: **the tests are the spec.** A design written in prose fails three ways —
it's ambiguous (two defensible readings), incomplete (a case it never mentions), or the code just
diverges from it. So before any implementation exists, the design is turned into an *executable*
spec: a list of demands bound to a spec-coverage graph, realized as end-to-end tests, committed and
reviewed on their own. Then the code is written against it. "Tests green" comes to mean "the code
follows intent" — which is not what it means when the tests were written afterwards, by the same
agent, from the same assumptions.

```
issue ──▶ discuss-issue ──▶ write-tests ──▶ write-code-from-spec ──▶ review ──▶ merge
                                  │                                     │
                              human gate:                          human gate:
                             approve the spec                     approve the merge
```

Two human gates, both placed where judgment is cheap and mistakes are expensive: once on the spec
(before code exists), once on the merge. Everything between them runs unattended.

## The skills

| Skill | What it does |
|---|---|
| `/spec-flow:discuss-issue` | Explains the issue in plain terms, checks it against the real code, surfaces the open questions. Produces understanding, not a design. |
| `/spec-flow:write-tests` | Turns the approved design into the executable spec: demands → spec-coverage graph → gate rules → binding test suite. Ships a **tests-only diff** and a handoff note. |
| `/spec-flow:write-code-from-spec` | Reads the committed spec, writes real code until it passes, ships a PR, watches CI, repairs to green. Never edits a test to make it pass. |
| `/spec-flow:review` | Meets the shipped PR **cold**: applies every fix it's confident in, files the rest, re-greens the PR. |
| `/spec-flow:ship` | Branch, commit, push, open a PR. Used by the phases above; useful on its own. |
| `/spec-flow:handoff` | Writes the terse note that lets a cold session resume the work. |
| `/spec-flow:init` | Writes the project profile. Run once per repo. |

Each stage is a **cold start**: a fresh session that never saw the previous one. GitHub is the only
channel between them — the issue, its comments, the branch, the PR. That constraint is what makes
the pipeline resumable and inspectable, and it is why `write-tests` ends by posting a handoff note.

### The one rule about who reads what

`write-tests` writes its handoff note **for the implementer**. `write-code-from-spec` reads it.
**`review` deliberately does not.**

A reviewer who has read the rationale behind every decision will confirm those decisions — the
argument is right there, already made, and agreeing is cheap. The review's entire value is that it
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
- `specGraph` — read as data by the two checkers: the project's source roots, entrypoint stems,
  actor/concept aliases, and an interpreter with PyYAML.
- `conventions` — the default branch, and the **danger lens**: what kind of hostile reality this
  system faces, which `write-tests` spends one of four enumeration lenses on.

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

`git`, the `gh` CLI (authenticated), and — for the spec_graph checks — a Python with PyYAML.
