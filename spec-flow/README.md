# spec-flow

A spec-first pipeline from GitHub issue to merged PR, as a Claude Code plugin.

The idea it is built on: **the tests are the spec.** A design written in prose fails three ways —
it's ambiguous (two defensible readings), incomplete (a case it never mentions), or the code just
diverges from it. So before any implementation exists, the design is turned into an *executable*
spec: a list of demands bound to a spec-coverage graph, realized as end-to-end tests — the tests
committed before implementation, the graph riding along as their machine-checked derivation.
Then the code is written against it. "Tests green" comes to mean "the code
follows intent" — which is not what it means when the tests were written afterwards, by the same
agent, from the same assumptions.

```
issue ──▶ discuss-issue ──▶ write-tests ──▶ write-code-from-spec ──▶ finalize ──▶ merge
                                  │                                     │
                              human seam:                          human gate:
                             resolve forks                        approve merge
```

Human judgment enters twice for different reasons: `write-tests` pauses only for genuine design
forks, before code exists, and the merge stays human-approved after review. Everything else runs
unattended. One discipline runs the whole pipe: enumerators interpret the design's language,
executed probes answer every question about existing reality, and humans decide only genuine forks
— nothing in between gets to guess.

## The skills

| Skill | What it does |
|---|---|
| `/spec-flow:discuss-issue` | Explains the issue in plain terms, checks it against the real code, surfaces the open questions — and when work heads to implementation, closes by posting the intent+design doc: typed obligations and mechanisms, with probed claims about existing reality. |
| `/spec-flow:write-tests` | Turns the intent+design doc into the executable spec: situations from the doc's language, mechanics from executed probes, forks to the human — bound through the spec-coverage graph and gate rules into a suite a null-stub run proves can fail. Ships a **tests + spec_graph diff** and a handoff note. |
| `/spec-flow:write-code-from-spec` | Reads the committed spec, writes real code until it passes, ships a PR, watches CI, repairs to green. Never edits a test to make it pass. |
| `/spec-flow:finalize` | Meets the shipped PR **cold**: applies every fix it's confident in, files the rest, feeds process findings back to the human, and re-greens the PR. |
| `/spec-flow:ship` | Branch, commit, push, open a PR. Used by the phases above; useful on its own. |
| `/spec-flow:handoff` | Writes the terse note that lets a cold session resume the work. |
| `/spec-flow:init` | Writes the project profile. Run once per repo. |
| `/spec-flow:symbol-refs` | Resolves a Python symbol's cross-file references / definitions via Pyrefly — the resolved sibling of grep and the Explore agent. Used by `discuss-issue`'s census; useful on its own. |

Each stage is a **cold start**: a fresh session that never saw the previous one. GitHub is the only
channel between them — the issue, its comments, the branch, the PR. That constraint is what makes
the pipeline resumable and inspectable, and it is why `write-tests` ends by posting a handoff note.

### The one rule about who reads what

`write-tests` writes its handoff note **for the implementer**. `write-code-from-spec` reads it.
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
- `specGraph` — read as data by the two checkers: the project's source roots and entrypoint stems.
  (The alias maps are an escape hatch, normally empty — a spec graph is supposed to name things what
  the code names them, and a private synonym silently disables the check for that concept.)
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

`git` and the `gh` CLI (authenticated). The spec_graph checks need a Python with PyYAML; the
bundled `spec-graph` command finds one (or falls back to `uv run --with pyyaml python`), so there is
nothing to configure.
