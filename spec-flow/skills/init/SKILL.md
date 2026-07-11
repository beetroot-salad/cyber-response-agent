---
name: init
description: "Write the spec-flow project profile (.claude/spec-flow.json) for this repo by reading its CI config, test layout, and lint rules — the small set of project facts the other spec-flow skills refuse to hardcode. Run once per repo, before the first write-tests."
---

# Init

The spec-flow skills are portable; a project's gate is not. This writes the one file that bridges them: `.claude/spec-flow.json`, the **project profile**. Everything the other skills need to know about *this* repo lives here, and nowhere else.

Derive it from the repo, not from the user. Ask only what the repo genuinely cannot tell you.

## Find the facts

- **The gate.** The CI config is the source of truth — find it (`.github/workflows/*.yml`, or the project's equivalent) and read what it actually runs. Separate the **test** command from the other **checks** (lint, types, custom project lints); the skills run the test command constantly and the full set once before shipping.
- **The test layout.** Where tests live. Whether an e2e/integration harness already exists that fakes the system's dependencies — `write-tests` builds on it rather than inventing parallel machinery, so name it precisely (path + how a new scenario is added, in a phrase).
- **The injection idioms.** How fakes are meant to enter the code under test — a `deps` parameter, a constructor argument, a fixture — and what the project's CI *forbids* (a lint that ratchets monkey-patching, for instance). If a lint enforces it, name the lint.
- **The traps.** The things that make a green local run a lie: a venv that resolves to the wrong tree from a worktree, an env var the suite needs, a service that must be up. These are what `gate.notes` is for.
- **The spec_graph targets.** Which source trees an execution-context census should scan (`codeRoots` — the project's own source, not vendored deps or tests) and any entrypoint stems that aren't obvious (`entrypointStems`). Leave `contextAliases` / `conceptAliases` **empty** — the graph is supposed to name things what the code names them (schema.md, "Coin ids from the code's name"), and an alias is an escape hatch for the cases where it can't, not a field to populate. Nothing here names an interpreter — the `spec-graph` command discovers its own.
- **The danger lens.** What kind of hostile reality this system faces — attacker-influenced input, resource exhaustion, concurrency. `write-tests` spends one of four enumeration lenses on it. This one you may have to ask about; the code often shows it (an auth boundary, a parser fed by the network, a job queue).

## Write it, then prove it

Write `.claude/spec-flow.json` in the shape below, then **run what you wrote** — the test command, the checks, and `spec-graph binds` / `spec-graph actors` against any existing graph. A profile that has never been executed is a guess: a path that doesn't resolve, a venv that isn't there from a worktree, a command that needs an env var you didn't know about. Fix what fails, and report anything you had to leave uncertain.

```json
{
  "project": "<one line: what this codebase is, language, test framework>",
  "gate": {
    "ciConfig": ".github/workflows/ci.yml",
    "test": "<the exact command CI runs for tests>",
    "checks": ["<lint>", "<types>", "<custom project lints>"],
    "notes": "<the traps: worktree/venv gotchas, required env, services>"
  },
  "tests": {
    "language": "<the language the tests are written in>",
    "dir": "<where tests live>",
    "harness": "<path to the existing fake/replay harness + how a scenario is added>",
    "idioms": "<how fakes enter; what CI forbids>"
  },
  "specGraph": {
    "artifacts": "<glob for the committed spec_graph_*.yaml>",
    "codeRoots": ["<the project's own source trees>"],
    "entrypointStems": [],
    "contextAliases": {},
    "conceptAliases": {}
  },
  "conventions": {
    "defaultBranch": "main",
    "dangerLens": "<the standing fourth enumeration lens, and why>"
  }
}
```

`specGraph` is consumed by the checkers as data (the plugin's own `scripts/spec_graph/_config.py`); every other field is read by a skill as prose, so write it to be *read* — a sentence that tells the next agent what to do beats a value it has to interpret.
