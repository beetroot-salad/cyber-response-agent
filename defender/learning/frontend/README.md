# Learning-loop frontend

A read-only view of the learning loop. Two pages, one build:

- **lessons** (`lessons.html`) — the loop's posture: the corpora it authors, read off the
  tenant's published knowledge (an export's `agent/`, #1108 P4).
- **queues** (`queues.html`, #903) — the loop's backlog on THIS host: per channel, the rows it
  gave up on (dead letters, with the reason and the row), the last non-retiring fault (the
  stuck record, append-only — so "last fault", never "stuck now"), and the rows held until a
  person moves them (or, on the pitfalls lane, re-offered to the curator until the offer
  ceiling — each lane says what its own hold means); plus what the drains set aside (markers
  they could not serve, batches committed but not delivered, tainted worktrees). Read off the
  state root (`DEFENDER_LEARNING_STATE_DIR`, else `defender/learning/`), so it is per-host and
  stale the moment it is built; the header says which root and when. The one exception is
  the tainted-worktree list, which lives beside the live worktrees under the REPO root
  (`.worktrees/quarantine`) and does not move with the state dir — the card names that
  directory, and its `held / cap` is the writer's own count of archives, so it agrees with
  the writer's refusal past the cap even when a manifest is missing or torn. Its contract is
  `serialize_queues.build_view` — the typed boundary: every value off disk is coerced there,
  and a wrong-typed record degrades to one row, never the page — and its channel list is that
  module's own literal (#922's rule). `build.main(paths)` / `stamped_view(paths)` take a
  `LoopPaths` so a test's roots are the whole input surface.

First panel: **lessons** — the two corpora the loop authors, in the tenant's `agent/`:

| Section | Corpus | Authored by |
|---------|--------|-------------|
| Defender lessons | `agent/lessons/` | `learning/author/lessons/run.py` |
| Questioner lessons | `agent/lessons-questioner/` | `learning/author/questioner/run.py` |

The corpora #922 retired (actor and environment lessons) are not in the tenant layout and
have no group (#1108 P4). A group still declares `retired` + `retired_note`, so a channel
that loses its producer can be badged rather than hidden.

## Build

```bash
python3 defender/learning/frontend/build.py
```

Writes four artifacts (git-ignored) into this directory:

- `lessons.json` / `queues.json` — the two view **contracts**
- `lessons.html` / `queues.html` — **self-contained** pages (open in a browser, no server),
  each linking to the other from its header

Open either directly. Re-run `build.py` after the loop authors new lessons, and after a
drain — the queue page is a snapshot.

## Design — representation decoupled from the api

```
filesystem  ──►  serialize.py  ──►  lessons.json  ──►  build.py + template  ──►  lessons.html
 (backend)       (api layer)       (the contract)        (the view)
```

- **`serialize.py`** is the api layer: it reads the corpora (whose
  frontmatter schemas differ) and normalizes them into one
  schema-agnostic contract. Each group declares `retired` + `retired_note`
  there — retirement is a property of the *channel*, so it is declared per
  group rather than inferred from any lesson's own `status: stale`.
  `build_view()` is pure; the CLI stamps `generated_at`. Each corpus is enumerated through the shared corpus walk
  (`defender.knowledge._corpus.iter_lessons`, the same reader the lesson CLIs and the
  curators go through): sorted `*.md`, underscore-skip, warn+skip on a
  malformed or unreadable lesson. Stale lessons are surfaced with a badge,
  not hidden — this is an author-facing view.
- **`lessons.json`** is the only coupling point between backend and view.
  Each group declares its `fields[]`, so the view renders metadata
  generically without knowing any corpus's schema. A real HTTP api could
  serve this same contract to the identical frontend.
- **`build.py`** + its inline template is the view. It reuses the run
  visualizer's visual language (`presentation/visualize_run.py` CSS tokens) so
  the page matches the transcript/runtime views: defender=blue,
  actor=red, environment=amber. Group order/identity come from the
  contract, so adding a corpus — or retiring one — is a `serialize.GROUPS`
  edit alone.

## Tests

```bash
defender/.venv/bin/python3 -m pytest defender/tests/learning/retrieval/test_lessons_frontend.py -v
```

## Not yet built (future panels)

Findings-queue AUTHORABLE depth vs `LEARNING_AUTHOR_THRESHOLD` — rows carrying `held_reason`
are queued but do not count (`learning/_pending/findings.jsonl`) —
episode history (the branched episodes under each tenant's `<data root>/<T>/episodes/`, with each
family's verdicts and the judge's buckets), and the consumed/audit trail.
