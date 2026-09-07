# Learning-loop frontend

A read-only view of the learning loop's current posture. First panel:
**lessons** — one corpus the loop still authors, and two it no longer does:

| Section | Corpus | Authored by |
|---------|--------|-------------|
| Defender lessons | `defender/lessons/` | `learning/author/lessons/run.py` |
| Actor lessons | `defender/lessons-actor/` | **retired** — producer deleted in #922 |
| Environment lessons | `defender/lessons-environment/` | **retired** — producer deleted in #922 |

The two retired corpora are **frozen archives**: files left in place, nothing
writing or reading them. Badged and dimmed rather than hidden — this is an
author-facing view, and a lesson that was learned should stay findable after its
channel closes (#922, `e9e11a48`). The headline counts
live and archived separately, so "the loop's posture" excludes what nothing
produces.

## Build

```bash
python3 defender/learning/frontend/build.py
```

Writes two artifacts (git-ignored) into this directory:

- `lessons.json` — the view **contract**
- `lessons.html` — a **self-contained** page (open in a browser, no server)

Open `lessons.html` directly. Re-run `build.py` after the loop authors
new lessons.

## Design — representation decoupled from the api

```
filesystem  ──►  serialize.py  ──►  lessons.json  ──►  build.py + template  ──►  lessons.html
 (backend)       (api layer)       (the contract)        (the view)
```

- **`serialize.py`** is the api layer: it reads the three corpora (whose
  frontmatter schemas differ) and normalizes them into one
  schema-agnostic contract. Each group declares `retired` + `retired_note`
  there — retirement is a property of the *channel*, so it is declared per
  group rather than inferred from any lesson's own `status: stale`.
  `build_view()` is pure; the CLI stamps `generated_at`. Each corpus is enumerated through the shared corpus walk
  (`defender._corpus.iter_lessons`, the same reader the lesson CLIs and the
  curators go through): sorted `*.md`, underscore-skip, warn+skip on a
  malformed or unreadable lesson. Stale lessons are surfaced with a badge,
  not hidden — this is an author-facing view.
- **`lessons.json`** is the only coupling point between backend and view.
  Each group declares its `fields[]`, so the view renders metadata
  generically without knowing any corpus's schema. A real HTTP api could
  serve this same contract to the identical frontend.
- **`build.py`** + its inline template is the view. It reuses the run
  visualizer's visual language (`scripts/visualize/visualize_run.py` CSS tokens) so
  the page matches the transcript/runtime views: defender=blue,
  actor=red, environment=amber. Group order/identity come from the
  contract, so adding a corpus — or retiring one — is a `serialize.GROUPS`
  edit alone.

## Tests

```bash
defender/.venv/bin/python3 -m pytest defender/tests/test_lessons_frontend.py -v
```

## Not yet built (future panels)

Findings-queue depth vs `LEARNING_AUTHOR_THRESHOLD` (`learning/_pending/findings.jsonl`),
episode history (the branched episodes under `$DEFENDER_EPISODES_BASE`, with each
family's verdicts and the judge's buckets), and the consumed/audit trail.
