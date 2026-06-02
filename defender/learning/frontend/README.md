# Learning-loop frontend

A read-only view of the learning loop's current posture. First panel:
**lessons** — the loop's output, the three corpora it authors:

| Section | Corpus | Authored by |
|---------|--------|-------------|
| Defender lessons | `defender/lessons/` | `author.py` |
| Actor lessons | `defender/lessons-actor/` | `author_actor.py` |
| Environment lessons | `defender/lessons-environment/` | `author_actor_benign.py` |

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
  schema-agnostic contract. `build_view()` is pure; the CLI stamps
  `generated_at`. Reuses the `iter_lessons` discovery primitives from
  `scripts/lessons_actor_index.py` / `scripts/lessons_env_retrieve.py`.
- **`lessons.json`** is the only coupling point between backend and view.
  Each group declares its `fields[]`, so the view renders metadata
  generically without knowing any corpus's schema. A real HTTP api could
  serve this same contract to the identical frontend.
- **`build.py`** + its inline template is the view. It reuses the run
  visualizer's visual language (`scripts/visualize_run.py` CSS tokens,
  `scripts/visualize_primitives.py` helpers) so the page matches the
  transcript/runtime views: defender=blue, actor=red, environment=amber.

## Tests

```bash
defender/.venv/bin/python3 -m pytest defender/tests/test_lessons_frontend.py -v
```

## Not yet built (future panels)

Pending-queue depth vs author thresholds (`learning/_pending/*.jsonl`),
run history (`learning/runs/`), and the consumed/audit trail.
