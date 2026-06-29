# Error disposition types: `RunUnprocessable` vs `StageAbort`

**Status:** design — implemented. Completes the arc #438 → #441
(`FatalConfigError` carve-off) → #443 (this). Composes with #442 (the
`dead_letter` re-raise primitive); lands before it, since it defines the
`StageAbort` type that primitive re-raises.

## What this is

The learning-loop stages raise two kinds of failure, and the boundary that
maps exceptions to process exit codes (`core/orchestrate._run_stage`) must tell
them apart:

- **`StageAbort`** — a systemic fault: the whole stage is doomed, abort with the
  contracted `exit 2`. `FatalConfigError` (a bad threshold / merge mode) is the
  one current cause; `StageAbort` is its base so future systemic faults have a
  home.
- **`RunUnprocessable`** — this one run's data/content is bad (malformed
  `report.md` / judge YAML, missing artifact, a `claude -p` non-zero rc). Raised
  only inside `run_one`'s call graph (the per-run pipeline + its validators).

Before #443 there was a single type, `LoopError`, with `FatalConfigError` as its
subclass, and `_run_stage` mapped **every** `LoopError → exit 2`. The
disposition a `LoopError` got — *quarantine this item* vs *kill this stage* — was
decided by **where** it was caught, not by its type. No live bug (every
bare-`LoopError` raise lived inside `run_one` and was either fenced by
`_process_marker` → quarantine, or hit the direct `loop.py <run_dir>` path →
exit 2, both correct), but the safety was *positional*: a future bare raise on an
author-drain path would silently become a stage-kill with no failing test.

## Design

**Two disjoint families, no subclassing trick** (`core/config.py`):

```python
class StageAbort(Exception): ...          # systemic -> exit 2
class FatalConfigError(StageAbort): ...    # the one current systemic cause
class RunUnprocessable(Exception): ...     # this run's data is bad; this run only
```

`FatalConfigError` moves off the per-run base onto `StageAbort`, dissolving the
old inverted hierarchy (the *more*-fatal type subclassing the *less*-fatal one,
purely so one `except` caught both). The ~30 per-run sites
(`core/validate.py`, `core/persist.py`, `core/runner.py`,
`pipeline/oracle/sample.py`, and `read_ground_truth` / `_validate_judge_yaml` in
`core/orchestrate.py`) re-tag `LoopError → RunUnprocessable`.

**The stage boundary splits by unit-of-work** — the load-bearing decision
(`core/orchestrate._run_stage`):

```python
def _run_stage(stage, *, allow_run_error=False):
    try:
        return stage()
    except StageAbort as e:                 # systemic -> exit 2 (every stage)
        print(f"[loop] FATAL: {e}", ...); return 2
    except RunUnprocessable as e:
        if allow_run_error:                 # direct single-run: bad run -> exit 2 (contract)
            print(f"[loop] FATAL: unprocessable run: {e}", ...); return 2
        raise                               # drain path: a leaked per-run raise is a BUG
```

- The three **drains** (`author_drain`, `lead_author_drain`, `learn_drain`) run
  with `allow_run_error=False`. A `RunUnprocessable` reaching here did **not**
  pass a per-item guard — it's a programming error, so it propagates uncaught (a
  loud exit-1 + traceback) instead of masquerading as a clean exit 2. **This is
  the structural guard**: the per-run type can no longer be silently read as a
  stage-kill.
- The **direct** `loop.py <run_dir>` path (`main()`) passes
  `allow_run_error=True`, preserving the contract (a single bad run exits 2 —
  there's no queue to quarantine into).

The drain re-raise clauses (`_drain_lead_author_markers`, `_drain_pitfalls`)
catch `StageAbort` (was `FatalConfigError`) before their broad
`except Exception` quarantine — catching the base keeps any future systemic type
re-raising for free, and composes with #442's `dead_letter`. `_process_marker`'s
broad guard is unchanged (it still catches `RunUnprocessable` → quarantine); its
asymmetry comment retargets: `run_one` raises no `StageAbort`, so no re-raise
clause is needed there, and adding a `RunUnprocessable` re-raise would regress
every corrupt-data run into a worker-killing exit 2.

**Guard test** (`tests/test_orchestrate_thresholds.py`, the #443 regression pin):
`StageAbort → 2` on a drain; a `RunUnprocessable` raised inside a drain
**propagates** (not a clean exit 2); the same `RunUnprocessable → 2` under
`allow_run_error=True`; and the type contract `FatalConfigError` is a
`StageAbort` and is **not** a `RunUnprocessable` (and vice versa).

## Kept / dropped

- **Kept:** the broad `except Exception` quarantine guards (poison resilience);
  the direct-run exit-2 contract; `_process_marker`'s deliberate non-re-raise;
  #441's `FatalConfigError` call sites and their fail-loud behavior.
- **Dropped:** the name `LoopError`; the `FatalConfigError(LoopError)`
  subclassing trick; `_run_stage`'s blanket `except LoopError → 2`.
- **Out of scope:** the import-time int-env family (`SUBAGENT_TIMEOUT`, curator
  `*_TIMEOUT_SECONDS`, `MAX_WORKERS`) — they crash at import, before any stage
  boundary exists (carried over from #438's non-goals).

## Open questions

- **`StageAbort` base vs reusing `FatalConfigError`.** With one fatal type today,
  `_run_stage` could catch `FatalConfigError` directly. We keep `StageAbort`
  because #443 anticipates systemic siblings and a base reads honestly at the
  boundary; collapse it only if no sibling ever materializes — cheap to do later.
