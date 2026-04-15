---
title: Migrate hooks from filesystem discovery to meta.json for run lookup
status: done
groups: hooks, reliability
---

Several hooks locate the current run directory by crawling the filesystem (e.g. sorting by mtime, matching path patterns). This is fragile: it breaks under concurrent runs, fails when the run dir hasn't been written yet, and silently picks the wrong run if timing is off.

`meta.json` (written at run start) is the authoritative record of which run directory belongs to the current invocation. Hooks should read it directly instead of re-deriving the path.

Work items:

1. Audit all hooks under `soc-agent/hooks/scripts/` for any `find`-latest-run or mtime-sort logic.
2. Replace each with a `meta.json` read — fail fast and loudly if `meta.json` is absent or malformed, rather than falling back to a guess.
3. Add or update tests in `soc-agent/tests/` to cover the lookup path and the failure modes.