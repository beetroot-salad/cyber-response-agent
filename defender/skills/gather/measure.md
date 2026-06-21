# Gather — measurement reference

Read this for statistics beyond plain `jq`, recording pipelines, or to
settle whether a bullet is computable or interpretive. The §4 happy path (a
single `--batch` `jq` object) covers most leads without this file.

## Tool suite (pure transforms only)

`jq` reshapes and filters JSON and covers most dimensions. For real
statistics (median, percentile, stddev, grouped aggregates) and
columnar/set work, pipe into **`datamash`** and the coreutils filters
(`sort`, `uniq -c`, `cut`, `comm`, `join`, `wc`, `tr`, `paste`, `nl`) —
flatten with `jq -r '… | @tsv'` first. To record a pipeline, **quote the
whole thing as one argument** so the outer shell doesn't split it:

```bash
defender-record-summary --lead {lead_id} --label srcip-distribution -- \
    "jq -r '.[].data.srcip' {raw-payload-path} | sort | uniq -c | sort -rn"
```

These filters are the only tools permitted — they have no exec/network/write
surface, so they need no sandbox. A snippet that reaches for anything else
(`python3`, `awk`, `sqlite3`, …) is denied; compute the dimension a
different way, or report it as not-computable.

## Interpretive bullets stay a narrow claim — anchored to the numbers

A bullet that asks for meaning rather than a value ("is this cadence
consistent with automation?") is not computable; answer it in one sentence,
sitting directly under the computed facts it rests on. The *salience* call —
which entity matters, which timestamp is the finding — is yours; the
*numbers* it rests on are computed, never asserted.

## Do not interpret — the full line

State observables, never their meaning. Banned: labelling activity
("interactive vs automated", "brute-force pattern", "consistent with local
console access"), benign/malicious calls, and attack-name pattern-matching.
Report "4 connections, sequential source ports, 2-second span" and stop — do
not append "indicating automated tooling." Characterizing the data is
ANALYZE, the defender's phase; an interpretation that contradicts the numbers
you reported sends the defender back into the raw payload. A striking value
(5-minute cadence, single source IP, 7-day baseline) stands on its own — its
size is the finding.

Every empty or sentinel result is already typed by the §3.5 validity check
before you reach §4 — report the **verified** result ("empty
(verified: ...)", or the resolved substitute), never a raw unchecked zero or
a bare sentinel.
