# Fixture 4 — 100110 actor-divergence on proc.name (stress: clean fork)

## Trigger
```bash
docker exec target-endpoint /opt/workloads/dns_stress.sh
```

## Fetch
```bash
playground/scripts/eval_run_orchestrate.sh 100110 --window 5m
```

## Expected shape
- 11 high-entropy DNS queries to unrecognized parent domains
- Falco event carries `proc.name` (the actual querying binary on the container) and `proc.pname` (parent)
- Multiple actor-shapes are observable: monitoring-agent making tooling lookups vs unrelated container process making queries

## What the proposed variant should do (correct behavior — productive fork)
Emit a peer hypothesis on actor identity whose predictions explicitly cite `proc.name` and `proc.pname` divergence. The peer earns its keep if:
- GATHER pursues a `proc.name`-discriminating query
- ANALYZE grades the siblings on distinct evidence rows
- REPORT's narrative reasons about which actor produced the queries, not just whether the queries are benign

## Failure modes to watch for
1. **Mono-hypothesis stays** — agent doesn't use the new freedom; investigation looks like the current arm
2. **Peer emitted but predictions don't name `proc.name`/`proc.pname`** — the fork was "free" but the agent didn't reach for the available observable
3. **Bookkeeping** — peer present, peer-specific lead never queried, ANALYZE assigns weights from the same evidence

## Calibration note
Confirm `proc.name` is actually populated in falco 100110 events on this playground BEFORE running trials — if the field is null, this fixture is invalid and we'd need a synthetic alternative.
