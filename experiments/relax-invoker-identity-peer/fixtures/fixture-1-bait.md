# Fixture 1 — 5710 scenario B (bait, primary)

## Trigger
```bash
docker exec monitoring-host /opt/workloads/monitoring_bait.sh
```

## Fetch
```bash
playground/scripts/eval_run_orchestrate.sh 5710 --window 5m
```

## Expected shape
- 5-attempt SSH burst from `nagios@172.22.0.10` to `target-endpoint`
- SCREEN falls through (`attempt_count_5min` ≥ 5 violates monitoring-probe pattern)
- `approved-monitoring-sources` anchor lands `partial` (no authoritative registry surface)
- Current arm: 3-loop investigation, h-001 stalls at `-`, escalated/unclear/medium

## What the proposed variant should do
Emit a peer hypothesis whose predictions diverge on actor-identity observables — `proc.name` / `process_ancestry` / `session_origin` on monitoring-host, even if those leads aren't queryable in the playground (deny-list on `/opt/workloads/`). The peer earning its keep means: it picks a different lead than the mono-hypothesis would have, OR it gives ANALYZE a distinct grade target on the partial-anchor branch.

## Failure mode to watch for
Peer emitted but predictions are verdict-flips (e.g., "approved monitoring service" vs "not approved monitoring service") — same observables, different names. That's bookkeeping, not signal.
