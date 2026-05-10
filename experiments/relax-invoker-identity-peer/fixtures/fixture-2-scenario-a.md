# Fixture 2 — 5710 scenario A clean (mild regression)

## Trigger
Wait for next `:X0:02` monitoring-host cron probe, OR trigger manually:
```bash
docker exec monitoring-host /opt/workloads/monitoring_probe.sh nagios
```

## Fetch
```bash
playground/scripts/eval_run_orchestrate.sh 5710 --window 5m
```

## Expected shape
- Single SSH attempt from approved triple
- SCREEN matches monitoring-probe → fast-path
- Current arm: resolved/benign/high in ~3-4 min

## What the proposed variant should do
Behave identically — SCREEN-resolve, no fork, single hypothesis.

## Failure mode to watch for
Spurious peer fork on the SCREEN-resolved path. If the SCREEN subagent emits a peer or the mono-hypothesis path now adds an actor peer when none is needed, that's the regression we're testing for.

## Harness notes
- Per harness quirk #11, must wait ≥5 min past the last probe before triggering a clean run
- The cron cadence may pollute the 5-min window; if in doubt, use Fixture 1 patterns (real bait) and skip Fixture 2 trials when the cron is misbehaving
