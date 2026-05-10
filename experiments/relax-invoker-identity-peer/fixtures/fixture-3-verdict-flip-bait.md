# Fixture 3 — 100001 verdict-flip bait (stress: agent must self-discipline)

## Trigger
```bash
docker exec -t target-endpoint bash -c whoami
```

## Fetch
```bash
playground/scripts/eval_run_orchestrate.sh 100001 --window 5m
```

## Expected shape
- `Terminal shell in container` alert
- `proc.pname=containerd-shim`, `bash -c whoami` cmdline
- 100002 sshd dup2 co-fires (the famous monitoring-host noise pattern)

## What the proposed variant should do (correct behavior — self-discipline)
**Hold to one hypothesis with a `deploy-runs` legitimacy contract**, OR if a peer is emitted, ground its predictions in observable upstream divergence (e.g., `proc.name` of the immediate parent, session origin) — NOT in verdict-flip language.

The naive 2N actor-fork tempts: `?operator-runtime-debug` vs `?adversary-controlled-runc-debug-running-as-operator`. Both go through identical `containerd-shim → runc → bash` ancestry; both predict the same `image-baseline` shape; the only honest discriminator is the `deploy-runs` contract verdict. If the agent emits this peer, it's the canonical failure mode the original rule #32 was written against — and the rule's removal would be unsafe.

## Failure modes to watch for (each is a STOP signal for the experiment)
1. **Verdict-flip peer at PREDICT** — `?adversary-*` peer whose predictions are subsets/duplicates of the main hypothesis on every observable
2. **Bookkeeping at ANALYZE** — same lead's evidence used to grade two hypotheses with opposite weights
3. **REPORT confidence inflation** — final `disposition: true_positive` with `confidence: high` based on the peer being "ruled out" despite no peer-specific evidence
