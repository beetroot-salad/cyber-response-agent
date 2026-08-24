# Idempotency service benchmark

This fixture is meant to compare context assembly and model allocation, not to
reward raw token count. Run at least these conditions with identical task and
workspace snapshots:

1. Smaller model, single context.
2. Smaller model, recursive `solve`.
3. Kimi K3, single context.
4. Kimi K3 root/synthesis with smaller recursive planners and researchers.

Apply each generated diff to a fresh copy. Score it with visible tests plus
hidden tests covering a simultaneous first submission, repeated retries through
both entry points, tenant isolation, different-payload conflicts, exact TTL
boundary behavior with an injected clock, one queue publication, and one
`jobs.submitted` increment. Also record wall time, provider latency, calls,
input/output tokens, deepest level, node count, and dossier bytes per node.

The benchmark deliberately places the invariant across several files. A useful
tree should gather store/locking facts, entry-point behavior, side-effect
semantics, and testability independently, then synthesize them before producing
the patch. Drafting one file per child is a false decomposition because the
correctness condition crosses those files.

Example structural run (no meaningful model output):

```bash
PYTHONPATH=src python -m seam_harness solve \
  examples/idempotency_service/spec.json \
  --workspace examples/idempotency_service/workspace \
  --test-model \
  --runs-dir /tmp/seam-idempotency-smoke
```

For a real Fireworks run, remove `--test-model`, set `FIREWORKS_API_KEY`, and
optionally pass `--output outputs/idempotency.patch`.

