# #1165 executable contract and verification

Grounding base: `c0ceb90dccb1d87c8c4783000ffbe887d41e46c5`. Original reviewed, immutable tests-only contract: `2c4096df103c65c386446126873e447e8cab547a`. The final executable tests-only amendment is `4f83b634a4a9a21e7f217f532bfd49d1fea355d3`; the original contract and every reviewed repair remain in the contract lineage. Binding intent is in `intent_1165.md`.

Implementation: `80ef1ce47dec250713b81740cde2effbeae11abc`, branch `impl/1165-run-record-io`, isolated worktree `/workspace/issue1165-implementation`. Production changes are separate from the tests-only commits.

| Obligation | Enforcing evidence |
|---|---|
| O1 handed Run / O2 host views | Real MAIN/gather/query backend forwarding and fault controls; required driver Run; source Run propagation; lifecycle startup, teardown and unsandboxed callbacks |
| O1 architectural boundary | Counted real-tree census, alias and reference controls, duplicate and stale residue checks, unknown-target and nonrecord laundering controls |
| O3 operations / O4 semantics | Member capabilities, query create, run-end replacement, exclusive claims, safe receipt deletion and structured read states; existing exception postures retained |
| O4 validation and logging | Real investigation/report schemas, self-baseline seeding, tolerant JSONL, opaque bytes; eager logger initialization/reopen, canonical identity, closure, encoding and error controls |
| O5 rooted mutations | Parent swaps at actual backend writes, unchanged outside trees, restored positive controls, leaf-alias reads and safe receipt unlink; full existing rooted matrix |
| O6 RunState | Query ordering under the shared lock, retained rows and spent sequences after view failure, poisoned views ignored, payload cap; existing budget/breaker regressions |
| O7 forks | Current alert wins, verified missing-alert fallback including stale record replacement, canonical opaque evidence, unexpected entries skipped before reading, empty recognized scaffolding preserved, inherited state only after successful table creation |

## Executed verification

- Final non-live, non-gate suite against the committed source: **20,462 passed, 2 failed, 297 skipped, 17 xfailed** in 1,246.68 seconds. Included the real container-boundary file; no file exclusion. Both failures are mandatory `runsc` prerequisites in `test_1222_alert_place.py`: the reachable Docker daemon registers `runc` and `io.containerd.runc.v2`, but not `runsc`. They are not claimed as passes. The implementation checkout was moved onto the existing shared `/workspace` mount to remove the initial Docker path limitation.
- Gate-marked suite against the committed source: **46 passed, 1 skipped** in 123.92 seconds.
- Spec-flow checks: **148 passed**. Ruff checks at both roots, mypy over **291 files**, all **34 custom CI lint scripts**, whitespace checks and duplication gate passed; duplicated tokens were **0.72%**.
- Focused implementation checks included **961 passed** for the rooted matrix, claim behavior and record operations; the final selected failure families plus all #1165 tests had **185 passed**, with only the two external `runsc` failures.

Every pytest invocation used `/tmp/defender-pytest.lock`; implementation runs used the worktree's `PYTHONPATH`, enforced budgets and at most four workers. Logs and exact commands are recorded locally in the implementation worktree's `.spec-flow/verification-1165.txt` and `/tmp/1165-*.log`.

## Independent adversarial evidence

A separately dispatched worker used its own production adapter and did not inspect the honest implementation. Its amended bounded baseline passed **115 tests, with 14 deselected**, on the final executable contract `4f83b634` in 3.12 seconds. Eight sampled violations were rejected: ceremonial I/O with a path bypass, append replaced by rewrite, wrong seed baseline, report reading an old baseline, held-stream logging, lost live query state, noncanonical inherited payload selection, and a duplicated real I/O occurrence. The counted mutation was rechecked after the alias-classifier correction. No survivor or full-gate finding is claimed; this is bounded evidence, not a correctness proof. Artifacts are under `/tmp/issue1165-adversary/.spec-flow/1165/`.

## Contract repair provenance

Tests were written and independently reviewed before implementation/adversary dispatch. Implementation-stage repairs were made only on the tests-only contract branch, reviewed, frozen and cherry-picked into the workers; tests were not edited to fit production inside the honest worktree.

Repairs included mechanical Run call/observer adapters, valid fixture IDs, newline expectations retaining the core's universal-newline behavior, fresh-scaffold cleanup, a nonempty oversized-prefix fixture, and narrow architecture mirrors. Base probes confirmed parent-versus-leaf claim postures and empty inherited directory presence. The invalid `FRESH CASE` stimulus was retained by renaming a valid seeded fixture. Existing behavioral assertions remained intact apart from explicit API/identity mirrors.

One newly authored flow assertion incorrectly demanded an `executed_queries` cut on a failed view append. Existing #1234/#1235 behavior and a base probe showed that O4 instead requires an escaping `OSError`, with live rows/charges retained and no fabricated summary. The new assertion was corrected, including its success-only sidecar check; the implementation's translation was removed. Existing failure assertions were preserved.

These repairs occurred after implementation began. The parent inspected limited honest-source signatures and fork snippets, and one compatibility author inspected signatures early in the repair stage; later fixture repair used traceback/signature facts only. Independent contract reviewers did not inspect the honest implementation. This exposure is disclosed rather than presenting the amendments as an independently authored preimplementation contract.
