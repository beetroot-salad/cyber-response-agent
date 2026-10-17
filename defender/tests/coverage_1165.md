# #1165 executable contract and verification

Grounding base: `c0ceb90dccb1d87c8c4783000ffbe887d41e46c5`. Original reviewed, immutable tests-only contract: `2c4096df103c65c386446126873e447e8cab547a`. The previously verified executable tests-only amendment is `4f83b634a4a9a21e7f217f532bfd49d1fea355d3`; the original contract and every reviewed repair remain in the contract lineage. Binding intent is in `intent_1165.md`.

Current reviewed query snapshot contract: `297fa8e72083833696d7c28815a3604cd64e2a62`, independently approved by `seed_review`; honest cherry-pick: `16e15909`. Amended production source: `bee61e0a73a00dec5905be719e45a1be83853c24`.

Prior implementation: `80ef1ce47dec250713b81740cde2effbeae11abc`, branch `impl/1165-run-record-io`, isolated worktree `/workspace/issue1165-implementation`. Production changes are separate from the tests-only commits.

| Obligation | Enforcing evidence |
|---|---|
| O1 handed Run / O2 host views | Real MAIN/gather/query backend forwarding and fault controls; required driver Run; source Run propagation; lifecycle startup, teardown and unsandboxed callbacks |
| O1 architectural boundary | Counted real-tree census, alias and reference controls, duplicate and stale residue checks, unknown-target and nonrecord laundering controls |
| O3 operations / O4 semantics | Member capabilities, query snapshot seed, run-end replacement, exclusive claims, safe receipt deletion and structured read states; existing exception postures retained |
| O4 validation and logging | Real investigation/report schemas, self-baseline seeding, tolerant JSONL, opaque bytes; eager logger initialization/reopen, canonical identity, closure, encoding and error controls |
| O5 rooted mutations | Parent swaps at actual backend writes, unchanged outside trees, restored positive controls, leaf-alias reads and safe receipt unlink; full existing rooted matrix |
| O6 RunState | Query ordering under the shared lock, retained rows and spent sequences after view failure, poisoned views ignored, payload cap; existing budget/breaker regressions |
| O7 forks | Current alert wins, verified missing-alert fallback including stale record replacement, canonical opaque evidence, unexpected entries skipped before reading, empty recognized scaffolding preserved, inherited state only after successful snapshot replacement |

## Historical verification before the query snapshot amendment

- Final non-live, non-gate suite against the committed source: **20,462 passed, 2 failed, 297 skipped, 17 xfailed** in 1,246.68 seconds. Included the real container-boundary file; no file exclusion. Both failures are mandatory `runsc` prerequisites in `test_1222_alert_place.py`: the reachable Docker daemon registers `runc` and `io.containerd.runc.v2`, but not `runsc`. They are not claimed as passes. The implementation checkout was moved onto the existing shared `/workspace` mount to remove the initial Docker path limitation.
- Gate-marked suite against the committed source: **46 passed, 1 skipped** in 123.92 seconds.
- Spec-flow checks: **148 passed**. Ruff checks at both roots, mypy over **291 files**, all **34 custom CI lint scripts**, whitespace checks and duplication gate passed; duplicated tokens were **0.72%**.
- Focused implementation checks included **961 passed** for the rooted matrix, claim behavior and record operations; the final selected failure families plus all #1165 tests had **185 passed**, with only the two external `runsc` failures.

Every pytest invocation used `/tmp/defender-pytest.lock`; implementation runs used the worktree's `PYTHONPATH`, enforced budgets and at most four workers. Logs and exact commands are recorded locally in the implementation worktree's `.spec-flow/verification-1165.txt` and `/tmp/1165-*.log`.

## Historical independent adversarial evidence

A separately dispatched worker used its own production adapter and did not inspect the honest implementation. Its amended bounded baseline passed **115 tests, with 14 deselected**, on the final executable contract `4f83b634` in 3.12 seconds. Eight sampled violations were rejected: ceremonial I/O with a path bypass, append replaced by rewrite, wrong seed baseline, report reading an old baseline, held-stream logging, lost live query state, noncanonical inherited payload selection, and a duplicated real I/O occurrence. The counted mutation was rechecked after the alias-classifier correction. No survivor or full-gate finding is claimed; this is bounded evidence, not a correctness proof. Artifacts are under `/tmp/issue1165-adversary/.spec-flow/1165/`.

## Contract repair provenance

Tests were written and independently reviewed before implementation/adversary dispatch. Implementation-stage repairs were made only on the tests-only contract branch, reviewed, frozen and cherry-picked into the workers; tests were not edited to fit production inside the honest worktree.

Repairs included mechanical Run call/observer adapters, valid fixture IDs, newline expectations retaining the core's universal-newline behavior, fresh-scaffold cleanup, a nonempty oversized-prefix fixture, and narrow architecture mirrors. Base probes confirmed parent-versus-leaf claim postures and empty inherited directory presence. The invalid `FRESH CASE` stimulus was retained by renaming a valid seeded fixture. Existing behavioral assertions remained intact apart from explicit API/identity mirrors.

One newly authored flow assertion incorrectly demanded an `executed_queries` cut on a failed view append. Existing #1234/#1235 behavior and a base probe showed that O4 instead requires an escaping `OSError`, with live rows/charges retained and no fabricated summary. The new assertion was corrected, including its success-only sidecar check; the implementation's translation was removed. Existing failure assertions were preserved.

These repairs occurred after implementation began. The parent inspected limited honest-source signatures and fork snippets, and one compatibility author inspected signatures early in the repair stage; later fixture repair used traceback/signature facts only. Independent contract reviewers did not inspect the honest implementation. This exposure is disclosed rather than presenting the amendments as an independently authored preimplementation contract.

## Query snapshot contract amendment — 2026-10-14

Owner approval replaces queries.create(text_or_bytes) with queries.seed(rows: list[dict]). This tests-only repair starts from contract-only `52d42400`, retaining grounding base `c0ceb90d` and original immutable contract `2c4096df`. The author did not inspect honest implementation source; implementation already exists, so this is an amendment rather than new preimplementation independence. Parent orchestration previously inspected limited honest source and supplied the approved design facts.

| Amendment promise | Enforcing cases |
|---|---|
| Record-owned JSONL snapshot; existing encoding/key order; normal append unchanged | `test_query_seed_serializes_a_snapshot_then_normal_append_continues` (absent/empty target × nonempty/empty rows) |
| Caller-owned freshness; generic replacement of prior view; no per-record content policy | `test_query_seed_can_replace_a_prior_view_under_caller_owned_freshness` (nonempty prior query view and already seeded investigation, then empty snapshot) |
| Selected nonempty and empty snapshots; tolerant malformed rows; state after successful replacement | `test_query_seed_replaces_the_snapshot_before_state_inheritance` (absent/empty target × nonempty/empty selected snapshot, exact rooted replace call and pre-write state) | <!-- lint-stale-ref: ok — retired by #1255 P2: the fork snapshot replaces the seed cut rules; the property lives in e2e/test_1255_snapshot_restore.py -->
| Failure retains absent/zero-byte view, no unlink/retry/append substitution, inherited state empty | `test_query_seed_failure_preserves_the_original_view_and_empty_live_state` (same matrix, failed backend call and retained zero-byte inode) | <!-- lint-stale-ref: ok — retired by #1255 P2: the fork snapshot replaces the seed cut rules; the property lives in e2e/test_1255_snapshot_restore.py -->
| Actual pre-fork freshness accepts zero-byte scaffolding | `test_open_main_session_accepts_a_zero_byte_query_scaffold` (nonempty/empty selected snapshot, real committed session and exact snapshot) | <!-- lint-stale-ref: ok — retired by #1255 P2: the fork snapshot replaces the seed cut rules; the property lives in e2e/test_1255_snapshot_restore.py -->
| Actual pre-fork freshness rejects populated or linked sibling table | `test_open_main_session_refuses_occupied_queries_before_fork` (unchanged real session count, view bytes and empty state) | <!-- lint-stale-ref: ok — retired by #1255 P2: the fork snapshot replaces the seed cut rules; the property lives in e2e/test_1255_snapshot_restore.py -->
| Capability/inventory and architectural mirrors expose seed and remove query create | `_spec1077.MEMBER_CAPABILITIES`, `test_generic_records_expose_only_their_added_store_operations`, `test_handled_record_operations_are_not_path_io`, #1234 call-record writer inventory and its synthetic control |

Independent intent reviewer `seed_review` approved immutable amendment `297fa8e7` before the honest worker implemented it through `write-code-from-tests`. The honest worktree received only the reviewed tests and metadata as `16e15909`, followed by the separate two-file production change `bee61e0a`. Historical suite and adversarial results above describe the earlier revision; current amended verification is recorded below.

Author checks for this amendment: focused collection of `test_1165_records.py`, `test_1165_fork.py` and `test_1165_census.py` collected **117 cases**. The focused amendment/machinery selection (including the #1234 inventory control) produced **2 passed, 17 expected API failures, 124 deselected** on the contract-only base. Five direct record cases stop at missing `RecordHandle.seed`; twelve branch cases stop during the existing Run-aware fixture's session-pointer write because baseline `write_case_pointer` still accepts a path. At that authoring checkpoint, their later snapshot, ordering, fault and pre-fork assertions were unexercised; the subsequent honest implementation run below reached and passed them. Ruff over all five changed Python files and `git diff --check` passed. Imports resolved to `/tmp/issue1165-contract` under the shared interpreter, and both pytest calls used the shared lock.

A direct unmodified-base probe, using its actual path signatures rather than implementing new APIs, verified both selected-snapshot fixtures pass branch validation: the nonempty case selects only `l-001`, and the empty case selects no leads despite a real later captured row. The same probe confirmed existing freshness accepts absent/zero-byte tables and refuses populated/symlink tables. These are fixture/base facts, not evidence of the amended production writer. The parent subsequently completed independent review, the unchanged-implementation red probe, and the implementation checks recorded below.

## Query snapshot implementation verification

The unchanged honest implementation rejected the amended regression selection with **15 failed, 2 passed, 81 deselected** in **1.83 seconds**. Five direct record cases stopped at the missing query seed API; ten branch/session cases reached behavior or mode assertions or raised FileExistsError over an existing empty scaffold. The two pre-fork refusal cases passed. This distinguishes the implemented branch behavior from the broader fixture API stops on the contract-only base. Raw evidence: `/tmp/1165-seed-red.log`.

After the production repair committed as `bee61e0a73a00dec5905be719e45a1be83853c24`:

- Focused implementation verification passed **787 tests** in **67.14 seconds**. The new actual-session cases reached and passed their zero-byte acceptance and pre-fork refusal assertions. This run streamed through tool output; `/tmp/issue1165-focused-implementation-evidence.txt` reconstructs the exact invocation and observed completion. There is no original raw focused stdout log, and no rerun is represented as that run.
- Full non-live, non-gate suite: **20,475 passed, 2 failed, 297 skipped, 17 xfailed, 5 warnings** in **1,358.13 seconds**. The failures are the same two mandatory missing-`runsc` prerequisites: `test_a1_runsc_box_cannot_change_the_alert_or_its_record` and `test_p151_production_runtime_meets_every_write_shape` in `tests/alert_front_door_1222/test_1222_alert_place.py`. They remain failures, not passes. Raw evidence: `/tmp/1165-seed-full.log`.
- Gate-marked suite: **46 passed, 1 skipped** in **148.25 seconds**, exit 0. Raw evidence: `/tmp/1165-seed-gate.log`.
- Spec-flow checks: **148 passed** in **22.37 seconds**, exit 0. Raw evidence: `/tmp/1165-seed-specflow.log`.
- Both Ruff checks, mypy over **291 files**, all **34 custom CI lint scripts**, the **37-case oracle check**, tacit check, whitespace check and duplication gate passed. Duplicated tokens remained **0.72%**. Evidence: `/tmp/1165-seed-checks.log`.

Every pytest invocation used the shared `/tmp/defender-pytest.lock`, the applicable worktree's `PYTHONPATH`, and at most four workers. Full, gate and spec-flow runs explicitly set `DEFENDER_BUDGET_ENFORCE=1`; the reconstructed focused command does not record an explicit budget environment setting. No test assertions or production changes accompany this verification metadata update.

## Query snapshot independent bounded adversary

The independent adapter worker did not inspect honest source. Its amended baseline reached and passed **13 direct record/fork seed cases**; **4 actual-session cases** stopped at the old adapter's missing `run`/`source_run` keyword interface, with **81 deselected**, in **4.31 seconds**. The actual-session cases are unexercised by this adversary and are covered by the honest focused verification above. This is bounded amendment evidence, not full-gate acceptance or a complete historical attack-deck replay. Report and reproducible mutation artifacts: `/tmp/issue1165-adversary/.spec-flow/1165-seed/report.md`.

| Sampled mutation | Observed result |
|---|---|
| Exclusive create in place of snapshot replace | 13 failed |
| Append in place of snapshot replace | 13 failed |
| Empty snapshot performs no write | 7 failed, 6 passed |
| Query seed repeats whole-Run freshness | 13 failed |
| Live state inherits before snapshot persistence | 4 failed, 9 passed |

All five sampled violations were rejected by their intended mode, presence, byte or state-order assertions. No surviving exploit was found in this sample. The worker restored its adapter baseline and left test assertions unchanged.

## Main-integration test compatibility repair — 2026-10-14

Current main `d4fea4cfd53a89fcdfff93f1c4ca6ef9c943e490` merged cleanly into the separate contract lineage as `0281def314dee5e7c2538f6d55c2c0a6f10c1377`, preserving the original base and every immutable contract reference. That integration merge is separate from this tests-only repair and must not be cherry-picked into the honest implementation. No production changes are authored by this repair.

The new main P2 startup test wrapper now passes its existing real fixture Run into the required lifecycle `run=` input, asserts the investigate callback receives that same object, and derives the unchanged path-based replay seam's directory/id from it. The shared replay seam has no Run override and is not extended here. Both #1165 lifecycle fixtures obtain an accepted fixture tenant ID and assert startup forwards it beside the tenant agent and verdict callback. Existing identity, message-zero, failure-precedence and verdict assertions remain.

Main removed the generated-roster writer and loader. The counted census removes exactly their three obsolete occurrences: `generate_roster`/`.mkdir`, `generate_roster`/`.write_text`, and `load_roster`/`read_text_utf8`. The retained audit reader and every other count remain unchanged; no new residue allowances are added. Grounding was the exact main removal diff and parent-provided signatures/failure evidence. No honest implementation source files or diffs were inspected by this author.

Parent's pre-repair integration run, `/tmp/1165-merge-tests.log`, recorded **23 failed, 119 passed** in **31.21 seconds**: twenty new main cases used the retired lifecycle directory keyword, two old #1165 fixtures lacked the newly forwarded tenant ID, and the census retained three obsolete roster occurrences. Ruff over the three repaired Python test files and `git diff --check` passed. Behavioral verification is pending the parent's focused run and independent review; the shared pytest lock is occupied by another task's full suite, so no redundant old-API baseline run was queued. This repair does not claim those pending checks passed.
