# #1165 executable contract candidate

Base: c0ceb90dccb1d87c8c4783000ffbe887d41e46c5. Design: current-design.md (owner-approved plan + independent design review); predecessor/evidence: design.md. Contract ref: pending tests-only commit. Production diff: none.

| Obligation | Cases / enforcing tests | Status |
|---|---|---|
| O1 handed Run / O2 host views | test_1165_flows actual MAIN/gather/query backend+failure, dependency identity, new required driver input; fork source chain; lifecycle startup/teardown/unsandboxed | Expected red at missing Run APIs; final triage pending |
| O1 architectural census | test_1165_census real directory sweep + alias/ref/raw I/O, counter duplicate and stale residue, unknown targets/nonrecord laundering | Pure machinery controls passed by direct Python invocation; pytest queued |
| O3 operations / O4 semantics | test_1165_records capabilities, query create, run_end replace, exclusive claims, receipt delete, structured read states | New APIs expected red; corrected/expanded rerun queued |
| O4 validation | seed self-baseline vs ordinary current baseline, report None baseline, real schema gates, opaque bytes and existing tolerant JSONL | Author real schema/legacy seed probes passed; new APIs expected red |
| O4 logging | test_1165_logging eager initialization/reopen, canonical identity, closure, ASCII/surrogate encoding, init-only denial fallback, later failures, one raw review append | New APIs expected red; author corrected frozen IoFault fixture errors |
| O5 rooted mutations | test_1165_records parent swap during actual backend write + restored positive controls, leaf alias reads, safe receipt unlink | Expected red until new ops |
| O6 RunState | test_1165_flows locking/order/state retained after view-write fault, poisoned views ignored, payload cap; existing #1235 regressions retained | Expected red at required run=; baseline controls inherited |
| O7 forks | test_1165_fork current alert wins, canonical opaque evidence, skip unknown before reading, query seed state-after-success, actual resumed driver source faults | Legacy fixture validation probes passed; new seams expected red |

Existing tests/harnesses are mechanically adapted to passed Run and actual directory identity; assertions remain, with intentional primary/capability matrix changes for new operations. No production skeletons. Some old lead-hook fdopen fault tests may need behavioral rather than obsolete primitive-specific injection; reviewer to disposition.

Common pytest lock occupied by another task's full suite. No pass is claimed when the lock was unavailable. Final contract author reports identify queued processes and expected preimplementation reds. Implementation-stage owner must execute every currently blocked assertion with real production code. Full gate includes DEFENDER_BUDGET_ENFORCE=1, all non-live non-gate tests, gate-marked tests, Ruff/mypy/custom checks; PYTHONPATH points at active worktree, every pytest uses shared flock.

Chosen interfaces supplement design: driver run= and source_run=; append_query_row(state,run=...); claim_lead(dispatch,run=...); branch seed_investigation/open_main_session(store,spec,state,run=...,source_run=...); store_factory_for(spec,source_run=...); denial_logger(run); challenge_gate._write_trace_row(run,...); scrub(...,write_verdict=...); box.start_box(...,write_verdict=...), stop_and_scrub(...,read_verdict=...,write_verdict=...); launch lifecycle(run=...). read callback returns serialized text|None; verdict write callback accepts dict.

## Independent contract review

Reviewer contract_review cleared the candidate for freeze after CR-1165-02 (real startup callback paths) and CR-1165-03 (unknown-target exemption laundering) were repaired and rechecked. The named-create descriptor fixture was also corrected to exercise the appropriate real core lane. Pure census controls and real-core fixture probes passed. Missing new APIs are expected preimplementation reds; full new-case execution remains mandatory during implementation. No production edits were included.

## Implementation-stage contract repair

Original immutable contract: 2c4096df103c65c386446126873e447e8cab547a. This tests-only follow-up repairs remaining mechanical Run call adapters, a path-oriented observation fake, newline expectations, fresh-scaffold cleanup, and the nonempty oversized-prefix fixture. Census controls now prove annotated record byte reads while rejecting path and unknown receivers; 17 controls passed, one actual production sweep deselected pending implementation. The legacy missing-alert/stale-record fallback is now covered and sanctioned by an explicit generic alert_record.replace operation; write remains exclusive.

These repairs occurred after implementation began. The parent inspected limited honest-source signatures and fork snippets; one compatibility author inspected signatures. Independent reviewer did not inspect honest source. They are disclosed compatibility/fixture repairs, not an independently authored preimplementation contract. Full focused and CI execution remains required on the implementation branch.

Further implementation-stage repairs preserve the existing parent-versus-leaf claim refusal distinction (independent base probe), recognized empty inherited directory presence (independent base probe), and adapt missed shared lifecycle/ticket observation fakes without changing assertions. Generic ensure_parent is limited to payloads/gather_summaries. Parent reviewed compatibility author fixtures; compatibility author independently reviewed parent scaffold regression.

Intentional API mirror repairs: deps field roster admits Run (no window field); lifecycle path callback is narrowly inventoried; replay identity fixtures now use the actual Run ID while retaining pool/payload assertions. The #1080 golden changes one assertion operand to the real Run adapter, preserving its copy-result assertion; no golden recapture. Curator telemetry role attribution explicitly supplies Run for that case only; ordinary non-run reads remain supported.
