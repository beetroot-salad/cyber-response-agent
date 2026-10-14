# CI harness repair, 2026-10-14

Original contract: `9281cbe2d258e5e7d0c7a78d3f31c2315f74667c`.
Original base: `c0ceb90dccb1d87c8c4783000ffbe887d41e46c5`.
Design: issue #1108 comment 6063781627; handoff comment 6065435835. No design change.

CI runs from defender/ with no exported PYTHONPATH. The marker-command stand-in inherited that environment, so its child could not import defender even though pytest could. This is a test machinery defect, not an identity refusal. The local command runner now uses the test interpreter and this worktree's explicit import root while preserving the supplied command's script/operands and text transport. AgentReadDocker continues to execute the actual command against its independent physical source; every existing P2 policy assertion is unchanged.

Four new regression cases clear the child PYTHONPATH and use CI's cwd. They require exactly one marker read, valid CRLF startup, and an owner-format refusal for bare CR across both Docker stand-ins. All four failed before the repair with the observed import error (`/tmp/1108-ci-author-red.log`). The shared baseline RecordingDocker call-site integration belongs on the implementation branch; these tests can remain red against the original production source.

The honest author had seen implementation. A separate fixture_review role independently approved design fidelity and discrimination, including the observed red run; root integrates and verifies the repair. This tests-only lineage preserves the original contract and excludes implementation source. Required independent adversarial sampling remains unexecuted after its previously recorded platform block; this repair does not supply that verdict.
