---
title: Shrink the mock-usage allowlist (baseline: 6 test files)
status: backlog
groups: testing, code-quality
---

`soc-agent/scripts/lint_mock_usage.py` (CI `lint` job) enforces a ratchet:
no new test file may use `unittest.mock` unless added to
`soc-agent/tests/.mock_allowlist`. Project preference is fixtures + fakes.

## Current allowlist

| File | Suggested replacement |
|------|----------------------|
| `tests/test_audit_hooks.py` | In-memory hook-event fixture |
| `tests/test_budget_enforcer.py` | Fake usage-counter fixture |
| `tests/test_cleanup_runs.py` | tmp_path fixture (mostly already used) — re-evaluate |
| `tests/test_host_query.py` | Fake adapter implementing `AdapterContract` |
| `tests/test_subagent_wrapper.py` | Fake `_invoke_subagent` (already a pattern in `test_handlers_report.py`) |
| `tests/test_wazuh_cli.py` | Fake OpenSearch client / recorded-fixture playback |

## Procedure

For each file:

1. Read the test to identify which boundary the mock is standing in for
   (subprocess, HTTP, file, etc.).
2. Build a small fake implementing the real interface for that boundary —
   put it in `tests/fakes/` (create the dir on the first one).
3. Rewrite the test to use the fake via a fixture.
4. Delete the file's line from `.mock_allowlist`.
5. Run `python soc-agent/scripts/lint_mock_usage.py` to confirm the ratchet
   moves with you.

## When mocks are still acceptable

The linter is a ratchet, not a ban. Genuine cases:

- Mocking a third-party SDK that has no in-memory mode (rare — most do)
- Asserting that a specific call was made in a specific order at a layer
  where the call **is** the behavior under test (e.g. ensuring a hook
  invokes the audit logger before returning)

When adding a new file to the allowlist, leave a comment in
`.mock_allowlist` above the line explaining why.
