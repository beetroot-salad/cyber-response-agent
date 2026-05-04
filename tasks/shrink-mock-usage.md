---
title: Shrink the mock-usage allowlist (baseline: 6 test files)
status: done
groups: testing, code-quality
---

`soc-agent/scripts/lint_mock_usage.py` (CI `lint` job) enforces a ratchet:
no new test file may use `unittest.mock` unless added to
`soc-agent/tests/.mock_allowlist`. Project preference is fixtures + fakes.

## Outcome

All 6 baseline files migrated. `tests/.mock_allowlist` removed entirely
— the linter now treats the steady state as "zero mocks in tests" and any
new offender fails CI without first re-creating the allowlist with a
written justification.

| File | Replacement |
|------|-------------|
| ~~`tests/test_audit_hooks.py`~~ | ✅ refactored `audit_tool_calls.main()` and `investigation_summary.main()` to take `stdin` / `runs_dir` / `env` as parameters; tests pass them directly |
| ~~`tests/test_budget_enforcer.py`~~ | ✅ refactored `budget_enforcer.main()` and `load_limits()` to take `stdin` / `runs_dir` / `soc_agent_root` as parameters |
| ~~`tests/test_cleanup_runs.py`~~ | ✅ `load_retention_policy(env=...)` and `cleanup_runs.main(runs_dir=..., env=...)` now take config as parameters |
| ~~`tests/test_host_query.py`~~ | ✅ `FakeDockerExec` recorder under `tests/fakes/`, installed via `monkeypatch.setattr` on the `docker_exec` boundary |
| ~~`tests/test_subagent_wrapper.py`~~ | ✅ `RecordingRunner` fake under `tests/fakes/`; `invoke_subagent` now takes a `_runner` injection seam |
| ~~`tests/test_wazuh_cli.py`~~ | ✅ `FakeOpenSearchClient` (programmable pages) under `tests/fakes/`; the stale `sys.modules["opensearchpy"] = MagicMock()` stub also dropped |

## Followups (optional, low-priority)

- Treat `tests/fakes/` as the canonical home for new fakes. Each new fake
  should record-and-verify against a real interface, not be a generic
  `MagicMock` substitute.
- If a future test legitimately needs `unittest.mock` (third-party SDK
  with no in-memory mode, ordering assertions where the call *is* the
  behavior), recreate `.mock_allowlist` with a comment explaining why.
