# Test changes

- This is the single collected test tree. Use existing fixtures and `e2e/_replay_harness.py` before adding parallel machinery.
- Inject collaborators through config/dependency seams; do not add `monkeypatch.setattr` sites. An oracle must not repeat the production operation it is meant to check.
- Run only affected test files and the relevant e2e replay locally; CI owns the full suite. Every pytest invocation on this machine uses `flock /tmp/defender-pytest.lock`.
- In a git worktree, set `PYTHONPATH=<worktree-root>` and verify imports resolve there: the shared venv can point at the main checkout.
- `.github/workflows/ci.yml` is authoritative for current checks. Before implementation, distinguish expected red from broken fixtures and unexercised assertions.
- Do not baseline a new lint finding; fix it or use the checker's documented suppression with a reason. See `../docs/development-lints.md` only for relevant entries.

## Root-only permission-test caveat

**Running the suite as root fails one test that is not broken:**
`tests/learning/judge/test_921_launcher_frame.py::test_921_judge_yaml_is_written_last_and_carries_the_enqueued_and_completed_counts`.
It simulates a failing write by chmod'ing a directory to `r-x`, and root ignores permission
bits — so the write lands and the test asserts "the failed write landed anyway". CI runs
non-root and it passes there. (The four accounting-failure tests that failed the same way
retired with #1235.) Confirm against CI before chasing them; don't "fix" the tests.
