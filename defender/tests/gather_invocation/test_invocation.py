"""Pytest wrapper around the gather invocation harness.

Each fixture under fixtures/ becomes one parametrized test. The test asserts
on `wrapper_invoked` only — output quality (whether gather summarized well)
is out of scope; we're testing the trigger logic.

Marked `@pytest.mark.llm` because each test spawns claude -p. Skip with
`-m "not llm"` in fast CI passes. Run targeted via
`pytest defender/tests/gather_invocation/ -m llm`.
"""

from __future__ import annotations

import pytest

from harness import FIXTURES_DIR, load_expected, run_fixture


def _discover_fixtures() -> list[str]:
    """List fixture directories — each has dispatch.json + expected.json."""
    if not FIXTURES_DIR.is_dir():
        return []
    out = []
    for child in sorted(FIXTURES_DIR.iterdir()):
        if not child.is_dir():
            continue
        if (child / "dispatch.json").exists() and (child / "expected.json").exists():
            out.append(child.name)
    return out


@pytest.mark.llm
@pytest.mark.parametrize("fixture", _discover_fixtures())
def test_gather_invocation(fixture: str):
    expected = load_expected(fixture)
    result = run_fixture(fixture)
    assert result.return_code == 0, f"claude -p failed: rc={result.return_code}\n{result.stderr}"
    assert result.wrapper_invoked == expected["wrapper_invoked"], result.diagnostics()
    if "wrapper_call_count" in expected:
        actual = len(result.wrapper_calls)
        assert actual == expected["wrapper_call_count"], (
            f"expected {expected['wrapper_call_count']} wrapper call(s), got {actual}\n"
            + result.diagnostics()
        )
