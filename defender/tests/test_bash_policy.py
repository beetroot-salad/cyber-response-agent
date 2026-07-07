"""Pure unit tests for the declarative Bash/Read gate policy loader (#379).

The policy is data the gate consults (`bash_policy.json`); these assert it loads
the expected shape and — the security-relevant part — fails closed to the
built-in deny-by-default defaults if the JSON is ever unreadable.
"""
from __future__ import annotations

import pytest

from defender.runtime import bash_policy


def test_policy_exposes_per_agent_capability():
    # The reader-lane program set moved into permission/policies/_common.py
    # (reader_patterns) with the #535 anchoring — bash_policy no longer exposes a
    # `viewers` list, so this loader owns only the per-agent capability + denylist.
    assert not hasattr(bash_policy, "viewers")
    # Adapters: gather may, main may not.
    assert bash_policy.adapters_allowed("gather")
    assert not bash_policy.adapters_allowed("main")
    assert bash_policy.adapter_sql_pipe_allowed("gather")
    assert not bash_policy.adapter_sql_pipe_allowed("main")


def test_read_deny_covers_secrets_and_groundtruth():
    subs = bash_policy.read_deny_substrings()
    assert {".env", "credentials", "ground_truth", "cases.json"} <= set(subs)
    assert ".ssh" in bash_policy.read_deny_dirs()


def test_unknown_agent_denies_adapter_by_default():
    # A typo'd / absent agent name must not silently grant adapter access.
    assert not bash_policy.adapters_allowed("nonsuch")
    assert not bash_policy.adapter_sql_pipe_allowed("nonsuch")


def test_fails_closed_to_defaults_when_json_unreadable(tmp_path):
    # The injected loader: a missing file must fall back to the built-in
    # deny-by-default defaults (which still deny secrets), not crash and not widen
    # anything. Uses the _load_policy(path) seam directly — no monkeypatching.
    policy = bash_policy._load_policy(tmp_path / "does-not-exist.json")
    assert policy is bash_policy._FALLBACK_POLICY
    assert ".env" in policy["read_deny"]["substrings"]
    assert policy["bash"]["agents"]["main"]["adapters"] is False


@pytest.mark.parametrize("bad", ["{ not json", ""])
def test_fails_closed_on_corrupt_json(tmp_path, bad):
    corrupt = tmp_path / "bash_policy.json"
    corrupt.write_text(bad)
    policy = bash_policy._load_policy(corrupt)
    assert policy is bash_policy._FALLBACK_POLICY
    assert ".ssh" in policy["read_deny"]["dirs"]
