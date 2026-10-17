"""Pure unit tests for the declarative READ DENYLIST loader (`bash_policy.json`, #379)."""
from __future__ import annotations

import pytest

from defender.runtime import bash_policy


def test_read_deny_covers_secrets_and_groundtruth():
    subs = bash_policy.read_deny_substrings()
    assert {".env", "credentials", "ground_truth", "cases.json"} <= set(subs)
    assert ".ssh" in bash_policy.read_deny_dirs()


def test_fails_closed_to_defaults_when_json_unreadable(tmp_path):
    policy = bash_policy._load_policy(tmp_path / "does-not-exist.json")
    assert policy is bash_policy._FALLBACK_POLICY
    assert ".env" in policy["read_deny"]["substrings"]
    assert ".ssh" in policy["read_deny"]["dirs"]


@pytest.mark.parametrize("bad", ["{ not json", ""])
def test_fails_closed_on_corrupt_json(tmp_path, bad):
    corrupt = tmp_path / "bash_policy.json"
    corrupt.write_text(bad)
    policy = bash_policy._load_policy(corrupt)
    assert policy is bash_policy._FALLBACK_POLICY
    assert ".ssh" in policy["read_deny"]["dirs"]


def test_fallback_denylist_is_not_weaker_than_the_committed_one():
    """The fail-closed net must actually be a net. The fallback DUPLICATES the JSON's strings on purpose (a..."""
    fb = bash_policy._FALLBACK_POLICY["read_deny"]
    assert set(bash_policy.read_deny_substrings()) <= set(fb["substrings"])
    assert set(bash_policy.read_deny_dirs()) <= set(fb["dirs"])
