"""Pure unit tests for the declarative READ DENYLIST loader (`bash_policy.json`, #379).

What this loader still owns after #575: the secret / ground-truth denylist the gate applies INSIDE
every allowed path, on BOTH read surfaces (`permission/files.denylisted`, shared with the bash
operand lane `bash._in_scope`). These assert it loads the expected shape and — the security-relevant
part — FAILS CLOSED to the built-in deny-by-default defaults if the JSON is ever unreadable.

WHAT LEFT, AND WHY THESE TESTS DID NOT JUST GET DELETED WITH IT (#575).
`adapters_allowed()` / `adapter_sql_pipe_allowed()` / `raw_reads_allowed()` and the whole
`{"bash": {"agents": {...}}}` config block are GONE. They were a second, DECLARATIVE model of a
permission the gate enforced somewhere else — the classic drift seam: a bit could say `adapters:
false` while the lane that decided it said otherwise, and nothing would notice. Each is now the
presence or absence of a `Grant` in the agent's own definition (the adapter capability IS a routed
grant; `raw_reads` IS "is the gather_raw shape in this agent's list"), so there is one place to look
and it is the place that decides.

So the three tests that pinned those accessors are DELETED here rather than ported — the mechanism
they pinned is gone by design, and the PROPERTIES they stood for are pinned where they are now
decided, through the real gate:

  * "gather may run adapters, main may not" → test_grant_gate_575::test_f1 (gather's lane carries the
    two `Route.CAPTURE_ADAPTER*` grants) + ::test_f3/::test_f4 (main's `defender-elastic query …`
    DENIES with its specific reason; the sanctioned `| defender-sql` pipe splits for gather only);
  * "main may not read gather_raw" → test_grant_gate_575::test_d1/::test_d2 — now POSITIVE
    enumeration (the shape is not in main's list) rather than a declared clamp;
  * "an unknown/typo'd agent name denies adapters by default" → there is no agent-name KEY left to
    typo. The successor safe-by-construction guard is stronger and lives at policy construction:
    `AgentPolicy.__post_init__` RAISES on a grant naming a program absent from `PROGRAMS`
    (test_grant_gate_575::test_b2/::test_b3), so an untabled — therefore UNGATED — program cannot
    ship at all, where the old default merely denied one capability on a name lookup miss.

The denylist half — the surviving security property — is kept and extended below.
"""
from __future__ import annotations

import pytest

from defender.runtime import bash_policy


def test_capability_bits_are_gone_from_the_loader():
    """#575 (negative): the loader exposes NO per-agent capability accessor and NO viewer list.

    Pinned as an explicit ABSENCE, not just dropped: a bit that no code reads is worse than dead
    code, because it still reads like policy — someone flips `adapters: false` expecting the gate to
    obey, and the gate never looks. If one of these ever comes back, it is a second model of a
    permission the grant list already owns, and it can drift from it."""
    for dead in ("adapters_allowed", "adapter_sql_pipe_allowed", "raw_reads_allowed", "viewers"):
        assert not hasattr(bash_policy, dead), f"the {dead!r} capability bit is back"
    assert "bash" not in bash_policy._policy()          # the whole agents/capability config block


def test_read_deny_covers_secrets_and_groundtruth():
    subs = bash_policy.read_deny_substrings()
    assert {".env", "credentials", "ground_truth", "cases.json"} <= set(subs)
    assert ".ssh" in bash_policy.read_deny_dirs()


def test_fails_closed_to_defaults_when_json_unreadable(tmp_path):
    # The injected loader: a missing file must fall back to the built-in deny-by-default
    # defaults (which still deny secrets), not crash and not widen anything. Uses the
    # _load_policy(path) seam directly — no monkeypatching.
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
    """The fail-closed net must actually be a net. The fallback DUPLICATES the JSON's strings on
    purpose (a security gate must keep denying secrets even if its config file is deleted), so pin
    that it is a SUPERSET of the live denylist — a fallback that silently dropped `.env` or `.ssh`
    would turn "config file missing" into "secrets readable", which is the exact failure the
    fail-closed design exists to prevent. (The old suite only spot-checked one key per axis, so a
    fallback that had drifted to a strict subset would have passed.)"""
    fb = bash_policy._FALLBACK_POLICY["read_deny"]
    assert set(bash_policy.read_deny_substrings()) <= set(fb["substrings"])
    assert set(bash_policy.read_deny_dirs()) <= set(fb["dirs"])
