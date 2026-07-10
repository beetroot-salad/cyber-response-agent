"""Loader for the declarative Bash/Read gate policy (`bash_policy.json`).

The policy is the deny-by-default allowlist the in-process gate
(`runtime/permission.py`) consults: the per-agent adapter capability and the read
denylist. It is data, not code — onboarding an adapter capability or a denied path
is a JSON edit, no gate logic change (#379). The reader-lane program set (which
viewers, in what anchored shape) moved into `permission/policies/_common.py`
(`reader_patterns_for`) with the #535 anchoring — it is no longer a JSON list.

Fail-closed: if the committed JSON is missing or corrupt, we fall back to the
built-in defaults below (which mirror the JSON) and warn, rather than crash the
run or — worse — widen the allowlist. The defaults duplicate a dozen strings on
purpose: a security gate must keep denying secrets even if its config file is
deleted, so the last-line denylist lives in code too.
"""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path

_POLICY_PATH = Path(__file__).with_name("bash_policy.json")

# Last-line fallback if bash_policy.json is unreadable. Mirrors the JSON; the JSON
# is the source of truth for edits, this is the fail-closed safety net.
_FALLBACK_POLICY: dict = {
    "bash": {
        "agents": {
            "main": {"adapters": False, "adapter_sql_pipe": False, "raw_reads": False},
            "gather": {"adapters": True, "adapter_sql_pipe": True, "raw_reads": True},
        },
    },
    "read_deny": {
        "substrings": [".env", "credentials", "ground_truth", "ground-truth", "cases.json"],
        "dirs": [".ssh"],
    },
}


def _load_policy(path: Path) -> dict:
    """Parse the policy at `path`, or fall back to the built-in deny-by-default
    defaults (and warn) if it is missing/corrupt. Pure in `path` — the injection
    seam the tests exercise, so no monkeypatching of module state is needed."""
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as e:
        print(
            f"bash_policy: could not load {path} ({e!r}); "
            "falling back to built-in deny-by-default defaults.",
            file=sys.stderr,
        )
        return _FALLBACK_POLICY


@lru_cache(maxsize=1)
def _policy() -> dict:
    return _load_policy(_POLICY_PATH)


def adapters_allowed(agent: str) -> bool:
    """May `agent` ('main' | 'gather') invoke a data-source adapter directly?"""
    return bool(_policy()["bash"]["agents"].get(agent, {}).get("adapters", False))


def adapter_sql_pipe_allowed(agent: str) -> bool:
    """May `agent` run the sanctioned `adapter | defender-sql` pipe?"""
    return bool(_policy()["bash"]["agents"].get(agent, {}).get("adapter_sql_pipe", False))


def raw_reads_allowed(agent: str) -> bool:
    """May `agent` read `gather_raw/**`? main: no (consumes the gather
    summary); gather + judge: yes (verify / refute against the raw payload)."""
    return bool(_policy()["bash"]["agents"].get(agent, {}).get("raw_reads", False))


def read_deny_substrings() -> tuple[str, ...]:
    """Filename substrings that are never readable (secrets / ground truth)."""
    return tuple(_policy()["read_deny"]["substrings"])


def read_deny_dirs() -> tuple[str, ...]:
    """Path components whose presence denies the read (e.g. `.ssh`)."""
    return tuple(_policy()["read_deny"]["dirs"])
