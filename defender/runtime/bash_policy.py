"""Loader for the declarative READ DENYLIST (`bash_policy.json`).

What is left here is the secret/ground-truth denylist the gate applies INSIDE every allowed
path, on both read surfaces (`permission/files.denylisted`). It is data, not code — denying a
new path is a JSON edit, no gate logic change.

The per-agent capability BITS this file used to carry (`adapters` / `adapter_sql_pipe` /
`raw_reads`) are GONE (#575). They were a second, declarative model of a permission the gate
enforced elsewhere — and a bit that no code reads is worse than dead code, because it still
reads like policy. Each is now the presence or absence of a `Grant` in the agent's own
definition: the adapter capability is a routed grant, and `raw_reads` is simply whether the
`gather_raw` shape is in that agent's list. One place to look, and it is the place that decides.

Fail-closed: if the committed JSON is missing or corrupt, we fall back to the built-in defaults
below (which mirror the JSON) and warn, rather than crash the run or — worse — widen the
allowlist. The defaults duplicate the strings on purpose: a security gate must keep denying
secrets even if its config file is deleted, so the last-line denylist lives in code too.
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
        return json.loads(path.read_text(encoding="utf-8"))
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


def read_deny_substrings() -> tuple[str, ...]:
    """Filename substrings that are never readable (secrets / ground truth)."""
    return tuple(_policy()["read_deny"]["substrings"])


def read_deny_dirs() -> tuple[str, ...]:
    """Path components whose presence denies the read (e.g. `.ssh`)."""
    return tuple(_policy()["read_deny"]["dirs"])
