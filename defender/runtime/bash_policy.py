
from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path

_POLICY_PATH = Path(__file__).with_name("bash_policy.json")

_FALLBACK_POLICY: dict = {
    "read_deny": {
        "substrings": [".env", "credentials", "ground_truth", "ground-truth", "cases.json"],
        "dirs": [".ssh"],
    },
}


def _load_policy(path: Path) -> dict:
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
    return tuple(_policy()["read_deny"]["substrings"])


def read_deny_dirs() -> tuple[str, ...]:
    return tuple(_policy()["read_deny"]["dirs"])
