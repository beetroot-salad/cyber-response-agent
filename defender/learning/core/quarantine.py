"""The tainted-tree quarantine folder as the queue page reads it: how many archives it holds
against its cap. Its writer went with the legacy worktree drain (#1108 P4); archives an earlier
host left there stay countable."""
from __future__ import annotations

from pathlib import Path

from defender.configuration._env import env_int

# How many tainted trees may accumulate before the lane stops preserving them. A cap, not a
# TTL: nothing is evicted, since an archive may be the only forensic record of a suspected
# in-box compromise.
_MAX_ENV = "LEARNING_TAINT_QUARANTINE_MAX"
_MAX_DEFAULT = 10


def quarantine_cap() -> int:
    """How many tainted trees the quarantine folder may hold, as the queue page shows it."""
    return env_int(_MAX_ENV, _MAX_DEFAULT)


def held_archives(quarantine_dir: Path) -> int:
    """How many tainted trees the directory holds, counted by archive (an archive whose
    manifest failed still spends a slot), for the queue page.

    A missing directory holds none; an unlistable one raises. `iterdir`, not `glob`, because
    `Path.glob` swallows `PermissionError` and answers "empty"."""
    if not quarantine_dir.is_dir():
        return 0
    return sum(1 for p in quarantine_dir.iterdir() if p.name.endswith(".tar.gz"))
