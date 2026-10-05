from __future__ import annotations

from collections.abc import Callable

from defender._git import GitError
from defender.learning.core.config import FatalConfigError, StageAbort
from defender.learning.core.state import StateRefused
from defender.runtime import box as box_mod
from defender.runtime.verbs import RegistryError


# Faults no single item caused, which must never be dead-lettered as one item's failure.
#
# `RunTainted`: `_run_stage` logs it CRITICAL + exit 2 whichever lane found it, and a tainted
# tree must never be filed as an ordinary item failure (it is raised outside `do_work` today,
# but this keeps it that way).
#
# `RegistryError`: an unreadable adapters directory (raised as
# `declared_systems.AdaptersUnreadable`). Dead-lettering it would bump every queued row's
# `attempts` each tick until the whole queue was graveyarded for a fault no retry clears.
#
# `StateRefused`: a link, hard link, FIFO or folder planted below the learning state root. Only a
# host actor can plant one, so it is a deployment fault no item caused: retrying, retiring or
# quarantining an item would not clear it, and `_run_stage` stops the tick naming the entry.
SYSTEMIC_FAULTS: tuple[type[BaseException], ...] = (
    StageAbort, FatalConfigError, GitError, box_mod.BoxFault, box_mod.RunTainted, RegistryError,
    StateRefused,
)


def run_or_dead_letter(
    fn: Callable[[], object],
    on_dead_letter: Callable[[Exception], None],
    *,
    propagate: tuple[type[BaseException], ...] = (),
) -> bool:
    reraise: tuple[type[BaseException], ...] = (*SYSTEMIC_FAULTS, *propagate)
    try:
        fn()
    except reraise:
        raise
    except Exception as e:  # noqa: BLE001 — the sole dead-letter guard for the drains
        on_dead_letter(e)
        return False
    return True
