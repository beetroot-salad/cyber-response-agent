from __future__ import annotations

from defender._git import GitError
from defender.learning.core.config import FatalConfigError, StageAbort
from defender import box as box_mod
from defender.systems.verbs import RegistryError


# Faults no single item caused, which stop the tick (`_run_stage`: CRITICAL, exit 2) and are never
# filed as one item's failure.
#
# `RunTainted`: whichever lane found it, a tainted tree is never an ordinary item failure.
#
# `RegistryError`: an unreadable adapters directory (raised as
# `declared_systems.AdaptersUnreadable`). Counting it against every claimed item each tick would
# spend the whole queue's attempts on a fault no retry clears.
SYSTEMIC_FAULTS: tuple[type[BaseException], ...] = (
    StageAbort,
    FatalConfigError,
    GitError,
    box_mod.BoxFault,
    box_mod.RunTainted,
    RegistryError,
)
