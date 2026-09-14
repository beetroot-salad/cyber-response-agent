from __future__ import annotations

from collections.abc import Callable

from defender._git import GitError
from defender.learning.core.config import FatalConfigError, StageAbort
from defender.runtime import box as box_mod
from defender.runtime.verbs import RegistryError


# `RunTainted` is here for TWO readers. `_run_stage` gives it `[loop] FATAL:` + exit 2
# instead of a bare traceback, so the operator-facing failure mode does not depend on which
# drain lane found it. And `run_or_dead_letter` re-raises rather than dead-letters it: the
# taint is raised from `stop_and_scrub`, outside `do_work`, so it never meets that guard
# today — but a tainted tree filed as one item's ordinary failure is exactly the silence this
# tuple prevents.
#
# `RegistryError` is the adapters directory this checkout cannot read — absent, unlistable,
# listable but not searchable (#1035). The lead-author resolver raises it as its own class
# (`declared_systems.AdaptersUnreadable`, a `LeadAuthorError` that IS a `RegistryError`), and
# without it here the dead-letter guard filed that as the batch's ordinary failure: every
# queued pitfall row's lifetime `attempts` bumped per tick, the whole queue retired to the
# graveyard at the ceiling, for a fault no row caused and no retry can clear.
SYSTEMIC_FAULTS: tuple[type[BaseException], ...] = (
    StageAbort, FatalConfigError, GitError, box_mod.BoxFault, box_mod.RunTainted, RegistryError,
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
