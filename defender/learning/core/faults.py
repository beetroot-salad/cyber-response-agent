from __future__ import annotations

from collections.abc import Callable

from defender._git import GitError
from defender.learning.core.config import FatalConfigError, StageAbort
from defender.runtime import box as box_mod


# #747: `RunTainted` belongs here for TWO readers, not one. `_run_stage` gives it
# `[loop] FATAL:` + exit 2 instead of the bare traceback and exit 1 an unhandled Exception
# got — a taint is as systemic as a fault gets, and the operator-facing failure mode should
# not depend on which drain lane found it. And `run_or_dead_letter` below re-raises it
# rather than dead-lettering it: today the taint is raised from `stop_and_scrub`, outside
# `do_work`, so it never meets that guard — but a tainted tree quietly filed as one item's
# ordinary failure is exactly the silence this tuple exists to prevent, and leaving it out
# left that one refactor away.
SYSTEMIC_FAULTS: tuple[type[BaseException], ...] = (
    StageAbort, FatalConfigError, GitError, box_mod.BoxFault, box_mod.RunTainted,
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
