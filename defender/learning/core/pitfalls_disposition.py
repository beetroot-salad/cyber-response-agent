"""What one pitfalls-curation tick consumes from its queue once its commit is sound — the
value the curator hands the drain, carried on the drain's `BatchDisposition`.

Lives in `core/` rather than beside the curator because `BatchDisposition` is a `@model`
whose fields are validated against the real class at decoration time, and `drains.py` (also
used by the lessons lane) must not import the lead-author package. `pitfalls_curator`
re-exports these names."""

from __future__ import annotations

import logging

from defender._model import model
from defender.learning.author import drain as _author_drain
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist

_logger = logging.getLogger(__name__)

#: The graveyard reason a held reducer row retires under. Distinct from the fault reasons
#: because no fault occurred: the offer was made and the curator declined it, a legitimate
#: outcome the ceiling only bounds.
HELD_CEILING_REASON = "reducer-offered-never-taught"

#: Queue-row field counting ticks that offered this row its surface and had the curator
#: decline. Separate from `attempts`, the fault counter: sharing one would let unrelated infra
#: faults spend a row's budget so its first decline retires it.
OFFERS_DECLINED_KEY = "offers_declined"


def _retire_exhausted_holds(
    paths, held_ids: list[str], *, timeout_seconds: int | None = None,
) -> int:
    """Bump every held row once, and retire the ones that have now been offered too often.

    A declined reducer row stays queued (a no-edit tick is legitimate), but without a ceiling
    a row the curator can never fix would re-open the wake gate and re-spawn the curator every
    pass forever. So it retires at `author_max_attempts()` declines via `drain.retire`, with
    the channel's usual graveyard and ledger records.

    Counted on `OFFERS_DECLINED_KEY`, not `attempts` (the fault counter), so the two ceilings
    are independent and infra faults can't spend a row's offer budget.
    """
    if not held_ids:
        return 0
    outcome = _author_drain.retire(
        channel=paths.pitfalls,
        batch_ids=held_ids,
        reason=HELD_CEILING_REASON,
        max_attempts=_loop_config.author_max_attempts(),
        counter_key=OFFERS_DECLINED_KEY,
        timeout_seconds=timeout_seconds,
    )
    if outcome.retired:
        _logger.info(
            f"pitfalls: retired {len(outcome.retired)} held reducer row(s) at the offer "
            f"ceiling ({_loop_config.author_max_attempts()} tick(s) offered and declined): "
            f"{list(outcome.retired)}"
        )
    return len(outcome.retired)


@model(frozen=True)
class PitfallsDisposition:
    """What one curation tick consumes from the pitfalls queue once its commit has landed:
    `committed_ids` (rotated to `consumed_committed` under `sha`) and `held_ids` (offered and
    declined; `offers_declined` bumped, retired at the ceiling).

    Never persisted. The curator's other dispositions (unattributable rotation, failing
    spawn) don't depend on the scrub and are applied at once; these depend on whether the
    commit is sound, which only the drain knows.

    `apply` is the lane's one success-path consumption: `run_pitfalls` calls it when no
    `on_curated` is given; the drain calls it once the tree has passed the scrub.

    @owns consumed_committed
    @owns offers_declined
    """

    committed_ids: tuple[str, ...]
    sha: str | None
    held_ids: tuple[str, ...]

    def apply(self, paths: _loop_config.LoopPaths, *, timeout_seconds: int | None) -> int:
        """Rotate the committed rows out, then bump the held ones. Returns how many held rows
        were retired at the offer ceiling.

        Rotation first, so a partial apply never bumps declines for a tick whose teaching
        wasn't recorded. `timeout_seconds` bounds both steps' waits on the append lock; the
        drain passes its configured wait since it holds the tick's locks."""
        if self.committed_ids:
            _loop_persist.rotate_pitfalls(
                list(self.committed_ids), self.sha, paths=paths,
                category="consumed_committed", timeout_seconds=timeout_seconds,
            )
        return _retire_exhausted_holds(
            paths, list(self.held_ids), timeout_seconds=timeout_seconds,
        )
