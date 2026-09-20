"""What one pitfalls-curation tick consumes from its queue once its commit is sound — the
value the curator HANDS the drain (#952 M4), and the drain's `BatchDisposition` carries.

In `core/`, beside the drain that carries it, rather than in `leads/pitfalls_curator.py`
where the tick that produces it lives: a field on a `@model` record (#1067) is validated
against the real class the moment the record is decorated, and `drains.py` — shared by the
lessons lane, which must never pay for the lead-author package's import tree — could name
this class only under `TYPE_CHECKING`, leaving `BatchDisposition`'s schema unfinished at
import and completed by a frame-introspecting rebuild at the lane's entry. The class needs
nothing of the curator's: its `apply` is the queue's own rotation and `drain.retire`, both of
which `drains.py` already imports at module top. The curator re-exports every name here under
its own module, so its readers still find them where they look."""

from __future__ import annotations

from defender._model import model
from defender.learning.author import drain as _author_drain
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist

#: The lane's own logger: these lines were the curator's before the move.
_log = _loop_config.lead_author_log

#: The graveyard reason a held reducer row finally retires under. Its own class, beside
#: `pitfalls_curator._deadletter_reason`'s three and `drains._retire_pitfalls_batch`'
#: `batch-error:`, because it is the one retirement that follows no fault at all: the tick
#: worked, the offer was made, and the curator declined it — which is a legitimate outcome
#: the ceiling exists to bound rather than an error to diagnose.
HELD_CEILING_REASON = "reducer-offered-never-taught"

#: The queue-row field counting how many ticks OFFERED this row its surface and had the
#: curator decline. Distinct from `attempts`, which is the lane's FAULT counter and is bumped
#: for the whole batch by `drains._retire_pitfalls_batch` on any tick that raised: a decline is
#: not a fault, and one counter serving both retires a row on its first decline whenever
#: unrelated infra faults happened to spend its budget first.
OFFERS_DECLINED_KEY = "offers_declined"


def _retire_exhausted_holds(
    paths, held_ids: list[str], *, timeout_seconds: int | None = None,
) -> int:
    """Bump every held row once, and retire the ones that have now been offered too often.

    FK-7 makes a no-edit reducer tick a first-class outcome — `lead_pitfalls.md`'s "skip that
    failure; never invent one" — and leaves the rows in the queue. What it did not give them is
    an EXIT. A row the curator can never turn into a concrete fix (PO-R2's own frequent shape,
    an undiagnosable reduce) satisfied the arrival gate on its own occurrences, was offered,
    was declined, and came back byte-identical on the next tick: the wake gate stayed open, the
    curator agent was re-spawned every drain pass, and nothing ever progressed. Measured over
    consecutive ticks before this: the queue unchanged, `attempts` still unset, one LLM spawn
    per pass, forever. Every OTHER exit from this queue is bounded — `consumed_committed` on a
    taught row, `consumed_unattributable` plus the graveyard on an undeclared name, the
    `batch-error:` ceiling on a faulting batch — and the hold was the one that was not.

    So the hold KEEPS its meaning and gains a ceiling: the row survives being declined, and
    survives being declined again, and leaves on the same `author_max_attempts()` the rest of
    the lane retires on, with a durable record naming what happened to it. `drain.retire` is
    the shared primitive that does exactly this, so the bump, the graveyard entry and the
    `consumed_retired` ledger row are the channel's own — not a fourth hand-rolled rotation.

    COUNTED ON ITS OWN COUNTER, and that is what makes the ceiling mean what it says. The bump
    happens only on a tick that actually made the offer — the caller reaches here past the
    arrival gate and the spawn — but `drain.retire`'s default `attempts` is the LANE'S FAULT
    counter, which `drains._retire_pitfalls_batch` bumps for every row in the batch on any tick
    that raised. Sharing it made each ceiling arrive early in the other's traffic: two
    infra-faulting ticks spent a freshly-queued row's whole offer budget, so its FIRST decline
    retired it terminally with its lesson never taught — verbatim the loss FK-7's hold exists
    to prevent, reintroduced by the bound meant to complete it. `OFFERS_DECLINED_KEY` therefore
    counts declines and nothing else, and the two ceilings are independent: a row may fault its
    way out, or be declined its way out, and neither spends the other's budget.
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
        _log(
            f"pitfalls: retired {len(outcome.retired)} held reducer row(s) at the offer "
            f"ceiling ({_loop_config.author_max_attempts()} tick(s) offered and declined): "
            f"{list(outcome.retired)}"
        )
    return len(outcome.retired)


@model(frozen=True)
class PitfallsDisposition:
    """What one curation tick consumes from the pitfalls queue ONCE its commit has landed —
    the rows the corpus edit taught (`committed_ids`, rotated to `consumed_committed` under
    `sha`) and the rows the curator was offered and declined (`held_ids`, whose
    `offers_declined` counter is bumped and, at the ceiling, retired).

    Derived per tick, never persisted. The curator's OTHER dispositions — the
    `consumed_unattributable` rotation with its graveyard entry, the `AuthorError` on a
    failing spawn — are not here: they are facts about the batch that no scrub can change, so
    `run_pitfalls` applies them at once (#952 O4). These two are facts about a commit, and the
    party that knows whether the commit is sound — the batch's tree passed the scrub — is
    the drain, not the curator (#952 M1).

    `apply` is the ONE place the lane consumes on success. `run_pitfalls` calls it itself when
    no `on_curated` is given (the by-hand contract, O5); the drain receives the disposition
    through `on_curated` and calls it once the batch's tree has passed the scrub.

    @owns consumed_committed
    @owns offers_declined
    """

    committed_ids: tuple[str, ...]
    sha: str | None
    held_ids: tuple[str, ...]

    def apply(self, paths: _loop_config.LoopPaths, *, timeout_seconds: int | None) -> int:
        """Rotate the committed rows out, then bump the held ones. Returns how many held rows
        were retired at the offer ceiling.

        The rotation FIRST, and the same `timeout_seconds` on BOTH steps — the bump's own
        locked rotation inside `drain.retire` waits on the same append lock. The drain runs
        this holding the tick's locks, so it passes its configured wait and neither step may
        wait forever on a wedged appender; a by-hand run passes `None` and waits as it always
        has. A partial apply that rotated nothing but bumped the declines would spend a held
        row's offer budget on a tick that taught nothing."""
        if self.committed_ids:
            _loop_persist.rotate_pitfalls(
                list(self.committed_ids), self.sha, paths=paths,
                category="consumed_committed", timeout_seconds=timeout_seconds,
            )
        return _retire_exhausted_holds(
            paths, list(self.held_ids), timeout_seconds=timeout_seconds,
        )
