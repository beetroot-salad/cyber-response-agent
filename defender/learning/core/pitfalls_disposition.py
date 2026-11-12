"""What one pitfalls-curation tick decided about its claim's pitfalls once its commit landed — the
value the curator hands the drain's `on_curated`.

Lives in `core/` rather than beside the curator because `drains.py` (also used by the lessons
lane) must not import the lead-author package. `pitfalls_curator` re-exports the name."""

from __future__ import annotations

from defender._model import model


@model(frozen=True)
class PitfallsDisposition:
    """The claim's pitfalls the curation took: `committed_ids` (they stay in the batch, cited by the
    commit `sha`) and `held_ids` (offered and declined: they wait again).

    Never persisted: the drain reads the committed ids to settle each pitfall's fate.
    """

    committed_ids: tuple[str, ...]
    sha: str | None
    held_ids: tuple[str, ...]
