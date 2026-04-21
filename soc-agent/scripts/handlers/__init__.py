"""Per-phase handlers for the investigation orchestrator.

Each handler receives a `Context` and returns a `PhaseResult` — see
`scripts/orchestrate.py` for the contract. Handlers invoke their phase's
subagent via the shared wrapper in `_subagent.py`, parse the terminal
output, and decide the next phase.

`default_handlers()` returns the production mapping used by the
`/investigate` entrypoint. Only migrated phases appear in the map; a
transition into an unwired phase trips the orchestrator's `no handler
registered for phase X` error by design, so migration progress is
self-surfacing.
"""

from schemas.state import Phase
from scripts.orchestrate import PhaseHandler
from scripts.handlers import analyze, contextualize, conclude, hypothesize, screen


def default_handlers() -> dict[Phase, PhaseHandler]:
    return {
        Phase.CONTEXTUALIZE: contextualize.handle,
        Phase.SCREEN: screen.handle,
        Phase.HYPOTHESIZE: hypothesize.handle,
        Phase.ANALYZE: analyze.handle,
        Phase.CONCLUDE: conclude.handle,
    }
