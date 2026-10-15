
from __future__ import annotations

import errno
import json
import sys

from defender._io import NotPlainEntry
from defender.run_repository import LEAD_ID_RE, Run, RunPaths  # noqa: F401 — re-export: this module is the claim gate's import surface

#: `claim_lead`'s answers. Success must be distinguishable from "nothing was written": the
#: sidecar's `O_EXCL` create is the only id-reuse gate, so dispatching without a row would let
#: unbounded sessions share an id and overwrite each other's `gather_summaries/{id}.md`.
CLAIMED = 1
NOT_CLAIMED = 0
ALREADY_CLAIMED = 2


def _say_already_dispatched(lead_id: object) -> None:
    """The model's remedy for a taken id, on stderr — the same for both `ALREADY_CLAIMED`
    arms, since to the model they are indistinguishable."""
    print(
        f"lead_id {lead_id!r} already dispatched; append a new :L "
        f"findings row and echo its id (a retry is a new lead, never "
        f"a reused id).",
        file=sys.stderr,
    )


def claim_lead(dispatch: dict, *, run: Run) -> int:
    """Exclusively claim the dispatch through the run's leads table."""
    lead_id = dispatch.get("lead_id")
    goal = dispatch.get("goal")
    wtc = dispatch.get("what_to_summarize") or []
    if (not dispatch.get("run_dir") or not lead_id or not goal
            or not str(goal).strip() or not isinstance(wtc, list)):
        return NOT_CLAIMED
    if not LEAD_ID_RE.match(str(lead_id)):
        return NOT_CLAIMED
    body = {"goal": str(goal).strip(), "what_to_summarize": list(wtc)}
    provenance = dispatch.get("provenance")
    if provenance:
        body["provenance"] = str(provenance)
    try:
        run.tables.leads(lead_id).write(json.dumps(body, indent=2) + "\n")
    except ValueError:
        return NOT_CLAIMED
    except OSError as error:
        leaf_alias = (getattr(error, "write_guarded_alias", False)
                      and not getattr(error, "record_parent_refused", False))
        occupied_leaf = (isinstance(error, NotPlainEntry)
                         and not getattr(error, "record_parent_refused", False))
        if isinstance(error, FileExistsError) or error.errno == errno.EEXIST or leaf_alias or occupied_leaf:
            _say_already_dispatched(lead_id)
            return ALREADY_CLAIMED
        return NOT_CLAIMED
    return CLAIMED
