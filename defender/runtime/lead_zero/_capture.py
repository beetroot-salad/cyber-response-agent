"""The correlation lead's run-folder bookkeeping: its queries rows, the spend of its spawn, and
the declaring `:L findings` row the harness lead must own before it may write anything."""
from __future__ import annotations

import logging
from pathlib import Path

from defender.run_repository import RunPaths

_logger = logging.getLogger(__name__)


def _declare_l_finding(run_dir: Path, lead_id: str, name: str, system: str) -> bool:
    """Write the harness lead's declaring `:L findings` row into `investigation.md` before
    MAIN's first turn; without it, a citation of the reserved id is refused as an undeclared
    lead. True when the row is on disk; False when it could not be written, which the caller
    names as the lead's own ending (it does not start).

    This write bypasses `permission.decide_write`, so the content schema is applied here via
    `validate_artifact`, keeping "a committed investigation parses" true. A seed that fails
    validation is not written. Never raises."""
    from defender._artifact_schema import validate_artifact
    from defender.run_repository import RUN_LAYOUT
    from defender._io import read_text_utf8, write_guarded

    path = RunPaths(run_dir).investigation
    block = (
        f"## lead-0 ({lead_id}) — harness-authored, declared before the investigation begins\n\n"
        "```invlang\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        f"{lead_id}|0|{name}|||{system}|n/a\n"
        "```\n\n"
    )
    try:
        # `None`, not `""`, for an absent file, matching `permission.decide_write`'s baseline.
        existing = read_text_utf8(path) if path.is_file() else None
        proposed = block if existing is None else existing + block
        reason = validate_artifact(RUN_LAYOUT.investigation.name, proposed, existing)
        if reason is not None:
            _logger.warning(
                f"refused to declare {lead_id} in investigation.md — the document "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
                f"would not pass validation, so nothing was written and the id stays "
                f"undeclared: {reason}"
            )
            return False
        write_guarded(path, proposed)
    except (OSError, ValueError) as e:  # noqa: BLE001 — never breaks the run
        _logger.warning(f"could not declare {lead_id} in investigation.md: {e!r}")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        return False
    return True
