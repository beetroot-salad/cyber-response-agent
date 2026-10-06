from __future__ import annotations

import re
from pathlib import Path

from defender.learning.author.verify_forward.shared import VerdictError
from defender._artifact_schema import SOURCE_REFS_FILE_MAX
from defender._io import read_text_utf8

HERE = Path(__file__).resolve().parent
PROMPT_PATH = HERE / "forward.md"


def load_run_context(run_id: str, *, runs_dir: Path) -> tuple[str, str]:
    """The cited case's transcript and its recorded disposition.

    A missing file or disposition raises `VerdictError`, like an unreadable verifier reply, so
    the drain gives it the same retry-once-then-BAD ending rather than letting an exit escape
    the fan-out and leave the row stuck."""
    # The layout import lives here, inside this deferred_legacy reader (#1105 D7, FR-1).
    from defender.run_repository import RunPaths

    run_dir = runs_dir / run_id
    paths = RunPaths(run_dir)
    investigation = paths.investigation
    refs = paths.source_refs
    if not investigation.is_file():
        raise VerdictError(f"verify_forward: missing {investigation.name} at {investigation}")
    if not refs.is_file():
        raise VerdictError(f"verify_forward: missing {refs.name} at {refs}")
    try:
        refs_text = read_text_utf8(refs, limit=SOURCE_REFS_FILE_MAX)
    except OSError as e:
        raise VerdictError(f"verify_forward: unreadable {refs.name} at {refs}: {e}") from e
    m = re.search(
        r"^normalized_disposition:\s*[\"']?([^\"'\n#]+?)[\"']?\s*(?:#.*)?$",
        refs_text,
        re.MULTILINE,
    )
    if not m:
        raise VerdictError(
            f"verify_forward: {refs.name} missing normalized_disposition: {refs}"
        )
    return read_text_utf8(investigation), m.group(1).strip()


def expected_disposition(direction: str, recorded: str) -> str:
    # No family-row guard here: `checks.skips_forward_check` keeps family rows out upstream.
    if direction == "benign":
        return "benign"
    return recorded
