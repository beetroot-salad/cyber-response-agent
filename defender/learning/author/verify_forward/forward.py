from __future__ import annotations

import re
from pathlib import Path

from defender.learning.author.verify_forward.shared import VerdictError
from defender._artifact_schema import SOURCE_REFS_FILE_MAX
from defender._io import READ_LIMIT, TEXT_READ_ERRORS, read_text_utf8

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
    # Both are box-writable: undecodable or over the cap is this loader's refusal.
    texts: dict[Path, str] = {}
    for path, limit in ((refs, SOURCE_REFS_FILE_MAX), (investigation, READ_LIMIT)):
        try:
            texts[path] = read_text_utf8(path, limit=limit)
        except TEXT_READ_ERRORS as e:
            raise VerdictError(f"verify_forward: unreadable {path.name} at {path}: {e}") from e
    refs_text, transcript = texts[refs], texts[investigation]
    m = re.search(
        r"^normalized_disposition:\s*[\"']?([^\"'\n#]+?)[\"']?\s*(?:#.*)?$",
        refs_text,
        re.MULTILINE,
    )
    if not m:
        raise VerdictError(
            f"verify_forward: {refs.name} missing normalized_disposition: {refs}"
        )
    return transcript, m.group(1).strip()


def expected_disposition(direction: str, recorded: str) -> str:
    # No family-row guard here: `checks.skips_forward_check` keeps family rows out upstream.
    if direction == "benign":
        return "benign"
    return recorded
