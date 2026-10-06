from __future__ import annotations

import re
from pathlib import Path

from defender.learning.author.verify_forward.shared import VerdictError

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
    m = re.search(
        r"^normalized_disposition:\s*[\"']?([^\"'\n#]+?)[\"']?\s*(?:#.*)?$",
        refs.read_text(encoding="utf-8"),  # lint-whole-read: ok — source_refs.yaml: no host writer, only a box process can write it in the rw run dir; bounded at the writer by the box fsize limit
        re.MULTILINE,
    )
    if not m:
        raise VerdictError(
            f"verify_forward: {refs.name} missing normalized_disposition: {refs}"
        )
    return investigation.read_text(encoding="utf-8"), m.group(1).strip()  # lint-whole-read: ok — investigation.md: host writers go through validate_artifact (64 KiB cap, INVESTIGATION_FILE_MAX); box-writable in the rw run dir, bounded by the box fsize limit; read per verify pass


def expected_disposition(direction: str, recorded: str) -> str:
    # No family-row guard here: `checks.skips_forward_check` keeps family rows out upstream.
    if direction == "benign":
        return "benign"
    return recorded
