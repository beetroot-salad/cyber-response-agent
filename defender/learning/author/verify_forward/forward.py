from __future__ import annotations

import re
from pathlib import Path

from defender._run_paths import RunPaths
from defender.learning.author.verify_forward.shared import VerdictError

HERE = Path(__file__).resolve().parent
PROMPT_PATH = HERE / "forward.md"


def load_run_context(run_id: str, *, runs_dir: Path) -> tuple[str, str]:
    """The cited case's transcript and its recorded disposition.

    A run dir missing either file, or a `source_refs.yaml` with no disposition, raises
    `VerdictError` — the same class an unreadable verifier reply raises — so the drain's
    per-pair handler gives a row whose case cannot be read the same ending as one whose
    verdict cannot be read (retry once, then BAD), instead of a process exit escaping the
    fan-out and leaving the row stuck forever."""
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
        refs.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not m:
        raise VerdictError(
            f"verify_forward: {refs.name} missing normalized_disposition: {refs}"
        )
    return investigation.read_text(encoding="utf-8"), m.group(1).strip()


def expected_disposition(direction: str, recorded: str) -> str:
    # NO RUNTIME TYPE GUARD HERE. A family row carries no resolved
    # `(direction, recorded-disposition)` pair at all, and J12 keeps it out of the forward
    # check UPSTREAM, at `checks.skips_forward_check` — which is the seam that decides which
    # rows reach this function. Re-asserting the signature's own types inside a function whose
    # one caller passes them from a `-> tuple[str, str]` reader defends against a call no code
    # makes, and puts the property in a second place where it can disagree with the first.
    if direction == "benign":
        return "benign"
    return recorded
