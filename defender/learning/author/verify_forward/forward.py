from __future__ import annotations

import re
from pathlib import Path

from defender._run_paths import RunPaths

HERE = Path(__file__).resolve().parent
PROMPT_PATH = HERE / "forward.md"


def load_run_context(run_id: str, *, runs_dir: Path) -> tuple[str, str]:
    run_dir = runs_dir / run_id
    investigation = RunPaths(run_dir).investigation
    refs = run_dir / "source_refs.yaml"
    if not investigation.is_file():
        raise SystemExit(f"verify_forward: missing investigation.md at {investigation}")
    if not refs.is_file():
        raise SystemExit(f"verify_forward: missing source_refs.yaml at {refs}")
    m = re.search(
        r"^normalized_disposition:\s*[\"']?([^\"'\n#]+?)[\"']?\s*(?:#.*)?$",
        refs.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not m:
        raise SystemExit(
            f"verify_forward: source_refs.yaml missing normalized_disposition: {refs}"
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
