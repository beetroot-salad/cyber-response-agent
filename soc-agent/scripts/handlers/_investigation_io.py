"""Read/write helpers for `investigation.md`, the invlang companion document.

Every phase handler appends a YAML-fenced block to `investigation.md` at the
end of its phase. Most callers want validation to fail loudly; predict's
retry loop needs to inspect validator errors without raising; report's
mechanical composers append a pre-validated conclude block. This module
exposes those three shapes explicitly so the choice is visible at the
call site.

The PreToolUse `invlang_validate.py` hook fires on `Write|Edit` against
`investigation.md`, but handlers write via `Path.write_text` (Python file I/O)
which is invisible to the harness. Library-mode validation here is the only
gate; missing validation = silent corpus pollution.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Optional

from scripts.orchestrate import OrchestrationError

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent

# Single sys.path mutation for hooks/scripts/invlang_validate. Without this,
# `from scripts.invlang_validate import validate_companion` fails because
# hooks/ is not a package and the validator isn't pip-installed.
_HOOKS_DIR = str(SOC_AGENT_ROOT / "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from scripts.invlang_validate import validate_companion  # type: ignore  # noqa: E402


def _read_current(run_dir: Path) -> str:
    inv_path = run_dir / "investigation.md"
    return inv_path.read_text() if inv_path.exists() else ""


def _compose(current: str, new_section: str) -> str:
    sep = "\n" if current and not current.endswith("\n") else ""
    return current + sep + new_section


def append_and_validate(
    run_dir: Path,
    new_section: str,
    *,
    phase: str,
    first_write_prefix: Optional[Callable[[], str]] = None,
) -> None:
    """Append `new_section` to investigation.md after running `validate_companion`.

    `phase` labels the OrchestrationError on validator failure.
    `first_write_prefix` returns text prepended to `new_section` on first write
    (used by CONTEXTUALIZE to stamp the file's creation timestamp at the top).
    """
    current = _read_current(run_dir)
    if not current and first_write_prefix is not None:
        new_section = first_write_prefix() + new_section
    proposed = _compose(current, new_section)

    errors = validate_companion(proposed, current if current else None)
    if errors:
        raise OrchestrationError(
            f"{phase} invlang validation failed:\n" + "\n".join(errors)
        )

    (run_dir / "investigation.md").write_text(proposed)


def validate_proposed_companion(run_dir: Path, new_section: str) -> list[str]:
    """Validate `current + new_section` and return the error list without raising.

    Used by PREDICT's retry loop, which surfaces validator errors as
    remediation notes on the next attempt rather than aborting the phase.
    """
    current = _read_current(run_dir)
    proposed = _compose(current, new_section)
    return validate_companion(proposed, current if current else None)


def append_unvalidated(run_dir: Path, new_section: str) -> None:
    """Append `new_section` without re-running the validator.

    For callers that have already gated on validation upstream:
      - PREDICT's retry loop validates each attempt; the post-loop append is
        guaranteed-clean.
      - REPORT's mechanical composers compose the conclude block from
        already-typed fields and Tier-1-validate the surrounding report.md.
    """
    (run_dir / "investigation.md").write_text(
        _compose(_read_current(run_dir), new_section)
    )
