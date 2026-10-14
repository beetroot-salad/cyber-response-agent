"""What the model is actually shown: the opening prompt, and the message each turn opens with.

Only assembles text (no agent, no budget), so the resume's substitution is testable alone.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any



from .. import orient

from defender import _clock
from defender._env import env_bool
from defender._frontmatter import strip_frontmatter
from defender._io import read_text_utf8

_logger = logging.getLogger(__name__)


BUDGET_ENFORCE_FLAG = "DEFENDER_BUDGET_ENFORCE"


def enforcement_enabled() -> bool:
    return env_bool(BUDGET_ENFORCE_FLAG, False)

DEFAULT_MODEL = "glm-5.3"
DEFAULT_GATHER_MODEL = "glm-5.3-flash"
DEFAULT_REQUEST_LIMIT = 60
GATHER_REQUEST_LIMIT = 40
DEFAULT_TOOL_RETRIES = 10



def _main_instructions(defender_dir: Path) -> str:
    """MAIN's system prompt: the SKILL's body, without its frontmatter.

    The frontmatter can carry an `allowed-tools:` line that would drift from the tools actually
    registered and teach the model to call a tool it does not have."""
    return strip_frontmatter(read_text_utf8(defender_dir / "SKILL.md"))


def _user_prompt(  # noqa: PLR0913 — the harness's own pre-turn seams
    run_dir: Path, alert_path: Path, defender_dir: Path,
    *, systems: Sequence[str], correlation_section: str | None,
    orient_shim: orient.ShimRunner | None = None,
    tenant_agent: Path | None = None,
) -> str:
    """The fresh run's opening prompt, carrying the one correlation section.

    The correlation lead has already run to its end (or its absence has been decided) when this
    is built, so `correlation_section` is final: the lead's framed summary or one fixed
    sentence, under a host heading naming the reserved id (`None` for a run that dispatches no
    lead at all)."""
    orientation = orient.orientation(
        run_dir, defender_dir, alert_path, systems=systems,
        lead_zero_section=correlation_section, shim=orient_shim, tenant_agent=tenant_agent,
    )
    return f"Begin the investigation.\n\n{_coordinates(run_dir, alert_path)}\n{orientation}"


def _coordinates(run_dir: Path, alert_path: Path) -> str:
    """The two lines telling MAIN where this run's tree is; shared by fresh and resumed runs.

    A resumed run needs them most: its inherited paths name the source run's dir, which
    `permission.decide_read` denies.
    """
    return f"run_dir: {run_dir}\nalert: {alert_path}\n"


def _opening_prompt(  # noqa: PLR0913 — `_user_prompt`'s parameters plus the resume it chooses between
    resume: Any, run_dir: Path, alert_path: Path, defender_dir: Path,
    *, systems: Sequence[str], correlation_section: str | None,
    orient_shim: orient.ShimRunner | None = None,
    tenant_agent: Path | None = None,
) -> str:
    """MAIN's first message — for a fresh run or a resumed one.

    A resumed run does not orient: the correlation lead is turn-0 work its history already
    holds (`run_investigation` dispatches none for it).

    The coordinate header is always added, though the continuation wording is the caller's: a
    sibling has its own run dir while the inherited prefix names the source's, and a model
    re-reading `<source>/…` off its history is denied by `permission.decide_read`. The header
    alone does not fix that; `seed_investigation` puts the document in the new run dir.
    """
    if resume is None:
        return _user_prompt(
            run_dir, alert_path, defender_dir, systems=systems,
            correlation_section=correlation_section, orient_shim=orient_shim,
            tenant_agent=tenant_agent,
        )
    return (
        f"{resume.continuation_prompt}\n\n"
        f"{_coordinates(run_dir, alert_path)}{_branch_clock(resume)}")


def _branch_clock(resume: Any) -> str:
    """The line telling a resumed run when it is.

    A coordinate, not instruction, so it is added here rather than left to the caller's
    `continuation_prompt`, where it could be forgotten or differ between siblings. It does not
    bound queries (the adapter does that on the wire); it lets MAIN place "now" against
    the dated evidence in its history instead of assuming the wall clock.

    Reads `resume.as_of` directly: it is required on `BranchSpec`, and an `AttributeError` is the
    right answer for any other shape.
    """
    return f"now: {_clock.z_seconds(resume.as_of)}\n"
