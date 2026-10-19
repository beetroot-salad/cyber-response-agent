"""What the model is actually shown: the opening prompt, and the message each turn opens with.

Only assembles text (no agent, no budget). A resumed run is shown no opening (#1255 P4).
"""
from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any



from .. import orient

from defender.configuration._env import env_bool
from defender._frontmatter import strip_frontmatter
from defender._io import read_text_utf8
from defender.runtime.model_view import ModelView

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
    down: Mapping[str, str],
    orient_shim: orient.ShimRunner | None = None,
    tenant_agent: Path | None = None,
) -> str:
    """The fresh run's opening prompt, carrying the one correlation section.

    The correlation lead has already run to its end (or its absence has been decided) when this
    is built, so `correlation_section` is final: the lead's framed summary or one fixed
    sentence, under a host heading naming the reserved id (`None` for a run that dispatches no
    lead at all). `down` is each granted system down at run start, with its cause (#1256 O-3)."""
    orientation = orient.orientation(
        run_dir, defender_dir, alert_path, systems=systems,
        lead_zero_section=correlation_section, shim=orient_shim, tenant_agent=tenant_agent,
        down=down,
    )
    view = ModelView(Path(run_dir), Path(defender_dir), tenant_agent)
    return f"Begin the investigation.\n\n{_coordinates(view, alert_path)}\n{orientation}"


def _coordinates(view: ModelView, alert_path: Path) -> str:
    """The two lines telling MAIN where this run's tree is, in the model view (#1255 P1): the
    run folder is `/runs/current` on every run, and the alert its model path."""
    return f"run_dir: {view.to_model(view.run_dir)}\nalert: {view.to_model(alert_path)}\n"


def _opening_prompt(  # noqa: PLR0913 — `_user_prompt`'s parameters plus the resume it chooses between
    resume: Any, run_dir: Path, alert_path: Path, defender_dir: Path,
    *, systems: Sequence[str], correlation_section: str | None,
    down: Mapping[str, str],
    orient_shim: orient.ShimRunner | None = None,
    tenant_agent: Path | None = None,
) -> str | None:
    """MAIN's first message for a fresh run; `None` for a resumed one.

    A resumed run is handed no message at all (#1255 D1, P4): its history ends on the branch
    response, the framework runs that response's calls against the arm's world, and the model's
    next request is exactly the one a natural run would have sent. It does not orient either:
    the correlation lead is turn-0 work its history already holds.
    """
    if resume is not None:
        return None
    return _user_prompt(
        run_dir, alert_path, defender_dir, systems=systems,
        correlation_section=correlation_section, down=down, orient_shim=orient_shim,
        tenant_agent=tenant_agent,
    )
