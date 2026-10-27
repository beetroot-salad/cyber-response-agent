#!/usr/bin/env python3
"""The episode launcher's command: fork one finished run into a family of worlds, calibrate it,
and run it (`learning/branch/cli.py` holds the steps). This entry sits above learning because it
supplies what learning may not import: the role-model preflight (`run.py`) and the episode page
renderer (`presentation/`)."""
from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Run by path, so Python puts only `cli/learning/` on `sys.path`: re-exec into the project
# venv when it exists, then add the workspace root before any `defender` import.
_DEFENDER_DIR = Path(__file__).resolve().parents[2]
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.branch import cli as launcher  # noqa: E402

if TYPE_CHECKING:
    from defender.records import RunsRepository
    from defender.tenancy._tenant import Tenant
    from defender.records._provenance import RunProvenance


def _render_episode_page(runs: RunsRepository[Tenant], episode_id: str) -> Path:
    """The episode page, with the page module imported inside the call: an import fault is then
    the launcher's logged warning ("the page could not be rendered"), not a fatal error."""
    from defender.presentation import visualize_episode

    return visualize_episode.render_episode(runs, episode_id)


def main(  # noqa: PLR0913 — the launcher's inputs plus its injection seams
    argv: list[str],
    *,
    spawn: Callable[..., int] | None = None,
    questioner: Any = None,
    preflight: Callable[..., int] | None = None,
    judge: Any = None,
    lessons_dir: Path | None = None,
    live_tree: Callable[[], RunProvenance] | None = None,
    oracle: Any = None,
    verifier: Any = None,
    roster: Any = None,
) -> int:
    """Launch one episode with the real role preflight unless one is injected."""
    from defender.run import preflight_role_models

    return launcher.main(
        argv, spawn=spawn, questioner=questioner,
        preflight=preflight_role_models if preflight is None else preflight,
        render_page=_render_episode_page, judge=judge, lessons_dir=lessons_dir,
        live_tree=live_tree, oracle=oracle, verifier=verifier, roster=roster)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    raise SystemExit(main(sys.argv[1:]))
