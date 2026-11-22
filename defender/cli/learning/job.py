"""A learning job's family step, in its job container (#1344, #1170): `python -m defender.cli.learning.job
--job <id> --tenant <T> --source <investigation id>`, started by the per-job host helper; the end of its stdin is its
SIGTERM (A5).

The steps are the job entry's (`learning/branch/job_entry.py`). This entry sits above learning,
as the operator's launch command does, because it supplies what learning may not import: the
role-model preflight (`run.py`), over every role the family reaches, the siblings' investigation
roles as well as the questioner, oracle, verifier and judge, and the episode page's renderer (`presentation`).
"""
from __future__ import annotations

import sys
from typing import Any

from defender.learning.branch import job_entry


def _preflight(model: str | None = None, **kwargs: Any) -> int:
    """The operator launch's role check, imported only once the entry runs one."""
    from defender.run import preflight_role_models

    return preflight_role_models(model, **kwargs)


def _render_page(runs: Any, episode_id: str) -> Any:
    """The episode page (`learning.html`, in the episode's own folder), which the entry pushes to its helper (#1546)."""
    from defender.presentation.visualize_episode import render_episode

    return render_episode(runs, episode_id)


def main(argv: list[str], **seams: Any) -> int:
    """The job entry with the real role preflight and the episode page's renderer unless one is injected."""
    seams.setdefault("preflight", _preflight)
    seams.setdefault("render_page", _render_page)
    return job_entry.main(argv, **seams)


if __name__ == "__main__":
    from defender import _log

    _log.configure_from_env()
    sys.exit(main(sys.argv[1:], watch_stdin=True))
