"""A learning job's family step, the worker's child (#1344): `python -m defender.cli.learning.job
--job <id> --tenant <T> --source <investigation id> --parent-pid <pid>`.

The steps are the job entry's (`learning/branch/job_entry.py`). This entry sits above learning,
as the operator's launch command does, because it supplies what learning may not import: the
role-model preflight (`run.py`), over every role the family reaches, the siblings' investigation
roles as well as the questioner, oracle, verifier and judge.
"""
from __future__ import annotations

import sys
from typing import Any

from defender.learning.branch import job_entry


def _preflight(model: str | None = None, **kwargs: Any) -> int:
    """The operator launch's role check, imported only once the entry runs one."""
    from defender.run import preflight_role_models

    return preflight_role_models(model, **kwargs)


def main(argv: list[str], **seams: Any) -> int:
    """The job entry with the real role preflight unless one is injected."""
    seams.setdefault("preflight", _preflight)
    return job_entry.main(argv, **seams)


if __name__ == "__main__":
    from defender import _log

    _log.configure_from_env()
    sys.exit(main(sys.argv[1:]))
