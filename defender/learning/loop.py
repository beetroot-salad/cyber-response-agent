#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

# Hand-rolled rather than `scripts/_venv.reexec_into_venv`, irreducibly: this must run BEFORE
# any `defender.*` import resolves, and reaching that helper is itself such an import.
_VENV_PY = Path(__file__).resolve().parents[2] / "defender" / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning import lead_repository  # noqa: E402
from defender.learning.core.config import (  # noqa: E402
    DEFAULT_PATHS,
    RunAlreadyLive,
    RunUnprocessable,
    StageAbort,
    LoopPaths,
)
from defender.learning.core.cli import main  # noqa: E402
from defender.learning.core.drains import (  # noqa: E402
    author_drain,
    lead_author_drain,
)
from defender.learning.core.persist import (  # noqa: E402
    derive_alert_rule_key,
)
from defender.learning.core.validate import (  # noqa: E402
    normalize_disposition,
    normalize_judge_yaml,
    strip_yaml_fence,
)
from defender.learning.core.prologue import extract_case_entities  # noqa: E402

#: THE TWO AUTHORING STAGES AND THE NAMES THEIR CALLERS ALREADY IMPORT FROM HERE.
#:
#: This module is a facade, and #922 is most of it leaving. It used to re-export the per-case
#: cycle (`run_one`, `learn_drain`), the four stage entry points, both judge wirings, the
#: subagent protocol, the judge/oracle document validators and the four queue appenders —
#: every one of which was the old pipeline's, and every one of which is deleted. What is left
#: is what still has a caller: the two drains, the CLI, and the handful of helpers other
#: packages read through this name rather than reaching into `core/`.
__all__ = [
    "DEFAULT_PATHS", "RunAlreadyLive", "RunUnprocessable", "StageAbort", "LoopPaths",
    "author_drain", "lead_author_drain",
    "main",
    "normalize_disposition", "strip_yaml_fence", "normalize_judge_yaml",
    "derive_alert_rule_key", "extract_case_entities",
    "lead_repository",
]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
