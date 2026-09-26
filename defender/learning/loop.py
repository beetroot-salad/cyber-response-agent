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
    MalformedReply,
    normalize_disposition,
    reply_document_text,
)

#: THE TWO AUTHORING STAGES AND THE NAMES THEIR CALLERS ALREADY IMPORT FROM HERE.
#:
#: This module is a facade: what is exported is what still has a caller — the two drains,
#: the CLI, and the handful of helpers other packages read through this name rather than
#: reaching into `core/`.
__all__ = [
    "DEFAULT_PATHS", "RunAlreadyLive", "RunUnprocessable", "StageAbort", "LoopPaths",
    "author_drain", "lead_author_drain",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    "main",
    "normalize_disposition", "reply_document_text", "MalformedReply",
    "derive_alert_rule_key",
    "lead_repository",
]


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv))
