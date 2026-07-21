#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

_VENV_PY = Path(__file__).resolve().parents[2] / "defender" / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning import lead_repository  # noqa: E402
from defender.learning.core.config import (  # noqa: E402
    DEFAULT_PATHS,
    RunUnprocessable,
    StageAbort,
    LoopPaths,
)
from defender.learning.core.directions import (  # noqa: E402
    ADVERSARIAL_WIRING,
    BENIGN_WIRING,
)
from defender.learning.core.orchestrate import (  # noqa: E402
    author_drain,
    enqueue_for_learning,
    lead_author_drain,
    learn_drain,
    main,
    run_one,
    _directions_for,
    _prepare_engines_for,
)
from defender.learning.core.persist import (  # noqa: E402
    append_actor_environment_observations,
    append_actor_observations,
    append_environment_observations,
    append_findings,
    derive_alert_rule_key,
    _anchor_with_case_key,
)
from defender.learning.core.subagents import (  # noqa: E402
    InProcessSubagents,
    Subagents,
    is_skip_story,
)
from defender.learning.pipeline.malicious_actor.run import invoke_actor  # noqa: E402
from defender.learning.pipeline.benign_actor.run import invoke_actor_benign  # noqa: E402
from defender.learning.pipeline.oracle.run import invoke_oracle  # noqa: E402
from defender.learning.pipeline.judge.run import invoke_judge  # noqa: E402
from defender.learning.core.validate import (  # noqa: E402
    dump_oracle_doc,
    normalize_disposition,
    normalize_judge_yaml,
    strip_yaml_fence,
    validate_judge_benign_doc,
    validate_judge_doc,
    _outcome_keyword,
)
from defender.learning.core.prologue import extract_case_entities  # noqa: E402

__all__ = [
    "DEFAULT_PATHS", "RunUnprocessable", "StageAbort", "LoopPaths", "InProcessSubagents", "Subagents",
    "run_one", "author_drain", "lead_author_drain", "learn_drain", "enqueue_for_learning",
    "main",
    "normalize_disposition", "strip_yaml_fence", "normalize_judge_yaml",
    "dump_oracle_doc",
    "validate_judge_doc", "validate_judge_benign_doc",
    "append_findings", "append_actor_observations", "append_environment_observations",
    "append_actor_environment_observations",
    "derive_alert_rule_key", "extract_case_entities",
    "invoke_actor", "invoke_actor_benign", "invoke_oracle",
    "invoke_judge", "ADVERSARIAL_WIRING", "BENIGN_WIRING", "_prepare_engines_for",
    "is_skip_story", "lead_repository",
    "_outcome_keyword", "_directions_for", "_anchor_with_case_key",
]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
