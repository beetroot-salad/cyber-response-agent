#!/usr/bin/env python3
"""Defender learning-loop orchestrator — thin entry point.

Per-run-dir API: ``loop.py <run_dir>``. One case at a time. The orchestration lives
in the ``_loop_*`` sibling modules; this file is the venv re-exec shim, the CLI entry,
and the stable import surface (`loop.run_one`, `loop.LoopError`, …).

Pipeline (per direction): normalize disposition → actor (gray-box story) → telemetry
oracle (per-lead synthesized events) → judge (outcome + findings) → persist → queue →
threshold-gated curators. Direction by disposition: benign→adversarial, malicious→
benign, inconclusive→both. See ``_loop_orchestrate._HELP_EPILOG`` or ``--help``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv if launched against a different interpreter. Compare
# unresolved paths — the venv python is typically a symlink to the system interpreter,
# so .resolve() would collapse both sides and skip the re-exec even when site-packages
# differ.
_VENV_PY = Path(__file__).resolve().parents[2] / "defender" / ".venv" / "bin" / "python3"
if _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

# Public surface re-exported for run.py, replay_actor.py, and the test suites.
import lead_repository  # noqa: E402
from _loop_config import (  # noqa: E402
    DEFAULT_PATHS,
    LoopError,
    LoopPaths,
)
from _loop_oracle import redact_exemplar  # noqa: E402
from _loop_orchestrate import (  # noqa: E402
    is_held_out,
    main,
    read_ground_truth,
    run_one,
    _directions_for,
)
from _loop_persist import (  # noqa: E402
    append_actor_observations,
    append_environment_observations,
    append_findings,
    derive_alert_rule_key,
    _anchor_with_case_key,
)
from _loop_subagents import (  # noqa: E402
    ClaudePrintSubagents,
    Subagents,
    invoke_actor,
    invoke_actor_benign,
    invoke_judge,
    invoke_judge_benign,
    invoke_oracle,
    is_skip_story,
)
from _loop_validate import (  # noqa: E402
    dump_oracle_doc,
    normalize_disposition,
    strip_yaml_fence,
    validate_judge_benign_doc,
    validate_judge_doc,
    validate_oracle_doc,
    _outcome_keyword,
)
from _prologue import extract_case_entities  # noqa: E402

__all__ = [
    "DEFAULT_PATHS", "LoopError", "LoopPaths", "ClaudePrintSubagents", "Subagents",
    "run_one", "main", "is_held_out", "read_ground_truth",
    "normalize_disposition", "strip_yaml_fence",
    "validate_oracle_doc", "dump_oracle_doc",
    "validate_judge_doc", "validate_judge_benign_doc",
    "redact_exemplar",
    "append_findings", "append_actor_observations", "append_environment_observations",
    "derive_alert_rule_key", "extract_case_entities",
    "invoke_actor", "invoke_actor_benign", "invoke_oracle",
    "invoke_judge", "invoke_judge_benign", "is_skip_story", "lead_repository",
    # Underscore names are part of the test-facing surface (loop._outcome_keyword,
    # loop._directions_for, loop._anchor_with_case_key); list them so they read as
    # intentional re-exports, not dead imports.
    "_outcome_keyword", "_directions_for", "_anchor_with_case_key",
]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
