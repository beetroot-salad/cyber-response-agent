#!/usr/bin/env python3
"""`bin/defender-lessons`'s command: runs the lessons engine
(`defender/runtime/lessons_engine/lessons_fm.py`).

Started by path, so the one bootstrap below first puts its own checkout root ahead of anything
else on `sys.path` (a foreign checkout named by `PYTHONPATH` must never answer for this one),
then re-launches under `defender/.venv` before the engine's third-party imports load.
`_venv` is the only `defender.*` import allowed above that re-exec: it is stdlib-only, while the
engine imports pydantic and PyYAML, which the bare launching interpreter lacks.
`test_corpus_fold_seed.test_c2c` pins this ordering.
"""
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from defender._venv import reexec_into_venv

    reexec_into_venv(__file__)

from defender.runtime.lessons_engine.lessons_fm import main

if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    sys.exit(main(sys.argv))
