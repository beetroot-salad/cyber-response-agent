"""A run copy's stage for a test that starts a run box over a bare agent folder.

A run box's agent folder is always a run copy's `stage/agent/`, with the startup token beside it
(#1108 P4, U9; `start_box` refuses an agent folder without one). Production builds that stage in
`run_knowledge.copy_for_run`; a test that only needs SOME tenant's agent half in a box stages a
copy of it here, shaped as the stage `_check_stage` judges: exactly `agent/` and the token.
"""
from __future__ import annotations

import secrets
import shutil
from pathlib import Path

#: The startup token's name in the stage (`run_knowledge.STAGE_TOKEN`).
TOKEN_NAME = "token"


def staged_agent(agent: Path, under: Path) -> tuple[Path, Path]:
    """`(stage/agent, stage/token)`: a copy of `agent` (links kept as links) in a fresh stage
    below `under`, with a fresh token beside it."""
    stage = Path(under) / f"run-copy-{secrets.token_hex(4)}" / "stage"
    shutil.copytree(agent, stage / "agent", symlinks=True)
    token = stage / TOKEN_NAME
    token.write_text(secrets.token_hex(16), encoding="utf-8")
    return stage / "agent", token


def new_staged_agent(under: Path) -> tuple[Path, Path]:
    """`(stage/agent, stage/token)` with an empty agent folder, for a test that fills it."""
    stage = Path(under) / f"run-copy-{secrets.token_hex(4)}" / "stage"
    (stage / "agent").mkdir(parents=True)
    token = stage / TOKEN_NAME
    token.write_text(secrets.token_hex(16), encoding="utf-8")
    return stage / "agent", token
