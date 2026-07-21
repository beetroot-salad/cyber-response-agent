
from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import sys
from pathlib import Path

from defender._run_paths import RunPaths

LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")


def claim_lead(dispatch: dict) -> int:
    run_dir = dispatch.get("run_dir")
    lead_id = dispatch.get("lead_id")
    goal = dispatch.get("goal")
    wtc = dispatch.get("what_to_summarize") or []

    if not run_dir or not lead_id or not goal:
        return 0
    if not isinstance(wtc, list):
        return 0
    if not LEAD_ID_RE.match(str(lead_id)):
        return 0

    sidecar_dir = RunPaths(Path(run_dir)).gather_raw
    try:
        sidecar_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return 0

    sidecar_path = sidecar_dir / f"{lead_id}.lead.json"
    payload = json.dumps(
        {"goal": str(goal).strip(), "what_to_summarize": list(wtc)}, indent=2
    ) + "\n"

    try:
        fd = os.open(sidecar_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except OSError as e:
        if e.errno == errno.EEXIST:
            print(
                f"lead_id {lead_id!r} already dispatched; append a new :L "
                f"findings row and echo its id (a retry is a new lead, never "
                f"a reused id).",
                file=sys.stderr,
            )
            return 2
        return 0
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
    except OSError:
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(sidecar_path)
        return 0
    return 0
