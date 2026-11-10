"""The helper's side of a box reached over the job socket (#1170 A4): the daemon-facing part of #1421.

The per-job host helper holds the daemon, so it classifies each exchange where the daemon is and answers the job's
`box.exec` with one word: `ok` (the command's frame, or the kill line when the in-box helper was killed), `output-limit`,
`timeout`, or `lost` with its class; and the job's `box.stop` with proof the box stopped, or a fault with the reason. The
job's executor (`RelayTransport`, `_spec.py`) keeps the refusal latch, readmit, the run clock and the typed endings.

A clean frame is the result whatever its code (no status asked); the output fence is `output-limit`; otherwise the
status is asked once and the exchange is classified by the one rule the job's own executor uses (`classify_unframed`):
not `running` (or no answer) is `lost`, a host timeout included; `running` with exec 137 is the kill line; a host
timeout or the in-box helper's own deadline (exec 3) is `timeout`; anything else is `lost`."""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from defender.execution.box_codec import KILLED_LINE, BoxFault, BoxResult, RawExec, decode_response, encode_response
from defender.records.run_end import TRUNCATED_BY_BOX_LOST

from ._docker import DockerFn, _container_status
from ._lifecycle import BoxRuns, stop_box
from ._output import BoxOutputLimitExceeded
from ._spec import (
    _KILLED_RC, KILLED, NOT_RUNNING, TIMED_OUT, BoxExecutor, _DockerTransport, box_status, classify_unframed,
)

_logger = logging.getLogger(__name__)

OUTPUT_LIMIT: dict[str, Any] = {"result": "output-limit"}
TIMEOUT: dict[str, Any] = {"result": "timeout"}
RELAY_LOST: dict[str, Any] = {"result": "lost", "class": TRUNCATED_BY_BOX_LOST}
STOPPED: dict[str, Any] = {"result": "stopped"}


def relay_exec(box: BoxExecutor, docker: DockerFn, frame: bytes, *, cwd: str, timeout: float) -> dict[str, Any]:
    """Run one frame in `box` (a box this helper started through `docker`) at `cwd` under the box output bound and
    `timeout`, and answer it in the relay's vocabulary (module doc). The `docker exec` is asked of `docker.popen`, so
    the helper's docker seam carries it."""
    transport = _DockerTransport(box.name, box.spec, popen=getattr(docker, "popen", subprocess.Popen))
    raw: RawExec | None = None
    failure: Exception | None = None
    try:
        raw = transport(frame, cwd=Path(cwd), timeout=timeout)
    except BoxOutputLimitExceeded:
        return dict(OUTPUT_LIMIT)
    except Exception as e:  # noqa: BLE001 — every exchange without a frame is classified below
        failure = e
    if raw is not None:
        try:
            decode_response(raw.stdout)
            return {"result": "ok", "frame": raw.stdout}
        except BoxFault as e:
            failure = e
    status = box_status(docker, box.name)
    verdict = classify_unframed(raw, failure, status)
    if verdict == NOT_RUNNING:
        _logger.error("the box %s is not running (its status: %s): lost", box.name, status or "no answer")
        return dict(RELAY_LOST)
    if verdict == KILLED:
        return {"result": "ok", "frame": encode_response(BoxResult(rc=_KILLED_RC, out=b"", err=KILLED_LINE))}
    if verdict == TIMED_OUT:
        return dict(TIMEOUT)
    said = f"exec rc {raw.rc}, no frame" if raw is not None else type(failure).__name__
    _logger.error("the box %s is running but did not answer as its helper does (%s): lost", box.name, said)
    return dict(RELAY_LOST)


def relay_stop(box: BoxExecutor, docker: DockerFn) -> dict[str, Any]:
    """Stop `box`, proven, then remove it and end its attached start. The proof is the box showing stopped after
    `docker stop -t 0` (`BoxRuns.stop`), or, failing that, the box gone once removed (`docker rm -f`), asked of a
    daemon that must answer: a removed box runs nothing, as the job's own `stop_box` takes it. Answers `stopped`, or
    `fault` with the reason when neither proof holds."""
    try:
        BoxRuns(box).stop()
    except BoxFault as unproven:
        try:
            stop_box(box, docker=docker)
            gone = _container_status(docker, box.name) is None
        except (BoxFault, OSError, subprocess.SubprocessError) as leftover:
            return {"result": "fault", "reason": f"{unproven}; and its removal could not be proven: {leftover}"}
        if not gone:
            return {"result": "fault", "reason": f"{unproven}; and it is still there after its removal"}
        return dict(STOPPED)
    try:
        stop_box(box, docker=docker)
    except BoxFault as leftover:
        # Proven stopped; only its removal failed. The helper's own end removes it by its claim's label.
        _logger.warning("the stopped box %s was not removed: %s", box.name, leftover)
    return dict(STOPPED)
