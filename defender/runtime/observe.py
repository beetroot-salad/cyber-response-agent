
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from pydantic_ai.messages import (
    ModelMessagesTypeAdapter,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
)

from defender._clock import now_iso
from defender._env import env_int
from defender._io import JSON_NESTING_LIMIT, guarded_mkdir, json_safe, open_guarded, write_guarded
from defender._run_paths import RUN_LAYOUT, RunPaths
from defender.runtime._wire import wire_digest

from defender.scripts.pricing import usage_cost

_logger = logging.getLogger(__name__)

WIRE_LOG_ENSURE_ASCII = True

#: Policy denials go to their own stream (path: `RunPaths.policy_denials`), separate from the
#: request stream, so "no denial happened" is distinguishable from "file predates denials".
POLICY_DENIAL_EVENT_TYPE = "policy_denial"

#: Denials record a bounded digest of the params, never the raw model-controlled blob.
_DENIAL_PARAM_DIGEST_LEN = 16

#: The deepest a logged message is written, the message itself counted; deeper values are cut
#: to their repr. The record wraps its message in one level, so every line stays readable
#: under `JSON_NESTING_LIMIT`. Only the log cuts (#1117): a call refused as too deep to store
#: stays in the lead's history and is logged again with every later request.
_MESSAGE_DEPTH = JSON_NESTING_LIMIT - 1


def _params_digest(params: Any) -> str:
    # The rule the query record keys the same call by, so a denial and a repeat identify a
    # call alike.
    normalized = json_safe(params, non_finite="text")
    text = json.dumps(normalized, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:_DENIAL_PARAM_DIGEST_LEN]



def _max_chars() -> int:
    return env_int("DEFENDER_LLM_LOG_MAX_CHARS", 0)


def _trim(obj: Any, cap: int) -> Any:
    if cap <= 0:
        return obj
    if isinstance(obj, str):
        return obj if len(obj) <= cap else obj[:cap] + f"…[+{len(obj) - cap} chars]"
    if isinstance(obj, list):
        return [_trim(x, cap) for x in obj]
    if isinstance(obj, dict):
        return {k: _trim(v, cap) for k, v in obj.items()}
    return obj


def _usage_dict(usage: Any) -> dict[str, int]:
    g = lambda n: int(getattr(usage, n, 0) or 0)  # noqa: E731
    cache_r = g("cache_read_tokens")
    cache_w = g("cache_write_tokens")
    return {
        "input_tokens": max(0, g("input_tokens") - cache_r - cache_w),
        "output_tokens": g("output_tokens"),
        "cache_read_input_tokens": cache_r,
        "cache_creation_input_tokens": cache_w,
    }


def encode_wire_record(record: dict) -> str:
    return json.dumps(record, ensure_ascii=WIRE_LOG_ENSURE_ASCII)


_ACTIVE_PATHS: set[str] = set()
#: Paths a RequestLogger has ever opened in this process (never removed). A fresh target is
#: truncated; one this process already logged to is appended to, so reopening doesn't clobber.
_EVER_LOGGER_PATHS: set[str] = set()


class RequestLogger:

    def __init__(self, path: Path):
        self.path = path
        key = None if str(path) == os.devnull else str(Path(path).resolve())
        if key is not None and key in _ACTIVE_PATHS:
            raise FileExistsError(f"a RequestLogger has already opened {path}")
        mode = "a" if key is not None and key in _EVER_LOGGER_PATHS else "w"
        # Open before registering: if `open_guarded` refuses a planted alias, the path must not
        # stay stuck in `_ACTIVE_PATHS` for the rest of the process.
        fh = open_guarded(path, mode)
        if key is not None:
            _ACTIVE_PATHS.add(key)
            _EVER_LOGGER_PATHS.add(key)
        self._key = key
        self._fh = fh
        self._cap = _max_chars()
        self.messages: list[dict] = []
        self._seq: dict[str, int] = {}
        self.n_requests = 0
        self._denial_seq = 0

    def _emit(
        self, agent_id: str, kind: str, message: dict, cap: int, **extra: Any
    ) -> None:
        seq = self._seq.get(agent_id, 0)
        self._seq[agent_id] = seq + 1
        rec = {
            "event_type": "message",
            "agent_id": agent_id,
            "writer_id": writer_id(agent_id),
            "seq": seq,
            "id": f"{agent_id}#{seq}",
            "kind": kind,
            **extra,
            "message": message,
        }
        self.messages.append(rec)
        # Cut first: the cut is a bounded walk, so no message can exhaust the stack in `_trim`
        # or the encoder either.
        on_disk = json_safe(message, non_finite="text", max_depth=_MESSAGE_DEPTH)
        self._write_record({**rec, "message": _trim(on_disk, cap)})

    def _write_record(self, rec: dict) -> None:
        """The single write path for every wire-log record kind.

        `encode_wire_record` uses ensure_ascii=True because a lone UTF-16 surrogate (reachable
        from a provider response via a `\\u` escape) would otherwise raise UnicodeEncodeError
        on write and halt the run."""
        self._fh.write(encode_wire_record(rec) + "\n")
        self._fh.flush()

    def log(
        self, *, request_messages: list[Any], response: Any, run_step: int = 0,
        duration_ms: float = 0.0, agent_id: str = "main", session_id: str | None = None,
        toon_gate: dict | None = None,
    ) -> None:
        cap = self._cap
        for dumped in ModelMessagesTypeAdapter.dump_python(request_messages, mode="json"):
            self._emit(agent_id, "request", dumped, cap)
        resp_dump = ModelMessagesTypeAdapter.dump_python([response], mode="json")[0]
        extra: dict[str, Any] = {}
        if toon_gate is not None:
            # The TOON gate's counters, carried on the response record.
            extra["toon_gate"] = toon_gate
        self._emit(
            agent_id, "response", resp_dump, cap,
            model=getattr(response, "model_name", None),
            usage=_usage_dict(getattr(response, "usage", None)),
            duration_ms=round(duration_ms, 1),
            run_step=run_step,
            session_id=session_id,
            wire_sha=wire_digest(request_messages),
            **extra,
        )
        self.n_requests += 1

    def log_policy_denial(
        self, *, role: str, system: str, verb: str, call_id: str, params: Any,
    ) -> dict:
        """Append one policy-denial record: role, system, verb, call id, and a digest of the
        param values (never the raw blob). A failed write propagates (unlike
        `log_budget_refusal`), after the refusal it audits has already taken effect."""
        seq = self._denial_seq
        self._denial_seq += 1
        rec = {
            "event_type": POLICY_DENIAL_EVENT_TYPE,
            "ts": now_iso(),
            "seq": seq,
            "role": role,
            "system": system,
            "verb": verb,
            "call_id": call_id,
            "params_digest": _params_digest(params),
        }
        self._write_record(rec)
        return rec

    def log_budget_refusal(self, *, tool_name: str, agent_id: str = "main") -> None:
        rec = {"event_type": "budget_refusal", "kind": "budget_refusal",
               "tool_name": tool_name, "agent_id": agent_id, "writer_id": writer_id(agent_id)}
        with contextlib.suppress(Exception):
            self._write_record(rec)

    def close(self) -> None:
        if self._key is not None:
            _ACTIVE_PATHS.discard(self._key)
        with contextlib.suppress(Exception):
            self._fh.close()


#: One policy-denial writer per run dir, shared by every denial site: `RequestLogger` refuses a
#: second open of the same path, and each gather lead has its own `QueryCapture`. Opened
#: lazily, so a clean run leaves no file.
_DENIAL_LOGGERS: dict[str, RequestLogger] = {}


def _denial_logger_or_null(path: Path) -> RequestLogger:
    """Open the denial stream, degrading to a null sink if the open is refused.

    It opens lazily, mid-run, after the box could have planted a symlink at the name; letting
    that refusal end the run would give the box a cheap denial-of-service lever. The denial
    itself still takes effect; only the record is lost (logged), and the reap scan reports the
    plant."""
    try:
        return RequestLogger(path)
    except OSError as e:
        _logger.error(
            f"the policy-denial log at {path} could not be opened ({e!r}); denials "
            f"for this run will be REFUSED AS NORMAL but not recorded",
        )
        return RequestLogger(Path(os.devnull))


def denial_logger(run_dir: Path) -> RequestLogger:
    path = RunPaths(run_dir).policy_denials
    key = str(path.resolve())
    logger = _DENIAL_LOGGERS.get(key)
    if logger is None:
        # Cache the null fallback too, so a plant doesn't cause per-call re-probing and logging.
        logger = _denial_logger_or_null(path)
        _DENIAL_LOGGERS[key] = logger
    return logger


def wire_log_path(run_dir: Path) -> Path:
    """The run's wire log (`<run_dir>/wire_logs/llm_requests.jsonl`), creating the holding dir.

    The subdirectory is a read-gate boundary (see `_run_paths.WIRE_LOG_DIR`). The assertion
    keeps this writer's path identical to the `RunPaths` accessor readers use."""
    path = stage_trace_path(run_dir, RUN_LAYOUT.wire_log.name)
    assert path == RunPaths(Path(run_dir)).wire_log, (
        "the wire log's writer and its RunPaths accessor have drifted apart"
    )
    return path


def stage_trace_path(root: Path, trace_name: str) -> Path:
    """A learning stage's trace (`<root>/wire_logs/<trace_name>`), creating the holding dir.

    Every wire log must sit under the `wire_logs` component, since
    `permission.files.names_wire_log_dir` keys its read deny on that directory."""
    root = Path(root)
    wire_logs = root / RUN_LAYOUT.wire_log_dir
    guarded_mkdir(wire_logs, base=root)
    return wire_logs / trace_name


def writer_id(agent_id: str) -> str:
    """The writer id on agent-produced wire-log records, attributing lines in the shared
    file. Main's is "MAIN", which readers check for; others use the `agent_id`."""
    return "MAIN" if agent_id == "main" else agent_id


def _tool_args(value: Any) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return {}
    return value if isinstance(value, dict) else {}


def _iso(ts: Any) -> Any:
    return ts.isoformat() if hasattr(ts, "isoformat") else ts


def _assistant_event(message: ModelResponse, coord: str) -> dict:
    content: list[dict] = []
    for part in message.parts:
        if isinstance(part, TextPart):
            content.append({"type": "text", "text": part.content})
        elif isinstance(part, ToolCallPart):
            content.append({
                "type": "tool_use", "name": part.tool_name,
                "id": part.tool_call_id, "input": _tool_args(part.args),
            })
        elif isinstance(part, ThinkingPart):
            content.append({"type": "thinking"})
    ev = {
        "type": "assistant",
        "message": {
            "id": coord,
            "model": message.model_name or "",
            "usage": _usage_dict(message.usage),
            "content": content,
        },
    }
    if getattr(message, "timestamp", None):
        ev["timestamp"] = _iso(message.timestamp)
    return ev


def _user_event(message: Any) -> dict | None:
    returns = [p for p in getattr(message, "parts", []) if isinstance(p, ToolReturnPart)]
    if not returns:
        return None
    ev = {
        "type": "user",
        "message": {"content": [{"type": "tool_result", "tool_name": p.tool_name}
                                for p in returns]},
    }
    ts = next((getattr(p, "timestamp", None) for p in returns if getattr(p, "timestamp", None)), None)
    if ts:
        ev["timestamp"] = _iso(ts)
    return ev


def write_trace(run_dir: Path, *, store: Any, session_id: str, wall_ms: float) -> None:
    """`{run_dir}/tool_trace.jsonl`: the events this run produced, and its own cost.

    Sliced at the branch point: a resumed run hydrates the source run's prefix too, which
    would otherwise be reported (and billed, e.g. in `run_stats.py`) once per sibling.
    """
    from . import session_store as ss  # local import — avoids a cycle at module load

    # `branch_point` first: a cheap lookup, so unforked runs skip the extra parent walk.
    cut = ss.branch_point(store, session_id)
    messages = ss.hydrate(store, session_id, role="analysis")
    coords = ss.hydrate(store, session_id, role="actor")
    if cut is not None:
        ids = ss.path_row_ids(store, session_id)
        if cut in ids:
            own = ids.index(cut) + 1
            messages, coords = messages[own:], coords[own:]

    events: list[dict] = []
    for message, row in zip(messages, coords, strict=True):
        if isinstance(message, ModelResponse):
            events.append(_assistant_event(message, row["coord"]))
        else:
            user = _user_event(message)
            if user:
                events.append(user)

    responses = [m for m in messages if isinstance(m, ModelResponse)]
    keys = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    totals = {k: 0 for k in keys}
    total_cost = 0.0
    for m in responses:
        d = _usage_dict(m.usage)
        for k in keys:
            totals[k] += d.get(k, 0)
        total_cost += usage_cost(m.model_name or "", d)

    events.append({
        "type": "result",
        "duration_ms": round(wall_ms),
        "duration_api_ms": round(wall_ms),
        "total_cost_usd": round(total_cost, 6),
        "num_turns": len(responses),
        "usage": totals,
    })
    write_guarded(RunPaths(run_dir).tool_trace, "".join(json.dumps(e) + "\n" for e in events))
