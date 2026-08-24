
from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import sys
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
from defender._io import guarded_mkdir, open_guarded, write_guarded
from defender._run_paths import WIRE_LOG_DIR, WIRE_LOG, RunPaths
from defender.runtime._wire import wire_digest

from defender.scripts.pricing import usage_cost

WIRE_LOG_ENSURE_ASCII = True

#: The fixed policy-denial stream, ONE per site (§7 R1). Kept SEPARATE from the request stream
#: (whose append-and-flush-per-record discipline it shares): folded in, "no denial happened"
#: would be indistinguishable from "this file predates the denial record".
POLICY_DENIALS = "policy_denials.jsonl"
POLICY_DENIAL_EVENT_TYPE = "policy_denial"

#: The bounded, normalized projection §7 R12 demands: the policy FACT, never the raw
#: model-controlled parameter blob.
_DENIAL_PARAM_DIGEST_LEN = 16


def _normalize_for_digest(value: Any) -> Any:
    if isinstance(value, float):
        return value if math.isfinite(value) else f"<non-finite:{value!r}>"
    if isinstance(value, dict):
        # No pre-sort: `_params_digest` dumps with sort_keys=True, which orders the stringified
        # keys itself — sorting here as well only pays for the same ordering twice.
        return {str(k): _normalize_for_digest(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_for_digest(v) for v in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return repr(value)


def _params_digest(params: Any) -> str:
    normalized = _normalize_for_digest(params)
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
#: Paths a RequestLogger has EVER opened in this process, never removed (unlike
#: `_ACTIVE_PATHS`) — distinguishes "fresh log target" (truncate; a file some OTHER writer
#: left there is not this logger's history to preserve) from "this process already logged here
#: and closed" (append, so a second construction does not clobber the first's lines).
_EVER_LOGGER_PATHS: set[str] = set()


class RequestLogger:

    def __init__(self, path: Path):
        self.path = path
        key = None if str(path) == os.devnull else str(Path(path).resolve())
        if key is not None and key in _ACTIVE_PATHS:
            raise FileExistsError(f"a RequestLogger has already opened {path}")
        mode = "a" if key is not None and key in _EVER_LOGGER_PATHS else "w"
        # The open happens BEFORE the registration: `open_guarded` refuses a planted alias,
        # and a registration made ahead of a failed open is never undone — the path would stay
        # in `_ACTIVE_PATHS` forever, disabling that log for the whole process even once the
        # alias is cleared.
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
            "seq": seq,
            "id": f"{agent_id}#{seq}",
            "kind": kind,
            **extra,
            "message": message,
        }
        self.messages.append(rec)
        disk = {**rec, "message": _trim(message, cap)} if cap > 0 else rec
        # `encode_wire_record` pins ensure_ascii=True deliberately: a lone UTF-16 surrogate
        # (reachable from a provider response body via a `\udXXX` escape) survives this encode
        # but raises UnicodeEncodeError where a raw str would be utf-8-encoded. Flipping it
        # reopens a content-triggered availability halt.
        self._fh.write(encode_wire_record(disk) + "\n")
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
            # The gate's operator-facing record: how many foreign results it examined,
            # refused, substituted, and how many bytes that saved. Rides the SAME wire-log
            # record every other run-level observable does — no new run-dir sink.
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
        """Append one policy-denial record — the bounded projection §7 R12 demands: role,
        system, verb, call id, and a digest of the parameter VALUES (never the raw blob). A
        failed write is NOT swallowed (§7 R2): it propagates, after the refusal it audits has
        already taken effect. Deliberately not `log_budget_refusal`'s blanket suppressor."""
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
        self._fh.write(json.dumps(rec, ensure_ascii=True) + "\n")
        self._fh.flush()
        return rec

    def log_budget_refusal(self, *, tool_name: str, agent_id: str = "main") -> None:
        rec = {"event_type": "budget_refusal", "kind": "budget_refusal",
               "tool_name": tool_name, "agent_id": agent_id}
        with contextlib.suppress(Exception):
            self._fh.write(json.dumps(rec, ensure_ascii=True) + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._key is not None:
            _ACTIVE_PATHS.discard(self._key)
        with contextlib.suppress(Exception):
            self._fh.close()


#: The ONE policy-denial writer per run dir, shared by every denial site in this process.
#: `RequestLogger` refuses a second open of a path it already holds, and the runtime builds a
#: separate `QueryCapture` for EVERY gather lead against one shared run dir — so a
#: per-capability logger turns the run's second denied call into an uncaught `FileExistsError`
#: out of the tool wrapper instead of a refusal. Still lazy: a clean run leaves no such file.
_DENIAL_LOGGERS: dict[str, RequestLogger] = {}


def _denial_logger_or_null(path: Path) -> RequestLogger:
    """Open the denial stream, degrading to a null sink rather than letting one refused open
    end the run (§7 D3, extended to the streaming lane).

    This logger opens LAZILY, on the first denial — mid-run, after the box has had every
    opportunity to plant a symlink at its name. `open_guarded` refuses that plant, and letting
    the refusal escape would hand the box a denial-of-service lever costing one planted entry.
    The refusal being audited has ALREADY taken effect, so the run survives and the model
    still sees its denial; only the RECORD is lost, announced on stderr, with the plant left
    on disk for the reap scan to report as taint. `log_policy_denial`'s own write stays
    non-swallowing (§7 R2): only a refused OPEN is a lever the box can pull at will."""
    try:
        return RequestLogger(path)
    except OSError as e:
        print(
            f"[observe] the policy-denial log at {path} could not be opened ({e!r}); denials "
            f"for this run will be REFUSED AS NORMAL but not recorded",
            file=sys.stderr,
        )
        return RequestLogger(Path(os.devnull))


def denial_logger(run_dir: Path) -> RequestLogger:
    path = Path(run_dir) / POLICY_DENIALS
    key = str(path.resolve())
    logger = _DENIAL_LOGGERS.get(key)
    if logger is None:
        # The null fallback is cached like any other: without that, every later denial re-probes
        # the planted name and re-prints, turning one plant into per-call stderr noise.
        logger = _denial_logger_or_null(path)
        _DENIAL_LOGGERS[key] = logger
    return logger


def wire_log_path(run_dir: Path) -> Path:
    """The run's wire log (`<run_dir>/wire_logs/llm_requests.jsonl`), creating the holding dir.

    The WRITER's half of a location `_run_paths` owns; why the log sits one level down rather
    than at the run root is documented there, on `WIRE_LOG_DIR` — it is a read-gate boundary,
    not tidiness. Callers ask here instead of joining the name onto a run dir, so the location
    cannot drift. The `RunPaths` assertion keeps the delegation honest: the accessor every
    READER resolves through must name the file this WRITER opens."""
    path = stage_trace_path(run_dir, WIRE_LOG)
    assert path == RunPaths(Path(run_dir)).wire_log, (
        "the wire log's writer and its RunPaths accessor have drifted apart"
    )
    return path


def stage_trace_path(root: Path, trace_name: str) -> Path:
    """A learning stage's trace (`<root>/wire_logs/<trace_name>`), creating the holding dir.

    `wire_log_path`'s twin for the OFFLINE lane, off a root that varies by stage. Same
    component, and it has to be: `permission.files.names_wire_log_dir` is ONE path-component
    test, so every wire log in the tree must land where that test finds it. Here the component
    is NOT what denies (see `files.WIRE_LOG_DENY_REASON`) — it is what makes the deny
    addressable: a rule keyed on a directory covers a trace name nobody has invented yet."""
    root = Path(root)
    guarded_mkdir(root / WIRE_LOG_DIR, base=root)
    return root / WIRE_LOG_DIR / trace_name


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
    """`{run_dir}/tool_trace.jsonl` — the events THIS run produced, and its own cost.

    SLICED AT THE BRANCH POINT. `path_row_ids` walks parents across a fork, so a resumed run
    (#920's turn-N branch) hydrates the source run's whole prefix alongside its own rows — and
    every number below is a sum over what it hydrates. Left whole, a sibling's trace reports
    the SOURCE's tool calls as its own and its `result` event bills the shared prefix's turns,
    tokens and dollars to the sibling: `scripts/analytics/run_stats.py` reads exactly that
    event, so an N-sibling sweep counts the prefix N times. `branch_point` answers `None` for
    every unforked session, so the ordinary run is untouched.
    """
    from . import session_store as ss  # local import — avoids a cycle at module load

    # `branch_point` FIRST: it is one indexed row lookup and answers `None` for every unforked
    # session, so the ordinary run pays that and nothing else. Asked after an unconditional
    # `path_row_ids`, every run paid a whole extra parent walk — one query per message — whose
    # result it then threw away.
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
    write_guarded(run_dir / "tool_trace.jsonl", "".join(json.dumps(e) + "\n" for e in events))
