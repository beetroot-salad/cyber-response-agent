
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
from defender.configuration import env_int
from defender._io import JSON_NESTING_LIMIT, guarded_mkdir, json_safe, open_guarded, write_guarded
from defender.records import Run, RUN_LAYOUT, RunPaths
from defender.records.formats import wire_digest

from defender.configuration import billed_usage as _usage_dict, usage_cost

_logger = logging.getLogger(__name__)

WIRE_LOG_ENSURE_ASCII = True

#: Policy denials go to their own stream (path: `RunPaths.policy_denials`), separate from the
#: request stream, so "no denial happened" is distinguishable from "file predates denials".
POLICY_DENIAL_EVENT_TYPE = "policy_denial"

#: Denials record a bounded digest of the params, never the raw model-controlled blob.
_DENIAL_PARAM_DIGEST_LEN = 16

#: The deepest a logged RESPONSE is written, the message itself counted; deeper values are cut
#: to their repr. The record wraps its message in one level, so the line stays readable under
#: `JSON_NESTING_LIMIT`. Only the log cuts (#1117). A response is where a model's too-deep
#: call arrives; the query tool then replaces its arguments in the history, so the requests
#: that re-send the history never carry it and are written as they are.
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


def encode_wire_record(record: dict) -> str:
    return json.dumps(record, ensure_ascii=WIRE_LOG_ENSURE_ASCII)


_ACTIVE_PATHS: set[str] = set()
#: Paths a RequestLogger has ever opened in this process (never removed). A fresh target is
#: truncated; one this process already logged to is appended to, so reopening doesn't clobber.
_EVER_LOGGER_PATHS: set[str] = set()


class _NoLedger:
    """The explicit "this logger keeps no spend ledger" (a learning stage, the policy-denial
    stream): its responses are not a failed spend write. A logger that is neither bound nor given
    this is a wiring fault, and each run-side response it records is a failed write (#1377)."""

    def __repr__(self) -> str:
        return "NO_LEDGER"


NO_LEDGER = _NoLedger()


class SpendLedger:
    """A run's spend ledger: the run's session store and the run id its rows are written under."""

    def __init__(self, store: Any, run_id: str) -> None:
        self.store, self.run_id = store, run_id

    def record(self, response: Any) -> None:
        """Append `response`'s row. Raises whatever the store raises; `RequestLogger.record_spend`
        is the caller that never lets it reach an agent."""
        from defender.records import session_store as ss

        ss.record_spend(self.store, self.run_id, getattr(response, "model_name", None) or "",
                        _usage_dict(getattr(response, "usage", None)))


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
        self._record = None
        self._closed = False
        self._cap = _max_chars()
        self.messages: list[dict] = []
        self._seq: dict[str, int] = {}
        self.n_requests = 0
        self._denial_seq = 0
        self._init_spend()

    def _init_spend(self) -> None:
        #: `None`: unbound. A `SpendLedger` once the run's store is open, or `NO_LEDGER`.
        self.ledger: SpendLedger | _NoLedger | None = None
        #: Set when a spend write failed (or none was bound): the run's cost is then a lower limit.
        self.spend_write_failed = False
        self._on_spend_failure: Any = None

    def bind_ledger(self, ledger: SpendLedger | _NoLedger, *, on_failure: Any = None) -> None:
        """Bind the run's ledger (or `NO_LEDGER`); `on_failure()` is called once per failed write."""
        self.ledger, self._on_spend_failure = ledger, on_failure

    def record_spend(self, response: Any) -> None:
        """The ledger write for one response, the first step after it returns. It never raises: a
        failure (or a missing binding) logs at ERROR, sets `spend_write_failed` and tells the
        failure sink, and the agent runs on. A raise here would change a verdict (the review
        gate forces `inconclusive` on any exception from a stage)."""
        ledger = self.ledger
        if ledger is NO_LEDGER:
            return
        try:
            if not isinstance(ledger, SpendLedger):
                raise RuntimeError("no spend ledger is bound to this run's request logger")
            ledger.record(response)
        except Exception as fault:  # noqa: BLE001 — bookkeeping never stops the run (#1377 S3)
            self.spend_write_failed = True
            _logger.error(f"spend write failed ({fault!r}); this run's cost is a lower limit")
            try:
                if self._on_spend_failure is not None:
                    self._on_spend_failure()
            except Exception:  # noqa: BLE001 — the sink is best effort too
                _logger.exception("the spend-failure sink raised")

    @classmethod
    def from_record(cls, record: Any, *, continuing: bool = False, no_ledger: bool = False) -> RequestLogger:
        """A logger writing to `record`. A stream is started empty the first time this process
        opens its path, unless `continuing`: then it is appended to, and its policy-denial
        numbering goes on from the denials it already holds (a branch arm's log, restored to
        what its source held at the branch point, #1255 P2)."""
        path = record.path
        key = str(Path(path).resolve())
        if key in _ACTIVE_PATHS:
            raise FileExistsError(f"a RequestLogger has already opened {path}")
        if continuing or key in _EVER_LOGGER_PATHS:
            record.append_text("")
        else:
            record.start_stream("")
        logger = cls.__new__(cls)
        logger.path, logger._key = path, key
        logger._record, logger._fh, logger._closed = record, None, False
        logger._cap = _max_chars()
        logger.messages = []
        logger._seq = {}
        logger.n_requests = logger._denial_seq = 0
        logger._init_spend()
        logger.ledger = NO_LEDGER if no_ledger else None
        if continuing:
            rows, _malformed, _read = record.read_rows()
            logger._denial_seq = sum(
                row.get("event_type") == POLICY_DENIAL_EVENT_TYPE for row in rows)
        _ACTIVE_PATHS.add(key)
        _EVER_LOGGER_PATHS.add(key)
        return logger

    def _emit(
        self, agent_id: str, kind: str, message: dict, cap: int, *, cut: bool = False,
        **extra: Any,
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
        # A cut message is cut first: the cut is a bounded walk, so `_trim` and the encoder
        # never walk past it.
        on_disk = json_safe(message, non_finite="text", max_depth=_MESSAGE_DEPTH) if cut else message
        disk = {**rec, "message": _trim(on_disk, cap)} if cut or cap > 0 else rec
        self._write_record(disk)

    def _write_record(self, rec: dict) -> None:
        """The single write path for every wire-log record kind.

        `encode_wire_record` uses ensure_ascii=True because a lone UTF-16 surrogate (reachable
        from a provider response via a `\\u` escape) would otherwise raise UnicodeEncodeError
        on write and halt the run."""
        if self._closed:
            raise ValueError("RequestLogger is closed")
        text = encode_wire_record(rec) + "\n"
        if self._record is not None:
            self._record.append_text(text)
        else:
            self._fh.write(text)
            self._fh.flush()

    def log(
        self, *, request_messages: list[Any], response: Any, run_step: int = 0,
        duration_ms: float = 0.0, agent_id: str = "main", session_id: str | None = None,
        toon_gate: dict | None = None,
    ) -> None:
        cap = self._cap
        for dumped in ModelMessagesTypeAdapter.dump_python(request_messages, mode="json"):
            self._emit(agent_id, "request", dumped, cap)
        try:
            resp_dump = ModelMessagesTypeAdapter.dump_python([response], mode="json")[0]
        except ValueError as e:
            # A response pydantic cannot dump (a tool call's arguments nested past its own
            # bound, about 250 levels) still cost a request: its record keeps the usage that
            # prices it, and says why its parts are not here.
            resp_dump = {"kind": "response", "parts": [], "unlogged": f"{type(e).__name__}"}
        extra: dict[str, Any] = {}
        if toon_gate is not None:
            # The TOON gate's counters, carried on the response record.
            extra["toon_gate"] = toon_gate
        self._emit(
            agent_id, "response", resp_dump, cap, cut=True,
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
        ts: str | None = None,
    ) -> dict:
        """Append one policy-denial record: role, system, verb, call id, and a digest of the
        param values (never the raw blob). A failed write propagates (unlike
        `log_budget_refusal`), after the refusal it audits has already taken effect.

        `ts` is the denied call's time: the run clock's reading when a run denied it (#1255 —
        the log is model-readable), the wall clock when omitted (no run)."""
        seq = self._denial_seq
        self._denial_seq += 1
        rec = {
            "event_type": POLICY_DENIAL_EVENT_TYPE,
            "ts": ts if ts is not None else now_iso(),
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
        self._closed = True
        if self._key is not None:
            _ACTIVE_PATHS.discard(self._key)
        with contextlib.suppress(Exception):
            self._fh.close()


#: One policy-denial writer per run dir, shared by every denial site: `RequestLogger` refuses a
#: second open of the same path, and each gather lead has its own `QueryCapture`. Opened
#: lazily, so a clean run leaves no file.
_DENIAL_LOGGERS: dict[str, RequestLogger] = {}


def _denial_logger_or_null(record: Any) -> RequestLogger:
    """Open the denial stream, degrading to a null sink if the open is refused.

    It opens lazily, mid-run, after the box could have planted a symlink at the name; letting
    that refusal end the run would give the box a cheap denial-of-service lever. The denial
    itself still takes effect; only the record is lost (logged), and the reap scan reports the
    plant."""
    try:
        # Continued, never started over: a branch arm's log already holds its source's denials
        # through the branch point; a fresh run's does not exist yet.
        return RequestLogger.from_record(record, continuing=True, no_ledger=True)
    except OSError as e:
        _logger.error(
            f"the policy-denial log at {record.path} could not be opened ({e!r}); denials "
            f"for this run will be REFUSED AS NORMAL but not recorded",
        )
        return RequestLogger(Path(os.devnull))


def denial_logger(run: Run) -> RequestLogger:
    record = run.tables.policy_denials
    path = record.path
    key = str(path.resolve())
    logger = _DENIAL_LOGGERS.get(key)
    if logger is None:
        # Cache the null fallback too, so a plant doesn't cause per-call re-probing and logging.
        logger = _denial_logger_or_null(record)
        _DENIAL_LOGGERS[key] = logger
    return logger


def wire_log_path(run_dir: Path) -> Path:
    """The run's wire log (`<run_dir>/wire_logs/llm_requests.jsonl`), creating the holding dir.

    The subdirectory is a read-gate boundary (see `_layout.WIRE_LOG_DIR`). The assertion
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


def write_trace(run_dir: Path, *, store: Any, session_id: str, wall_ms: float, run_id: str,
                spend_write_failed: bool = False) -> None:
    """`{run_dir}/tool_trace.jsonl`: the events this run produced, and its own cost.

    The events are sliced at the branch point: a resumed run hydrates the source run's prefix too,
    which would otherwise be reported once per sibling. The result line's cost and usage are the
    spend ledger's rows for `run_id` (#1377 S5): every response the run received (main, every
    lead's last one, the review), never the saved conversation. `num_turns` stays MAIN's turns,
    which run health reads. The total is marked a lower limit when a spend write failed. A ledger
    that cannot be read leaves the events whole with a null total and usage (the job's cost is unknown then too).
    """
    from defender.records import session_store as ss  # local import — avoids a cycle at module load

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
    total_cost: float | None
    totals: dict[str, int] | None
    try:
        counts = dict.fromkeys(ss.SPEND_COUNTS, 0)
        spend = 0.0
        for spent in ss.run_spend(store, run_id):
            for k in ss.SPEND_COUNTS:
                counts[k] += spent.usage.get(k, 0)
            spend += usage_cost(spent.model, spent.usage)
        total_cost, totals = spend, counts
    except Exception as e:  # noqa: BLE001 — an unreadable ledger leaves the events whole and the total unknown
        _logger.error(f"the spend ledger could not be read for the run file ({e!r}); its total is left null")
        total_cost = totals = None

    events.append({
        "type": "result",
        "duration_ms": round(wall_ms),
        "duration_api_ms": round(wall_ms),
        "total_cost_usd": None if total_cost is None else round(total_cost, 6),
        "total_cost_is_lower_limit": spend_write_failed and total_cost is not None,
        "num_turns": len(responses),
        "usage": totals,
    })
    write_guarded(RunPaths(run_dir).tool_trace, "".join(json.dumps(e) + "\n" for e in events))


# Public path-mode helpers remain available to learning and tooling callers.
__all__ = [
    "RequestLogger", "encode_wire_record", "denial_logger", "wire_log_path",
    "stage_trace_path", "writer_id", "write_trace", "NO_LEDGER", "SpendLedger",
]
