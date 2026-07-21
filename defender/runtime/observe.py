
from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

from pydantic_ai.messages import ModelMessagesTypeAdapter

from defender._env import env_int

from defender.scripts.pricing import usage_cost



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


class RequestLogger:

    def __init__(self, path: Path):
        self.path = path
        self._fh = path.open("w", encoding="utf-8")
        self._cap = _max_chars()
        self.messages: list[dict] = []
        self._seen: dict[str, int] = {}
        self._seq: dict[str, int] = {}
        self.n_requests = 0

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
        self._fh.write(json.dumps(disk, default=str) + "\n")
        self._fh.flush()

    def log(
        self, *, request_messages: list[Any], response: Any, run_step: int = 0,
        duration_ms: float = 0.0, agent_id: str = "main",
    ) -> None:
        cap = self._cap
        seen = self._seen.get(agent_id, 0)
        if seen > len(request_messages):
            seen = 0
        for dumped in ModelMessagesTypeAdapter.dump_python(
            request_messages[seen:], mode="json"
        ):
            self._emit(agent_id, dumped.get("kind", "request"), dumped, cap)
        self._seen[agent_id] = len(request_messages)
        resp_dump = ModelMessagesTypeAdapter.dump_python([response], mode="json")[0]
        self._emit(
            agent_id, "response", resp_dump, cap,
            model=getattr(response, "model_name", None),
            usage=_usage_dict(getattr(response, "usage", None)),
            duration_ms=round(duration_ms, 1),
            run_step=run_step,
        )
        self._seen[agent_id] += 1
        self.n_requests += 1

    def log_budget_refusal(self, *, tool_name: str, agent_id: str = "main") -> None:
        rec = {"event_type": "budget_refusal", "kind": "budget_refusal",
               "tool_name": tool_name, "agent_id": agent_id}
        with contextlib.suppress(Exception):
            self._fh.write(json.dumps(rec) + "\n")
            self._fh.flush()

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._fh.close()



def _main_messages(messages: list[dict]) -> list[dict]:
    return [m for m in messages if m.get("agent_id", "main") == "main"]


def _tool_args(part: dict) -> dict:
    args = part.get("args")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, ValueError):
            return {}
    return args if isinstance(args, dict) else {}


def _assistant_event(rec: dict) -> dict:
    msg = rec.get("message") or {}
    content: list[dict] = []
    for part in msg.get("parts", []):
        pk = part.get("part_kind")
        if pk == "text":
            content.append({"type": "text", "text": part.get("content", "")})
        elif pk == "tool-call":
            content.append({
                "type": "tool_use",
                "name": part.get("tool_name", ""),
                "id": part.get("tool_call_id", ""),
                "input": _tool_args(part),
            })
        elif pk == "thinking":
            content.append({"type": "thinking"})
    ev = {
        "type": "assistant",
        "message": {
            "id": rec.get("id"),
            "model": rec.get("model") or "",
            "usage": rec.get("usage") or {},
            "content": content,
        },
    }
    if msg.get("timestamp"):
        ev["timestamp"] = msg["timestamp"]
    return ev


def _user_event(rec: dict) -> dict | None:
    msg = rec.get("message") or {}
    returns = [p for p in msg.get("parts", []) if p.get("part_kind") == "tool-return"]
    if not returns:
        return None
    ev = {
        "type": "user",
        "message": {"content": [{"type": "tool_result", "tool_name": p.get("tool_name", "")} for p in returns]},
    }
    ts = next((p.get("timestamp") for p in returns if p.get("timestamp")), None)
    if ts:
        ev["timestamp"] = ts
    return ev


def _trace_events(messages: list[dict]) -> list[dict]:
    events: list[dict] = []
    for rec in _main_messages(messages):
        if rec.get("kind") == "response":
            events.append(_assistant_event(rec))
        else:
            user = _user_event(rec)
            if user:
                events.append(user)
    return events


def _usage_totals(messages: list[dict]) -> dict[str, int]:
    keys = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    return {
        k: sum(int((r.get("usage") or {}).get(k, 0) or 0)
               for r in messages if r.get("kind") == "response")
        for k in keys
    }


def write_trace(run_dir: Path, messages: list[dict], *, wall_ms: float) -> None:
    events = _trace_events(messages)
    totals = _usage_totals(messages)
    total_cost = sum(
        usage_cost(r.get("model") or "", r.get("usage") or {})
        for r in messages if r.get("kind") == "response"
    )
    main_responses = sum(1 for r in _main_messages(messages) if r.get("kind") == "response")
    events.append({
        "type": "result",
        "duration_ms": round(wall_ms),
        "duration_api_ms": round(wall_ms),
        "total_cost_usd": round(total_cost, 6),
        "num_turns": main_responses,
        "usage": totals,
    })
    (run_dir / "tool_trace.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
