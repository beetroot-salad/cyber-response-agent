"""Message payload encoding and representation checks."""
from __future__ import annotations
import json
import math
from typing import Any
from pydantic_ai.messages import (
    ModelMessagesTypeAdapter,
    ToolCallPart,
    ToolReturnPart,
)
from defender.records._run_id import CASE_ID_RE  # noqa: F401 — re-export; the rule lives with the id rules
from defender.records._store_errors import InvalidCaseId, StoreError  # noqa: F401 — re-exports
from defender.records.run_end import (  # noqa: F401 — re-exports
    TRUNCATED_BY_ABORTED,
    TRUNCATED_BY_BUDGET,
    TRUNCATED_BY_DEAD_END,
    TRUNCATED_BY_EXECUTED_QUERIES,
    TRUNCATED_BY_PROVIDER_DOWN,
    TRUNCATED_BY_REQUEST_LIMIT,
    TRUNCATED_BY_RETRY_EXHAUSTED,
    TRUNCATED_BY_SERVED_LEDGER,
    TRUNCATED_BY_STORE,
    TRUNCATED_BY_TIMED_OUT,
    TRUNCATED_BY_VALUES,
    normalized_truncated_by,
)

from ._schema import PayloadSchemaSkew, _MAX_PAYLOAD_DEPTH, _TOO_DEEP



# gather_boundary's extraction: pure Python, registered as a SQL function, and swallowing
# every error so a malformed or pathologically deep `args` value can never abort the query.

def _first_wins_pairs(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k not in out:
            out[k] = v
    return out




def _lead_id_from_args(args: Any) -> str | None:
    if isinstance(args, str):
        try:
            args = json.loads(args, object_pairs_hook=_first_wins_pairs)
        except Exception:  # noqa: BLE001 — untrusted, possibly-hostile text
            return None
    if not isinstance(args, dict) or "lead_id" not in args:
        return None
    value = args["lead_id"]
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, separators=(",", ":"))
        except Exception:  # noqa: BLE001 — untrusted content boundary
            return None
    return None




def _extract_lead_id(payload_text: str) -> str | None:
    try:
        payload = json.loads(payload_text, object_pairs_hook=_first_wins_pairs)
        parts = payload.get("parts") if isinstance(payload, dict) else None
        if not isinstance(parts, list):
            return None
        for part in parts:
            if not isinstance(part, dict) or part.get("part_kind") != "tool-call":
                continue
            lead_id = _lead_id_from_args(part.get("args"))
            if lead_id is not None:
                return lead_id
        return None
    except Exception:  # noqa: BLE001 — never abort the query
        return None




def _tool_name(message: Any) -> str | None:
    """Every distinct tool named by the message, comma-joined in first-seen order (a response
    can carry several parallel calls). Must agree with `observe.write_trace`, which lists all."""
    names: list[str] = []
    for part in getattr(message, "parts", []):
        if isinstance(part, (ToolCallPart, ToolReturnPart)) and part.tool_name not in names:
            names.append(part.tool_name)
    return ",".join(names) if names else None




def _is_nonrepresentable_leaf(obj: Any) -> bool:
    if isinstance(obj, float):
        return not math.isfinite(obj)
    return isinstance(obj, (bytes, bytearray, set))




def _children(obj: Any) -> Any:
    if isinstance(obj, dict):
        return obj.values()
    if isinstance(obj, (list, tuple)):
        return obj
    if hasattr(obj, "__dict__"):
        return vars(obj).values()
    return ()




def _find_nonrepresentable(obj: Any) -> Any:
    """Iterative and depth-capped: tool-call `args` are attacker-influenced, and both a
    recursive scan and `dump_python` crash on deep nesting."""
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_PAYLOAD_DEPTH:
            return _TOO_DEEP
        if _is_nonrepresentable_leaf(current):
            return current
        stack.extend((child, depth + 1) for child in _children(current))
    return None




def _message_from_payload(text: str) -> Any:
    return ModelMessagesTypeAdapter.validate_python([json.loads(text)])[0]




# payload validation, standalone (skew detection)

def _has_extra_keys(raw: Any, redumped: Any) -> bool:
    if isinstance(raw, dict):
        if not isinstance(redumped, dict):
            return True
        for k, v in raw.items():
            if k not in redumped:
                return True
            if _has_extra_keys(v, redumped[k]):
                return True
        return False
    if isinstance(raw, list):
        # A type change or dropped element is skew (e.g. an adapter reshaping `parts`).
        if not isinstance(redumped, list) or len(raw) != len(redumped):
            return True
        return any(_has_extra_keys(a, b) for a, b in zip(raw, redumped, strict=True))
    return False




def load_payload(json_text: str) -> Any:
    raw = json.loads(json_text)
    message = ModelMessagesTypeAdapter.validate_python([raw])[0]
    redumped = ModelMessagesTypeAdapter.dump_python([message], mode="json")[0]
    if _has_extra_keys(raw, redumped):
        raise PayloadSchemaSkew(
            "payload carries a field the installed adapter does not recognize")
    return message
