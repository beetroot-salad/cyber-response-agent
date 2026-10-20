"""JSON bounds, decoding, and normalization primitives."""
from __future__ import annotations


import dataclasses

import datetime as _dt



import json

import math


import re



import sys


from collections.abc import Callable, Mapping


from typing import Any, Literal




#: The deepest nesting a box-written JSON artifact may carry and still be readable, judged on
#: the bytes before decoding. `json.loads` recurses on the shared stack, so without this bound
#: the same line could decode from a shallow caller and hit `RecursionError` from a deep one,
#: and a writer and reader could disagree on whether it is a row. 100 is far past any real
#: artifact and far short of the stack budget.
JSON_NESTING_LIMIT = 100



#: A string literal or a bracket. A string with no closing quote runs to the end of the text:
#: the match can never fail, so the scan never backs up and restarts at a later quote, which on
#: an unclosed run of escaped quotes made the scan quadratic in the text's length.
_JSON_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"?|[\[\]{}]')




def json_nesting_depth(text: str) -> int:
    """The deepest container nesting in ``text``, judged without decoding it.

    Exact for valid JSON (brackets inside string literals are not counted); invalid JSON is
    refused by the decoder anyway. One pass, linear in the text's length whatever it holds, so
    it is safe on model- or box-written text of any size."""
    depth = deepest = 0
    for token in _JSON_TOKEN.finditer(text):
        bracket = text[token.start()]
        if bracket == '"':
            continue
        if bracket in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif depth:
            depth -= 1
    return deepest




# lint-parse: ok — returns `object`, not `Any`, so each caller must narrow the shape itself.
def load_json_artifact(
    text: str, *, object_pairs_hook: Callable[[list[tuple[str, Any]]], Any] | None = None,
) -> tuple[object, str | None]:
    """Decode one JSON artifact a box could have written: ``(value, None)``, or ``(None,
    reason)`` when it is not one. Success is ``reason is None`` — ``null`` decodes to ``None``.

    The single place malformed-artifact tolerance is decided. Nesting is checked before
    decoding (see :data:`JSON_NESTING_LIMIT`) rather than catching ``RecursionError``, whose
    occurrence depends on the caller's stack depth. ``object_pairs_hook`` is ``json.loads``'s,
    for a caller with a stricter object rule (the episode record refuses a duplicate key): a
    ``ValueError`` it raises is that document's ``reason``."""
    if json_nesting_depth(text) > JSON_NESTING_LIMIT:
        return None, f"nested deeper than {JSON_NESTING_LIMIT}"
    try:
        return json.loads(text, object_pairs_hook=object_pairs_hook), None
    except ValueError as e:
        return None, str(e)




def parse_jsonl_row(line: str) -> dict | None:
    """One physical line as a JSONL row (a JSON object), or ``None``.

    Public because ``challenge_gate._write_trace_row`` must apply exactly the predicate the
    readers do, from any stack depth. Non-dict JSON is not a row, so consumers can call
    ``row.get(...)`` safely.
    """
    s = line.strip()
    if not s:
        return None
    obj, reason = load_json_artifact(s)
    return obj if reason is None and isinstance(obj, dict) else None




class JsonTooDeep(ValueError):
    """`json_safe(..., deeper="refuse")` met a container past `max_depth`."""




def json_safe(value: Any, *, non_finite: Literal["text", "null"],
              max_depth: int | None = None, deeper: Literal["repr", "refuse"] = "repr",
              naive_is_utc: bool = False) -> Any:
    """`value` with only the parts the JSON encoder cannot carry replaced; text, numbers,
    booleans and null are left as the encoder would write them."""
    if non_finite not in ("text", "null"):
        raise ValueError(f"non_finite must be 'text' or 'null', not {non_finite!r}")
    if deeper not in ("repr", "refuse"):
        raise ValueError(f"deeper must be 'repr' or 'refuse', not {deeper!r}")
    rules = _JsonRules(non_finite, sys.maxsize if max_depth is None else max_depth,
                       deeper == "refuse", naive_is_utc)
    return _json_safe_walk(value, rules, 0)




@dataclasses.dataclass(frozen=True)
class _JsonRules:
    non_finite: str
    max_depth: int
    refuse_deeper: bool
    naive_is_utc: bool




def _json_safe_walk(v: Any, rules: _JsonRules, depth: int) -> Any:
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        if math.isfinite(v):
            return v
        return None if rules.non_finite == "null" else _non_finite_text(v)
    if depth >= rules.max_depth:
        if not rules.refuse_deeper:
            return repr(v)
        # Only a container adds a level; a date at the limit is still one text value.
        if isinstance(v, (Mapping, list, tuple, set, frozenset)):
            raise JsonTooDeep(f"a value nests deeper than {rules.max_depth} levels")
    if isinstance(v, Mapping):
        return {_json_key(k, rules): _json_safe_walk(x, rules, depth + 1) for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        items = [_json_safe_walk(x, rules, depth + 1) for x in v]
        if isinstance(v, (set, frozenset)):
            # By written JSON: text in text order, and `1` never ties `"1"`, so the order never
            # depends on how the set happens to iterate.
            items.sort(key=lambda x: json.dumps(x, ensure_ascii=False))
        return items
    return _json_text(v, rules)




def _json_key(k: Any, rules: _JsonRules) -> str:
    # Always text, so a caller that sorts keys never compares `1` with `"b"`; a key the encoder
    # carries is spelled as the encoder would write it (`true`, `null`, `1`, `NaN`).
    if k is None or isinstance(k, (bool, int, float)):
        return json.dumps(k)
    return _json_text(k, rules)




def _json_text(v: Any, rules: _JsonRules) -> str:
    if isinstance(v, _dt.datetime):
        if v.utcoffset() is None and rules.naive_is_utc:
            v = v.replace(tzinfo=_dt.UTC)
        if v.utcoffset() is None:
            return v.isoformat(timespec="microseconds")
        utc = v.astimezone(_dt.UTC).replace(tzinfo=None)
        return utc.isoformat(timespec="microseconds") + "Z"
    if isinstance(v, _dt.time):
        return v.isoformat(timespec="microseconds")
    return str(v)  # a date's text is already ISO 8601




def _non_finite_text(v: float) -> str:
    return "NaN" if math.isnan(v) else "Infinity" if v > 0 else "-Infinity"
