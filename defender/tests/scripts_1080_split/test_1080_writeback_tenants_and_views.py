"""The payload view: passthrough ceiling and payload shapes. Goldens: `goldens/tenants.json`."""
from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "tenants"

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
PASSTHROUGH_ENV = "DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES"


# ======================================================================================
# Goldens and the one normalization
# ======================================================================================


def _golden(demand: str) -> Mapping[str, Any]:
    data = S.golden(GOLDEN)
    assert demand in data, f"goldens/{GOLDEN}.json holds no entry for {demand}"
    return data[demand]


def _norm(value: Any, tmp: Path | None = None) -> Any:
    """THE normalization: inside every string of `value` (a canon record), the case's tmp root
    reads `<TMP>`, the test's data root `<DATA_ROOT>` and this checkout's root `<REPO>`. The
    capture and the tests both go through here."""
    subs: list[tuple[str, str]] = []
    if tmp is not None:
        subs.append((str(tmp), "<TMP>"))
    data_root = os.environ.get(DATA_ROOT_ENV)
    if data_root:
        subs.append((data_root, "<DATA_ROOT>"))
    subs.append((str(S.REPO_ROOT), "<REPO>"))
    subs.sort(key=lambda s: -len(s[0]))

    def fix(v: Any) -> Any:
        if isinstance(v, str):
            for old, new in subs:
                v = v.replace(old, new)
            return v
        if isinstance(v, list):
            return [fix(x) for x in v]
        if isinstance(v, dict):
            return {fix(k): fix(x) for k, x in v.items()}
        return v

    return fix(value)


def _text_digest(text: str) -> Any:
    """A long view kept small in the golden: its length, its hash and both ends."""
    if len(text) <= 2000:
        return text
    return {"len": len(text), "sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass"))
            .hexdigest(), "head": text[:400], "tail": text[-200:]}


def _outcome_of(fn: Callable[..., Any], *args: Any, view: Callable[[Any], Any] = S.canon,
                **kw: Any) -> dict[str, Any]:
    """`S.outcome` with a caller-chosen view of the return value (a `CaseMapping`'s repr carries
    an address, so it is viewed through `.plain()`)."""
    try:
        value = fn(*args, **kw)
    except Exception as e:  # noqa: BLE001 — the exception IS the observed outcome
        return {"raises": type(e).__name__, "message": str(e)}
    return {"returns": view(value)}


# ======================================================================================
# The payload view
# ======================================================================================


def _view() -> Any:
    return S.moved_module("passthrough_max_bytes")


def _ceiling_cases() -> dict[str, tuple[str, int | None]]:
    """(payload text, explicit ceiling or None for the variable's) per case."""
    c = 64
    rows = json.dumps({"total": 3, "returned": 3, "rows": ["a" * 10, "b" * 10, "c" * 10]})
    return {
        "text_one_under": ("t" * (c - 1), c),
        "text_at": ("t" * c, c),
        "text_one_over": ("t" * (c + 1), c),
        "json_one_under": (json.dumps({"v": "j" * (c - 1 - 9)}), c),
        "json_at": (json.dumps({"v": "j" * (c - 9)}), c),
        "json_one_over": (json.dumps({"v": "j" * (c + 1 - 9)}), c),
        "envelope_at": (rows, len(rows)),
        "envelope_one_over": (rows, len(rows) - 1),
        "multibyte_across_the_cut": ("a" * 30 + "🙂é中" * 20, 40),
        "multibyte_at_the_cut_json": (json.dumps({"v": "é" * 40}, ensure_ascii=False), 40),
        "ceiling_smaller_than_a_character": ("🙂" * 4, 1),
        "ceiling_zero": ("🙂" * 4, 0),
        "ceiling_negative": ('{"a": 1}', -5),
        "through_the_variable": ("v" * 200, None),
    }


def _observe_at_ceiling(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    view = _view()
    text, ceiling = _ceiling_cases()[case]
    mp.setenv(PASSTHROUGH_ENV, "100")
    kw = {} if ceiling is None else {"ceiling": ceiling}
    return _norm({"render": _outcome_of(view.render, text, None, tmp, view=_text_digest, **kw)},
                 tmp)


@pytest.mark.parametrize("case", list(_ceiling_cases()))
def test_payload_at_the_ceiling(case, tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A payload one byte under, at and one over the ceiling,
    with a multi-byte character across the cut and a ceiling smaller than one character, is
    clipped at the same boundary as today.

    The moved `render` over plain text, a JSON document and a server envelope at each side of
    the ceiling, multi-byte text cut mid-character, ceilings of one, zero and below zero, and
    once through the variable; the view against the base golden."""
    assert _observe_at_ceiling(case, tmp_path, monkeypatch) == _golden("s173")[case]


def _nested(depth: int) -> Any:
    value: Any = "leaf"
    for i in range(depth):
        value = {"k": value} if i % 2 else [value]
    return value


def _shape_cases() -> dict[str, tuple[str, int | None]]:
    """(payload text, explicit ceiling or None) per awkward shape."""
    leaf = 600
    return {
        "empty": ("", 64),
        "plain_text": ("plain words, not JSON. " * 20, 64),
        "deeply_nested": (json.dumps(_nested(60)), 64),
        "nested_past_the_parser": ("[" * 100000 + "]" * 100000, 64),  # quirk pin: base behavior, not a requirement
        "leaf_at_the_string_bound": (json.dumps({"a": "s" * leaf, "pad": "p" * 300}), 400),
        "leaf_one_over_the_string_bound": (json.dumps({"a": "s" * (leaf + 1), "pad": "p" * 300}),
                                           400),
        "invalid_utf8_as_surrogates": (
            b'{"msg": "bad \xff\xfe bytes", "rows": [1, 2, 3]}'.decode("utf-8",
                                                                     "surrogateescape"), 16),
        "escaped_lone_surrogate": ('{"msg": "\\udcff lone", "rows": [1, 2, 3]}', 16),
        "scalar_number": ("1234567890" * 10, 16),
        "scalar_string": (json.dumps("s" * 100), 16),
        "scalar_null": ("null", 2),
        "top_level_list": (json.dumps(list(range(200))), 64),
        "ten_thousand_items": (json.dumps([{"i": i, "host": f"h-{i}"} for i in range(10000)]),
                               None),
        "wide_flat_object": (json.dumps({f"field_{i}": i for i in range(300)}), 256),
        "wide_row": (json.dumps({"columns": ["a"], "values": [list(range(400))]}), 256),
    }


def _observe_shape(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    view = _view()
    text, ceiling = _shape_cases()[case]
    mp.delenv(PASSTHROUGH_ENV, raising=False)
    kw = {} if ceiling is None else {"ceiling": ceiling}
    return _norm({"render": _outcome_of(view.render, text, None, tmp, view=_text_digest, **kw)},
                 tmp)


@pytest.mark.parametrize("case", list(_shape_cases()))
def test_payload_shapes_the_view_must_not_choke_on(case, tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Empty, plain-text, deeply nested JSON, boundary-length
    string leaves, invalid UTF-8, scalar-top-level and ten-thousand-item payloads are viewed as
    today without a new failure.

    `render` takes text (`query_tool` hands it `json.dumps(payload)`), so invalid UTF-8 reaches
    it as the surrogate-escaped characters a lossless decode leaves; each shape through the
    moved `render` against the base golden (a long view by its length, hash and ends).

    Case `nested_past_the_parser` (the view raises `RecursionError`): quirk pin: base behavior,
    not a requirement."""
    assert _observe_shape(case, tmp_path, monkeypatch) == _golden("s174")[case]


# ======================================================================================
# s204 / s205 — fresh-process imports and module-level state
# ======================================================================================


# ======================================================================================
# Shared by the capture script (the `_observe_*` functions above ARE the capture)
# ======================================================================================

