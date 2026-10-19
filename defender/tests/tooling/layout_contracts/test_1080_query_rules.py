"""Query-id / request-key rules: model-supplied query ids and params normalisation.
Goldens: `goldens/queryrules.json`."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _writer_run_1165

import datetime as _dt
import hashlib
import importlib
import json
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender.tests.tooling.layout_contracts import _spec1080 as S

GOLDEN = "queryrules"

#: The two flat-tier rules `S.QUERY_RULE_PUBLIC` spells (the identity map since the 2026-10-04
#: cut). Read from the shared table so every file of the suite agrees.
_JSP = "_json_safe_params"
_RK = "_request_key"


def _g() -> Any:
    return S.golden(GOLDEN)


def _flat_rule(base_name: str) -> tuple[str, str]:
    """`(module relpath, name in that module)` of a flat-tier query rule.

    Each rule is looked up inside `S.FLAT_TIER` under the spelling `S.QUERY_RULE_PUBLIC` gives
    it (its base name: the table is the identity map since the 2026-10-04 cut). Under
    `SPEC1080_AT_BASE` (the authoring self-check, never set in CI) the locator answers with the
    base definition, so the behavioural tests prove their goldens against the base through the
    same assertions."""
    public = S.QUERY_RULE_PUBLIC.get(base_name, base_name)
    if S.AT_BASE and public != base_name:
        try:
            return S.home_of(public, home=S.QUERY_RULES), public
        except AssertionError:
            return S.home_of(base_name), base_name
    return S.home_of(public, home=S.QUERY_RULES), public


def _flat(base_name: str) -> Any:
    home, name = _flat_rule(base_name)
    return getattr(importlib.import_module(S.dotted(home)), name)


#: A golden value whose canonical JSON is longer than this is stored as its digest.
_BIG = 4000


def _summ(value: Any) -> Any:
    """`S.canon(value)`, or its sha256 and length when the encoding is large (a 10 000-char
    segment, a 10 000-key map)."""
    c = S.canon(value)
    text = json.dumps(c, ensure_ascii=False, sort_keys=True)
    if len(text) <= _BIG:
        return c
    return {"sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
            "chars": len(text)}


def _out(fn: Any, *args: Any, **kw: Any) -> dict[str, Any]:
    """`S.outcome`, with a large return value digested by `_summ`."""
    try:
        value = fn(*args, **kw)
    except Exception as e:  # noqa: BLE001 — the exception IS the observed outcome
        return {"raises": type(e).__name__, "message": str(e)}
    return {"returns": _summ(value)}


def _trip(t: Any) -> Any:
    """A guard verdict as a golden value: `None`, or its type and two integers."""
    if t is None:
        return None
    return {"type": type(t).__name__, "first_seq": t.first_seq, "occurrence": t.occurrence}


def awkward_cases() -> dict[str, tuple[Any, Any, Any]]:
    """s167's table: case id -> (system, verb, params). Built fresh per call (mutable values)."""
    tz2 = _dt.timezone(_dt.timedelta(hours=2))
    return {
        "nan": ("elastic", "query", {"x": float("nan")}),
        "inf": ("elastic", "query", {"x": float("inf")}),
        "neg_inf": ("elastic", "query", {"x": float("-inf")}),
        "neg_zero": ("elastic", "query", {"x": -0.0}),
        "pos_zero": ("elastic", "query", {"x": 0.0}),
        "nan_in_list": ("elastic", "query", {"x": [float("nan"), 1, float("-inf")]}),
        "huge_int": ("elastic", "query", {"x": 2**64}),
        "huge_neg_int": ("elastic", "query", {"x": -(10**30)}),
        "int_past_2_53": ("elastic", "query", {"x": 2**53 + 1}),
        "int_one": ("elastic", "query", {"x": 1}),
        "float_one": ("elastic", "query", {"x": 1.0}),
        "bool_true": ("elastic", "query", {"x": True}),
        "bool_false": ("elastic", "query", {"x": False}),
        "bytes": ("elastic", "query", {"x": b"\x00\xffab"}),
        "bytearray": ("elastic", "query", {"x": bytearray(b"ab")}),
        "set_ints": ("elastic", "query", {"x": {3, 1, 2}}),
        "set_mixed": ("elastic", "query", {"x": {1, "1", "a", None}}),
        "frozenset": ("elastic", "query", {"x": frozenset({"b", "a"})}),
        "tuple": ("elastic", "query", {"x": (1, "a", None)}),
        "nested_tuple": ("elastic", "query", {"x": ((1, 2), [3, (4,)])}),
        "date": ("elastic", "query", {"x": _dt.date(2026, 1, 2)}),
        "datetime_naive": ("elastic", "query", {"x": _dt.datetime(2026, 1, 2, 3, 4, 5)}),
        "datetime_aware": ("elastic", "query", {"x": _dt.datetime(2026, 1, 2, 3, 4, 5, 6, tz2)}),
        "time": ("elastic", "query", {"x": _dt.time(1, 2, 3)}),
        "decimal": ("elastic", "query", {"x": Decimal("1.10")}),
        "path_abs": ("elastic", "query", {"x": PurePosixPath("/var/log/x.json")}),
        "path_rel": ("elastic", "query", {"x": Path("rel/x.json")}),
        "int_vs_str_keys": ("elastic", "query", {1: "a", "2": "b"}),
        "colliding_keys_int_first": ("elastic", "query", {1: "int", "1": "str"}),
        "colliding_keys_str_first": ("elastic", "query", {"1": "str", 1: "int"}),
        "odd_keys": ("elastic", "query", {True: 1, None: 2, 1.5: 3, float("nan"): 4,
                                          _dt.date(2026, 1, 2): 5}),
        "order_ab": ("elastic", "query", {"a": 1, "b": 2}),
        "order_ba": ("elastic", "query", {"b": 2, "a": 1}),
        "nested_order": ("elastic", "query", {"z": {"b": 1, "a": 2}, "y": [{"d": 1, "c": 2}]}),
        "unicode_value": ("elastic", "query", {"x": "ü​\u2028"}),
        "lone_surrogate": ("elastic", "query", {"x": "\ud800"}),
        "empty_params": ("elastic", "query", {}),
        "params_none": ("elastic", "query", None),
        "params_list": ("elastic", "query", [1, 2]),
        "params_str": ("elastic", "query", "not-a-map"),
        "system_none": (None, "query", {"x": 1}),
        "system_int": (1, "query", {"x": 1}),
        "verb_none": ("elastic", None, {"x": 1}),
        "verb_int": ("elastic", 2, {"x": 1}),
        "system_verb_non_ascii": ("élastic", "requête", {"q": "ü"}),
        "system_verb_cjk": ("日本", "検索", {"q": "値"}),
        "system_empty": ("", "", {}),
    }


#: The query ids s162-s165 send through the query tool's rule: case id -> (system, verb, id).
QUERY_ID_CASES: dict[str, tuple[str, str, Any]] = {
    # s162 — empty, whitespace, reserved, leading space
    "s162/none": ("elastic", "esql", None),
    "s162/empty": ("elastic", "esql", ""),
    "s162/space": ("elastic", "esql", " "),
    "s162/spaces": ("elastic", "esql", "   "),
    "s162/tab": ("elastic", "esql", "\t"),
    "s162/ideographic_space": ("elastic", "esql", "　"),
    "s162/sentinel_above_guard": ("elastic", "esql", "∅.above-repeat-guard"),
    "s162/sentinel_bash_shim": ("elastic", "esql", "∅.bash-shim"),
    "s162/sentinel_denied": ("elastic", "esql", "∅.denied"),
    "s162/sentinel_repeat_trip": ("elastic", "esql", "∅.repeat-trip"),
    "s162/prefix_plus_text": ("elastic", "esql", "∅.hunt-creds"),
    "s162/prefix_alone": ("elastic", "esql", "∅."),
    "s162/empty_set_no_dot": ("elastic", "esql", "∅hunt"),
    "s162/prefix_mid_id": ("elastic", "esql", "elastic.∅.x"),
    "s162/leading_space": ("elastic", "esql", " elastic.hunt-creds"),
    "s162/space_after_dot": ("elastic", "esql", "elastic. hunt-creds"),
    "s162/well_formed": ("elastic", "esql", "elastic.hunt-creds"),
    "s162/no_verb_fallback": ("elastic", "", "fakesys.hunt"),
    # s163 — forbidden characters and their look-alikes
    "s163/slash": ("elastic", "esql", "elastic.a/b"),
    "s163/backslash": ("elastic", "esql", "elastic.a\\b"),
    "s163/dotdot": ("elastic", "esql", "elastic.a..b"),
    "s163/nul": ("elastic", "esql", "elastic.a\x00b"),
    "s163/newline": ("elastic", "esql", "elastic.a\nb"),
    "s163/cr": ("elastic", "esql", "elastic.a\rb"),
    "s163/hash": ("elastic", "esql", "elastic.a#b"),
    "s163/traversal": ("elastic", "esql", "../elastic.x"),
    "s163/division_slash": ("elastic", "esql", "elastic.a∕b"),
    "s163/fraction_slash": ("elastic", "esql", "elastic.a⁄b"),
    "s163/fullwidth_solidus": ("elastic", "esql", "elastic.a／b"),
    "s163/fullwidth_reverse_solidus": ("elastic", "esql", "elastic.a＼b"),
    "s163/two_dot_leader": ("elastic", "esql", "elastic.a‥b"),
    "s163/fullwidth_full_stops": ("elastic", "esql", "elastic.a．．b"),
    "s163/fullwidth_number_sign": ("elastic", "esql", "elastic.a＃b"),
    "s163/line_separator": ("elastic", "esql", "elastic.a\u2028b"),
    "s163/paragraph_separator": ("elastic", "esql", "elastic.a\u2029b"),
    "s163/next_line": ("elastic", "esql", "elastic.a\x85b"),
    "s163/vertical_tab": ("elastic", "esql", "elastic.a\x0bb"),
    "s163/form_feed": ("elastic", "esql", "elastic.a\x0cb"),
    "s163/zero_width_space": ("elastic", "esql", "elastic.a​b"),
    "s163/nbsp": ("elastic", "esql", "elastic.a\xa0b"),
    # s164 — a prefix that nearly matches the system
    "s164/exact": ("elastic", "esql", "elastic.hunt"),
    "s164/title_case": ("elastic", "esql", "Elastic.hunt"),
    "s164/upper_case": ("elastic", "esql", "ELASTIC.hunt"),
    "s164/fullwidth_letter": ("elastic", "esql", "ｅlastic.hunt"),
    "s164/cyrillic_ie": ("elastic", "esql", "еlastic.hunt"),
    "s164/nfd_vs_nfc_system": ("caf\xe9", "get", "café.hunt"),
    "s164/nfc_matches_nfc_system": ("caf\xe9", "get", "caf\xe9.hunt"),
    "s164/kelvin_sign": ("kafka", "get", "Kafka.hunt"),
    "s164/trailing_dot_no_segment": ("elastic", "esql", "elastic."),
    "s164/no_separator": ("elastic", "esql", "elastic"),
    "s164/double_dot_separator": ("elastic", "esql", "elastic..hunt"),
    "s164/trailing_dot_after_segment": ("elastic", "esql", "elastic.hunt."),
    "s164/extra_segment": ("elastic", "esql", "elastic.foo.bar"),
    "s164/prefix_with_extra_segment": ("elastic", "esql", "elastic.x.hunt"),
    "s164/hyphen_system_underscore_id": ("change-mgmt", "get", "change_mgmt.hunt"),
    "s164/underscore_system_hyphen_id": ("change_mgmt", "get", "change-mgmt.hunt"),
    "s164/hyphen_both": ("change-mgmt", "get", "change-mgmt.hunt"),
    "s164/system_suffix": ("elastic", "esql", "elasticx.hunt"),
    "s164/system_prefix_only": ("elastic", "esql", "elast.hunt"),
    "s164/foreign_system": ("elastic", "esql", "fakesys.hunt-creds"),
    "s164/space_before_dot": ("elastic", "esql", "elastic .hunt"),
    # s165 — segment shapes
    "s165/leading_hyphen": ("elastic", "esql", "elastic.-hunt"),
    "s165/leading_underscore": ("elastic", "esql", "elastic._hunt"),
    "s165/all_digits": ("elastic", "esql", "elastic.123"),
    "s165/trailing_newline": ("elastic", "esql", "elastic.hunt\n"),
    "s165/arabic_indic_digits": ("elastic", "esql", "elastic.١٢٣"),
    "s165/fullwidth_digits": ("elastic", "esql", "elastic.１２"),
    "s165/non_ascii_letter": ("elastic", "esql", "elastic.h\xfcnt"),
    "s165/single_char": ("elastic", "esql", "elastic.x"),
    "s165/single_hyphen": ("elastic", "esql", "elastic.-"),
    "s165/single_digit": ("elastic", "esql", "elastic.7"),
    "s165/upper_segment": ("elastic", "esql", "elastic.Hunt_Creds-2"),
    "s165/inner_space": ("elastic", "esql", "elastic.hunt creds"),
    "s165/ten_thousand": ("elastic", "esql", "elastic." + "a" * 10_000),
    "s165/ten_thousand_plus_hyphen": ("elastic", "esql", "elastic.-" + "a" * 9_999),
}


def nested_params(kind: str, levels: int) -> Any:
    """Params `levels` containers deep, the params map itself counting as one level, the
    innermost container holding the scalar `1`. `kind` is `dict` (maps all the way down),
    `list` (a map over a list nest), `mix` (a map, then list and map alternating) or
    `top_list` (lists all the way, no map at the top)."""
    if kind not in ("dict", "list", "mix", "top_list"):
        raise ValueError(kind)

    def is_list(i: int) -> bool:  # level i, 0 the outermost
        if kind == "top_list":
            return True
        if i == 0 or kind == "dict":
            return False
        return kind == "list" or i % 2 == 1

    v: Any = 1
    for i in reversed(range(levels)):
        v = [v] if is_list(i) else {"k": v}
    return v


def nesting_cases(limit: int) -> dict[str, tuple[Any, dict[str, str]]]:
    """s166's table around `limit`: case id -> (value, keyword args)."""
    out: dict[str, tuple[Any, dict[str, str]]] = {}
    for kind in ("dict", "list", "mix", "top_list"):
        for name, levels in (("under", limit - 1), ("at", limit), ("past", limit + 1)):
            out[f"{kind}/{name}"] = (nested_params(kind, levels), {})
    out["dict/past/named_field"] = (nested_params("dict", limit + 1),
                                    {"field": "discriminator.envelope.params"})
    out["mix/at/named_field"] = (nested_params("mix", limit),
                                 {"field": "discriminator.envelope.params"})
    out["wide_shallow"] = ({f"k{i}": i for i in range(10_000)}, {})
    out["wide_shallow_lists"] = ({f"k{i}": [i, [i]] for i in range(2_000)}, {})
    out["far_past"] = (nested_params("dict", 5 * limit), {})
    out["scalar"] = (7, {})
    return out


def write_calls(append: Any, run: Any, calls: list[dict[str, Any]]) -> list[dict]:
    """Record each call through `append` (the queries-table writer), as a granted query. `run`
    is what the writer takes first: the run's state (`RunState`, #1235)."""
    out = []
    for c in calls:
        text = c["payload_text"]
        out.append(append(
            run, run=_writer_run_1165(run.run_dir), lead_id=c["lead_id"], system=c["system"], verb=c["verb"],
            query_id=c["query_id"], params=c["params"], raw_command=f"{c['system']} {c['verb']}",
            payload_text=text, exit_code=c.get("exit_code", 0),
            payload_status=c.get("payload_status", "ok"),
            payload_digest=c.get("payload_digest", f"{len(text)} bytes, 1 line(s)"),
            system_key=""))
    return out


#: s168's live call: a tuple and an int-keyed map among its params.
def roundtrip_call() -> dict[str, Any]:
    return {"lead_id": "l-1", "system": "elastic", "verb": "query", "query_id": "elastic.hunt",
            "params": {"ids": (3, 1, 2), "by": {1: "a", 2: ("b", 3)}, "plain": "x"},
            "payload_text": json.dumps({"hits": []})}


def drive_roundtrip(state: Any, *, request_key: Any, append: Any,
                    repeat_trip: Any) -> dict[str, Any]:
    """s168: the live key, the row the writer stores, and the keys the learning side computes
    from that row after it is read back from disk (the repository's typed row, the raw record,
    the ledger's join key), plus the guard over the read-back rows with the live params — the
    rows the run's `state` holds, each the written line read back (#1235)."""
    from defender.learning import lead_repository
    from defender.learning.branch import ledger

    c = roundtrip_call()
    run_dir = state.run_dir
    live_key = request_key(c["system"], c["verb"], c["params"])
    written = write_calls(append, state, [c])[0]
    (row,) = lead_repository.load_queries(run_dir)
    raw = json.loads((run_dir / "executed_queries.jsonl").read_text(encoding="utf-8"))
    return {
        "live_key": live_key,
        "stored_params": S.canon(written["params"]),
        "read_back_params": S.canon(row.params),
        "learning_row_key": ledger.request_key(row.system, row.verb, row.params),
        "learning_record_key": ledger.correlation_key_of(row.record()),
        "rule_over_raw_record": request_key(raw["system"], raw["verb"], raw["params"]),
        "guard": _trip(repeat_trip(state.lead_rows(c["lead_id"]), c["lead_id"],
                                   system=c["system"], verb=c["verb"], params=c["params"],
                                   threshold=2)),
    }


def _query_id_verdicts() -> dict[str, dict[str, Any]]:
    pytest.importorskip("pydantic_ai")
    from defender.runtime import query_tool

    resolve = S.moved("resolve_query_id")
    is_reserved = _flat("is_reserved_query_id")
    assert query_tool.resolve_query_id is resolve, (
        "the query tool must apply the one moved rule, not a copy")
    screen = query_tool.QueryCapture(None)
    out = {}
    for case, (system, verb, qid) in QUERY_ID_CASES.items():
        out[case] = {
            "reject": _summ(screen._forbidden_reject(qid)),
            "recorded": _out(resolve, system, verb, qid),
            "reserved": None if qid is None else is_reserved(qid),
        }
    return out


def _assert_query_ids(group: str) -> None:
    g = _g()["query_ids"]
    got = _query_id_verdicts()
    cases = [c for c in QUERY_ID_CASES if c.startswith(group + "/")]
    assert cases
    for case in cases:
        assert got[case] == g[case], case


def test_model_query_id_empty_or_reserved():
    _assert_query_ids("s162")


def test_model_query_id_with_forbidden_characters_and_lookalikes():
    _assert_query_ids("s163")


def test_params_nested_exactly_at_the_depth_limit():
    g = _g()
    limit = _flat("PARAMS_NESTING_LIMIT")
    assert limit == g["constants"]["PARAMS_NESTING_LIMIT"]
    normalise, fault = _flat(_JSP), _flat("ParamsTooDeep")
    for case, (value, kw) in nesting_cases(limit).items():
        assert _out(normalise, value, **kw) == g["nesting"][case], case
    with pytest.raises(fault) as raised:
        normalise(nested_params("mix", limit + 1), field="the call's arguments")
    assert raised.value.field == "the call's arguments"


def test_params_values_of_every_awkward_kind():
    g = _g()["awkward"]
    normalise, request_key = _flat(_JSP), _flat(_RK)
    for case, (system, verb, params) in awkward_cases().items():
        assert _out(normalise, params) == g[case]["safe"], case
        assert _out(request_key, system, verb, params) == g[case]["key"], case


def test_same_call_live_and_after_the_row_is_read_back(tmp_path):
    g = _g()["roundtrip"]
    request_key = _flat(_RK)
    rq = S.module_at("defender/runtime/record_query.py")
    # Never driven: the writer takes the run's state, started as a run's start starts it (#1235).
    from defender.runtime.run_state import RunState

    (tmp_path / "run").mkdir()
    got = drive_roundtrip(RunState(tmp_path / "run", "r1080-roundtrip"),
                          request_key=request_key, append=rq.append_query_row,
                          repeat_trip=rq.repeat_trip)
    assert got["live_key"] == got["learning_row_key"] == got["learning_record_key"] \
        == got["rule_over_raw_record"]
    assert got["guard"] == {"type": "RepeatTrip", "first_seq": 0, "occurrence": 2}
    assert got == g
