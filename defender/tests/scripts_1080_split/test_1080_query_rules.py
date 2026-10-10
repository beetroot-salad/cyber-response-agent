"""#1080 group `queryrules` — the query-id / request-key rules leave `record_query`.

`defender/scripts/gather_tools/record_query.py` holds, at base 80888efb, the rules every
queries-table reader and writer must agree on: the request key (`_request_key`), the params
normaliser and its nesting bound (`_json_safe_params`, `PARAMS_NESTING_LIMIT`, `ParamsTooDeep`),
the reserved `∅.` query ids and their prefix test, the query-id screen (`resolve_query_id`), the
argv-to-system rule (`derive_system`, `_ADAPTER_RE`) and the payload-operand-to-system rule. The
move sends the request-key and query-id rules to the flat `defender/_*.py` tier under their
BASE names (values byte-identical, because request keys are persisted); `record_query` keeps
everything else and imports the rules from there.

SCOPE CUT (2026-10-04, human): dF11's public rename, `derive_system`'s move to
`runtime/verbs.py` and the guards' and writers' moves are parked (#1165, #1172), with their tests
(`spec-flow/specs/parked/1080/parked_query_rules.py`). `S.QUERY_RULE_PUBLIC` is the identity map;
every lookup of a rule goes through `_flat_rule`, which reads that table, so a later rename is
made there, never here. The guard and the writers are reached at `record_query`'s staying path
(`S.module_at`, E5).

Every "as today" expectation is `goldens/queryrules.json`, captured at the base by running
`record_query` (and the unmoved learning / runtime readers) over the input tables and fixture
builders defined at module level below — the same builders the tests drive, so the input is
written once. Fixture runs written "before the move" are frozen in the golden as the exact
bytes the base writer produced; a test materialises them into `tmp_path` and drives the moved
code over them. The tmp root never appears in a golden: outputs are system names, keys, row
columns (run-relative paths only) and verdicts.

Underscore helpers here are private to this file; the shared machinery is `_spec1080`.
"""
from __future__ import annotations

import ast
import datetime as _dt
import hashlib
import importlib
import json
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "queryrules"

#: The two flat-tier rules `S.QUERY_RULE_PUBLIC` spells (the identity map since the 2026-10-04
#: cut). Read from the shared table so every file of the suite agrees.
_JSP = "_json_safe_params"
_RK = "_request_key"

#: The flat-tier names t_query_rules_in_flat_tier pins, as the base spells them.
_FLAT_RULES = (
    _JSP, _RK, "is_reserved_query_id",
    "ABOVE_GUARD_QUERY_ID", "BASH_SHIM_QUERY_ID", "DENIED_QUERY_ID", "REPEAT_TRIP_QUERY_ID",
)
_RESERVED_IDS = ("ABOVE_GUARD_QUERY_ID", "BASH_SHIM_QUERY_ID", "DENIED_QUERY_ID",
                 "REPEAT_TRIP_QUERY_ID")


def _g() -> Any:
    return S.golden(GOLDEN)


# ======================================================================================
# Locating the moved rules
# ======================================================================================


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
            return S.home_of(public, home=S.FLAT_TIER), public
        except AssertionError:
            return S.home_of(base_name), base_name
    return S.home_of(public, home=S.FLAT_TIER), public


def _flat(base_name: str) -> Any:
    home, name = _flat_rule(base_name)
    return getattr(importlib.import_module(S.dotted(home)), name)


# ======================================================================================
# Shared encoders (capture and test both go through these)
# ======================================================================================

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


def _snapshot(run_dir: Path) -> dict[str, str]:
    """Every regular file under `run_dir`, run-relative POSIX path -> text."""
    return {p.relative_to(run_dir).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted(run_dir.rglob("*")) if p.is_file() and not p.is_symlink()}


def _materialize(run_dir: Path, files: dict[str, str]) -> Path:
    """Write a frozen run (`_snapshot`'s shape) under `run_dir`, byte for byte."""
    for relpath, text in files.items():
        p = run_dir / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
    return run_dir


# ======================================================================================
# Input tables
# ======================================================================================


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

#: Ids s087 runs the reserved-prefix test over: case id -> id.
RESERVED_PROBES: dict[str, str] = {
    "above_guard": "∅.above-repeat-guard",
    "bash_shim": "∅.bash-shim",
    "denied": "∅.denied",
    "repeat_trip": "∅.repeat-trip",
    "unknown_sentinel": "∅.future-kind",
    "prefix_alone": "∅.",
    "empty_set_alone": "∅",
    "no_dot": "∅bash-shim",
    "mid_id": "elastic.∅.x",
    "leading_space": " ∅.denied",
    "latin_o_stroke": "\xd8.denied",
    "diameter_sign": "⌀.denied",
    "near_miss_system_id": "elastic.bash-shim",
    "empty": "",
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


# ======================================================================================
# Fixture builders (capture and test both drive these)
# ======================================================================================


#: s086's earlier run: the calls the base writer recorded, (lead, system, verb, query id,
#: params, payload text). Their live params are rebuilt per call (`stored_call_params`).
def stored_calls() -> list[dict[str, Any]]:
    return [
        {"lead_id": "l-1", "system": "elastic", "verb": "query", "query_id": "elastic.hunt",
         "params": {"index": "logs-*", "size": 10, "ids": (1, 2), "by": {1: "a", "2": "b"}},
         "payload_text": json.dumps({"hits": [{"host": "h1", "n": 1}]})},
        {"lead_id": "l-1", "system": "cmdb", "verb": "get-host", "query_id": "cmdb.get-host",
         "params": {"host": "canary-1", "threshold": float("inf"), "zero": -0.0,
                    "since": _dt.date(2026, 1, 2)},
         "payload_text": json.dumps({"owner": "estate", "role": "canary"})},
        {"lead_id": "l-2", "system": "elastic", "verb": "esql", "query_id": "elastic.esql",
         "params": {"z": {"b": 1, "a": 2}, "tags": {"y", "x"}, "nan": float("nan")},
         "payload_text": json.dumps({"columns": [{"name": "a"}], "values": [[1]]})},
        {"lead_id": "l-2", "system": "identity", "verb": "user", "query_id": "identity.user",
         "params": {"user": "\xfc​", "flags": [True, 1, 1.0]},
         "payload_text": json.dumps({"user": "u"})},
    ]


def write_calls(append: Any, run_dir: Path, calls: list[dict[str, Any]]) -> list[dict]:
    """Record each call through `append` (the queries-table writer), as a granted query."""
    out = []
    for c in calls:
        text = c["payload_text"]
        out.append(append(
            run_dir, lead_id=c["lead_id"], system=c["system"], verb=c["verb"],
            query_id=c["query_id"], params=c["params"], raw_command=f"{c['system']} {c['verb']}",
            payload_text=text, exit_code=c.get("exit_code", 0),
            payload_status=c.get("payload_status", "ok"),
            payload_digest=c.get("payload_digest", f"{len(text)} bytes, 1 line(s)"),
            system_key=""))
    return out


#: s087's earlier run: rows carrying each reserved id, with the exit code its writer uses.
def reserved_calls() -> list[dict[str, Any]]:
    def call(lead: str, system: str, verb: str, qid: str, rc: int, **kw: Any) -> dict:
        ok = rc == 0
        return {"lead_id": lead, "system": system, "verb": verb, "query_id": qid,
                "params": kw.pop("params", {"q": "x"}),
                "payload_text": json.dumps({"hits": []}) if ok else "", "exit_code": rc,
                "payload_status": "ok" if ok else "error",
                "payload_digest": "13 bytes, 1 line(s)" if ok else f"exit={rc}; refused", **kw}
    return [
        call("l-1", "elastic", "query", "elastic.query", 0),
        call("l-1", "elastic", "query", "∅.above-repeat-guard", 64),
        call("l-1", "elastic", "query", "∅.above-repeat-guard", 2),
        call("l-1", "ticket", "get-ticket", "∅.denied", 77),
        call("l-1", "elastic", "query", "∅.repeat-trip", 64),
        call("l-1", "", "bash", "∅.bash-shim", 1, params={"command": "defender-sql 'x'"}),
        call("l-1", "elastic", "query", "elastic.bash-shim", 1),
        call("l-1", "elastic", "query", "∅.future-kind", 64),
        call("l-1", "elastic", "query", "∅bash-shim", 1),
        call("l-2", "ticket", "get-ticket", "∅.denied", 77),
        call("l-3", "cmdb", "get-host", "∅.bash-shim", 1),
    ]


def classify_reserved(run_dir: Path) -> dict[str, Any]:
    """Learning's classification of every row of `run_dir`: the repository's query/sentinel
    split, the judge's refused entries, the pitfall lane's reducer test and the extractor's
    reducer-failure test — the unmoved readers of the reserved ids."""
    from defender.learning import lead_repository
    from defender.learning.core import persist
    from defender.learning.judge import family
    from defender.learning.leads import lead_extraction

    joined = lead_repository.joined(run_dir)
    leads = []
    for jl in joined:
        entries = family.refused_entries(jl)
        leads.append({
            "lead_id": jl.lead_id, "orphan": jl.orphan,
            "queries": [[q.seq, q.query_id] for q in jl.queries],
            "sentinels": [[q.seq, q.query_id] for q in jl.sentinels],
            "refused": S.canon(entries), "rendered": family.render_refused(entries),
            "rows": [{"seq": q.seq, "query_id": q.query_id, "is_sentinel": q.is_sentinel,
                      "error_class": q.error_class,
                      "is_reducer_row": persist.is_reducer_row(q.record()),
                      "pitfall_owner": persist.pitfall_key(q.record())[0]} for q in jl.rows],
        })
    extracted = [[e.lead_id, e.query_index, e.query_id, e.is_sentinel,
                  lead_extraction._is_reducer_failure(e)]
                 for e in lead_extraction.extract_from_joined(joined)]
    return {"leads": leads, "extracted": extracted}


def drive_stored_run(run_dir: Path, episode_dir: Path, *, request_key: Any, lead_rows: Any,
                     repeat_trip: Any, append: Any) -> dict[str, Any]:
    """s086 over a materialised earlier run: today's key per stored call, the repeat guard's
    verdict over the stored rows, learning's ledger replaying the run (prime the family base
    from the run's capture, then serve each live call from it), and the run resumed — one more
    identical call recorded into the stored table, then the guard's default verdict."""
    from defender._episode_handle import Episode
    from defender.learning.branch import capture, ledger

    calls = stored_calls()
    keys = [request_key(c["system"], c["verb"], c["params"]) for c in calls]
    guard = [_trip(repeat_trip(lead_rows(run_dir, c["lead_id"]), c["lead_id"],
                               system=c["system"], verb=c["verb"], params=c["params"],
                               threshold=2)) for c in calls]
    stored_rows = [json.loads(line) for line in
                   (run_dir / "executed_queries.jsonl").read_text(encoding="utf-8").splitlines()]
    with Episode.create(episode_dir) as episode:
        report = capture.prime_base(run_dir, episode)
        world = ledger.Ledger.for_world(episode, "w-1")
        served = [world.base_payload(c["system"], c["verb"], c["params"]) for c in calls]
    ledger_keys = [ledger.request_key(c["system"], c["verb"], c["params"]) for c in calls]
    row_keys = [ledger.correlation_key_of(r) for r in stored_rows]
    first = calls[0]
    resumed = write_calls(append, run_dir, [first])[0]
    resumed_trip = _trip(repeat_trip(lead_rows(run_dir, first["lead_id"]), first["lead_id"],
                                     system=first["system"], verb=first["verb"],
                                     params=first["params"]))
    return {
        "keys": keys, "guard_threshold_2": guard,
        "prime": {"primed": report.primed, "duplicates": report.duplicates,
                  "failed": report.failed, "sentinels": report.sentinels,
                  "unreadable": report.unreadable},
        "served": served, "ledger_keys": ledger_keys, "row_keys": row_keys,
        "resumed_row": S.canon(resumed), "resumed_trip": resumed_trip,
    }


#: s168's live call: a tuple and an int-keyed map among its params.
def roundtrip_call() -> dict[str, Any]:
    return {"lead_id": "l-1", "system": "elastic", "verb": "query", "query_id": "elastic.hunt",
            "params": {"ids": (3, 1, 2), "by": {1: "a", 2: ("b", 3)}, "plain": "x"},
            "payload_text": json.dumps({"hits": []})}


def drive_roundtrip(run_dir: Path, *, request_key: Any, append: Any, lead_rows: Any,
                    repeat_trip: Any) -> dict[str, Any]:
    """s168: the live key, the row the writer stores, and the keys the learning side computes
    from that row after it is read back from disk (the repository's typed row, the raw record,
    the ledger's join key), plus the guard over the read-back rows with the live params."""
    from defender.learning import lead_repository
    from defender.learning.branch import ledger

    c = roundtrip_call()
    live_key = request_key(c["system"], c["verb"], c["params"])
    written = write_calls(append, run_dir, [c])[0]
    (row,) = lead_repository.load_queries(run_dir)
    raw = json.loads((run_dir / "executed_queries.jsonl").read_text(encoding="utf-8"))
    return {
        "live_key": live_key,
        "stored_params": S.canon(written["params"]),
        "read_back_params": S.canon(row.params),
        "learning_row_key": ledger.request_key(row.system, row.verb, row.params),
        "learning_record_key": ledger.correlation_key_of(row.record()),
        "rule_over_raw_record": request_key(raw["system"], raw["verb"], raw["params"]),
        "guard": _trip(repeat_trip(lead_rows(run_dir, c["lead_id"]), c["lead_id"],
                                   system=c["system"], verb=c["verb"], params=c["params"],
                                   threshold=2)),
    }


# ======================================================================================
# The census helper (t_query_rules_in_flat_tier, s085, s087)
# ======================================================================================


def _names_taken_from(importer_rel: str, home_rel: str, root: Path = S.REPO_ROOT) -> set[str]:
    """The names `importer_rel` takes from the module at `home_rel`: every name a
    `from <home> import …` binds, plus — when it imports the home module itself
    (`import defender._x`, `from defender import _x`) — every attribute name it reads."""
    src = (root / importer_rel).read_bytes()
    home_mod = S.dotted(home_rel)
    pkg, _, leaf = home_mod.rpartition(".")
    names: set[str] = set()
    module_imported = False
    for st in S.import_statements(importer_rel, src):
        if st.module == home_mod:  # lint-ast-resolve: ok — a static census over a fixed module's own source; its import spellings are the observation
            if st.names:
                names.update(st.names)
            else:
                module_imported = True
        elif st.module == pkg and leaf in st.names:  # lint-ast-resolve: ok — a static census over a fixed module's own source; its import spellings are the observation
            module_imported = True
    if module_imported:
        names.update(n.attr for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Attribute))
    return names


#: Who takes which flat-tier rule today (claims P8 / G13 / F31): importer -> base names. Pure
#: re-exports are left out (query_tool's `_json_safe_params`, kept for a test's import).
_IMPORTERS: dict[str, tuple[str, ...]] = {
    "defender/learning/branch/ledger.py": (_JSP, _RK),
    "defender/learning/branch/estate/registry.py": (_JSP,),
    "defender/learning/judge/family.py": _RESERVED_IDS,
    "defender/learning/core/persist.py": ("BASH_SHIM_QUERY_ID",),
    "defender/learning/leads/lead_extraction.py": ("BASH_SHIM_QUERY_ID",),
    "defender/learning/lead_repository.py": ("is_reserved_query_id",),
    "defender/runtime/branch/__init__.py": ("is_reserved_query_id",),
    "defender/runtime/query_tool.py": ("ABOVE_GUARD_QUERY_ID", "DENIED_QUERY_ID",
                                       "REPEAT_TRIP_QUERY_ID"),
    "defender/runtime/tools/_bash.py": ("BASH_SHIM_QUERY_ID",),
}


def _census_misses(importers: dict[str, tuple[str, ...]]) -> list[str]:
    misses = []
    for importer, base_names in importers.items():
        for base_name in base_names:
            home, name = _flat_rule(base_name)
            if name not in _names_taken_from(importer, home):
                misses.append(f"{importer} does not take `{name}` from {home}")
    return misses


# ======================================================================================
# The tests
# ======================================================================================


def test_1080_query_id_and_request_key_rules_live_in_the_flat_tier_with_todays_values():
    """The request-key and query-id rules are defined in a flat-tier `defender/_*.py` module:
    `_json_safe_params`, `_request_key`, `is_reserved_query_id` and the reserved ids
    `ABOVE_GUARD_QUERY_ID`, `BASH_SHIM_QUERY_ID`, `DENIED_QUERY_ID` and `REPEAT_TRIP_QUERY_ID`.
    Their importers in learning and runtime take them from there. The request key for a fixed
    (system, verb, params) table is byte-identical to the base's, because request keys are
    persisted.

    Every rule keeps its base name (the 2026-10-04 scope cut parks dF11's public rename with
    #1165; `S.QUERY_RULE_PUBLIC` is the identity map). The values come first (the reserved strings and the key table against the base golden), then
    the census: each importer the ledger (P8, G13) names imports the rule from the one flat-tier
    home, by name or through the home module."""
    g = _g()
    for n in _FLAT_RULES:
        _flat_rule(n)  # one flat-tier definition each (fails naming the symbol otherwise)
    for n in _RESERVED_IDS:
        assert _flat(n) == g["constants"][n], n
    is_reserved = _flat("is_reserved_query_id")
    assert [is_reserved(v) for v in RESERVED_PROBES.values()] == \
        [g["reserved_probe"][k] for k in RESERVED_PROBES]

    request_key = _flat(_RK)
    for case, (system, verb, params) in awkward_cases().items():
        got = _out(request_key, system, verb, params)
        assert got == g["awkward"][case]["key"], case
        if "returns" in got:  # byte-identical, not merely equal as text
            assert got["returns"].encode("utf-8", "surrogatepass") == \
                g["awkward"][case]["key"]["returns"].encode("utf-8", "surrogatepass"), case

    misses = _census_misses(_IMPORTERS)
    assert not misses, "\n".join(misses)


def test_query_rules_are_imported_by_learning_and_runtime_under_the_private_names():
    """The request-key and params-normalising rules are defined once, under their base names
    (`_json_safe_params`, `_request_key`), in the flat tier; the repeat guard, the ledger, the
    estate registry all import that one definition, and no local copy exists — none is left in
    `record_query`. (10-03 flat-tier placement; F30. dF11's public rename is parked with #1165
    by the 2026-10-04 scope cut. The branch family's envelope normaliser went with the
    envelope, #1224.)

    Structural: each rule, spelled as `S.QUERY_RULE_PUBLIC` gives it (the identity map), has
    exactly one definition in the whole tree (`defender/scripts/` included), and it is in the
    flat tier; the ledger, the estate registry and the module holding the repeat guard — `record_query`, which stays, reached at its staying path (E5) — take the
    rule from that home."""
    guard = "defender/scripts/gather_tools/record_query.py"
    S.module_at(guard)
    assert guard in S.definitions("repeat_trip"), "the repeat guard left record_query"
    homes = {}
    for base_name, name in S.QUERY_RULE_PUBLIC.items():
        home = S.home_of(name, home=S.FLAT_TIER)
        homes[base_name] = home
        assert S.definitions(name) == (home,), (
            f"`{name}` is defined at {list(S.definitions(name))}: one definition, in the flat "
            f"tier, and no local copy left in {guard}")

    importers = {
        "defender/learning/branch/ledger.py": (_JSP, _RK),
        "defender/learning/branch/estate/registry.py": (_JSP,),
        guard: (_RK,),
    }
    misses = _census_misses(importers)
    assert not misses, "\n".join(misses)


def test_request_keys_stored_before_the_move_are_compared_with_keys_computed_after_it(tmp_path):
    """The request key for a given request is byte-identical before and after the move, so a
    key stored in an earlier run compares equal to the key computed today by the repeat guard
    and by learning's ledger replaying that run, and a run resumed across the move behaves the
    same. The move changes the rule's module, not its output (O5; F30).

    The earlier run is the golden's frozen `stored_run`: the queries table, payload sidecars and
    lead claims the base writer produced for `stored_calls()`, with the keys the base computed
    for those calls. Today's rule must reproduce each stored key byte for byte; the guard,
    reading the stored rows, must find each live call's row; learning's ledger, priming a family
    base from that run and serving each live call from it, must hit every stored answer; and one
    more identical call recorded by the writer must continue the stored table's seq and trip the
    guard on the pre-move row. The guard and the writer stay in `record_query` under the
    2026-10-04 scope cut, so they are reached at its staying path (E5)."""
    g = _g()["stored_run"]
    request_key = _flat(_RK)
    rq = S.module_at("defender/scripts/gather_tools/record_query.py")
    lead_rows, repeat_trip = rq.lead_rows, rq.repeat_trip
    append = rq.append_query_row
    for call, stored in zip(stored_calls(), g["keys"], strict=True):
        assert request_key(call["system"], call["verb"], call["params"]) == stored, call

    run_dir = _materialize(tmp_path / "run", g["files"])
    (tmp_path / "episodes").mkdir()
    got = drive_stored_run(run_dir, tmp_path / "episodes" / "ep-1", request_key=request_key,
                           lead_rows=lead_rows, repeat_trip=repeat_trip, append=append)
    assert got["keys"] == g["keys"]
    assert got["ledger_keys"] == g["keys"]
    assert got["row_keys"] == g["keys"]
    assert all(s is not None for s in got["served"]), "the ledger missed a stored answer"
    assert got == g["replay"]


def test_reserved_query_ids_are_read_by_learning_from_rows_written_before_the_move(tmp_path):
    """Learning classifies each pre-move row carrying the shim, guard-trip or denied reserved
    ids exactly as before, row by row, reading the constants and the prefix test from the flat
    tier: the reserved id strings and the prefix are unchanged. (F31.)

    The pre-move rows are the golden's frozen `reserved_run` (written by the base writer for
    `reserved_calls()`: each reserved id, an unknown `∅.` id, a near-miss `elastic.bash-shim`, a
    dotless `∅bash-shim`, an ordinary row, and a sentinel-only lead). The classification is
    learning's own — the repository's split, the judge's refused entries and rendering, the
    pitfall lane's reducer test, the extractor's reducer-failure test — compared with the base
    golden row by row; the constants and the prefix test are the flat-tier ones, the prefix
    test is the very function the repository calls, and each reader takes its constant from the
    flat-tier home."""
    g = _g()
    for n in _RESERVED_IDS:
        assert _flat(n) == g["constants"][n], n
    assert _flat("RESERVED_QUERY_ID_PREFIX") == g["constants"]["RESERVED_QUERY_ID_PREFIX"]
    is_reserved = _flat("is_reserved_query_id")
    for case, value in RESERVED_PROBES.items():
        assert is_reserved(value) == g["reserved_probe"][case], case

    from defender.learning import lead_repository

    assert getattr(lead_repository, "is_reserved_query_id", is_reserved) is is_reserved
    misses = _census_misses({
        "defender/learning/lead_repository.py": ("is_reserved_query_id",),
        "defender/learning/core/persist.py": ("BASH_SHIM_QUERY_ID",),
        "defender/learning/leads/lead_extraction.py": ("BASH_SHIM_QUERY_ID",),
        "defender/learning/judge/family.py": _RESERVED_IDS,
    })
    assert not misses, "\n".join(misses)

    run_dir = _materialize(tmp_path / "run", g["reserved_run"]["files"])
    got = classify_reserved(run_dir)
    assert got == g["reserved_run"]["classified"]
    sentinel_ids = {qid for lead in got["leads"] for _, qid in lead["sentinels"]}
    assert {g["constants"][n] for n in _RESERVED_IDS} <= sentinel_ids  # every id was classified


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
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). An empty, whitespace-only, reserved-sentinel or
    reserved-prefix- plus-text query id, or one with a leading space, is accepted or rejected
    exactly as today by the same rule.

    The query tool's rule is the pair it applies: its forbidden-character screen (the refusal
    text, or none) and the moved `resolve_query_id` (the id the row is recorded under — the
    model's own when accepted, the `{system}.{verb}` fallback when not), plus the reserved-prefix
    test; each is compared with the base golden per id, and the query tool must hold the moved
    rule itself, not a copy."""
    _assert_query_ids("s162")


def test_model_query_id_with_forbidden_characters_and_lookalikes():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Query ids with a slash, backslash, `..`, NUL, newline, CR,
    `#` and the Unicode look-alikes are rejected or accepted exactly as today by the same rule.

    Observed as in s162: the screen's refusal text and the recorded id, per id, against the
    base golden."""
    _assert_query_ids("s163")


def test_model_query_id_prefix_that_nearly_matches_the_system():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A query-id prefix that nearly matches the system (case,
    normalization, trailing dot, extra segment, hyphen versus underscore) is judged as today by
    the same rule (probe PO5).

    Observed as in s162. The exact-match row is the positive control: a well-formed id on its own
    system is kept verbatim, so the near misses are refused by the rule, not by everything."""
    _assert_query_ids("s164")
    assert _g()["query_ids"]["s164/exact"]["recorded"] == {"returns": "elastic.hunt"}


def test_model_query_id_segment_shapes():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Segments starting with a hyphen, all digits, with a
    trailing newline, non-ASCII digits, a single character or ten thousand characters are
    accepted or rejected as today.

    Observed as in s162; a recorded id of ten thousand characters is compared by digest."""
    _assert_query_ids("s165")


def test_params_nested_exactly_at_the_depth_limit():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Params nested one level under, exactly at and one past the
    nesting limit pass or raise the nesting fault as today, as dicts, lists and mixes; a wide
    shallow map passes. The limit's value is unchanged.

    The limit, the fault class and the normaliser are the flat-tier ones ([26]: the fault and
    its limit travel with the normaliser). Each case's outcome — the normalised value, or the
    fault's class and sentence naming the field — is the base golden; the fault raised is an
    instance of the flat-tier class and carries the field."""
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
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). NaN, infinity, negative zero, huge integers,
    `1`/`1.0`/`True`, bytes, sets, tuples, dates, paths, int-versus-str dict keys, insertion
    order and None/int/non- ASCII system and verb values render to the same safe params and the
    same request key as before.

    Both outcomes per row of `awkward_cases()` against the base golden, through `S.canon`, so a
    tuple turning into a list, `1` into `1.0` or a key's type changing is a difference."""
    g = _g()["awkward"]
    normalise, request_key = _flat(_JSP), _flat(_RK)
    for case, (system, verb, params) in awkward_cases().items():
        assert _out(normalise, params) == g[case]["safe"], case
        assert _out(request_key, system, verb, params) == g[case]["key"], case


def test_same_call_live_and_after_the_row_is_read_back(tmp_path):
    """A call's params with a tuple and an int-keyed dict give the same request key live as the
    learning side computes from the stored row after a JSON round trip, as today. The key rule
    is identical before and after the move (F30).

    The call is recorded by the writer into a real queries table in `tmp_path`, read back by
    learning's repository, and keyed by the ledger from the typed row and from the raw record;
    the live key, every read-back key and the guard over the read-back rows agree, and the whole
    record equals the base golden. The writer and the guard stay in `record_query` under the
    2026-10-04 scope cut, so they are reached at its staying path (E5)."""
    g = _g()["roundtrip"]
    request_key = _flat(_RK)
    rq = S.module_at("defender/scripts/gather_tools/record_query.py")
    got = drive_roundtrip(tmp_path / "run", request_key=request_key,
                          append=rq.append_query_row, lead_rows=rq.lead_rows,
                          repeat_trip=rq.repeat_trip)
    assert got["live_key"] == got["learning_row_key"] == got["learning_record_key"] \
        == got["rule_over_raw_record"]
    assert got["guard"] == {"type": "RepeatTrip", "first_seq": 0, "occurrence": 2}
    assert got == g
