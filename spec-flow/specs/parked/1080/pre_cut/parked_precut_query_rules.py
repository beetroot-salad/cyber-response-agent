# PRE-CUT COPY 2026-10-04 (scope cut of #1080, human-decided; 94-reconciliation-cut.md F-2): preserved, NOT collected.
# This is defender/tests/scripts_1080_split/test_1080_query_rules.py as it stood before the cut, copied verbatim
# from the cut author's scratch backup; the only additions are these `#` comment lines. It keeps
# the cells the cut removed from KEPT tests: the OUT halves of narrowed tests, and the tables and
# helpers the cut narrowed or deleted. Each such node carries a `# PRE-CUT …` marker naming the
# issue(s) that own its cut cells; an owner adopts those cells when its module moves. Nodes without
# a marker are unchanged in the live suite, or were parked whole (their canonical copy is
# ../parked_query_rules.py, annotated with their owners). The file name does not match test_*.py, so pytest never
# collects it. It imports the LIVE helper modules; their pre-cut versions are
# parked_precut__spec1080.py and parked_precut__census1080.py beside this file (_pointers1080.py did
# not change). The goldens it reads are split between the suite's goldens/ and ../goldens/. Each
# narrowed kept demand's `parked_cells` block in spec-flow/specs/spec_graph_1080-scripts-split.yaml
# points at its pre-cut function here.
"""#1080 group `queryrules` — the query-id / request-key rules leave `record_query`.

`defender/scripts/gather_tools/record_query.py` holds, at base 80888efb, the rules every
queries-table reader and writer must agree on: the request key (`_request_key`), the params
normaliser and its nesting bound (`_json_safe_params`, `PARAMS_NESTING_LIMIT`, `ParamsTooDeep`),
the reserved `∅.` query ids and their prefix test, the query-id screen (`resolve_query_id`), the
argv-to-system rule (`derive_system`, `_ADAPTER_RE`) and the payload-operand-to-system rule. The
move sends the request-key and query-id rules to the flat `defender/_*.py` tier under PUBLIC
names (dF11, auto: values byte-identical, because request keys are persisted), `derive_system`
to `runtime/verbs.py` (pinned by demand text), and the rest wherever the symbol lands (dF0).

The public spellings dF11 asks for are coined ONCE, in `S.QUERY_RULE_PUBLIC`; every lookup of a
renamed rule goes through `_flat_rule`, which reads that table. Rename there, never here.

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

#: The renamed flat-tier rules, base spelling -> the coined public spelling (dF11). Read from
#: the shared table so every file of the suite agrees; see `_spec1080.QUERY_RULE_PUBLIC`.
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


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1165 (dF11's public rename).
def _flat_rule(base_name: str) -> tuple[str, str]:
    """`(module relpath, name in that module)` of a flat-tier query rule.

    The renamed rules are looked up under their coined public spelling (`S.QUERY_RULE_PUBLIC`)
    inside `S.FLAT_TIER`; the others under their own name. Under `SPEC1080_AT_BASE` (the
    authoring self-check, never set in CI) a renamed rule that has no public definition falls
    back to its base definition under its base spelling, so the behavioural tests can prove
    their goldens against the base through the same assertions."""
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

#: argv lists derive_system is asked about (t_derive_system_in_verbs, s029).
ARGVS: dict[str, list[str]] = {
    "shim": ["defender-elastic", "query", "x"],
    "shim_hyphenated": ["defender-change-mgmt", "get"],
    "shim_underscore": ["defender-change_mgmt", "get"],
    "shim_upper": ["defender-Elastic", "query"],
    "shim_empty_name": ["defender-", "query"],
    "shim_sql": ["defender-sql", "SELECT 1"],
    "shim_lessons": ["defender-lessons", "--tags"],
    "shim_invlang": ["defender-invlang", "check"],
    "shim_policy": ["defender-policy", "show"],
    "shim_with_slash": ["defender-elastic/x", "query"],
    "shim_with_equals": ["defender-a=b", "query"],
    "shim_then_adapter": ["defender-invlang", "/x/cmdb_adapter.py"],
    "abs_path": ["/opt/defender/scripts/adapters/elastic_adapter.py", "query"],
    "rel_path": ["scripts/adapters/elastic_adapter.py", "query"],
    "dot_slash": ["./elastic_adapter.py", "query"],
    "bare_file": ["elastic_adapter.py", "query"],
    "python3_path": ["python3", "scripts/adapters/change_mgmt_adapter.py", "get"],
    "python_path": ["python", "/x/cmdb_adapter.py"],
    "env_prefix_then_shim": ["FOO=bar", "defender-elastic", "query"],
    "env_prefix_naming_adapter": ["X=/a/elastic_adapter.py", "cat"],
    "env_prefix_naming_shim": ["X=defender-elastic", "cat"],
    "hyphen_stem": ["/x/change-mgmt_adapter.py"],
    "underscore_stem": ["/x/change_mgmt_adapter.py"],
    "upper_stem": ["/x/Elastic_adapter.py"],
    "upper_suffix": ["/x/elastic_ADAPTER.py"],
    "empty_stem": ["/x/_adapter.py"],
    "underscore_only_stem": ["/x/__adapter.py"],
    "bak_suffix": ["/x/elastic_adapter.py.bak"],
    "trailing_slash": ["/x/elastic_adapter.py/"],
    "trailing_newline": ["/x/elastic_adapter.py\n"],
    "invlang_adapter_file": ["/x/invlang_adapter.py"],
    "non_ascii_stem": ["/x/\xe9lastic_adapter.py"],
    "module_form": ["python3", "-m", "defender.scripts.adapters.elastic_adapter"],
    "sh_c_string": ["sh", "-c", "defender-elastic query"],
    "cat": ["cat", "/run/gather_raw/l-1/0.json"],
    "jq": ["jq", ".hits"],
    "ls": ["ls"],
    "empty_argv": [],
}

#: Adapter file names the registry's own rule in `runtime/verbs.py` maps to system names (the
#: second adapter-filename rule in that module, s029).
REGISTRY_FILENAMES: dict[str, str] = {
    "plain": "elastic_adapter.py",
    "underscore": "change_mgmt_adapter.py",
    "hyphen": "change-mgmt_adapter.py",
    "upper": "Elastic_adapter.py",
    "empty_stem": "_adapter.py",
    "underscore_only": "__adapter.py",
}

#: Bash commands whose permission decision carries the hook pattern's refusal wording (s029).
HOOK_COMMANDS: dict[str, str] = {
    "python3_rel_adapter": "python3 defender/scripts/adapters/elastic_adapter.py query",
    "bare_rel_adapter": "defender/scripts/adapters/elastic_adapter.py query",
    "abs_adapter": "python3 /opt/defender/scripts/adapters/cmdb_adapter.py get",
    "shim": "defender-elastic query x",
    "adapter_outside_scripts_adapters": "python3 /x/elastic_adapter.py query",
    "piped_adapter": "python3 scripts/adapters/elastic_adapter.py q | defender-sql 'SELECT 1'",
    "non_adapter": "cat /tmp/x",
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


def _row(lead: str, seq: int, system: str, **extra: Any) -> dict[str, Any]:
    return {"lead_id": lead, "seq": seq, "system": system, "verb": "query",
            "query_id": f"{system or 'x'}.query", "params": {}, **extra}


def operand_fixture(root: Path) -> dict[str, list[Path]]:
    """s169: two runs under `root` (cwd is pinned to `root` by the caller), real payload files,
    a directory, links in and out, and the operand list for each case. Rows are written as a
    stored queries table, by hand: they are the input, the system lookup is the subject."""
    run = root / "run"
    raw = run / "gather_raw"
    other = root / "other-run"
    outside = root / "elsewhere"
    for d in (raw / "l-1", raw / "l-2", raw / "L 1", other / "gather_raw" / "l-1", outside):
        d.mkdir(parents=True, exist_ok=True)
    rows = [
        _row("l-1", 0, "elastic"), _row("l-1", 1, "cmdb"), _row("l-1", 3, "dirsys"),
        _row("l-1", 4, "nofile"), _row("l-1", 5, "linkedout"), _row("l-1", 6, ""),
        _row("l-1", 7, " spaced "), _row("l-1", 10, "tensys"), _row("l-2", 0, "l2sys"),
        _row("L 1", 0, "badlead"), _row("l-1", -1, "negsys"),
    ]
    (run / "executed_queries.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (other / "executed_queries.jsonl").write_text(
        json.dumps(_row("l-1", 0, "othersys")) + "\n", encoding="utf-8")
    for rel in ("l-1/0.json", "l-1/1.json", "l-1/6.json", "l-1/7.json", "l-1/10.json",
                "l-2/0.json", "L 1/0.json", "l-1/abc.json", "l-1/0.txt", "l-1/0.JSON"):
        (raw / rel).write_text("{}\n", encoding="utf-8")
    (other / "gather_raw" / "l-1" / "0.json").write_text("{}\n", encoding="utf-8")
    (raw / "l-1" / "3.json").mkdir()                       # a directory named like a payload
    (outside / "5.json").write_text("{}\n", encoding="utf-8")
    (raw / "l-1" / "5.json").symlink_to(outside / "5.json")      # a link out of the tree
    (root / "link-in.json").symlink_to(raw / "l-1" / "0.json")   # a link from outside, in
    (raw / "l-9").symlink_to(raw / "l-2", target_is_directory=True)  # a linked lead folder
    (raw / "l-1" / "sub").mkdir()
    (raw / "l-1" / "sub" / "0.json").write_text("{}\n", encoding="utf-8")
    bare = root / "bare-run"                                # no queries table at all
    (bare / "gather_raw" / "l-1").mkdir(parents=True)
    (bare / "gather_raw" / "l-1" / "0.json").write_text("{}\n", encoding="utf-8")
    return {
        "absolute": [raw / "l-1" / "0.json"],
        "relative": [Path("run/gather_raw/l-1/0.json")],
        "relative_dot_slash": [Path("./run/gather_raw/l-1/1.json")],
        "dotdot_back_in": [raw / "l-2" / ".." / "l-1" / "0.json"],
        "dotdot_back_in_from_run": [raw / ".." / "gather_raw" / "l-2" / "0.json"],
        "relative_dotdot_back_in": [Path("run/gather_raw/l-2/../l-1/1.json")],
        "dotdot_leaving": [raw / "l-1" / ".." / ".." / "executed_queries.jsonl"],
        "dotdot_leaving_to_other_run": [raw / ".." / ".." / "other-run" / "gather_raw"
                                        / "l-1" / "0.json"],
        "symlink_in": [root / "link-in.json"],
        "symlink_out": [raw / "l-1" / "5.json"],
        "symlinked_lead_folder": [raw / "l-9" / "0.json"],
        "other_run": [other / "gather_raw" / "l-1" / "0.json"],
        "lead_folder_as_directory": [raw / "l-1"],
        "payload_named_directory": [raw / "l-1" / "3.json"],
        "gather_raw_itself": [raw],
        "nonexistent_with_row": [raw / "l-1" / "4.json"],
        "nonexistent_no_row": [raw / "l-1" / "99.json"],
        "nonexistent_lead_folder": [raw / "l-404" / "0.json"],
        "non_numeric_stem": [raw / "l-1" / "abc.json"],
        "stem_with_space": [raw / "l-1" / " 1.json"],
        "stem_plus": [raw / "l-1" / "+1.json"],
        "stem_underscore_digits": [raw / "l-1" / "1_0.json"],
        "stem_leading_zero": [raw / "l-1" / "01.json"],
        "stem_negative": [raw / "l-1" / "-1.json"],
        "stem_arabic_indic_digit": [raw / "l-1" / "١.json"],
        "stem_hex": [raw / "l-1" / "0x1.json"],
        "suffix_txt": [raw / "l-1" / "0.txt"],
        "suffix_upper": [raw / "l-1" / "0.JSON"],
        "too_deep": [raw / "l-1" / "sub" / "0.json"],
        "too_shallow": [raw / "0.json"],
        "invalid_lead_folder_with_row": [raw / "L 1" / "0.json"],
        "invalid_lead_folder_no_row": [raw / "bad.lead" / "0.json"],
        "row_with_empty_system": [raw / "l-1" / "6.json"],
        "row_with_spaced_system": [raw / "l-1" / "7.json"],
        "first_operand_without_row_then_row": [raw / "l-1" / "99.json", raw / "l-2" / "0.json"],
        "two_rows_first_wins": [raw / "l-2" / "0.json", raw / "l-1" / "0.json"],
        "empty_system_row_then_row": [raw / "l-1" / "6.json", raw / "l-1" / "1.json"],
        "no_operands": [],
    }


def operand_bare_run(root: Path) -> Path:
    return root / "bare-run"


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


# PRE-CUT 2026-10-04 (scope cut): deleted from the live suite; owner none: unused even in the pre-cut suite; deleted under E4.
def write_lead_claims(run_dir: Path, leads: list[str]) -> None:
    from defender._run_paths import RunPaths

    for lead in leads:
        p = Path(RunPaths(run_dir).lead_claim(lead))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"goal": f"goal of {lead}", "what_to_summarize": []}) + "\n",
                     encoding="utf-8")


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


#: s210's call: the identical request is issued straight after it is recorded.
def repeat_call() -> dict[str, Any]:
    return {"lead_id": "l-7", "system": "cmdb", "verb": "get-host", "query_id": "cmdb.hunt",
            "params": {"host": "h1", "ports": (22, 443), "by": {1: "x"}},
            "payload_text": json.dumps({"owner": "estate"})}


def drive_repeat(run_dir: Path, *, append: Any, lead_rows: Any, repeat_trip: Any,
                 repeat_note: Any) -> dict[str, Any]:
    """s210: record the call through the row writer, then ask the guard about the identical
    request at once — at a threshold of two (does it see the row), at its default (no trip yet),
    its note, the controls (another lead, other params), and after a second identical row."""
    c = repeat_call()
    lead, sysname, verb, params = c["lead_id"], c["system"], c["verb"], c["params"]
    first = write_calls(append, run_dir, [c])[0]
    rows = lead_rows(run_dir, lead)
    seen = _trip(repeat_trip(rows, lead, system=sysname, verb=verb, params=params, threshold=2))
    default = _trip(repeat_trip(rows, lead, system=sysname, verb=verb, params=params))
    note = repeat_note(run_dir, lead, seq=len(rows), system=sysname, verb=verb, params=params,
                       payload_digest=first["payload_digest"],
                       payload_sha256=first["payload_sha256"], exit_code=0)
    other_lead = _trip(repeat_trip(lead_rows(run_dir, "l-8"), "l-8", system=sysname, verb=verb,
                                   params=params, threshold=2))
    other_params = _trip(repeat_trip(rows, lead, system=sysname, verb=verb,
                                     params={**params, "host": "h2"}, threshold=2))
    second = write_calls(append, run_dir, [c])[0]
    after_two = _trip(repeat_trip(lead_rows(run_dir, lead), lead, system=sysname, verb=verb,
                                  params=params))
    return {
        "first_row": S.canon(first), "rows_read": S.canon(rows),
        "seen_at_threshold_2": seen, "default_after_one": default, "note": note,
        "other_lead": other_lead, "other_params": other_params,
        "second_row": S.canon(second), "default_after_two": after_two,
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


# PRE-CUT 2026-10-04 (scope cut): deleted from the live suite; owner #1165 (dF11's public rename).
def _private_spelling_uses(relpaths: list[str], root: Path = S.REPO_ROOT,
                           ) -> list[tuple[str, int, str]]:
    """Every place in `relpaths` that spells a renamed rule's OLD private name in code: an
    import of it (as the imported name or as the alias), or an attribute read of it."""
    old = set(S.QUERY_RULE_PUBLIC)
    hits: list[tuple[str, int, str]] = []
    for rel in relpaths:
        tree = ast.parse((root / rel).read_bytes(), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for a in node.names:
                    for n in (a.name.rsplit(".", 1)[-1], a.asname):  # lint-ast-resolve: ok — a static census over a fixed module's own source; its import spellings are the observation
                        if n in old:
                            hits.append((rel, node.lineno, n))
            elif isinstance(node, ast.Attribute) and node.attr in old:
                hits.append((rel, node.lineno, node.attr))
    return hits


#: Who takes which flat-tier rule today (claims P8 / G13 / F31): importer -> base names. Pure
#: re-exports are left out (query_tool's `_json_safe_params`, kept for a test's import).
_IMPORTERS: dict[str, tuple[str, ...]] = {
    "defender/learning/branch/ledger.py": (_JSP, _RK),
    "defender/learning/branch/estate/registry.py": (_JSP,),
    "defender/runtime/branch/_family.py": (_JSP,),
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


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand t_query_rules_in_flat_tier); the cut cells are owned by #1165 (dF11's public rename).
def test_1080_query_id_and_request_key_rules_live_in_the_flat_tier_with_todays_values():
    """The request-key and query-id rules are defined in a flat-tier `defender/_*.py` module:
    `_json_safe_params`, `_request_key`, `is_reserved_query_id` and the reserved ids
    `ABOVE_GUARD_QUERY_ID`, `BASH_SHIM_QUERY_ID`, `DENIED_QUERY_ID` and `REPEAT_TRIP_QUERY_ID`.
    Their importers in learning and runtime take them from there. The request key for a fixed
    (system, verb, params) table is byte-identical to the base's, because request keys are
    persisted.

    dF11 (auto): the two private rules carry PUBLIC names in the flat tier, spelled as
    `S.QUERY_RULE_PUBLIC` coins them; the reserved ids and the prefix test keep theirs. The
    values come first (the reserved strings and the key table against the base golden), then
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


def test_1080_the_adapter_path_to_system_rule_lives_in_runtime_verbs_with_todays_answers():
    """`derive_system` and its adapter-path pattern are defined in `runtime/verbs.py`. For a
    fixed table of command argv lists they return the same system names as the base
    `record_query.derive_system`.

    Located by symbol under the pinned `runtime/verbs.py`; the answers are the base golden over
    `ARGVS` (shims, paths, interpreter and assignment prefixes, case, empty stems, near-miss
    suffixes, non-adapter programs)."""
    g = _g()
    home = S.home_of("derive_system", home=S.VERBS)
    assert S.home_of("_ADAPTER_RE", home=S.VERBS) == home, \
        "derive_system and its adapter-path pattern must share runtime/verbs.py"
    verbs = importlib.import_module(S.dotted(home))
    for case, argv in ARGVS.items():
        assert _out(verbs.derive_system, list(argv)) == g["derive_system"][case], case
    assert verbs._ADAPTER_RE.pattern == g["patterns"]["_ADAPTER_RE"]


def test_two_adapter_filename_rules_in_one_module():
    """The system derived from a bash command's argv is exactly what it is today for every argv
    form (bare `defender-<name>` shim, absolute/relative/`./` path, `python3 <path>`,
    `NAME=value` prefix, hyphen/underscore, upper case, empty stem, `x_adapter.py.bak`, trailing
    slash, non- adapter shims). The bash hook's separate path-anchored pattern is unchanged
    (adapters stay put; K5), so the refusal wording for an adapter path is unchanged. Moving
    `derive_system` beside the registry rule changes where it lives, not its answers.

    Three rules are read side by side over the same inputs: the moved `derive_system` (base
    golden over `ARGVS`), the registry's own filename rule already in `runtime/verbs.py` (its
    base answers over `REGISTRY_FILENAMES`, so neither rule absorbed the other), and the hook's
    `scripts/adapters/`-anchored pattern (its text, its stage verdict over `ARGVS`, and the real
    permission decision's refusal for adapter-path commands). The adapters themselves stay in
    `defender/scripts/adapters/` (M-A), which is what keeps the hook's anchor true."""
    g = _g()
    verbs = importlib.import_module(S.dotted(S.home_of("derive_system", home=S.VERBS)))
    for case, argv in ARGVS.items():
        assert _out(verbs.derive_system, list(argv)) == g["derive_system"][case], case
    from defender.runtime import verbs as registry

    for case, name in REGISTRY_FILENAMES.items():
        assert registry._system_of(Path(name)) == g["registry_filenames"][case], case

    from defender.hooks import _cmd_segments
    from defender.runtime import permission
    from defender.runtime.permission import command_shape

    assert _cmd_segments.ADAPTER_RE.pattern == g["patterns"]["hook_ADAPTER_RE"]
    assert (S.SCRIPTS / "adapters" / "elastic_adapter.py").is_file()
    for case, argv in ARGVS.items():
        assert command_shape.is_adapter_stage(list(argv)) == g["hook_stage"][case], case
    for case, cmd in HOOK_COMMANDS.items():
        d = permission.decide_bash(cmd, policy=permission.AgentPolicy())
        assert {"allow": d.allow, "reason": d.reason} == g["hook_decisions"][case], case
    # The refusal an adapter path earns is the adapter wording, and a non-adapter is not it.
    assert g["hook_decisions"]["python3_rel_adapter"]["reason"] == \
        permission.ADAPTER_RETIRED_REASON
    assert g["hook_decisions"]["non_adapter"]["reason"] != permission.ADAPTER_RETIRED_REASON


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s085); the cut cells are owned by #1165 (dF11's public rename: the two inverted cells).
def test_query_rules_are_imported_by_learning_and_runtime_under_the_private_names(tmp_path):
    """The request-key and params-normalising rules are defined once, publicly named, in the
    flat tier; the repeat guard, the ledger and the branch family all import that one
    definition, no importer uses the old private spelling and no local copy exists. (10-03
    flat-tier placement; F30.)

    Structural: the coined public names (`S.QUERY_RULE_PUBLIC`) each have exactly one flat-tier
    definition, the old private names are defined nowhere, the ledger, the estate registry, the
    branch family and the module holding the repeat guard take the public rule from that home,
    and no non-test module under `defender/` or the repository's `scripts/` spells the private
    names in an import or attribute read. The scanner's positive control is a planted module that aliases the public rule back
    to its private name. `request_key` is also the name of the ledger's own delegating wrapper
    (base fact, `learning/branch/ledger.py`), the one other definition that name may have."""
    homes = {}
    for base_name, public in S.QUERY_RULE_PUBLIC.items():
        home = S.home_of(public, home=S.FLAT_TIER)
        homes[base_name] = home
        assert not S.definitions(base_name), (
            f"`{base_name}` is still defined at {S.definitions(base_name)}: a local copy under "
            "the old private name")
    assert set(S.definitions(S.QUERY_RULE_PUBLIC[_JSP])) == {homes[_JSP]}
    assert set(S.definitions(S.QUERY_RULE_PUBLIC[_RK])) <= {
        homes[_RK], "defender/learning/branch/ledger.py"}

    guard_home = S.home_of("repeat_trip")
    importers = {
        "defender/learning/branch/ledger.py": (_JSP, _RK),
        "defender/learning/branch/estate/registry.py": (_JSP,),
        "defender/runtime/branch/_family.py": (_JSP,),
    }
    if guard_home != homes[_RK]:
        importers[guard_home] = (_RK,)
    misses = _census_misses(importers)
    assert not misses, "\n".join(misses)

    planted = tmp_path / "defender" / "planted.py"
    planted.parent.mkdir(parents=True)
    planted.write_text("from defender._rules import request_key as _request_key\n"
                       "import defender._rules as r\nr._json_safe_params({})\n",
                       encoding="utf-8")
    seen = _private_spelling_uses(["defender/planted.py"], root=tmp_path)
    assert [(line, n) for _, line, n in seen] == [(1, _RK), (3, _JSP)], seen
    hits = _private_spelling_uses(S.py_files(tops=("defender", "scripts")))
    assert not hits, f"the old private spelling is still used: {hits}"


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s086); the cut cells are owned by #1165 (the writer and guard reached at a moved home, S.moved).
def test_request_keys_stored_before_the_move_are_compared_with_keys_computed_after_it(tmp_path):
    """The request key for a given request is byte-identical before and after the move, so a
    key stored in an earlier run compares equal to the key computed today by the repeat guard
    and by learning's ledger replaying that run, and a run resumed across the move behaves the
    same. The move changes the rule's module, not its output (O5; F30).

    The earlier run is the golden's frozen `stored_run`: the queries table, payload sidecars and
    lead claims the base writer produced for `stored_calls()`, with the keys the base computed
    for those calls. Today's rule must reproduce each stored key byte for byte; the moved guard,
    reading the stored rows, must find each live call's row; learning's ledger, priming a family
    base from that run and serving each live call from it, must hit every stored answer; and one
    more identical call recorded by the moved writer must continue the stored table's seq and
    trip the guard on the pre-move row."""
    g = _g()["stored_run"]
    request_key = _flat(_RK)
    lead_rows, repeat_trip = S.moved("lead_rows"), S.moved("repeat_trip")
    append = S.moved("append_query_row")
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


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s168); the cut cells are owned by #1165 (the writer and guard reached at a moved home, S.moved).
def test_same_call_live_and_after_the_row_is_read_back(tmp_path):
    """A call's params with a tuple and an int-keyed dict give the same request key live as the
    learning side computes from the stored row after a JSON round trip, as today. The key rule
    is identical before and after the move (F30).

    The call is recorded by the moved writer into a real queries table in `tmp_path`, read back
    by learning's repository, and keyed by the ledger from the typed row and from the raw
    record; the live key, every read-back key and the guard over the read-back rows agree, and
    the whole record equals the base golden."""
    g = _g()["roundtrip"]
    request_key = _flat(_RK)
    got = drive_roundtrip(tmp_path / "run", request_key=request_key,
                          append=S.moved("append_query_row"), lead_rows=S.moved("lead_rows"),
                          repeat_trip=S.moved("repeat_trip"))
    assert got["live_key"] == got["learning_row_key"] == got["learning_record_key"] \
        == got["rule_over_raw_record"]
    assert got["guard"] == {"type": "RepeatTrip", "first_seq": 0, "occurrence": 2}
    assert got == g


def test_payload_operand_path_forms_when_deriving_a_system(tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Payload operands named relative, absolute, via `..` back
    in, leaving, through a symlink, in another run's folder, as a directory, nonexistent, with a
    non- numeric stem or an invalid lead folder derive the system (or none) exactly as today.

    The rule that names a system from payload operands is `system_for_payload_operands` (the
    reducer-shim row's system; `derive_system` answers argv, and is asked here about the same
    operands as a `cat` argv). Real files, a directory, links in and out of the run, a linked
    lead folder and a second run are built in `tmp_path` by `operand_fixture`; relative operands
    resolve against the process working directory, which the test pins to the fixture root, as
    the capture did. Each case's system is the base golden."""
    g = _g()["operands"]
    for_operands = S.moved("system_for_payload_operands")
    derive = S.moved("derive_system", home=S.VERBS)
    operands = operand_fixture(tmp_path)
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "run"
    for case, ops in operands.items():
        got = {"system": for_operands(run_dir, ops),
               "derive_system": derive(["cat", *map(str, ops)])}
        assert got == g[case], case
    assert for_operands(operand_bare_run(tmp_path),
                        [operand_bare_run(tmp_path) / "gather_raw" / "l-1" / "0.json"]) \
        == g["_bare_run_without_a_table"]


def test_repeat_guard_after_a_row_was_recorded_a_moment_earlier(tmp_path):
    """A query recorded and the identical request issued straight afterwards in the same lead:
    the repeat guard sees the row, because the guard and the row writer agree on the request key
    and on the row, now that they live in different modules. Behavior is unchanged from today.

    The moved row writer records the call (a tuple and an int-keyed map among its params) into a
    real queries table; straight afterwards the moved guard, over the moved reader's rows, is
    asked about the identical request. It sees the row (a trip naming seq 0 at a threshold of
    two, the REPEAT note), and does not see it for another lead or other params (the controls);
    after a second identical row its default threshold trips. All against the base golden."""
    g = _g()["repeat"]
    got = drive_repeat(tmp_path / "run", append=S.moved("append_query_row"),
                       lead_rows=S.moved("lead_rows"), repeat_trip=S.moved("repeat_trip"),
                       repeat_note=S.moved("repeat_note"))
    assert got["seen_at_threshold_2"] == {"type": "RepeatTrip", "first_seq": 0, "occurrence": 2}
    assert got["other_lead"] is None
    assert got["other_params"] is None
    assert got == g
