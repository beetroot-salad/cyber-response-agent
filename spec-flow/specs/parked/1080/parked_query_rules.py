# PARKED 2026-10-04 (scope cut of #1080, human-decided): preserved, NOT collected.
# Moved verbatim out of defender/tests/scripts_1080_split/test_1080_query_rules.py by the cut author:
# 4 test function(s) whose demands were parked with an owner issue, plus the
# imports, constants and helpers they use (a helper the live file still uses is COPIED, not
# moved). The file name does not match test_*.py, so pytest never collects it. Each
# demand is a `form: clause` in spec-flow/specs/spec_graph_1080-scripts-split.yaml whose
# `parked.preserved_test` names its function here; the owner adopts the test into its own
# spec (restoring form: test) when it lands. The module docstring below is the source file's,
# unchanged: it describes the whole suite file as it stood before the cut.
# GOLDENS: the files only parked tests read (exitcodes.json, integrations.json, pages/*.html,
# runpage/*.html) moved to ./goldens/ beside this file; every other golden stays in
# defender/tests/scripts_1080_split/goldens/ (a kept test still reads it). `S.golden` and
# `S.GOLDENS` read the suite's folder, so the adopter moves the parked goldens back with the test.
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

import hashlib
import importlib
import json
from pathlib import Path
from typing import Any

from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "queryrules"


def _g() -> Any:
    return S.golden(GOLDEN)

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


# PARKED 2026-10-04 (scope cut): owner #1172; demand t_derive_system_in_verbs
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


# PARKED 2026-10-04 (scope cut): owner #1172; demand s029
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


# PARKED 2026-10-04 (scope cut): owner #1172; demand s169
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


# PARKED 2026-10-04 (scope cut): owner #1165; demand s210
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
