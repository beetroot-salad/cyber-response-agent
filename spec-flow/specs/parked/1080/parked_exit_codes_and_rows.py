# PARKED 2026-10-04 (scope cut of #1080, human-decided): preserved, NOT collected.
# Moved verbatim out of defender/tests/scripts_1080_split/test_1080_exit_codes_and_rows.py by the cut author:
# 18 test function(s) whose demands were parked with an owner issue, plus the
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
"""#1080 phase E, group `exitcodes` — the exit-code vocabulary, the queries-table writers and the
rows they leave behind.

The change moves `error_class_for_exit`, `INFRA_EXIT_CODES`, `DENIED_EXIT_CODE` and the three
error-class names out of `runtime/circuit_breaker.py` into the flat-tier `defender/_exit_codes.py`
(m1: a path pinned by demand text), and splits `scripts/gather_tools/record_query.py` three ways
(M-E (a)): the row and payload writers to the runs side beside `defender/_run_handle.py`, the
guards and their prose to the investigation side, the query-id rules to the flat tier. Every
moved name is reached at CALL time through `S.home_of` / `S.moved` — the vocabulary always with
`home=S.EXIT_CODES`, because at the base it already lives outside `scripts/` (in the circuit
breaker), so an unconstrained lookup would be green there and pin nothing. The record_query
names are found by symbol (dF0): no path is pinned for them.

Every "as today" value is `goldens/exitcodes.json`, captured at 80888efb by running THESE
helpers (the `_scenario`-style functions below) under `SPEC1080_AT_BASE=1`, so the capture and
the test go through one normalisation (`_norm`: the test's temp dir becomes `<TMP>`). A test
never imports an old `defender.scripts.*` path to compute its expected side.

Faults, in the brief's order: real input through the real primitive wherever it can be built —
a symlink planted at the queries table, a regular file planted where the payload directory
goes, a stale payload left in a slot, a non-integer exit code handed to the writer. Exit
statuses and fault classes reach the query tool through the replay harness's `verbs=` seam
(`FakeVerbs`): the fake raises the real exception the query tool maps (`SystemExit(code)` through
`query_tool._fault_exit`, a located `AdapterFault` subclass through its `except AdapterFault`
arm) and never classifies. The reducer's exit status reaches the bash lane through the deps'
`box=` seam (a recorder returning a canned `BoxResult`, the test_959 pattern). No
`monkeypatch.setattr` anywhere.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib
import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "exitcodes"

#: The lead every scenario writes under, and the system its rows name.
LEAD = "l-001"

#: The exit-code vocabulary m1 moves (the names and the classifier).
VOCAB = (
    "error_class_for_exit", "INFRA_EXIT_CODES", "DENIED_EXIT_CODE",
    "INFRA_ERROR_CLASS", "AGENT_FIXABLE_ERROR_CLASS", "DENIED_ERROR_CLASS",
)

VOCAB_VALUES = VOCAB[1:]

EXIT_CODES_MODULE = S.dotted(S.EXIT_CODES)

CIRCUIT_BREAKER_MODULE = "defender.runtime.circuit_breaker"

#: exit_code.domain's 24 distinguished members (GT2), by the demand that binds them.
M1_CODES = (0, 1, 2, 64, 77, 124)

BAND_CODES = (0, 1, 2, 3, 63, 64, 65, 76, 77, 78, 123, 124, 125, 126, 127)

OUTSIDE_CODES = (255, 256, 1000, -1, -9, 130, 137, 139, 143)

DOMAIN_CODES = tuple(dict.fromkeys(M1_CODES + BAND_CODES + OUTSIDE_CODES))

#: s160: what the row writer can be handed that is not an integer.
NOT_INT_CODES = (None, True, False, "2", "0", "", "abc", 2.0, 0.0, -0.0, 124.0, 77.0, 1.5,
                 float("nan"), float("inf"))

ALL_CODES = DOMAIN_CODES + NOT_INT_CODES

#: The defender-sql engine's exit constants (s158 "the engine's constants").
ENGINE_CONSTANTS = ("EXIT_OK", "EXIT_QUERY_ERROR", "EXIT_INPUT_ERROR", "EXIT_NO_RUNTIME")

#: The four names the bash lane takes from the record_query split (s009, claim G13/:349).
BASH_LANE_NAMES = ("SHIM_COMMAND_MAX_CHARS", "append_query_row", "system_for_payload_operands",
                   "BASH_SHIM_QUERY_ID")

BASH_TOOL = "defender/runtime/tools/_bash.py"

#: A fragment of each above-guard trip phrase, as it is spelled in source (s027).
PHRASE_MARKERS = ("repeat of request already", "request in this lead rejected before it ran")

#: The survival sequence fed to the real breaker: every member of the 24-code table once, across
#: five systems; the fifth infra status (2/124) is the call the base kills the run on.
BREAKER_SEQUENCE = (
    ("elastic", 0), ("elastic", 1), ("elastic", 2), ("identity", 3), ("identity", 63),
    ("identity", 64), ("cmdb", 65), ("cmdb", 76), ("cmdb", 77), ("ticket", 78),
    ("ticket", 123), ("elastic", 124), ("ticket", 125), ("ticket", 126), ("ticket", 127),
    ("cmdb", 255), ("cmdb", 256), ("identity", 1000), ("identity", -1), ("host-state", -9),
    ("host-state", 130), ("host-state", 137), ("identity", 2), ("host-state", 139),
    ("host-state", 143), ("cmdb", 124), ("ticket", 2), ("elastic", 1),
)

SYSTEMS = ("elastic", "identity", "cmdb", "ticket", "host-state")

#: The driver half: one gather lead's query statuses (each drawn from the table, 2/124/77
#: included); `identity` trips at its second infra failure, so its next call is answered "down".
DRIVER_SEQUENCE = (
    ("elastic", 1), ("elastic", 77), ("identity", 124), ("cmdb", 64), ("elastic", 2),
    ("cmdb", 0), ("ticket", 126), ("identity", 255), ("identity", 2), ("identity", 1),
    ("host-state", 124), ("ticket", 137), ("cmdb", -9), ("ticket", 2), ("elastic", 3),
)

#: s171: the recorded command's lengths around the limit, and the multi-byte tail that sits
#: across the cut (`é`, an emoji, `e` + a combining acute, a thumbs-up + a skin-tone modifier).
SHIM_TAIL = "é\U0001F600é\U0001F44D\U0001F3FD"

SHIM_PREFIX = "echo hi | defender-sql 'SELECT "

SHIM_LENGTHS = (1999, 2000, 2001, 2002, 2003)

#: s170: (case, lead id, seq, text) — each varies one argument of a canonical call.
MEGA = object()  # stands for three mebibytes of text, built at call time

PERSIST_CASES = (
    ("canonical", LEAD, 0, "{}"),
    ("lead-empty", "", 0, "{}"),
    ("lead-unprefixed", "abc", 0, "{}"),
    ("lead-64-chars", "l-" + "a" * 62, 0, "{}"),
    ("lead-65-chars", "l-" + "a" * 63, 0, "{}"),
    ("lead-traversal", "../x", 0, "{}"),
    ("lead-inner-traversal", "l-1/../../x", 0, "{}"),
    ("lead-dotdot", "..", 0, "{}"),
    ("lead-newline", "l-1\nx", 0, "{}"),
    ("lead-non-ascii", "l-é", 0, "{}"),
    ("seq-negative", LEAD, -1, "{}"),
    ("seq-huge", LEAD, 10**20, "{}"),
    ("seq-string", LEAD, "3", "{}"),
    ("seq-float", LEAD, 1.5, "{}"),
    ("seq-none", LEAD, None, "{}"),
    ("seq-bool", LEAD, True, "{}"),
    ("text-empty", LEAD, 0, ""),
    ("text-nul", LEAD, 0, "a\x00b"),
    ("text-lone-surrogate", LEAD, 0, "a\ud800b"),
    ("text-megabytes", LEAD, 0, MEGA),
    ("text-bytes", LEAD, 0, b'{"b": 1}'),
    ("text-int", LEAD, 0, 123),
    ("text-none", LEAD, 0, None),
)

#: s211: what an earlier attempt left in the `(lead, seq)` slot before the next write.
SLOT_CASES = ("stale-payload", "stale-empty", "stale-after-one-row", "directory", "dangling-link",
              "link-to-outside-file")


def golden(key: str) -> Any:
    return S.golden(GOLDEN)[key]


def _norm(value: Any, tmp: Path) -> Any:
    """`value` (already JSON-shaped) with the test's temp dir spelled `<TMP>`."""
    if isinstance(value, str):
        out = value
        for spelling in {str(Path(tmp).resolve()), str(tmp)}:
            out = out.replace(spelling, "<TMP>")
        return out
    if isinstance(value, list):
        return [_norm(v, tmp) for v in value]
    if isinstance(value, dict):
        return {k: _norm(v, tmp) for k, v in value.items()}
    return value


def _key(code: Any) -> str:
    """A code's identity in a golden table: `True`, `1` and `1.0` stay three keys."""
    return json.dumps(S.canon(code), sort_keys=True)


def _vocab(name: str) -> Any:
    return S.moved(name, home=S.EXIT_CODES)


def _append(  # noqa: PLR0913 — one parameter per row column a scenario varies
        run_dir: Path, *, exit_code: Any, lead_id: str = LEAD, system: str = "elastic",
            verb: str = "probe", query_id: str = "elastic.probe", params: dict | None = None,
            payload_text: Any = "", payload_status: str = "error",
            payload_digest: str = "fixed digest", system_key: str = "") -> dict:
    """One call of the located row writer with fixed columns."""
    return S.moved("append_query_row")(
        run_dir, lead_id=lead_id, system=system, verb=verb, query_id=query_id,
        params={} if params is None else params, raw_command=f"{system} {verb}",
        payload_text=payload_text, exit_code=exit_code, payload_status=payload_status,
        payload_digest=payload_digest, system_key=system_key,
    )


def _table(run_dir: Path) -> str | None:
    """The queries table's text as written, or `None` when nothing is at its name."""
    path = Path(run_dir) / "executed_queries.jsonl"
    if path.is_symlink() or not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _tree(root: Path) -> dict[str, Any]:
    """Everything under `root`: each entry's kind, and a file's size and sha256 (a link's
    target), keyed by its root-relative path."""
    out: dict[str, Any] = {}
    root = Path(root)
    if not root.exists() and not root.is_symlink():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        for name in sorted(dirnames + filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                out[rel] = {"kind": "link", "to": os.readlink(p)}
            elif p.is_dir():
                out[rel] = {"kind": "dir"}
            else:
                data = p.read_bytes()
                out[rel] = {"kind": "file", "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()}
    return dict(sorted(out.items()))


def _untimed(state: Any) -> Any:
    """A breaker document with each `tripped_at` timestamp replaced by a marker."""
    if isinstance(state, dict):
        return {k: ("<at>" if k == "tripped_at" else _untimed(v)) for k, v in state.items()}
    return state


def _breaker_reading(run_dir: Path, code: Any) -> dict:
    from defender.runtime import circuit_breaker

    run_dir.mkdir(parents=True, exist_ok=True)
    state = circuit_breaker.record_outcome(run_dir, "elastic", code)
    return {"state": _untimed(state), "tripped": circuit_breaker.is_tripped(run_dir, "elastic")}


def _code_record(tmp: Path, code: Any) -> dict:
    """Everything the tree answers for one exit status: the classifier, the row the writer
    appends for it (as an above-guard row, so the rejection guard has a reading), the row read
    back by the lead repository and by the guards' own reader, the breaker's reading and the
    bash lane's translation of a reducer status."""
    from defender.learning import lead_repository
    from defender.runtime import circuit_breaker
    from defender.runtime.tools import _bash

    run = tmp / "row"
    run.mkdir(parents=True)
    above = S.moved("ABOVE_GUARD_QUERY_ID")
    record = {
        "class": S.outcome(_vocab("error_class_for_exit"), code),
        "row": S.outcome(_append, run, exit_code=code, query_id=above),
        "line": _table(run),
        "read_back": [{"exit_code": S.canon(q.exit_code), "error_class": q.error_class}
                      for q in lead_repository.load_queries(run)],
        "rejection_domain": [S.moved("in_rejection_domain")(r)
                             for r in S.moved("lead_rows")(run, LEAD)],
        "infra": S.outcome(circuit_breaker.is_infra_failure, code),
        "breaker": S.outcome(_breaker_reading, tmp / "breaker", code),
        "shim": S.outcome(_bash._shim_exit_code, code) if type(code) is int else None,
    }
    return _norm(record, tmp)


def _golden_codes() -> dict[str, dict]:
    return {entry["key"]: entry for entry in golden("codes")}


def _compare_codes(tmp_path: Path, codes: Iterable[Any], aspects: tuple[str, ...]) -> list[str]:
    """Each `code`'s record against the golden, aspect by aspect; the differences, named."""
    want = _golden_codes()
    diffs: list[str] = []
    for i, code in enumerate(codes):
        got = _code_record(tmp_path / f"c{i}", code)
        exp = want[_key(code)]
        for aspect in aspects:
            if got[aspect] != exp[aspect]:
                diffs.append(f"exit status {code!r}: {aspect} is {got[aspect]!r}, the base "
                             f"gave {exp[aspect]!r}")
    return diffs


def _module_source(relpath: str, root: Path = S.REPO_ROOT) -> bytes:
    return (Path(root) / relpath).read_bytes()


def _chain(node: ast.AST) -> str | None:
    """`a.b.c` for an attribute chain rooted at a name, else `None`."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _import_bindings(relpath: str, tree: ast.AST, names: set[str]
                     ) -> tuple[dict[str, str], list[tuple[str, str, int]]]:
    """The file's import bindings (local name -> the dotted thing it names, relative forms
    resolved against the importer's package) and each `from M import name` of a wanted name."""
    pkg = S.dotted(relpath).split(".")
    if not relpath.endswith("__init__.py"):
        pkg = pkg[:-1]
    aliases: dict[str, str] = {}
    hits: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    aliases.setdefault(top, top)
        elif isinstance(node, ast.ImportFrom):
            base = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
            mod = (".".join([*base, node.module] if node.module else base) if node.level
                   else node.module or "")
            for a in node.names:
                aliases[a.asname or a.name] = f"{mod}.{a.name}"
                if a.name in names:
                    hits.append((a.name, mod, node.lineno))
    return aliases, hits


def name_sources(relpath: str, names: Iterable[str], root: Path = S.REPO_ROOT,
                 source: bytes | str | None = None) -> list[tuple[str, str, int]]:
    """Every place the module at `relpath` reaches one of `names` from another module, as
    `(name, module, line)`: a `from M import name` (relative forms resolved), or `<x>.name`
    where `<x>` resolves through the file's own imports to module `M` (`import M as x`,
    `from P import x`, `from . import x`, a dotted `M.name`)."""
    names = set(names)
    src = _module_source(relpath, root) if source is None else source
    tree = ast.parse(src, filename=relpath)
    aliases, out = _import_bindings(relpath, tree, names)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Attribute) and node.attr in names):
            continue
        chain = _chain(node.value)
        head, *rest = (chain or "").split(".")
        if chain is not None and head in aliases:
            out.append((node.attr, ".".join([aliases[head], *rest]), node.lineno))
    return sorted(set(out), key=lambda t: (t[2], t[0], t[1]))


def vocabulary_reached_through_the_circuit_breaker(root: Path = S.REPO_ROOT) -> list[str]:
    """Every non-test module (under `defender/` and the repo's `scripts/`, dF13) that takes an
    exit-code vocabulary name from `runtime.circuit_breaker`, as `path:line name`."""
    hits: list[str] = []
    for relpath in S.py_files(root, ("defender", "scripts")):
        for name, mod, line in name_sources(relpath, VOCAB, root):
            if mod == CIRCUIT_BREAKER_MODULE:
                hits.append(f"{relpath}:{line} {name}")
    return hits


def _string_constants(tree: ast.AST) -> Iterable[str]:
    """Every string constant in `tree` except docstrings (bare-expression strings)."""
    docstrings = {id(n.value) for n in ast.walk(tree)
                  if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings:
            yield n.value


def phrase_sites(root: Path = S.REPO_ROOT) -> list[str]:
    """Every non-test module whose code (not its docstrings) spells an above-guard trip
    phrase."""
    sites = []
    for relpath in S.py_files(root, ("defender", "scripts")):
        tree = ast.parse(_module_source(relpath, root), filename=relpath)
        if any(m in s for s in _string_constants(tree) for m in PHRASE_MARKERS):
            sites.append(relpath)
    return sites


def column_copies(columns: tuple[str, ...], root: Path = S.REPO_ROOT) -> list[str]:
    """Every non-test module holding a module-level literal (tuple, list, set, or a
    `frozenset(...)`/`tuple(...)` of one) whose strings are exactly the queries-table columns."""
    want = set(columns)
    found = []
    for relpath in S.py_files(root, ("defender", "scripts")):
        tree = ast.parse(_module_source(relpath, root), filename=relpath)
        for node in tree.body:
            value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            if isinstance(value, ast.Call) and value.args:
                value = value.args[0]
            if isinstance(value, (ast.Tuple, ast.List, ast.Set)) and value.elts and all(
                    isinstance(e, ast.Constant) and isinstance(e.value, str)
                    for e in value.elts) and {e.value for e in value.elts} == want:
                found.append(relpath)
    return sorted(set(found))


def _persist_case(tmp: Path, lead_id: Any, seq: Any, text: Any) -> dict:
    run = tmp / "run"
    run.mkdir(parents=True)
    if text is MEGA:
        text = "x" * (3 * 2**20)
    got = S.outcome(S.moved("persist_payload"), run, lead_id, seq, text)
    return _norm({"outcome": got, "tree": _tree(run)}, tmp)


def _query_view(q: Any, run: Path) -> dict:
    return {
        "lead_id": q.lead_id, "seq": q.seq, "system": q.system, "verb": q.verb,
        "query_id": q.query_id, "params": q.params, "raw_command": q.raw_command,
        "exit_code": q.exit_code, "error_class": q.error_class,
        "payload_status": q.payload_status, "payload_digest": q.payload_digest,
        "raw_ref": None if q.raw_ref is None else str(q.raw_ref),
        "payload_sha256": q.payload_sha256, "system_key": q.system_key,
        "is_sentinel": q.is_sentinel,
    }


def _readers(run: Path, payload: Path) -> dict:
    """What each reader of a run directory makes of it: the lead repository (rows, the
    unreadable count, the join), the learning extractor (rows whose payload is a file), the
    guards' own row reader, and the payload-to-system join."""
    from defender.learning import lead_repository
    from defender.learning.leads import lead_extraction

    def report() -> dict:
        rows, unreadable = lead_repository.load_queries_report(run)
        return {"rows": [_query_view(q, run) for q in rows], "unreadable": unreadable}

    def join() -> list:
        return [{"lead_id": j.lead_id, "orphan": j.orphan,
                 "queries": [q.seq for q in j.queries],
                 "sentinels": [q.seq for q in j.sentinels]}
                for j in lead_repository.joined(run)]

    def extracted() -> list:
        return [{"lead_id": e.lead_id, "query_index": e.query_index, "query_id": e.query_id,
                 "error_class": e.error_class, "raw_ref": str(e.raw_ref),
                 "is_sentinel": e.is_sentinel}
                for e in lead_extraction.extract(run)[1]]

    return {
        "queries": S.outcome(report),
        "joined": S.outcome(join),
        "extracted": S.outcome(extracted),
        "lead_rows": S.outcome(lambda: [r.get("seq") for r in S.moved("lead_rows")(run, LEAD)]),
        "system_of_payload": S.outcome(S.moved("system_for_payload_operands"), run, [payload]),
    }


def _slot_case(tmp: Path, case: str) -> dict:
    """s211: the slot `gather_raw/l-001/<seq>.json` holds what an earlier attempt left, then the
    writer appends the next row for the lead."""
    run = tmp / "run"
    lead_dir = run / "gather_raw" / LEAD
    lead_dir.mkdir(parents=True)
    seq = 0
    if case == "stale-after-one-row":
        _append(run, exit_code=0, payload_text='{"first": 1}', payload_status="ok")
        seq = 1
    slot = lead_dir / f"{seq}.json"
    outside = tmp / "outside.json"
    outside.write_text('{"outside": 1}', encoding="utf-8")
    if case in ("stale-payload", "stale-after-one-row"):
        slot.write_text('{"stale": true}', encoding="utf-8")
    elif case == "stale-empty":
        slot.write_text("", encoding="utf-8")
    elif case == "directory":
        slot.mkdir()
    elif case == "dangling-link":
        slot.symlink_to(tmp / "nowhere.json")
    elif case == "link-to-outside-file":
        slot.symlink_to(outside)
    got = S.outcome(_append, run, exit_code=0, payload_text='{"new": 2}', payload_status="ok")
    last = json.loads(_table(run).splitlines()[-1]) if _table(run) else None
    agrees = None
    if last is not None and last.get("payload_path"):
        target = run / last["payload_path"]
        agrees = (not target.is_symlink() and target.is_file()
                  and hashlib.sha256(target.read_bytes()).hexdigest() == last["payload_sha256"])
    return _norm({"outcome": got, "table": _table(run), "tree": _tree(tmp),
                  "row_agrees_with_file": agrees,
                  "readers": _readers(run, slot)}, tmp)


def _torn_case(tmp: Path, case: str) -> dict:
    """s212: the row append fails after the payload landed (a dangling link planted at the
    queries table, which the append refuses to follow), or the payload write fails and the row
    is appended (a regular file planted where the lead's payload directory goes)."""
    run = tmp / "run"
    (run / "gather_raw").mkdir(parents=True)
    table = run / "executed_queries.jsonl"
    if case == "row-append-fails":
        table.symlink_to(tmp / "elsewhere.jsonl")
    elif case == "payload-write-fails":
        (run / "gather_raw" / LEAD).write_text("not a directory", encoding="utf-8")
    got = S.outcome(_append, run, exit_code=0, payload_text='{"landed": 1}',
                    payload_status="ok")
    after = {"outcome": got, "tree": _tree(tmp)}
    if case == "row-append-fails":
        table.unlink()  # the process stopped there: what is left is the payload, no row
    payload = run / "gather_raw" / LEAD / "0.json"
    after["readers"] = _readers(run, payload)
    return _norm(after, tmp)


class Box:
    """The bash tool's execution seam, faked at the value the deps carry: it RECORDS each
    command it is handed and returns the canned result (the reducer's exit status)."""

    def __init__(self, rc: int, err: bytes = b"Binder Error: no such column") -> None:
        from defender.runtime.box_codec import BoxResult

        self.result = BoxResult(rc, b"", err)
        self.commands: list[str] = []

    def run_parsed(self, pipelines, *, command, cwd, timeout):  # noqa: ANN001 — the seam's shape
        self.commands.append(command)
        return self.result


def _gather_deps(tmp: Path, box: Box) -> Any:
    """A real gather lead's deps over a real run dir, the box seam handed `box`."""
    from defender.runtime.agent_definition import bind
    from defender.tests import _tenants1106 as T1106

    run = tmp / "run"
    dfn = tmp / "tree" / "defender"
    (run / "gather_raw" / LEAD).mkdir(parents=True, exist_ok=True)
    dfn.mkdir(parents=True, exist_ok=True)
    return dataclasses.replace(bind(T1106.fixture_gather_def(), run, defender_dir=dfn, box=box),
                               lead_id=LEAD)


def _shim_command(length: int) -> str:
    pad = length - len(SHIM_PREFIX) - len("' ") - len(SHIM_TAIL)
    cmd = SHIM_PREFIX + "x" * pad + "' " + SHIM_TAIL
    assert len(cmd) == length
    return cmd


def _shim_cut(tmp: Path) -> dict:
    """s171: a failing reducer whose command is 1999..2003 characters long, the multi-byte
    tail across the cut; what the bash lane records for each."""
    from defender.runtime.tools import _tool_bash

    out = {}
    for length in SHIM_LENGTHS:
        box = Box(1)
        deps = _gather_deps(tmp / f"len{length}", box)
        cmd = _shim_command(length)
        _tool_bash(deps, cmd)
        out[str(length)] = {"table": _table(deps.run_dir),
                            "box_ran_the_whole_command": box.commands == [cmd]}
    return _norm(out, tmp)


def _shim_lane(tmp: Path) -> dict:
    """s009: a payload row seeded through the located writer, then a failing reduce over that
    payload (its system is the payload's) and one over no run payload (no system)."""
    from defender.runtime.tools import _tool_bash

    box = Box(1)
    deps = _gather_deps(tmp, box)
    run = deps.run_dir
    _append(run, exit_code=0, query_id="elastic.auth-window", payload_text='{"hits": [1, 2]}',
            payload_status="ok", payload_digest="16 bytes, 1 line(s)")
    payload = run / "gather_raw" / LEAD / "0.json"
    _tool_bash(deps, f"cat {payload} | defender-sql 'SELECT count(*) FROM payload'")
    _tool_bash(deps, "echo hi | defender-sql 'SELECT 2'")
    return _norm({"table": _table(run), "box": box.commands}, tmp)


def _phrases() -> dict:
    """The guards' prose for fixed trips, through the located producers."""
    repeat = S.moved("RepeatTrip")
    budget = S.moved("RejectionBudgetTrip")
    trips = {
        "repeat-0-3": repeat(first_seq=0, occurrence=3),
        "repeat-none-11": repeat(first_seq=None, occurrence=11),
        "repeat-12-22": repeat(first_seq=12, occurrence=22),
        "budget-6-6": budget(occurrence=6, budget=6),
        "budget-7-6": budget(occurrence=7, budget=6),
    }
    tails = ("", "boom", "x" * 200)
    out: dict[str, Any] = {}
    for name, trip in trips.items():
        if name.startswith("repeat"):
            out[f"repeat_trip_detail/{name}"] = S.outcome(S.moved("repeat_trip_detail"), trip)
            out[f"dead_end_reason/{name}"] = S.outcome(
                S.moved("dead_end_reason"), "elastic", "probe", trip, 2)
        for tail in tails:
            out[f"rejection_detail/{name}/{len(tail)}"] = S.outcome(
                S.moved("rejection_detail"), trip, tail)

        def dead_end(trip: Any = trip) -> list:
            e = S.moved("rejection_dead_end")(trip, target="elastic", verb="probe")
            return [type(e).__name__, e.reason, e.escape]

        out[f"rejection_dead_end/{name}"] = S.outcome(dead_end)
    return out


def _harness() -> Any:
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e import _replay_harness

    return _replay_harness


def _q(system: str, params: dict | None = None) -> Any:
    return _harness().Turn(tool_calls=[("query", {"system": system, "verb": "probe",
                                                  "params": params or {}})])


def _dispatch(lead: str, system: str = "elastic") -> Any:
    return _harness().Turn(tool_calls=[("gather", {
        "lead_id": lead, "system": system, "goal": "measure this lead",
        "what_to_summarize": ["auth events"]})])


def _own_rows(run_dir: Path) -> list[dict]:
    """The scenario's own rows (lead zero's harness-authored leads excluded, as the replay
    suites do)."""
    from defender._io import read_jsonl_rows
    from defender.runtime.lead_zero import RESERVED_LEAD_IDS

    return [r for r in read_jsonl_rows(run_dir / "executed_queries.jsonl")
            if r.get("lead_id") not in RESERVED_LEAD_IDS]


def _row_view(r: dict) -> dict:
    keep = ("lead_id", "seq", "system", "verb", "query_id", "exit_code", "error_class",
            "payload_status", "payload_digest", "system_key")
    return {k: S.canon(r.get(k)) for k in keep}


def _guard_replay(tmp: Path) -> dict:
    """Three leads in one real run: l-001 asks elastic the same thing three times (the repeat
    guard), l-002 names an undeclared system three times (the companion guard), l-003 names six
    different undeclared systems (the rejection budget). Rows and the family judge's reading."""
    from defender.learning import lead_repository
    from defender.learning.judge import family

    H = _harness()

    def probe(ctx: Any, *, code: int = 0) -> list[dict]:
        return [{"event": "auth", "n": 1}]

    verbs = H.FakeVerbs({"elastic": {"probe": probe}})
    gather = H.ReplayFn(
        [_q("elastic")] * 3 + [H.Turn(text="l-001 summary")]
        + [_q("nosuch")] * 3 + [H.Turn(text="l-002 summary")]
        + [_q(f"ghost-{c}") for c in "abcdef"] + [H.Turn(text="l-003 summary")]
        + [H.Turn(text="never reached")])
    main = H.ReplayFn([_dispatch("l-001"), _dispatch("l-002"), _dispatch("l-003"),
                       H.Turn(text="Investigation complete.")])
    run_dir = H.materialize(tmp, H.GOLDEN_AB3)
    H.drive(run_dir, run_id="x1080-guards", main=main, gather=gather, verbs=verbs)
    leads = {j.lead_id: j for j in lead_repository.joined(run_dir)}
    return _norm({
        "rows": [_row_view(r) for r in _own_rows(run_dir)],
        "refused": {lid: family.refused_entries(leads.get(lid))
                    for lid in ("l-001", "l-002", "l-003")},
    }, tmp)


def _breaker_sequence(run_dir: Path) -> dict:
    """The real breaker fed `BREAKER_SEQUENCE`: each call's answer, which systems read as
    tripped after it, and the call that ends the run."""
    from defender.runtime import circuit_breaker

    run_dir.mkdir(parents=True, exist_ok=True)
    calls = []
    for i, (system, code) in enumerate(BREAKER_SEQUENCE):
        try:
            state = circuit_breaker.record_outcome(run_dir, system, code)
        except circuit_breaker.RunAborted as e:
            return {"calls": calls, "aborted_at": i, "total_failures": e.total_failures,
                    "systems": e.systems, "message": str(e)}
        calls.append({"answer": _untimed(state),
                      "tripped": [s for s in SYSTEMS if circuit_breaker.is_tripped(run_dir, s)]})
    return {"calls": calls, "aborted_at": None}


def _driver_abort(tmp: Path) -> dict:
    """The real run: main dispatches one gather lead whose queries exit with
    `DRIVER_SEQUENCE`'s statuses (the fake raises `SystemExit(code)`, which the query tool
    records as that exit code); the run ends where the breaker kills it."""
    H = _harness()

    def probe(ctx: Any, *, code: int = 0) -> list[dict]:
        if code:
            raise SystemExit(code)
        return [{"ok": 1}]

    verbs = H.FakeVerbs({s: {"probe": probe} for s in SYSTEMS})
    gather = H.ReplayFn([_q(s, {"code": c}) for s, c in DRIVER_SEQUENCE]
                        + [H.Turn(text="never reached")])
    main = H.ReplayFn([_dispatch("l-001"), H.Turn(text="should not be reached")])
    run_dir = H.materialize(tmp, H.GOLDEN_AB3)
    result = H.drive(run_dir, run_id="x1080-breaker", main=main, gather=gather, verbs=verbs)
    breaker = json.loads((run_dir / "circuit_breaker.json").read_text(encoding="utf-8"))
    return _norm({
        "summary": {k: S.canon(result.get(k)) for k in
                    ("output", "requests", "truncated_by", "closed_before_cut", "exit_reason")},
        "gather_calls": gather.calls, "main_calls": main.calls,
        "rows": [_row_view(r) for r in _own_rows(run_dir)],
        "breaker": _untimed(breaker),
    }, tmp)


def _fault_subclasses(tmp: Path) -> dict:
    """s161: subclasses of the located `AdapterFault` that reuse a reserved code (denied,
    infrastructure, the usage code), raised by an adapter's verb inside a real run, each on its
    own system; the rows the query tool writes for them and the classifier's answer."""
    H = _harness()
    fault = S.moved("AdapterFault", home=S.INTEGRATIONS)

    class DeniedCode(fault):
        exit_code = 77

    class InfraCode(fault):
        exit_code = 2

    class TimeoutCode(fault):
        exit_code = 124

    class UsageCode(fault):
        exit_code = 64

    raised = {"elastic": DeniedCode, "identity": InfraCode, "cmdb": TimeoutCode,
              "ticket": UsageCode, "host-state": fault}

    def verb_for(cls: type) -> Callable[..., Any]:
        def probe(ctx: Any) -> list[dict]:
            raise cls(f"{cls.__name__} raised by the adapter")
        return probe

    verbs = H.FakeVerbs({s: {"probe": verb_for(c)} for s, c in raised.items()})
    gather = H.ReplayFn([_q(s) for s in raised] + [H.Turn(text="l-001 summary"),
                                                   H.Turn(text="never reached")])
    main = H.ReplayFn([_dispatch("l-001"), H.Turn(text="Investigation complete.")])
    run_dir = H.materialize(tmp, H.GOLDEN_AB3)
    H.drive(run_dir, run_id="x1080-faults", main=main, gather=gather, verbs=verbs)
    breaker_path = run_dir / "circuit_breaker.json"
    classify = _vocab("error_class_for_exit")
    return _norm({
        "codes": {s: {"exit_code": S.canon(c("d").exit_code),
                      "class": S.outcome(classify, c("d").exit_code)}
                  for s, c in raised.items()},
        "rows": [_row_view(r) for r in _own_rows(run_dir)],
        "breaker": _untimed(json.loads(breaker_path.read_text(encoding="utf-8")))
        if breaker_path.is_file() else None,
    }, tmp)


def materialize_recorded_run(run: Path, files: dict[str, str] | None = None) -> None:
    """The run directory the BASE writers wrote at capture time, replayed byte for byte."""
    for rel, text in (golden("recorded_run")["files"] if files is None else files).items():
        path = run / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def read_recorded_run(tmp: Path, run: Path) -> dict:
    """Every reader of the queries table over a run recorded before the move: the lead
    repository (rows, join, the joined-leads render), the learning extractor, the family
    judge's refusals, the branch ledger's request key, the guards replayed over the recorded
    rows, and the payload-to-system join."""
    from defender.learning import lead_repository
    from defender.learning.branch import ledger
    from defender.learning.judge import family

    rows = [q.record() for q in lead_repository.load_queries(run)]
    leads = {j.lead_id: j for j in lead_repository.joined(run)}
    repeat_trip = S.moved("repeat_trip")
    rejection_trip = S.moved("rejection_trip")
    budget_trip = S.moved("rejection_budget_trip")

    def trip_view(trip: Any) -> Any:
        if trip is None:
            return None
        return {"type": type(trip).__name__,
                **{k: S.canon(v) for k, v in dataclasses.asdict(trip).items()}}

    out = _readers(run, run / "gather_raw" / LEAD / "0.json")
    out.update({
        "render": S.outcome(lead_repository.render_joined_yaml, run),
        "refused": {lid: S.outcome(family.refused_entries, leads.get(lid))
                    for lid in sorted(leads)},
        "request_keys": [S.outcome(ledger.request_key, r.get("system"), r.get("verb"),
                                   r.get("params")) for r in rows],
        "repeat_trip": {lid: S.outcome(lambda lid=lid: trip_view(repeat_trip(
            rows, lid, system="elastic", verb="probe", params={"q": "x"})))
            for lid in ("l-001", "l-002")},
        "rejection_trip": S.outcome(lambda: trip_view(rejection_trip(
            rows, "l-002", system="", verb="probe", params={}, system_key="k"))),
        "budget_trip": {str(b): S.outcome(lambda b=b: trip_view(budget_trip(rows, "l-002",
                                                                            budget=b)))
                        for b in (2, 3, 6)},
        "next_seq": S.outcome(lambda: _append(run, exit_code=0, payload_text="{}",
                                              payload_status="empty")["seq"]),
    })
    return _norm(out, tmp)


# PARKED 2026-10-04 (scope cut): owner #1165 or #1172; demand m1_exit_codes_in_flat_tier
def test_1080_the_exit_code_vocabulary_and_error_class_for_exit_live_in_the_flat_tier():
    """`defender/_exit_codes.py` defines `error_class_for_exit`, `INFRA_EXIT_CODES`,
    `DENIED_EXIT_CODE` and the error-class names. `runtime/circuit_breaker.py` no longer defines
    them. `lead_repository` and `judge/family` import them from the flat tier.

    Observed: the locator, constrained to the pinned home, finds each name defined there (and
    only there); the AST of `circuit_breaker.py` binds none of them at module level; every place
    `learning/lead_repository.py` and `learning/judge/family.py` reach a vocabulary name
    resolves to `defender._exit_codes` (and each reaches at least one — the positive control
    that the resolver sees their imports at all)."""
    problems: list[str] = []
    for name in VOCAB:
        try:
            home = S.home_of(name, home=S.EXIT_CODES)
        except AssertionError as e:
            problems.append(str(e))
            continue
        if home != S.EXIT_CODES:
            problems.append(f"`{name}` is defined in {home}, not in {S.EXIT_CODES}")
    cb = "defender/runtime/circuit_breaker.py"
    still = sorted(set(VOCAB) & set(S.module_level_names(_module_source(cb), cb)))
    if still:
        problems.append(f"{cb} still defines {still}")
    for reader in ("defender/learning/lead_repository.py", "defender/learning/judge/family.py"):
        sources = name_sources(reader, VOCAB)
        if not sources:
            problems.append(f"{reader} reaches no exit-code vocabulary name at all")
        wrong = [f"{n} from {m} (line {ln})" for n, m, ln in sources if m != EXIT_CODES_MODULE]
        if wrong:
            problems.append(f"{reader} takes the vocabulary from elsewhere: {wrong}")
    assert not problems, "\n".join(problems)


# PARKED 2026-10-04 (scope cut): owner #1165 or #1172; demand m1_error_class_answers_unchanged
def test_1080_error_class_for_exit_answers_every_code_as_today():
    """`error_class_for_exit` returns the same class as at the base for exit codes 0, 1, 2, 64,
    77, 124 and every other code in a fixed table, `None` included where the base returns it.

    The fixed table is exit_code.domain's 24 distinguished members plus the non-integer values
    s160 hands the writer; the classifier is reached at its pinned home and each answer
    (value, or the exception) compared with the base's, type for type."""
    classify = _vocab("error_class_for_exit")
    want = _golden_codes()
    diffs = [f"{code!r}: {S.outcome(classify, code)!r}, the base gave {want[_key(code)]['class']!r}"
             for code in ALL_CODES if S.outcome(classify, code) != want[_key(code)]["class"]]
    assert not diffs, "\n".join(diffs)


# PARKED 2026-10-04 (scope cut): owner #1165 or #1172; demand m1_row_writer_reads_no_circuit_breaker
def test_1080_the_queries_table_writer_imports_nothing_from_circuit_breaker_and_still_classifies(
        tmp_path):
    """The module defining `append_query_row` imports nothing from `runtime.circuit_breaker`. A
    row it writes for a failed call still carries the `error_class` that
    `_exit_codes.error_class_for_exit` gives.

    The negative reads every import statement of the writer's home (module level or not,
    relative forms resolved). The positive control is the paired m1_error_class_answers_unchanged
    reading on the row itself: a row the located writer appends for statuses 1, 2 and 77 (and the
    success 0) carries the class the base classifier gave, so an empty or broken writer cannot
    pass the negative alone."""
    want = _golden_codes()
    for code in (0, 1, 2, 77):
        run = tmp_path / f"c{code}"
        run.mkdir()
        row = _append(run, exit_code=code)
        assert {"returns": row["error_class"]} == want[_key(code)]["class"], (
            f"the row for exit {code} carries {row['error_class']!r}; the base classifier gave "
            f"{want[_key(code)]['class']!r}")
    home = S.home_of("append_query_row")
    stmts = list(S.import_statements(home, _module_source(home)))
    from_breaker = [
        f"line {s.line}: {s.module} {list(s.names)}" for s in stmts
        if s.module == CIRCUIT_BREAKER_MODULE or s.module.startswith(CIRCUIT_BREAKER_MODULE + ".")
        or (s.module == "defender.runtime" and "circuit_breaker" in s.names)]
    assert not from_breaker, f"{home} imports from the circuit breaker: {from_breaker}"


# PARKED 2026-10-04 (scope cut): owner #1165 or #1172; demand s083
def test_exit_code_vocabulary_lives_once_in_the_flat_tier_with_unchanged_values(
        tmp_path):
    """The exit-code names and `error_class_for_exit` exist once, in the flat-tier
    `_exit_codes.py`; the circuit breaker no longer defines them, so no home can drift. Values
    and the error-class answers are unchanged, and the queries-table writer, the learning lead
    repository and the judge family all read the same home.

    Observed: every vocabulary name has exactly one definition in the whole tree (`scripts/`
    included) and it is `defender/_exit_codes.py`; the imported circuit-breaker module holds
    none of the names, not even as an import binding (the [30] reading: every importer is
    repointed); no module anywhere reaches a vocabulary name through the circuit breaker (a
    census whose positive control is a planted reader in a temp tree); the values and the
    classifier's answers over the whole code table equal the base's; the writer's home, the
    lead repository and the family judge each reach the vocabulary only through
    `defender._exit_codes`."""
    values = {n: S.canon(_vocab(n)) for n in VOCAB_VALUES}
    assert values == golden("vocabulary"), "a vocabulary value changed in the move"
    classify = _vocab("error_class_for_exit")
    want = _golden_codes()
    assert all(S.outcome(classify, c) == want[_key(c)]["class"] for c in ALL_CODES)

    # Positive control for the census: a reader planted in a temp tree is reported.
    planted = tmp_path / "defender" / "runtime" / "planted_reader.py"
    planted.parent.mkdir(parents=True)
    planted.write_text("from . import circuit_breaker as cb\n"
                       "X = cb.DENIED_EXIT_CODE\n", encoding="utf-8")
    assert vocabulary_reached_through_the_circuit_breaker(tmp_path) == [
        "defender/runtime/planted_reader.py:2 DENIED_EXIT_CODE"]

    problems: list[str] = []
    for name in VOCAB:
        defs = S.definitions(name)
        if defs != (S.EXIT_CODES,):
            problems.append(f"`{name}` is defined at {list(defs)}; one home, {S.EXIT_CODES}")
    cb = importlib.import_module(CIRCUIT_BREAKER_MODULE)
    held = [n for n in VOCAB if hasattr(cb, n)]
    if held:
        problems.append(f"runtime.circuit_breaker still holds {held}")
    through = vocabulary_reached_through_the_circuit_breaker()
    if through:
        problems.append(f"readers still take the vocabulary from the breaker: {through}")
    readers = ["defender/learning/lead_repository.py", "defender/learning/judge/family.py"]
    try:
        readers.insert(0, S.home_of("append_query_row"))
    except AssertionError as e:
        problems.append(str(e))
    for relpath in readers:
        sources = name_sources(relpath, VOCAB)
        if not sources or any(m != EXIT_CODES_MODULE for _n, m, _ln in sources):
            problems.append(f"{relpath} does not read the vocabulary from {EXIT_CODES_MODULE}: "
                            f"{sources}")
    assert not problems, "\n".join(problems)

_FLAT_TIER_ONLY = """
import json, sys
from pathlib import Path


class _FlatTierOnly:
    # Refuses every `defender.<sub>` whose <sub> is not a flat-tier `_` module — except the
    # writer's own module (and the packages holding it), so what is refused is its imports.
    def find_spec(self, name, path=None, target=None):
        parts = name.split(".")
        own = name == sys.argv[1] or sys.argv[1].startswith(name + ".")
        if parts[0] == "defender" and len(parts) > 1 and not parts[1].startswith("_") \
                and not own:
            raise ModuleNotFoundError(f"{name!r} is refused: only the flat tier is available")
        return None


sys.meta_path.insert(0, _FlatTierOnly())
try:
    import defender.runtime.circuit_breaker  # noqa: F401
except ImportError:
    pass
else:
    raise SystemExit("the block did not fire: defender.runtime imported")
import defender._run_paths  # noqa: F401,E402 — the flat tier itself stays importable
import importlib
writer = importlib.import_module(sys.argv[1])
out = {}
for code in (0, 1, 2, 77, 124):
    run = Path(sys.argv[2]) / f"c{code}"
    run.mkdir(parents=True)
    row = writer.append_query_row(
        run, lead_id="l-001", system="elastic", verb="probe", query_id="elastic.probe",
        params={}, raw_command="elastic probe", payload_text="", exit_code=code,
        payload_status="error", payload_digest="fixed digest", system_key="")
    out[str(code)] = row["error_class"]
print(json.dumps({"classes": out,
                  "runtime_loaded": sorted(m for m in sys.modules
                                           if m.startswith("defender.runtime"))}))
"""


# PARKED 2026-10-04 (scope cut): owner #1165; demand s084
def test_queries_table_writer_is_imported_where_the_runtime_package_cannot_be_loaded(tmp_path):
    """The queries-table writer imports with only the flat tier available (it takes the
    exit-code vocabulary from `_exit_codes`, not the circuit breaker): a bare interpreter, the
    box or a lint can import it without the runtime package's heavy dependencies, and a row it
    writes carries the same error class for a failing exit as before.

    Observed in a child pinned to this tree: the agent framework, the model providers and the
    MCP stack are refused by `_import_blocker`, and every `defender.<sub>` that is not a
    flat-tier `_` module (so `defender.runtime`, `defender.learning`, `defender.scripts`) by a
    second finder, the writer's own module excepted. The child first proves the block fires
    (importing the circuit breaker must fail) and the flat tier still imports, then imports the
    located writer's module and appends a row per status; the classes it prints equal the
    base's, and no `defender.runtime` module was loaded."""
    from defender.tests import _import_blocker

    writer = S.dotted(S.home_of("append_query_row"))
    proc = _import_blocker.run_blocked(
        _FLAT_TIER_ONLY, block=list(S.BOX_BLOCKED), argv=[writer, str(tmp_path)],
        env=S.child_env(), cwd=S.REPO_ROOT)
    assert proc.returncode == 0, (
        f"the writer {writer} did not import and write with only the flat tier available:\n"
        f"{proc.stderr.decode(errors='replace')[-3000:]}")
    got = json.loads(proc.stdout.decode().strip().splitlines()[-1])
    want = _golden_codes()
    assert {c: {"returns": v} for c, v in got["classes"].items()} == {
        str(c): want[_key(c)]["class"] for c in (0, 1, 2, 77, 124)}
    assert got["runtime_loaded"] == []


# PARKED 2026-10-04 (scope cut): owner #1165 or #1172; demand s158
def test_exit_codes_at_every_band_boundary(tmp_path):
    """For every exit status the engine produces (0, 1, 2, 3, 63, 64, 65, 76-78, 123-127), the
    stored error class, the breaker's reading and the repeat guard's reading are what they
    were: the engine's constants, the classifier table and the stored class agree status by
    status, and the row is written with the same bytes. (O5; the vocabulary moves, its answers
    do not.)

    Per status: the classifier's answer; the bytes of the row the located writer appends (an
    above-guard row, so the rejection guard has a reading) and the row as the lead repository
    reads it back; the guards' own reader's verdict on it (`in_rejection_domain` — the count of
    agent-fixable rejections); the breaker's answer when that status is charged to a system;
    and the bash lane's translation of a reducer exit status. The defender-sql engine's exit
    constants, at the engine's home, equal the base's."""
    engine = S.moved_module("EXIT_NO_RUNTIME")
    constants = {n: S.canon(getattr(engine, n)) for n in ENGINE_CONSTANTS}
    assert constants == golden("engine_constants")
    diffs = _compare_codes(tmp_path, BAND_CODES, (
        "class", "row", "line", "read_back", "rejection_domain", "infra", "breaker", "shim"))
    assert not diffs, "\n".join(diffs)


# PARKED 2026-10-04 (scope cut): owner #1165 or #1172; demand s159
def test_exit_codes_outside_the_byte_range(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A status of 255, 256, 1000, -1, -9 or a signal-derived
    130/137/139/143 is classified and stored as today (probe PO2 pins today's mapping).

    PO2 is not in the claims ledger; the base itself is the probe: each status's classifier
    answer, stored row bytes, read-back, guard and breaker readings and the bash lane's
    translation, captured at 80888efb."""
    diffs = _compare_codes(tmp_path, OUTSIDE_CODES, (
        "class", "row", "line", "read_back", "rejection_domain", "infra", "breaker", "shim"))
    assert not diffs, "\n".join(diffs)


# PARKED 2026-10-04 (scope cut): owner #1165 or #1172; demand s160
def test_exit_code_that_is_not_an_integer(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A None, bool, string or float exit code handed to the row
    writer is stored and classified exactly as today (probe PO2).

    The writer's outcome and the row's bytes (where `True`, `1.0` and `"1"` stay distinct), the
    classifier, the lead repository's read-back and the breaker's reading, per value."""
    diffs = _compare_codes(tmp_path, NOT_INT_CODES, (
        "class", "row", "line", "read_back", "rejection_domain", "infra", "breaker"))
    assert not diffs, "\n".join(diffs)


# PARKED 2026-10-04 (scope cut): owner #1172; demand s161
@pytest.mark.e2e
def test_tenant_fault_subclass_reusing_a_reserved_code(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A fault subclass given a code equal to a reserved one
    (denied, infrastructure, usage) is classified by that code exactly as today; the move adds
    no new guard. The adapter authoring surface moves to #1172.

    Subclasses of the located `AdapterFault` carrying 77, 2, 124 and 64 are raised by an
    adapter's verb inside a real run (the replay harness's `verbs=` seam); the query tool's own
    `except AdapterFault` arm records them. The rows, the breaker document and the classifier's
    answer for each code equal the base's, and `USAGE_EXIT_CODE` keeps its value."""
    assert S.canon(S.moved("USAGE_EXIT_CODE", home=S.INTEGRATIONS)) == golden("usage_exit_code")
    assert _fault_subclasses(tmp_path) == golden("fault_subclasses")


# PARKED 2026-10-04 (scope cut): owner #1165 or #1172; demand survival_breaker_trips_as_before_the_vocabulary_moves
@pytest.mark.e2e
def test_1080_the_circuit_breaker_trips_at_the_same_call_and_the_driver_ends_the_run_as_before(
        tmp_path):
    """A circuit breaker fed a fixed sequence of exit statuses drawn from the 24 members of the
    exit-code table (including 2, 124 and 77) trips at the same call as the base golden, now
    that the exit-code vocabulary lives in `_exit_codes` and the breaker, the row writer, the
    lead repository, the judge family, the query tool, the gather tools and lead zero no longer
    import one another for it. The driver, which catches `RunAborted`, ends the run with the
    same exit reason (`RunAborted`) and the same exit code as the base. The bare
    vocabulary-location assertions (m1_exit_codes_in_flat_tier, s083) do not run the breaker;
    this one does.

    Two halves. The real `record_outcome` over `BREAKER_SEQUENCE` (all 24 statuses): each
    call's answer, which systems read as tripped after it, and the call `RunAborted` is raised
    at with its count, systems and message. Then a real run (replay harness) whose gather lead's
    queries exit with `DRIVER_SEQUENCE`'s statuses: the run summary (exit reason, the exit class
    the driver stamps, output), the gather call the run ended on, the rows with their exit codes
    and classes, and the breaker document. Green at the base by design: a survival pin."""
    assert _breaker_sequence(tmp_path / "breaker") == golden("breaker_sequence")
    got = _driver_abort(tmp_path / "driver")
    want = golden("driver_abort")
    assert got["summary"] == want["summary"], got["summary"]
    assert got == want


# PARKED 2026-10-04 (scope cut): owner #1165; demand s027
@pytest.mark.e2e
def test_guard_prose_written_by_one_side_and_matched_by_readers(tmp_path):
    """A guard trip's row carries the same phrase as before, byte for byte, and run end and the
    family judge identify which guard fired from one shared definition of the phrases (no
    independently spelled copy), for rows written by this run and rows recorded before the
    move. The writer on the runs side and the guards on the investigation side agree on the
    prose. (O5: query rows unchanged.)

    Observed: the located phrase producers give the base's text for fixed trips; a real run
    whose three leads trip the repeat guard, the companion guard and the rejection budget
    writes the base's rows (the trip rows' `payload_digest` carrying the phrase) and the family
    judge reads the base's refusal kinds off them; the trip phrases are spelled in exactly one
    non-test module, the home of `rejection_detail`, so neither `run_end` nor the family judge
    nor the writer's side holds a copy. (At the base no reader parses the phrase: `run_end`
    names its owner in a docstring, JD2, and the family judge keys on the sentinel `query_id`.)
    The rows-recorded-before half is s034's recorded run, read here through the family judge
    as well."""
    assert _phrases() == golden("phrases")
    home = S.home_of("rejection_detail")
    assert S.home_of("repeat_trip_detail") == home
    sites = phrase_sites()
    assert sites == [home], f"the trip phrases are spelled in {sites}; one home, {home}"
    got = _guard_replay(tmp_path / "guards")
    assert got == golden("guard_replay")
    run = tmp_path / "recorded" / "run"
    materialize_recorded_run(run)
    from defender.learning import lead_repository
    from defender.learning.judge import family

    leads = {j.lead_id: j for j in lead_repository.joined(run)}
    assert {lid: S.outcome(family.refused_entries, leads.get(lid)) for lid in sorted(leads)} \
        == golden("recorded_run")["readers"]["refused"]


# PARKED 2026-10-04 (scope cut): owner #1165; demand s028
def test_row_schema_constant_and_its_readers_on_opposite_sides(tmp_path):
    """The queries-table column list has one definition; the row writer and learning's lead
    repository read the same list, in the same order, so a row appended after the move has the
    same columns as before and the lead repository reads it. Which module owns the constant is
    the implementer's; a second copy in a reader is a failure.

    Observed: `QUERY_ROW_COLUMNS` has one home (the locator's one-home rule) and the base's
    value; a row the located writer appends has exactly those keys in that order, on disk and
    as returned; the lead repository's reader hands back that record with the same key order,
    and its typed row declares the same column set (`raw_ref` is its name for `payload_path`);
    no other non-test module holds a literal of the same column set, and if the lead repository
    binds the name at all it is the same object."""
    from defender.learning import lead_repository

    columns = S.moved("QUERY_ROW_COLUMNS")
    home = S.home_of("QUERY_ROW_COLUMNS")
    assert S.canon(columns) == golden("row_columns")
    run = tmp_path / "run"
    run.mkdir()
    row = _append(run, exit_code=1)
    assert tuple(row) == columns
    on_disk = json.loads(_table(run).splitlines()[-1])
    assert tuple(on_disk) == columns
    read = lead_repository.load_queries(run)
    assert [tuple(q.record()) for q in read] == [columns]
    typed = [f.name for f in dataclasses.fields(lead_repository.QueryRow)
             if not f.name.startswith("_")]
    assert {"payload_path" if f == "raw_ref" else f for f in typed} == set(columns)
    assert column_copies(columns) == [home], "a second spelling of the queries-table columns"
    if hasattr(lead_repository, "QUERY_ROW_COLUMNS"):
        assert lead_repository.QUERY_ROW_COLUMNS is columns, \
            "the lead repository holds its own copy of the column list"


# PARKED 2026-10-04 (scope cut): owner #1165; demand s034
def test_run_recorded_before_the_move_is_read_after_it(tmp_path):
    """A run directory written before the move reads the same after it: rows, payload files,
    trip rows, review records, the page and the ticket receipt are classified and rendered by
    lead repository, ledger, branch replay, family judge, page re-render and the ticket step
    exactly as they were, because the stored formats do not change (O5: query rows and payload
    paths unchanged). No stored record depends on a module path or class name that moved
    (probe P6 checks).

    The recorded run is the queries table and payload files the BASE writers wrote at capture
    time (ordinary, failed, infra and denied rows; repeat-trip, above-guard and bash-shim
    sentinels; a row in the pre-`error_class` format; a payload with no row and a row with no
    payload), replayed byte for byte into a temp run dir. Read after the move by the lead
    repository (rows, join, render), the learning extractor, the family judge, the branch
    ledger's request key, the guards replayed over the recorded rows, the payload-to-system
    join, and the writer's next seq: each answer equals the base's. Review records, the run
    page and the ticket receipt are not pinned here (their renderers are other groups')."""
    run = tmp_path / "run"
    materialize_recorded_run(run)
    got = read_recorded_run(tmp_path, run)
    want = golden("recorded_run")["readers"]
    diffs = [k for k in want if got.get(k) != want[k]]
    assert not diffs, f"readers that read the recorded run differently: {diffs}\n" + "\n".join(
        f"{k}: {got.get(k)!r}\n  base: {want[k]!r}" for k in diffs)


# PARKED 2026-10-04 (scope cut): owner #1165; demand s212
def test_payload_written_and_the_row_append_fails_or_the_reverse(tmp_path):
    """If the payload file is on disk but the process stops before the row is appended, or the
    row is appended and the payload write failed, each reader of the run directory sees what it
    saw before the move: the write order of payload and row is unchanged by the writers' move.

    Two real faults through the located writer: a dangling link planted at the queries table
    (the append refuses to follow it, after the payload has landed — the payload-first order is
    visible on disk; the link is then removed, leaving what a stopped process leaves), and a
    regular file planted where the lead's payload directory goes (the payload write fails and
    the row is appended without a payload path). The writer's outcome, the tree, and every
    reader's view equal the base's."""
    for case in ("row-append-fails", "payload-write-fails"):
        got = _torn_case(tmp_path / case, case)
        assert got == golden("torn")[case], case


# PARKED 2026-10-04 (scope cut): owner #1165; demand s211
def test_payload_slot_already_occupied_by_an_aborted_earlier_attempt(tmp_path):
    """A payload slot already occupied by an aborted earlier attempt is kept, replaced or
    refused exactly as today when the same lead-and-sequence slot is written again, and the row
    written next agrees with the file on disk (probe P15 pins today's behavior).

    The ledger's P15 is a different claim (#1106 merged); the base is the probe here. Occupants
    planted with real primitives: a stale payload, a stale empty payload, a stale payload in the
    slot after one recorded row, a directory, a dangling link and a link to a file outside the
    run. The writer's outcome, the table, the whole temp tree (the outside file included),
    whether the row's sha256 matches the file at its payload path, and the readers' view equal
    the base's."""
    for case in SLOT_CASES:
        got = _slot_case(tmp_path / case, case)
        assert got == golden("slot")[case], case


# PARKED 2026-10-04 (scope cut): owner #1165; demand s170
def test_lead_id_seq_and_payload_text_forms(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A lead id that is empty, unprefixed, 64 versus 65
    characters, with traversal, newline or non-ASCII; a sequence of zero, negative, huge or
    non-integer; and text that is empty, with NUL or lone surrogates, megabytes, or not text,
    are persisted or refused as today (probe PO18).

    PO18 is not in the claims ledger; the base is the probe. Each case varies one argument of a
    canonical call to the located `persist_payload`; its outcome (the relative path, `None`, or
    the exception) and everything it left under the run dir equal the base's."""
    want = golden("persist")
    diffs = []
    for case, lead_id, seq, text in PERSIST_CASES:
        got = _persist_case(tmp_path / case, lead_id, seq, text)
        if got != want[case]:
            diffs.append(f"{case}: {got!r}\n  base: {want[case]!r}")
    assert not diffs, "\n".join(diffs)


# PARKED 2026-10-04 (scope cut): owner #1165; demand s171
def test_shim_command_text_at_the_recording_length_limit(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A recorded shim command one character under, at, and one
    over the recording limit, with multi-byte characters straddling the cut, is cut at the same
    point as today; the limit's value is unchanged.

    Through the real bash tool (the reducer's failure comes from the deps' box seam): commands
    of 1999 to 2003 characters whose last six code points (an accented letter, an emoji, a
    letter with a combining accent, an emoji with a skin-tone modifier) sit across the cut; the
    row the lane records for each equals the base's byte for byte, and the box ran the whole
    command each time (only the record is cut). The limit at its new home keeps its value."""
    assert S.canon(S.moved("SHIM_COMMAND_MAX_CHARS")) == golden("shim_command_max_chars")
    assert _shim_cut(tmp_path) == golden("shim_cut")


# PARKED 2026-10-04 (scope cut): owner #1165; demand s009
def test_one_consumer_takes_names_from_all_three_sides_of_the_record_query_split(tmp_path):
    """The bash-shim lane records its call exactly as today: the command is capped at the same
    recording limit, the system derived from the payload operands with the same rule, the
    reserved shim query id stamped, and the row appended with the same columns and bytes. All
    four names resolve at their new homes (investigation side, flat tier, runs side) with no
    stale module alias. (O5: query rows unchanged.)

    Observed: each of the four names has one home outside `scripts/`; the writer, the
    payload-to-system join and the shim id live in three different modules (the three sides);
    `runtime/tools/_bash.py` imports nothing from `defender.scripts`, and every place it reaches
    one of the four names resolves to that name's own home (no module standing in for another).
    Then the lane runs: a failing reduce over a payload recorded for elastic, and one over no
    run payload; the table equals the base's, byte for byte."""
    assert _shim_lane(tmp_path) == golden("shim_lane")
    homes = {n: S.home_of(n) for n in BASH_LANE_NAMES}
    sides = {homes["append_query_row"], homes["system_for_payload_operands"],
             homes["BASH_SHIM_QUERY_ID"]}
    assert len(sides) == 3, f"the three sides are not three modules: {homes}"
    stale = [f"line {s.line}: {s.module}" for s in
             S.import_statements(BASH_TOOL, _module_source(BASH_TOOL))
             if s.module == "defender.scripts" or s.module.startswith("defender.scripts.")]
    assert not stale, f"{BASH_TOOL} still imports from scripts/: {stale}"
    sources = name_sources(BASH_TOOL, BASH_LANE_NAMES)
    assert {n for n, _m, _ln in sources} == set(BASH_LANE_NAMES), sources
    wrong = [f"{n} via {m} (line {ln}); its home is {S.dotted(homes[n])}"
             for n, m, ln in sources if m != S.dotted(homes[n])]
    assert not wrong, f"{BASH_TOOL} reaches a name through a module that is not its home: {wrong}"
