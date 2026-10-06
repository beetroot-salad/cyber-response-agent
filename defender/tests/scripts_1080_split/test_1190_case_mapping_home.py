"""#1190 — the case-mapping module (`case_ticket.py`) moves whole from
`defender/scripts/case_history/` to `defender/runtime/case_ticket.py`: same names, same behaviour,
no re-export shim at the old path. Its tests were #1080's, parked with this follow-up by the
2026-10-04 scope cut; this file adopts them (demands s_case_mapping_read_at_run_start, s090,
s187, s188 and s217 of `spec-flow/specs/spec_graph_1080-scripts-split.yaml`, `form: test` again)
and adds the env-read lint's net for the move (the design's O3).

THE HOME IS PINNED UNDER `defender/runtime/` (F-C, human, 2026-10-03; the #1190 design). Every
lookup of the case-mapping code goes through `_spec1080`'s symbol locator with
`home=S.RUNTIME`, so a definition outside `defender/scripts/` that is NOT under
`defender/runtime/` is "the move has not happened", and a second definition is a duplicate home.
Nothing from the new home is imported at module level: before the move each test fails on its
own, naming the symbol, never as a collection error.

THE WRITE-BACK DOES NOT MOVE HERE. `ticket_writer.py` stays in `defender/scripts/case_history/`
until #1165 moves it, so `_writer_home` takes `record_case_ticket`'s home outside `scripts/` when
one exists and its base module otherwise (s217's parked `_writer` asked only for the former).

GOLDENS ARE THE BASE: `goldens/tenants.json`, captured at 80888efb by running the `_observe_*`
functions below (the parked file's, unchanged but for the `home=` pin) under
`SPEC1080_AT_BASE=1`. With that variable set the locator answers with the base definitions, so
the behavioural tests here pass at a tree where the move has not happened: that is the check that
the goldens are still the code's behaviour. The structural tests stay red under it, since they
read the tree, not the locator: the env-read lint's lists, the whole-file name census (every base
name is still in `scripts/case_history/`) and the import-cycle check.

FAULTS ARE REAL INPUTS: real mapping files (BOM, undecodable bytes, a link out of the tenant
folder, a directory, a FIFO, the 1 MiB bound and one byte over), a real fresh interpreter per
module for the import-cycle check, the REAL `run.main` under `--update-ticket` with the store behind a `docker` shim
first on PATH (`_spec1107.DockerShim`), and the real lint's `scan` over a planted copy.
"""
from __future__ import annotations

import functools
import importlib
import inspect
import json
import os
import textwrap
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from defender.tests._by_path import load_lint_gate
from defender.tests.scripts_1080_split import _spec1080 as S
from defender.tests.scripts_1080_split.test_1080_writeback_tenants_and_views import (
    _children,
    _golden,
    _norm,
    _outcome_of,
)
from defender.tests.tenant_1107_settings import _census_1107 as C1107
from defender.tests.tenant_1107_settings import _spec1107 as T7
from defender.tests.tenant_1107_settings.test_1107_census_lint import _reported

#: Every planted tenant's marker (its config values carry it) and its id (the D9 tenant). The
#: goldens were captured with exactly these.
MARKER = "t1080"

TENANT = "playground"

#: The receipt's suffix beside the run dir (`run_repository.TICKET_WRITE_SUFFIX`, #1105's door) — used only
#: to pick receipts out of a runs base listing; where the writer puts one is the golden's.
RECEIPT_SUFFIX = ".ticket-write.json"


# ======================================================================================
# Where the code lives
# ======================================================================================


def _case_module() -> Any:
    """The case-mapping module: the one module under `defender/runtime/` defining
    `load_case_mapping` (the base module under `SPEC1080_AT_BASE`)."""
    return S.moved_module("load_case_mapping", home=S.RUNTIME)


def _moved(name: str) -> Any:
    """A case-mapping name from its home under `defender/runtime/`."""
    return S.moved(name, home=S.RUNTIME)


def _writer_home() -> str:
    """The write-back module's path, wherever it lives: `record_case_ticket`'s one home outside
    `defender/scripts/` once #1165 has moved it (the locator's one-home rule decides), else its
    one definition under `scripts/` — `case_history/ticket_writer.py`, which #1190 leaves in
    place. Decided by the definitions, never by catching the locator's failure (that would also
    swallow a duplicate home)."""
    defs = S.definitions("record_case_ticket")
    if any(not S.under(d, "defender/scripts") for d in defs):
        return S.home_of("record_case_ticket")
    assert len(defs) == 1, f"`record_case_ticket` has {len(defs)} definitions: {list(defs)}"
    return defs[0]


def _writer() -> Any:
    """The write-back module, imported by its dotted name."""
    return importlib.import_module(S.dotted(_writer_home()))


def _run_main_default_writer() -> Any:
    """`run.main`'s `ticket_writer` seam default — the module the production post-step reaches."""
    run = importlib.import_module("defender.run")
    return inspect.signature(run.main).parameters["ticket_writer"].default


# ======================================================================================
# A tenant, its record, a run
# ======================================================================================

#: The case-history mapping every scenario's tenant carries — spelled here, never copied from a
#: committed tenant. Its comment body renders the signature and case id too, so the alert and
#: the run id reach the outbound comment.
MAPPING = textwrap.dedent("""\
    source:
      signature: rule.id
      summary: rule.description
      event_time: timestamp
    open:
      key: "{case_id}"
      summary: "{summary}"
      description: "Opened from alert {case_id} (rule {signature})."
      status: open
      reporter: defender
      labels:
        - "sig:{signature}"
        - "evt:{event_time}"
    comment:
      author: defender-1080
      body: "[{signature}] {disposition} — {cause}\\n\\n{narrative}"
    released:
      status: closed
    """)

#: A mapping the loader refuses for its own lifecycle rule (open.status == released.status).
MAPPING_COLLIDING = MAPPING.replace("  status: closed\n", "  status: open\n")

#: A ticket patch that writes comments without releasing the case — what `applier.unservable`
#: judges with the mapping's released status.
TICKET_PATCH: dict[str, Any] = {"ticket": {"C-1": {"comments": [{"body": "x"}],
                                                   "status": "open"}}}


def report_text(disposition: str = "benign",
                cause: str = "the disposition was recorded without a challenge review",
                body: str = "Disposition recorded by the close gate. outcome=stands.") -> str:
    """`report.md` as the close gate writes it (YAML frontmatter; `_triplet_947.report_text`'s
    shape). `cause` is spelled verbatim into the frontmatter, so a caller quotes it if needed."""
    return (f"---\ndisposition: {disposition}\noutcome: stands\ncause: {cause}\n---\n{body}\n")


def _tenant(mapping: str | bytes | None = MAPPING) -> tuple[Path, Path]:
    """The D9 tenant set up under THIS test's data root (`DEFENDER_DATA_ROOT`), its knowledge
    replaced by a complete #1107 tenant (`_spec1107.plant`), its mapping file `mapping` when
    given. Returns (data root, knowledge folder)."""
    from defender.tests._data_root_1078 import current_data_root, ensure_d9_tenant

    ensure_d9_tenant()
    root = current_data_root()
    folder = T7.plant(root, marker=MARKER)
    if mapping is not None:
        path = T7.mapping_path(folder)
        if isinstance(mapping, bytes):
            path.write_bytes(mapping)
        else:
            path.write_text(mapping, encoding="utf-8")
    return root, folder


def _record(root: Path) -> Any:
    """The run's record, resolved the way run start resolves it (`run_tenant.resolve_tenant`,
    unmoved)."""
    from defender.runtime import run_tenant

    return run_tenant.resolve_tenant(root, TENANT, defender_dir=S.DEFENDER,
                                     dispatches_lead_zero=False)


def _held(mapping: Any) -> dict[str, Any]:
    """What a record holds as its `ticket_mapping`: the mapping's content, or the kept error."""
    if isinstance(mapping, BaseException):
        return {"error": type(mapping).__name__, "message": str(mapping)}
    return {"mapping": S.canon(mapping.plain())}


def _plain(mapping: Any) -> Any:
    return S.canon(mapping.plain())


def _store_ok(key: str) -> list[dict[str, Any]]:
    """The store's answers to one open + record: the case created, read back unreleased, the
    comment accepted."""
    return [T7.answer(json.dumps({"key": key}), "201"),
            T7.answer(json.dumps({"key": key, "status": "open", "comments": []}), "200"),
            T7.answer(json.dumps({"id": 1}), "201")]


def _calls(shim: Any) -> list[list[str]]:
    """Every docker argv the store saw, in order."""
    return [c["argv"] for c in shim.calls()]


def _posts(calls: list[list[str]]) -> int:
    """How many comments reached the store (a POST to `/comments`)."""
    return sum(1 for a in calls if "POST" in a and any(x.endswith("/comments") for x in a))


def _receipts(runs: Path) -> list[list[Any]]:
    """Every receipt beside the run dirs: `[name, its text]`, or `[name, {"link": target}]` /
    `[name, {"dir": [entries]}]` for an entry at a receipt's name that is not a plain file."""
    if not runs.is_dir():
        return []
    out: list[list[Any]] = []
    for p in sorted(runs.iterdir()):
        if not p.name.endswith(RECEIPT_SUFFIX):
            continue
        if p.is_symlink():
            out.append([p.name, {"link": os.readlink(p)}])
        elif p.is_dir():
            out.append([p.name, {"dir": sorted(c.name for c in p.iterdir())}])
        else:
            out.append([p.name, p.read_text(encoding="utf-8")])
    return out


def _drive_run(tmp: Path, mp: Any, *, answers: list[dict[str, Any]],
               before: Callable[[Path, Path], None] | None = None,
               report: str | None = report_text()) -> dict[str, Any]:
    """The REAL `run.main` under `--update-ticket`, its `ticket_writer` seam left at its
    production default, the store behind the docker shim (on THIS process's PATH, which run.py
    builds the run env from). The lifecycle fake leaves `report` in the run dir, then runs
    `before(run_dir, tenant folder)`. Returns what an operator could observe: the exit, the
    store's calls, the receipts."""
    root, folder = _tenant()
    alert = T7.plant_alert(tmp / "alert")
    shim = T7.DockerShim(tmp / "shim", answers)
    mp.setenv("PATH", shim.path_value())

    def lifecycle_tail(run_dir: Path) -> None:
        if report is not None:
            (run_dir / "report.md").write_text(report, encoding="utf-8")
        if before is not None:
            before(run_dir, folder)

    rec = T7.RunRecorder(tmp / "runs" / "r1080",
                         summary={"output": "spec1080", "requests": 0, "truncated_by": None},
                         before_lifecycle=lifecycle_tail)
    rc, refused = T7.drive_run(T7.run_argv(alert, root, update_ticket=True), rec,
                               visualize=rec.visualize)
    calls = _calls(shim)
    return {"rc": rc, "refused": None if refused is None else str(refused.code),
            "order": rec.order, "calls": calls, "posts": _posts(calls),
            "receipts": _receipts(tmp / "runs")}


# ======================================================================================
# s_case_mapping_read_at_run_start — the run-start record reads the moved module
# ======================================================================================


def _records_at_run_start() -> tuple[Any, Any]:
    """The run's record over a planted tenant, then again after its mapping is made one the
    loader refuses (open and released status equal): (good, bad)."""
    root, folder = _tenant()
    good = _record(root)
    T7.mapping_path(folder).write_text(MAPPING_COLLIDING, encoding="utf-8")
    return good, _record(root)


def _view_at_run_start(good: Any, bad: Any, tmp: Path) -> dict[str, Any]:
    from defender.learning.branch.estate import applier
    from defender.runtime import query_tool

    released = {"status": "closed"}
    unreleased = {"status": "open"}
    pred_good = query_tool._release_predicate(good)
    pred_bad = query_tool._release_predicate(bad)
    return _norm({
        "record_good": _held(good.ticket_mapping),
        "record_bad": _held(bad.ticket_mapping),
        "query_tool_good": [pred_good(released), pred_good(unreleased)],
        "query_tool_bad": [pred_bad(released), pred_bad(unreleased)],
        "applier_good": _outcome_of(applier.unservable, TICKET_PATCH, good.ticket_mapping),
        "applier_bad": _outcome_of(applier.unservable, TICKET_PATCH, bad.ticket_mapping),
    }, tmp)


def _observe_mapping_at_run_start(tmp: Path, mp: Any) -> dict[str, Any]:
    return _view_at_run_start(*_records_at_run_start(), tmp)


def test_1080_the_case_mapping_is_read_at_run_start_from_the_tenants_home(tmp_path):
    """The run-start record build (`run_tenant`) loads `CaseMapping` through `load_case_mapping`
    in its new home under `defender/runtime/`. A fixture tenant's mapping reads as at the base,
    and a bad mapping surfaces the moved `CaseTicketError`. `query_tool` and `estate/applier`
    reach the same module.

    Observed through the unmoved readers: `run_tenant.resolve_tenant` over a planted tenant holds
    an instance of the moved `CaseMapping` (content as at the base), and over a mapping the
    loader refuses (open and released status equal) an instance of the moved `CaseTicketError`
    (text as at the base). `query_tool._release_predicate` answers through the moved
    `ReleasePredicate`, and `applier.unservable` handed the record's kept error lists the
    refusal rather than letting it escape — which it would if the applier caught another copy of
    the error class. Every moved name is found under `defender/runtime/`, so a home anywhere
    else fails here."""
    home = _case_module()
    case_mapping, case_error = _moved("CaseMapping"), _moved("CaseTicketError")
    predicate_cls = _moved("ReleasePredicate")
    assert {case_mapping.__module__, case_error.__module__, predicate_cls.__module__} == {
        home.__name__}, "the case-mapping types are not all defined in the tenants home"

    from defender.runtime import query_tool

    good, bad = _records_at_run_start()
    assert isinstance(good.ticket_mapping, case_mapping), (
        f"the record holds {type(good.ticket_mapping)!r}, not the tenants home's CaseMapping")
    assert type(query_tool._release_predicate(good).__self__) is predicate_cls, (
        "query_tool's release predicate is not the tenants home's ReleasePredicate")
    assert isinstance(bad.ticket_mapping, case_error), (
        f"a refused mapping is held as {type(bad.ticket_mapping)!r}, not the moved "
        "CaseTicketError")

    assert _view_at_run_start(good, bad, tmp_path) == _golden(
        "s_case_mapping_read_at_run_start")


# ======================================================================================
# s090 — no import cycle, in any first-import order
# ======================================================================================

_COLD_IMPORT = r"""
import importlib, json, sys
first, watch = sys.argv[1], json.loads(sys.argv[2])
importlib.import_module(first)
print(json.dumps(sorted(m for m in watch if m in sys.modules)))
"""

#: The three modules that import the case-mapping module and that #1190 is about: the run-start
#: record build, the query door and the estate applier.
_NAMED_IMPORTERS = ("defender.runtime.run_tenant", "defender.runtime.query_tool",
                    "defender.learning.branch.estate.applier")
_SETTINGS = "defender.runtime.tenant_settings"


def _module_level_importers(module: str) -> set[str]:
    """Every non-test module under `defender/` whose MODULE-LEVEL code imports `module` (`import
    a.b`, `from a import b`, `from a.b import x` all count). An import inside a function runs
    after loading, so it cannot close an import cycle and is not counted."""
    parent, _, leaf = module.rpartition(".")
    out: set[str] = set()
    for rel in S.py_files(S.REPO_ROOT, ("defender",)):
        if S.is_test_path(rel):
            continue
        for st in S.import_statements(rel, (S.REPO_ROOT / rel).read_bytes()):
            if st.top_level and (st.module == module or (st.module == parent and leaf in st.names)):
                out.add(S.dotted(rel))
    return out


def test_case_mapping_module_is_imported_by_the_run_tenant_record_and_itself_imports_the_settings_module():  # noqa: E501
    """No import cycle among the case-mapping module, tenant settings, the run-tenant record, the
    query tool and the applier, so every first-import order of them works.

    Shown without enumerating orders. For each of the five modules, a fresh interpreter imports
    it ALONE and has then loaded none of its module-level importers (read off the tree, not
    listed by hand). A cycle through a module means loading it reaches something that imports
    it back at load time, so this covers every cycle that touches any of the five, whether or not
    it runs through the case-mapping module. Positive controls: the case-mapping module's import
    loads `runtime/tenant_settings`, and each of the three named importers, imported first,
    loads the case-mapping module."""
    case_mod = S.dotted(S.home_of("load_case_mapping", home=S.RUNTIME))
    modules = (case_mod, _SETTINGS, *_NAMED_IMPORTERS)
    importers = {m: _module_level_importers(m) for m in modules}
    assert set(_NAMED_IMPORTERS) <= importers[case_mod], (
        f"the census of {case_mod}'s importers misses named ones: {sorted(importers[case_mod])}")

    watch = json.dumps(sorted({case_mod, *modules, *(i for s in importers.values() for i in s)}))
    results = _children([["-c", _COLD_IMPORT, m, watch] for m in modules])
    failed = [(m, r.returncode, r.stderr.decode(errors="replace")[-600:])
              for m, r in zip(modules, results, strict=True) if r.returncode != 0]
    assert not failed, f"a cold first import fails: {failed[:3]}"
    loaded = {m: set(json.loads(r.stdout)) for m, r in zip(modules, results, strict=True)}
    cycles = {m: sorted(loaded[m] & importers[m]) for m in modules if loaded[m] & importers[m]}
    assert not cycles, f"importing a module alone loads its own importers (a cycle): {cycles}"
    assert _SETTINGS in loaded[case_mod], f"{case_mod} did not load {_SETTINGS}"
    for first in _NAMED_IMPORTERS:
        assert case_mod in loaded[first], f"{first} did not load {case_mod}"


def test_1190_the_whole_case_ticket_module_moved_to_one_runtime_home():
    """Pure whole-file move (design, decided: no split). Every module-level name the base
    `scripts/case_history/case_ticket.py` defined is, wherever it is still defined, defined in
    the ONE home under `defender/runtime/` (the module defining `load_case_mapping`); a name
    later deleted outright (dead code) is allowed. The home has no module-level `__getattr__`,
    which could serve a name from another module by a string import the AST census cannot see.

    A split that moves part of the module elsewhere (a sibling runtime module re-exported, or
    the comment half kept beside `ticket_writer`) leaves names defined outside the home and not
    in it, and fails. Since the code stays in the home, the env-read sweep of the home covers it.
    Positive control: the census is non-empty and includes names from both halves (the mapping
    loader and the comment payloads), all defined in the home today."""
    base = S.base_inventory()["py_names"]["defender/scripts/case_history/case_ticket.py"]
    home = S.home_of("load_case_mapping", home=S.RUNTIME)
    both_halves = {"load_case_mapping", "case_record_to_comment", "WIRE_BOUND_BYTES"}
    assert both_halves <= set(base)
    assert all(home in S.definitions(n) for n in both_halves), "control: the home lacks a half"
    elsewhere = {n: list(S.definitions(n)) for n in base
                 if S.definitions(n) and home not in S.definitions(n)}
    assert not elsewhere, f"names of the base module now defined only outside {home}: {elsewhere}"
    assert "__getattr__" not in S.module_level_names((S.REPO_ROOT / home).read_bytes(), home)


# ======================================================================================
# s187 — the mapping file in each state
# ======================================================================================

_LARGE = 1 << 20  # `tenant_settings.SETTINGS_MAX_BYTES` at the base


def _pad_to(text: str, size: int) -> bytes:
    """`text` followed by one YAML comment line making the file exactly `size` bytes."""
    head = text.encode("utf-8")
    filler = size - len(head) - 3
    return head + b"# " + b"x" * filler + b"\n"


#: Each file state, as the bytes put at the mapping's path. `None` content means the state is
#: set up by hand in `_put_state` (`outside` is a folder beyond the tenant's).
FILE_STATES: dict[str, Any] = {
    "absent": None,
    "empty": b"",
    "whitespace_only": b"  \n\t \n\n",
    "bom_prefixed": b"\xef\xbb\xbf" + MAPPING.encode("utf-8"),
    "non_utf8": MAPPING.replace("defender-1080", "défense").encode("latin-1", "replace"),
    "at_the_bound": _pad_to(MAPPING, _LARGE),
    "one_byte_over": _pad_to(MAPPING, _LARGE + 1),
    "symlink_out_of_the_tenant_folder": None,
    "directory": None,
    "fifo": None,
}


def _put_state(path: Path, state: str, outside: Path) -> None:
    path.unlink(missing_ok=True)
    content = FILE_STATES[state]
    if content is not None:
        path.write_bytes(content)
    elif state == "symlink_out_of_the_tenant_folder":
        outside.mkdir(parents=True, exist_ok=True)
        target = outside / "mapping.yaml"
        target.write_text(MAPPING, encoding="utf-8")
        path.symlink_to(target)
    elif state == "directory":
        path.mkdir()
    elif state == "fifo":
        os.mkfifo(path)


def _observe_mapping_file(state: str, tmp: Path, mp: Any) -> dict[str, Any]:
    load = _moved("load_case_mapping")
    root, folder = _tenant()
    _put_state(T7.mapping_path(folder), state, tmp / "outside")
    loaded = _outcome_of(load, T7.settings_of(folder), view=_plain)
    try:
        held: Any = _held(_record(root).ticket_mapping)
    except Exception as e:  # noqa: BLE001 — a refusal at run start is the observed outcome
        held = {"refused": type(e).__name__, "message": str(e)}
    return _norm({"load_case_mapping": loaded, "held_on_run_tenant": held}, tmp)


@pytest.mark.parametrize("state", list(FILE_STATES))
def test_case_mapping_file_in_each_state(state, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A case-mapping file that is absent, empty,
    whitespace-only, BOM- prefixed, non-UTF-8, very large, a symlink out of the tenant folder or
    a directory loads, or yields the same CaseTicketError, as today and is held on RunTenant at
    run start.

    Each state is a real file put at the tenant's mapping path (the size states at the base's
    1 MiB settings bound and one byte over it; a FIFO besides). Observed twice: the moved
    `load_case_mapping` (its home under `defender/runtime/`) over the settings folder, and what
    `run_tenant.resolve_tenant` holds as the record's `ticket_mapping` (or how run start
    refuses) — both against the base golden."""
    assert _observe_mapping_file(state, tmp_path, None) == _golden("s187")[state]


# ======================================================================================
# s188 — YAML of the wrong shape
# ======================================================================================

#: YAML documents of the wrong shape (each a complete file).
YAML_SHAPES: dict[str, str] = {
    "list": "- source\n- open\n",
    "scalar": "just a sentence\n",
    "null_tilde": "~\n",
    "null_word": "null\n",
    "comment_only": "# nothing here\n",
    "duplicate_top_level_key": MAPPING + "comment:\n  author: someone-else\n  body: \"{case_id}\"\n",
    "duplicate_nested_key": MAPPING.replace("  status: closed\n",
                                            "  status: closed\n  status: open\n"),
    "unknown_keys": MAPPING + "escalate:\n  to: nobody\nextra: 1\n",
    "open_status_an_integer": MAPPING.replace("  status: open\n", "  status: 42\n"),
    "open_status_a_template": MAPPING.replace("  status: open\n", "  status: \"{signature}\"\n"),
    "released_a_scalar": MAPPING.replace("released:\n  status: closed\n", "released: closed\n"),
    "comment_author_a_list": MAPPING.replace("  author: defender-1080\n",
                                             "  author: [a, b]\n"),
    "comment_missing": MAPPING.replace(
        "comment:\n  author: defender-1080\n"
        "  body: \"[{signature}] {disposition} — {cause}\\n\\n{narrative}\"\n", ""),
    "anchor_and_alias": MAPPING.replace("open:\n", "base: &b {status: open}\nopen:\n")
    .replace("released:\n  status: closed\n", "released: *b\n"),
    "merge_key": MAPPING.replace("open:\n", "base: &b {reporter: defender}\nopen:\n  <<: *b\n"),
    "python_object_tag": MAPPING + "hook: !!python/object/apply:os.getcwd []\n",
    "python_name_tag": MAPPING + "hook: !!python/name:os.system\n",
    "invalid_yaml": "open: [unclosed\n",
    "tab_indented": "open:\n\tstatus: open\n",
    "two_documents": MAPPING + "---\nsecond: doc\n",
}


def _observe_yaml_shape(shape: str, tmp: Path, mp: Any) -> dict[str, Any]:
    load, predicate = _moved("load_case_mapping"), _moved("release_predicate")
    settings = tmp / "settings"
    path = settings / "systems" / "case-history" / "mapping.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(YAML_SHAPES[shape], encoding="utf-8")
    loaded = _outcome_of(load, settings, view=_plain)
    used: Any = None
    if "returns" in loaded:
        used = _outcome_of(lambda: predicate(load(settings)).released_status)
    return _norm({"load_case_mapping": loaded, "release_predicate": used}, tmp)


@pytest.mark.parametrize("shape", list(YAML_SHAPES))
def test_case_mapping_yaml_of_the_wrong_shape(shape, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A mapping that parses as a list, scalar or null, or with
    duplicate or unknown keys, wrong-typed values, anchors/aliases or a language-object tag is
    accepted or refused as today.

    Each shape is a real file read by the moved `load_case_mapping` (its home under
    `defender/runtime/`); an accepted one is also used once (the moved `release_predicate`, the
    reader every consumer goes through). Both outcomes against the base golden."""
    assert _observe_yaml_shape(shape, tmp_path, None) == _golden("s188")[shape]


# ======================================================================================
# s217 — the snapshot taken at run start is what the post-step uses
# ======================================================================================

#: What changes in the tenant's folder after run start (inside the lifecycle).
EDITS: dict[str, Callable[[Path], None]] = {
    "mapping_edited": lambda folder: T7.mapping_path(folder).write_text(
        MAPPING.replace("[{signature}]", "EDITED {case_id}").replace("defender-1080", "editor"),
        encoding="utf-8"),
    "mapping_removed": lambda folder: T7.mapping_path(folder).unlink(),
    "mapping_made_invalid": lambda folder: T7.mapping_path(folder).write_text(
        "open: [unclosed\n", encoding="utf-8"),
    "ticket_config_edited": lambda folder: T7.set_key(
        folder, "case-history", "CASE_HISTORY_URL_BASE", "http://edited-store:9999"),
    "ticket_config_removed": lambda folder: T7.config_path(folder, "case-history").unlink(),
}


def _observe_edit(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    edit = EDITS[case]
    return _norm(_drive_run(tmp, mp, answers=_store_ok("r1080"),
                            before=lambda _run_dir, folder: edit(folder)), tmp)


@pytest.mark.parametrize("case", list(EDITS))
def test_case_mapping_edited_or_removed_between_run_start_and_the_post_step(case, tmp_path,
                                                                            monkeypatch):
    """The post-step uses the case mapping snapshot taken at run start (it is held on RunTenant
    at run start), not the file as edited or removed afterwards; the ticket system's own config
    is read when the writer runs, as today. The move changes neither.

    The REAL `run.main` under `--update-ticket`, the tenant's folder changed inside the
    lifecycle (after run start, before the post-step): the mapping edited, removed or made
    invalid, the case-history `config.env` edited or removed. The store's calls (which store,
    which comment) and the receipt against the base golden. The production writer is the
    write-back module wherever it lives (`ticket_writer` stays under `scripts/` until #1165).
    That the snapshot on the record is the tenants home's `CaseMapping` is pinned once, by
    `test_1080_the_case_mapping_is_read_at_run_start_from_the_tenants_home`."""
    assert _run_main_default_writer() is _writer(), "run.main's post-step is not the writer"
    assert _observe_edit(case, tmp_path, monkeypatch) == _golden("s217")[case]


# ======================================================================================
# O3 — the env-read lint still sweeps the case-mapping code
# ======================================================================================

ENV_LINT = "lint_tenant_env_reads"

#: A swept tree that stays where it is: the plant there proves the scan's observation channel.
ENV_CONTROL = "defender/scripts/adapters/cmdb_adapter.py"

#: The plant: one environment lookup inside a uniquely named function.
ENV_PLANT = (
    "\n\nimport os as _spec1190_os  # planted by #1190's env-read lint test\n\n\n"
    "def _spec1190_plant():\n"
    '    return _spec1190_os.environ.get("SPEC1190_PLANT")\n'
)


@functools.cache
def _env_lint() -> Any:
    return load_lint_gate(ENV_LINT, name=f"{ENV_LINT}_spec1190")


def _plant_env_read(root: Path, relpath: str) -> int:
    """A copy of `relpath`'s CURRENT source (this checkout's) at `root/relpath` with `ENV_PLANT`
    appended; the 1-based line of the planted environment read."""
    before = (S.REPO_ROOT / relpath).read_text(encoding="utf-8")
    if not before.endswith("\n"):
        before += "\n"
    T7.plant_module(root, relpath, before + ENV_PLANT)
    head, _, _ = ENV_PLANT.partition(".environ")
    return before.count("\n") + head.count("\n") + 1


def test_1190_the_env_read_lint_sweeps_the_moved_case_mapping_module_and_the_staying_writer(
        tmp_path):
    """The env-read lint (`lint_tenant_env_reads`, #1107 O7) still sweeps the case-mapping code
    after the move, and the move narrows nothing: the module defining `load_case_mapping` (under
    `defender/runtime/`) is in the lint's own file set over the real tree, and so is the
    write-back module (`record_case_ticket`'s, which stays in `defender/scripts/case_history/`
    until #1165). The lint itself refuses a swept entry missing from this repo (its own test,
    `test_o7_lint_refuses_a_swept_entry_missing_from_this_repo`); its test twin
    `_census_1107.SWEPT` lists the same entries and reaches both modules. The moved module carries no environment read in the real
    tree.

    Driven: an `os.environ` read planted in a tmp copy of the moved module, at the path the
    real tree gives it, is reported by the lint's own `scan` (not `main`: the lint keeps no
    baseline, and nothing can hide the plant); so is the same plant in a copy of the write-back
    module. Positive control: the same plant in the cmdb adapter, a swept tree that stays, is
    reported by the same scan, so a scan that sees nothing cannot pass."""
    lint = _env_lint()
    mapping = S.home_of("load_case_mapping", home=S.RUNTIME)
    writer = _writer_home()

    assert set(lint.SWEPT) == set(C1107.SWEPT), (
        f"the env-read lint and its test twin sweep different trees: lint only "
        f"{sorted(set(lint.SWEPT) - set(C1107.SWEPT))}, twin only "
        f"{sorted(set(C1107.SWEPT) - set(lint.SWEPT))}")
    swept = {S.rel(p) for p in lint._swept_files(S.REPO_ROOT)}
    twin = {S.rel(p) for p in C1107.swept_py(S.REPO_ROOT)}
    for module in (mapping, writer):
        assert module in swept, f"{module} is outside lint_tenant_env_reads' sweep"
        assert module in twin, f"{module} is outside _census_1107.swept_py"
    in_real = [f for f in lint.scan(S.REPO_ROOT) if f.startswith(f"{mapping}:")]
    assert in_real == [], f"the moved case-mapping module reads the environment: {in_real}"

    root = tmp_path / "tree"
    planted = {r: _plant_env_read(root, r) for r in dict.fromkeys((ENV_CONTROL, mapping, writer))}
    found = "\n".join(lint.scan(root))
    assert _reported(found, ENV_CONTROL, planted[ENV_CONTROL]), (
        f"control: the env read planted in {ENV_CONTROL} was not reported: {found}")
    missed = [r for r in (mapping, writer) if not _reported(found, r, planted[r])]
    assert not missed, f"env reads planted in {missed} were not reported: {found}"


#: demand -> (observer, its case names or None): the capture of `goldens/tenants.json` for the
#: demands this file adopts (run at the base under `SPEC1080_AT_BASE=1`, each case in a fresh
#: data root and tmp dir: `observer(case, tmp, mp)`, or `observer(tmp, mp)` for one case).
OBSERVERS: Mapping[str, tuple[Callable[..., Any], list[str] | None]] = {
    "s_case_mapping_read_at_run_start": (_observe_mapping_at_run_start, None),
    "s187": (_observe_mapping_file, list(FILE_STATES)),
    "s188": (_observe_yaml_shape, list(YAML_SHAPES)),
    "s217": (_observe_edit, list(EDITS)),
}
