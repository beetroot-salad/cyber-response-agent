# PRE-CUT COPY 2026-10-04 (scope cut of #1080, human-decided; 94-reconciliation-cut.md F-2): preserved, NOT collected.
# This is defender/tests/scripts_1080_split/test_1080_writeback_tenants_and_views.py as it stood before the cut, copied verbatim
# from the cut author's scratch backup; the only additions are these `#` comment lines. It keeps
# the cells the cut removed from KEPT tests: the OUT halves of narrowed tests, and the tables and
# helpers the cut narrowed or deleted. Each such node carries a `# PRE-CUT …` marker naming the
# issue(s) that own its cut cells; an owner adopts those cells when its module moves. Nodes without
# a marker are unchanged in the live suite, or were parked whole (their canonical copy is
# ../parked_writeback_tenants_and_views.py, annotated with their owners). The file name does not match test_*.py, so pytest never
# collects it. It imports the LIVE helper modules; their pre-cut versions are
# parked_precut__spec1080.py and parked_precut__census1080.py beside this file (_pointers1080.py did
# not change). The goldens it reads are split between the suite's goldens/ and ../goldens/. Each
# narrowed kept demand's `parked_cells` block in spec-flow/specs/spec_graph_1080-scripts-split.yaml
# points at its pre-cut function here.
"""#1080 (group `tenants`) — the write-back home, the tenants home and the two model-facing views.

What moves, and how each test reaches it (homes are FOUND BY SYMBOL, dF0):

  * the case-mapping format (`case_ticket.py`) — into the tenants home, a package that may import
    runtime (M-G (b)): `S.home_of("load_case_mapping")`. Its readers do not move:
    `runtime/run_tenant.py` (the record built at run start), `runtime/query_tool.py` and
    `learning/branch/estate/applier.py`.
  * the ticket write-back (`ticket_writer.py`) — `S.home_of("record_case_ticket")`. It keeps
    importing `scripts/adapters/_stub_transport` (H4 (i): a named O1 exception). `run.py`'s
    `--update-ticket` post-steps reach it through `run.main`'s `ticket_writer` seam, whose
    production default is the module itself.
  * the workspace map (`workspace_map.py`, its `__main__` dropped, M-D (a)) —
    `S.home_of("workspace_map")`; `runtime/orient.py` splices it into message zero under
    `## Workspace`, with `_(unavailable: …)_` as the fallback (G8, RG4).
  * the payload view (`gather_tools/payload_view.py`) — `S.home_of("passthrough_max_bytes")`
    (`render` and `walk` are reached as attributes of that module: `render` has six homes).

Nothing from a new home is imported at module level: a missing home is one failing test, never a
collection error.

GOLDENS ARE THE BASE. Every "as today" expectation is `goldens/tenants.json`, captured once at
80888efb by running the `_observe_*` functions below — the very code the tests run — with
`SPEC1080_AT_BASE` set to 1, so the locator resolved the base definitions. `_norm` is the ONE place a
volatile string is rewritten (the case's tmp root, the data root, this checkout's root), used by
the capture and the tests alike.

FAULTS ARE REAL INPUTS: the mapping files are real files (BOM, undecodable bytes, a link out of
the tenant folder, a directory, a 1 MiB + 1 file), the run-dir entries are real names, the
checkout copies are real directory trees at awkward paths, the environment variable is really
set. The one dependency too expensive to drive is the docker CLI, faked the way CX8 (executed)
says it can be: a `docker` executable first on the PATH the transport forks with
(`_spec1107.DockerShim`), recording every argv and answering in curl's body + status-line shape
(the transport's own contract; AP3 for `curl_refused`). The interrupted post-step is a real
SIGKILL of the real writer process, sent by a shim at the moment the store accepts the comment.
"""
from __future__ import annotations

import hashlib
import importlib
import inspect
import itertools
import json
import logging
import os
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from defender.tests.scripts_1080_split import _spec1080 as S
from defender.tests.tenant_1107_settings import _spec1107 as T7

GOLDEN = "tenants"

#: Every planted tenant's marker (its config values carry it) and its id (the D9 tenant).
MARKER = "t1080"
TENANT = "playground"
DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
PASSTHROUGH_ENV = "DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES"

#: The receipt's suffix beside the run dir (`_run_paths.TICKET_WRITE_SUFFIX`, unmoved) — used only
#: to pick receipts out of a runs base listing; where the writer puts one is the golden's.
RECEIPT_SUFFIX = ".ticket-write.json"


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


def _section(text: str, heading: str) -> list[str]:
    """The lines of the `## …` section of a map that starts with `heading`, up to its blank
    line; `[]` when the map has no such section."""
    assert isinstance(text, str), f"the workspace map is not text: {text!r}"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(heading):
            out = [line]
            for nxt in lines[i + 1:]:
                if not nxt.strip():
                    break
                out.append(nxt)
            return out
    return []


def _workspace_section(message_zero: str) -> str:
    """Orient's `## Workspace` section, as spliced into message zero (up to the next section,
    the invlang catalog)."""
    start = message_zero.index("## Workspace\n")
    end = message_zero.find("\n\n## invlang catalog", start)
    return message_zero[start:end if end >= 0 else None]


def _children(argvs: Sequence[Sequence[str]], *, env: Mapping[str, str] | None = None,
              limit: int = 6, timeout: float = 120) -> list[subprocess.CompletedProcess[bytes]]:
    """Each argv as a fresh child of this interpreter (cwd this checkout, PYTHONPATH this
    checkout, `S.child_env`), at most `limit` at once; results in input order."""
    env = dict(S.child_env(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1") if env is None else env)
    results: list[subprocess.CompletedProcess[bytes] | None] = [None] * len(argvs)
    pending = list(enumerate(argvs))
    running: list[tuple[int, list[str], subprocess.Popen[bytes]]] = []
    while pending or running:
        while pending and len(running) < limit:
            i, argv = pending.pop(0)
            full = [sys.executable, *argv]
            running.append((i, full, subprocess.Popen(  # noqa: S603 — argv built by the test
                full, cwd=S.REPO_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)))
        i, full, proc = running.pop(0)
        out, err = proc.communicate(timeout=timeout)
        results[i] = subprocess.CompletedProcess(full, proc.returncode, out, err)
    return [r for r in results if r is not None]


# ======================================================================================
# The tenant, the run dir, the store (the ticket post-step's world)
# ======================================================================================

#: The case-history mapping every ticket scenario's tenant carries — spelled here, never copied
#: from a committed tenant. Its comment body renders the signature and case id too, so the alert
#: and the run id reach the outbound comment.
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

#: An alert as the run dir holds it.
ALERT: dict[str, Any] = {"alert_id": "a-1080", "rule": {"id": "r-1080",
                                                       "description": "spec 1080 rule"},
                         "timestamp": "2026-10-03T00:00:00Z"}


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


def _run_dir(runs: Path, name: str | bytes, *, alert: Any = ALERT,
             report: str | None = None) -> Path:
    """A finished run dir `runs/<name>` holding `alert.json` (unless `alert` is None) and
    `report.md` (when `report` is given)."""
    runs.mkdir(parents=True, exist_ok=True)
    path = Path(os.fsdecode(os.path.join(os.fsencode(runs), os.fsencode(name))))
    path.mkdir()
    if alert is not None:
        (path / "alert.json").write_text(json.dumps(alert), encoding="utf-8")
    if report is not None:
        (path / "report.md").write_text(report, encoding="utf-8")
    return path


def _store_ok(key: str) -> list[dict[str, Any]]:
    """The store's answers to one open + record: the case created, read back unreleased, the
    comment accepted."""
    return [T7.answer(json.dumps({"key": key}), "201"),
            T7.answer(json.dumps({"key": key, "status": "open", "comments": []}), "200"),
            T7.answer(json.dumps({"id": 1}), "201")]


def _shim_env(shim: Any) -> dict[str, str]:
    """The run env the writer is handed: a bare environment (UTF-8 mode, so a non-ASCII argv
    reaches the shim whatever the box's locale) with the shim first on PATH."""
    return shim.env(base=S.child_env(pythonpath=False, PYTHONUTF8="1"))


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


def _writer() -> Any:
    """The write-back module, wherever the move put it."""
    return S.moved_module("record_case_ticket")


def _run_main_default_writer() -> Any:
    """`run.main`'s `ticket_writer` seam default — the module the production post-step reaches."""
    run = importlib.import_module("defender.run")
    return inspect.signature(run.main).parameters["ticket_writer"].default


def _post_step(writer: Any, run_dir: Path, record: Any, shim: Any, *, opened: bool = False,
               **kw: Any) -> None:
    """`run.py`'s `--update-ticket` post-step(s), called as run.py calls them (`tenant`,
    `defender_dir`, `env` keywords): the open leg when `opened`, then the record leg."""
    env = _shim_env(shim)
    if opened:
        writer.open_case_ticket(run_dir, tenant=record, defender_dir=S.DEFENDER, env=env)
    writer.record_case_ticket(run_dir, tenant=record, defender_dir=S.DEFENDER, env=env, **kw)


class _Recorder(T7.RunRecorder):
    """`_spec1107.RunRecorder` (one recording fake per `run.main` seam) with two faults it can
    inject: a preflight that refuses (`preflight_rc`), and a materialize that leaves no
    `alert.json` in the run dir (`alert_in_run=False`)."""

    def __init__(self, run_dir_at: Path, *, preflight_rc: int = 0, alert_in_run: bool = True,
                 **kw: Any) -> None:
        super().__init__(run_dir_at, **kw)
        self.preflight_rc = preflight_rc
        self.alert_in_run = alert_in_run

    def preflight(self, model: str | None = None) -> int:
        self.order.append("preflight")
        return self.preflight_rc

    def materialize(self, alert: Path, run_id: str | None, **kw: Any) -> Any:
        run = super().materialize(alert, run_id, **kw)
        if not self.alert_in_run:
            (self.run_dir_at / "alert.json").unlink()
        return run


def _drive_run(tmp: Path, mp: Any, *, answers: list[dict[str, Any]],
               summary: dict[str, Any] | None = None, before: Any = None,
               report: str | None = report_text(), **rec_kw: Any) -> dict[str, Any]:
    """The REAL `run.main` under `--update-ticket`, its `ticket_writer` seam left at its
    production default, the store behind the docker shim (on THIS process's PATH, which run.py
    builds the run env from). The lifecycle fake leaves `report` in the run dir, then runs
    `before(run_dir)`. Returns what an operator could observe: the exit, the store's calls, the
    receipts."""
    root, folder = _tenant()
    alert = T7.plant_alert(tmp / "alert")
    shim = T7.DockerShim(tmp / "shim", answers)
    mp.setenv("PATH", shim.path_value())

    def lifecycle_tail(run_dir: Path) -> None:
        if report is not None:
            (run_dir / "report.md").write_text(report, encoding="utf-8")
        if before is not None:
            before(run_dir, folder)

    rec = _Recorder(tmp / "runs" / "r1080", summary={"output": "spec1080", "requests": 0,
                                                    "truncated_by": None, **(summary or {})},
                    before_lifecycle=lifecycle_tail, **rec_kw)
    rc, refused = T7.drive_run(T7.run_argv(alert, root, update_ticket=True), rec,
                               visualize=rec.visualize)
    calls = _calls(shim)
    return {"rc": rc, "refused": None if refused is None else str(refused.code),
            "order": rec.order, "calls": calls, "posts": _posts(calls),
            "receipts": _receipts(tmp / "runs")}


# ======================================================================================
# The case mapping: read once at run start, from the tenants home
# ======================================================================================

#: A mapping the loader refuses for its own lifecycle rule (open.status == released.status).
MAPPING_COLLIDING = MAPPING.replace("  status: closed\n", "  status: open\n")

#: A ticket patch that writes comments without releasing the case — what `applier.unservable`
#: judges with the mapping's released status.
TICKET_PATCH: dict[str, Any] = {"ticket": {"C-1": {"comments": [{"body": "x"}],
                                                   "status": "open"}}}


def _observe_mapping_at_run_start(tmp: Path, mp: Any) -> dict[str, Any]:
    from defender.learning.branch.estate import applier
    from defender.runtime import query_tool

    root, folder = _tenant()
    good = _record(root)
    T7.mapping_path(folder).write_text(MAPPING_COLLIDING, encoding="utf-8")
    bad = _record(root)
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


def test_1080_the_case_mapping_is_read_at_run_start_from_the_tenants_home(tmp_path):
    """The run-start record build (`run_tenant`) loads `CaseMapping` through `load_case_mapping`
    in its new home. A fixture tenant's mapping reads as at the base, and a bad mapping surfaces
    the moved `CaseTicketError`. `query_tool` and `estate/applier` reach the same module.

    Observed through the unmoved readers: `run_tenant.resolve_tenant` over a planted tenant holds
    an instance of the moved `CaseMapping` (content as at the base), and over a mapping the
    loader refuses (open and released status equal) an instance of the moved `CaseTicketError`
    (text as at the base). `query_tool._release_predicate` answers through the moved
    `ReleasePredicate`, and `applier.unservable` handed the record's kept error lists the
    refusal rather than letting it escape — which it would if the applier caught another copy of
    the error class."""
    home = S.moved_module("load_case_mapping")
    case_mapping, case_error = S.moved("CaseMapping"), S.moved("CaseTicketError")
    predicate_cls = S.moved("ReleasePredicate")
    assert {case_mapping.__module__, case_error.__module__, predicate_cls.__module__} == {
        home.__name__}, "the case-mapping types are not all defined in the tenants home"

    from defender.runtime import query_tool

    root, folder = _tenant()
    good = _record(root)
    assert isinstance(good.ticket_mapping, case_mapping), (
        f"the record holds {type(good.ticket_mapping)!r}, not the tenants home's CaseMapping")
    assert type(query_tool._release_predicate(good).__self__) is predicate_cls, (
        "query_tool's release predicate is not the tenants home's ReleasePredicate")
    T7.mapping_path(folder).write_text(MAPPING_COLLIDING, encoding="utf-8")
    bad = _record(root)
    assert isinstance(bad.ticket_mapping, case_error), (
        f"a refused mapping is held as {type(bad.ticket_mapping)!r}, not the moved "
        "CaseTicketError")

    assert _observe_mapping_at_run_start(tmp_path, None) == _golden(
        "s_case_mapping_read_at_run_start")


# ======================================================================================
# The ticket post-step through run.main's seam
# ======================================================================================


def _observe_post_step(tmp: Path, mp: Any) -> dict[str, Any]:
    return _norm(_drive_run(tmp, mp, answers=_store_ok("r1080")), tmp)


def test_1080_the_ticket_post_step_reaches_the_moved_writer(tmp_path, monkeypatch):
    """`run.py`'s `--update-ticket` post-step calls `record_case_ticket` in the write-back home
    through the `ticket_writer=` seam, and records the same comment as at the base.

    The seam's production default IS the write-back home's module (so run.py, not a test,
    chose it), and `run.main` driven with that default under `--update-ticket` makes the same
    store calls — the open, the read-back, the one comment POST with the same body — and leaves
    the same receipt as the base did (golden). The positive control is the golden itself: one
    comment posted."""
    default = _run_main_default_writer()
    assert default is _writer(), (
        f"run.main's ticket_writer seam defaults to {default!r}, not the write-back home")
    got = _observe_post_step(tmp_path, monkeypatch)
    assert got["posts"] == 1, f"the post-step posted {got['posts']} comments: {got['calls']}"
    assert got == _golden("s_ticket_post_step")


# ======================================================================================
# s042 — the logger name the existing suite filters on
# ======================================================================================


def test_existing_test_filters_log_records_by_the_moved_modules_logger_name(tmp_path, caplog):
    """A test that filters log records by a module's logger name still observes the warning it
    asserts about: the filter selects the logger of the module that now emits the warnings, and
    the test fails if a warning is emitted by a logger it does not collect (a positive control).
    'No warning was logged' passing on an empty filter is a failure. The O5 suites keep their
    assertions; fixtures are repointed.

    The existing filter is `test_1107_ticket_writer`'s (`TW_LOGGER`, `_warnings`), the one test
    module that filters on the writer's logger name. It must name the moved module, and driven
    with a real fault (the tenant's case-history `config.env` deleted) the moved writer's
    warning must reach that filter — every WARNING the step emits is on that logger, and the
    filter is not empty."""
    writer = _writer()
    existing = importlib.import_module(
        "defender.tests.tenant_1107_settings.test_1107_ticket_writer")
    assert writer.__name__ == existing.TW_LOGGER, (
        f"test_1107 filters on {existing.TW_LOGGER!r}; the write-back module logs as "
        f"{writer.__name__!r}")

    root, folder = _tenant()
    T7.config_path(folder, "case-history").unlink()
    record = _record(root)
    run_dir = _run_dir(tmp_path / "runs", "r1080", report=report_text())
    shim = T7.DockerShim(tmp_path / "shim")
    caplog.set_level(logging.INFO)
    caplog.clear()
    _post_step(writer, run_dir, record, shim)

    warned = existing._warnings(caplog)
    assert warned, "the existing filter collected no warning from the moved writer"
    stray = [(r.name, r.getMessage()) for r in caplog.records
             if r.levelno >= logging.WARNING and r.name != existing.TW_LOGGER]
    assert not stray, f"warnings the existing filter does not collect: {stray}"
    receipt = _receipts(tmp_path / "runs")
    assert receipt, "the warned-about failure left no receipt"
    assert json.loads(receipt[0][1])["status"] == "error", receipt
    assert not _calls(shim), "a tenant with no case-history config still reached the store"


# ======================================================================================
# s090 — cold imports in every first-import order
# ======================================================================================

_COLD_IMPORT = r"""
import importlib, json, sys
order, case_mod, settings_mod = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
seen = []
for name in order:
    importlib.import_module(name)
    seen.append([name, case_mod in sys.modules, settings_mod in sys.modules])
print(json.dumps(seen))
"""


def test_case_mapping_module_is_imported_by_the_run_tenant_record_and_itself_imports_the_settings_module():  # noqa: E501
    """A cold import of each of the four modules (case mapping, RunTenant, the query tool, the
    applier) works in every first-import order: no import cycle among the case-mapping module,
    tenant settings and the run-tenant record, wherever the tenants home sits.

    All 24 orders, each in a fresh interpreter (PYTHONPATH this checkout). In every order the
    run-tenant record's import has loaded the case-mapping module, and the case-mapping
    module's import has loaded `runtime/tenant_settings`."""
    case_mod = S.dotted(S.home_of("load_case_mapping"))
    run_tenant, settings = "defender.runtime.run_tenant", "defender.runtime.tenant_settings"
    modules = (case_mod, run_tenant, "defender.runtime.query_tool",
               "defender.learning.branch.estate.applier")
    orders = list(itertools.permutations(modules))
    results = _children([["-c", _COLD_IMPORT, json.dumps(order), case_mod, settings]
                         for order in orders])
    failed = [(order[0], r.returncode, r.stderr.decode(errors="replace")[-600:])
              for order, r in zip(orders, results, strict=True) if r.returncode != 0]
    assert not failed, f"a first-import order fails: {failed[:3]}"
    for order, r in zip(orders, results, strict=True):
        seen = {name: (case_loaded, settings_loaded)
                for name, case_loaded, settings_loaded in json.loads(r.stdout)}
        assert seen[run_tenant][0], f"{order}: run_tenant did not load {case_mod}"
        assert seen[case_mod][1], f"{order}: {case_mod} did not load {settings}"


# ======================================================================================
# s187 / s188 — the mapping file in each state, and YAML of the wrong shape
# ======================================================================================

_LARGE = 1 << 20  # `tenant_settings.SETTINGS_MAX_BYTES` at the base


def _pad_to(text: str, size: int) -> bytes:
    """`text` followed by one YAML comment line making the file exactly `size` bytes."""
    head = text.encode("utf-8")
    filler = size - len(head) - 3
    return head + b"# " + b"x" * filler + b"\n"


#: Each file state, as a function that puts it at the mapping's path (`outside` is a folder
#: beyond the tenant's). `None` content means the state is set up by hand below.
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


def _plain(mapping: Any) -> Any:
    return S.canon(mapping.plain())


def _observe_mapping_file(state: str, tmp: Path, mp: Any) -> dict[str, Any]:
    load = S.moved("load_case_mapping")
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
    `load_case_mapping` over the settings folder, and what `run_tenant.resolve_tenant` holds as
    the record's `ticket_mapping` (or how run start refuses) — both against the base golden."""
    assert _observe_mapping_file(state, tmp_path, None) == _golden("s187")[state]


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
    load, predicate = S.moved("load_case_mapping"), S.moved("release_predicate")
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

    Each shape is a real file read by the moved `load_case_mapping`; an accepted one is also
    used once (the moved `release_predicate`, the reader every consumer goes through). Both
    outcomes against the base golden."""
    assert _observe_yaml_shape(shape, tmp_path, None) == _golden("s188")[shape]


# ======================================================================================
# s189 / s190 — the comment and the receipt for unusual inputs
# ======================================================================================

_LONG_BODY = ("Evidence line with é and 中文 and 🙂. " * 200).strip()

#: (alert, report) per case; `None` alert or report means the run dir has none.
COMMENT_INPUTS: dict[str, tuple[Any, str | None]] = {
    "control": (ALERT, report_text()),
    "no_alert": (None, report_text()),
    "no_report": (ALERT, None),
    "alert_not_json": ("{not json", report_text()),
    "markup": ({**ALERT, "rule": {"id": "r-<b>1</b>",
                                  "description": "<script>alert(1)</script> **bold** `tick`"}},
               report_text(body="<script>alert(1)</script>\n# Heading\n**bold** [l](http://x)\n"
                                "| a | b |\n| --- | --- |\n---\nplanted: fence\n")),
    "very_long_body": (ALERT, report_text(body=_LONG_BODY)),
    "newline_in_single_line_fields": (
        {**ALERT, "rule": {"id": "r-1\nforged: x", "description": "line one\nline two"},
         "timestamp": "2026-10-03T00:00:00Z\n"},
        report_text(cause='"first line\\nsecond line"')),
    "non_ascii": ({**ALERT, "rule": {"id": "règle-ü", "description": "検知 — 🙂"}},
                  report_text(cause="caused by ü and 中文", body="Évaluation: 結論 🙂\n")),
    "control_characters": ({**ALERT, "rule": {"id": "r\x1b[31m", "description": "bell\x07"}},
                           report_text(body="esc \x1b[2J and nul-free\x0b vt\n")),
}


def _observe_comment_input(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    alert, report = COMMENT_INPUTS[case]
    root, _folder = _tenant()
    record = _record(root)
    run_dir = tmp / "runs" / "r1080"
    run_dir.mkdir(parents=True)
    if alert is not None:
        (run_dir / "alert.json").write_text(
            alert if isinstance(alert, str) else json.dumps(alert), encoding="utf-8")
    if report is not None:
        (run_dir / "report.md").write_text(report, encoding="utf-8")
    shim = T7.DockerShim(tmp / "shim", _store_ok("r1080"))
    _post_step(_writer(), run_dir, record, shim, opened=True)
    calls = _calls(shim)
    return _norm({"calls": calls, "posts": _posts(calls), "receipts": _receipts(tmp / "runs")},
                 tmp)


@pytest.mark.parametrize("case", list(COMMENT_INPUTS))
def test_ticket_comment_inputs(case, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). The post-run ticket write on a missing alert or report,
    markup, a very long body, an embedded newline in a single-line field or non-ASCII text
    posts or refuses exactly as today. (O5: the ticket post-step.)

    Each case is a real run dir handed to the moved writer's open and record legs, the store
    behind the docker shim; the store's every argv (the open payload and the comment body ride
    in it) and the receipt are compared with the base golden."""
    assert _observe_comment_input(case, tmp_path, None) == _golden("s189")[case]


#: Run-dir names a receipt is keyed by. `earlier_receipt` finds a receipt an earlier attempt
#: left at its name.
RUN_IDS: dict[str, str] = {
    "space": "run with space",
    "non_ascii": "rün-ñame-検",
    "leading_dot": ".hidden-run",
    "receipt_name_at_255_bytes": "r" * (255 - len(RECEIPT_SUFFIX)),
    "receipt_name_past_255_bytes": "r" * (256 - len(RECEIPT_SUFFIX)),
    "percent_and_hash": "run%2F#1",
    "earlier_receipt": "r1080",
}


def _observe_receipt(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    root, _folder = _tenant()
    record = _record(root)
    runs = tmp / "runs"
    name = RUN_IDS[case]
    run_dir = _run_dir(runs, name, report=report_text())
    if case == "earlier_receipt":
        (runs / f"{name}{RECEIPT_SUFFIX}").write_text(
            json.dumps({"key": name, "status": "error", "url": None, "ok": False,
                        "reason": "an earlier attempt"}), encoding="utf-8")
    shim = T7.DockerShim(tmp / "shim", _store_ok(name)[1:])
    _post_step(_writer(), run_dir, record, shim)
    calls = _calls(shim)
    return _norm({"calls": calls, "posts": _posts(calls), "receipts": _receipts(runs)}, tmp)


@pytest.mark.parametrize("case", list(RUN_IDS))
def test_ticket_receipt_for_an_unusual_run_id(case, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A receipt for a run id with a space, non-ASCII letters, a
    leading dot, a very long name or one already used by an earlier receipt is written or
    refused as today.

    Each name is a real run dir under a runs base; the moved writer's record leg runs against
    the docker shim, and the receipts beside the run dirs (names and bytes) and the store's
    calls are compared with the base golden. The long names put the receipt's own name at the
    255-byte name bound and one byte past it."""
    assert _observe_receipt(case, tmp_path, None) == _golden("s190")[case]


# ======================================================================================
# s214 / s215 / s216 / s217 — the post-step's sequences
# ======================================================================================

#: The receipt states a second invocation can meet at the run's receipt name.
RERUN_STATES = ("second_invocation", "empty_receipt", "half_written_receipt",
                "receipt_is_a_link")


def _observe_rerun(state: str, tmp: Path, mp: Any) -> dict[str, Any]:
    root, _folder = _tenant()
    record = _record(root)
    runs = tmp / "runs"
    run_dir = _run_dir(runs, "r1080", report=report_text())
    shim = T7.DockerShim(tmp / "shim", _store_ok("r1080")[1:])
    writer = _writer()
    receipt = runs / f"r1080{RECEIPT_SUFFIX}"
    steps: list[Any] = []
    if state == "second_invocation":
        _post_step(writer, run_dir, record, shim)
        steps.append({"posts": _posts(_calls(shim)), "receipts": _receipts(runs)})
    elif state == "empty_receipt":
        receipt.write_bytes(b"")
    elif state == "half_written_receipt":
        receipt.write_text('{\n  "key": "r1080",\n  "status": "comm', encoding="utf-8")
    elif state == "receipt_is_a_link":
        (tmp / "elsewhere.json").write_text("{}\n", encoding="utf-8")
        receipt.symlink_to(tmp / "elsewhere.json")
    _post_step(writer, run_dir, record, shim)
    calls = _calls(shim)
    steps.append({"posts": _posts(calls), "receipts": _receipts(runs)})
    return _norm({"steps": steps, "calls": calls,
                  "link_target": (tmp / "elsewhere.json").read_text(encoding="utf-8")
                  if state == "receipt_is_a_link" else None}, tmp)


@pytest.mark.parametrize("state", RERUN_STATES)
def test_ticket_post_step_run_twice_for_one_run(state, tmp_path):
    """Invoking the ticket post-step a second time for a run it already posted for leaves the
    same number of external comments and the same receipt content as the pre-move writer did on
    a second invocation (O5: the ticket post-step behaves as today; a run with the same run id
    and a present, empty or half-written receipt is met as today). Probe P16 pins today's
    behavior.

    The record leg of the moved writer, run twice over one run dir (and once over a receipt
    that is empty, cut off mid-write, or a link); the store's comment count, every argv and the
    receipts after each invocation are compared with the base golden — which is the probe."""
    assert _observe_rerun(state, tmp_path, None) == _golden("s214")[state]


#: The killing shim: a `docker` that records its argv and answers like `_spec1107`'s, and on
#: the answer marked `kill_parent` SIGKILLs the process that forked it (the writer) right after
#: the store has taken the call — the post-step dies between the external write and the
#: receipt.
_KILL_SHIM = r'''
import json, os, signal, sys
LOG, SPEC = {log!r}, {spec!r}
with open(LOG, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({{"argv": sys.argv[1:]}}) + "\n")
with open(LOG, encoding="utf-8") as fh:
    n = sum(1 for _ in fh) - 1
with open(SPEC, encoding="utf-8") as fh:
    answers = json.load(fh)
a = answers[min(n, len(answers) - 1)]
if a.get("kill_parent"):
    os.kill(os.getppid(), signal.SIGKILL)
sys.stdout.write(a["stdout"] + "\n" + a["status"])
'''

#: The writer as its own process (so a SIGKILL takes it, not the test): the record leg over one
#: run dir, the tenant resolved from the data root it is handed.
_WRITER_CHILD = r"""
import importlib, sys
from pathlib import Path
from defender.runtime import run_tenant
writer = importlib.import_module(sys.argv[1])
run_dir, root, path_dir = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
record = run_tenant.resolve_tenant(root, sys.argv[5], defender_dir=Path(sys.argv[6]),
                                   dispatches_lead_zero=False)
env = {"PATH": path_dir + ":/usr/bin:/bin", "PYTHONUTF8": "1"}
writer.record_case_ticket(run_dir, tenant=record, defender_dir=Path(sys.argv[6]), env=env)
"""


def _kill_shim(where: Path, answers: list[dict[str, Any]]) -> tuple[Path, Path]:
    bindir = where / "fakebin"
    bindir.mkdir(parents=True)
    log, spec = where / "calls.jsonl", where / "spec.json"
    spec.write_text(json.dumps(answers), encoding="utf-8")
    exe = bindir / "docker"
    exe.write_text(f"#!{sys.executable}\n" + _KILL_SHIM.format(log=str(log), spec=str(spec)),
                   encoding="utf-8")
    exe.chmod(0o755)
    return bindir, log


#: The two real interruptions between the store accepting the comment and the receipt.
INTERRUPTIONS = ("killed_after_the_store_accepted", "receipt_write_failed_after_the_store_accepted")


def _observe_interrupted(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    root, _folder = _tenant()
    runs = tmp / "runs"
    run_dir = _run_dir(runs, "r1080", report=report_text())
    receipt = runs / f"r1080{RECEIPT_SUFFIX}"
    read_back = {"stdout": json.dumps({"key": "r1080", "status": "open"}), "status": "200"}
    accepted = {"stdout": json.dumps({"id": 1}), "status": "201"}
    first: dict[str, Any] = {}
    if case == "killed_after_the_store_accepted":
        bindir, log = _kill_shim(tmp / "kill", [read_back, {**accepted, "kill_parent": True}])
        child = S.python("-c", _WRITER_CHILD, S.dotted(S.home_of("record_case_ticket")),
                         str(run_dir), str(root), str(bindir), TENANT, str(S.DEFENDER),
                         env=S.child_env(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1"))
        argvs = [json.loads(ln)["argv"] for ln in log.read_text(encoding="utf-8").splitlines()]
        first = {"exit": child.returncode, "posts": _posts(argvs), "receipts": _receipts(runs)}
    else:  # the receipt's name is squatted by a directory: the write after the POST fails
        receipt.mkdir()
        shim = T7.DockerShim(tmp / "squat", [T7.answer(read_back["stdout"], "200"),
                                             T7.answer(accepted["stdout"], "201")])
        _post_step(_writer(), run_dir, _record(root), shim)
        first = {"exit": None, "posts": _posts(_calls(shim)),
                 "receipt_is_dir": receipt.is_dir()}
        receipt.rmdir()
    shim = T7.DockerShim(tmp / "again", [T7.answer(read_back["stdout"], "200"),
                                         T7.answer(accepted["stdout"], "201")])
    _post_step(_writer(), run_dir, _record(root), shim)
    calls = _calls(shim)
    return _norm({"first": first, "second": {"calls": calls, "posts": _posts(calls),
                                             "receipts": _receipts(runs)}}, tmp)


@pytest.mark.parametrize("case", INTERRUPTIONS)
def test_ticket_post_step_interrupted_between_the_external_write_and_the_local_receipt(
        case, tmp_path):
    """A post-step interrupted after the external system accepted the comment and before the
    local receipt was written, then re-run, does on the second attempt exactly what the pre-move
    writer did (including whether it posts a second comment); the move reorders nothing in the
    open, record, receipt sequence.

    Two real interruptions: the writer process SIGKILLed by the store's shim the moment it
    accepted the comment POST (a child process running the moved writer), and a directory
    squatting the receipt's name so the receipt write after the POST fails. Then the record leg
    again; the comments the store took on each attempt and the final receipt against the base
    golden."""
    got = _observe_interrupted(case, tmp_path, None)
    assert got["first"]["posts"] == 1, f"the first attempt never reached the store: {got}"
    assert got == _golden("s215")[case]


#: How the run stops short of its case being opened.
ABORT_CASES = ("preflight_refused", "open_step_failed_then_aborted",
               "open_skipped_no_alert_then_aborted", "open_ok_then_aborted")


def _observe_abort(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    not_found = T7.answer(json.dumps({"detail": "no such ticket"}), "404")
    aborted = {"truncated_by": "aborted"}
    if case == "preflight_refused":
        got = _drive_run(tmp, mp, answers=_store_ok("r1080"), preflight_rc=3)
    elif case == "open_step_failed_then_aborted":
        # AP3 (executed, `_spec1107.curl_refused`): curl could not connect, rc 7, status 000.
        got = _drive_run(tmp, mp, answers=[T7.curl_refused("case-history-t1080"), not_found],
                         summary=aborted, report=None)
    elif case == "open_skipped_no_alert_then_aborted":
        got = _drive_run(tmp, mp, answers=[not_found], summary=aborted, report=None,
                         alert_in_run=False)
    else:
        got = _drive_run(tmp, mp, answers=_store_ok("r1080"), summary=aborted, report=None)
    return _norm(got, tmp)


@pytest.mark.parametrize("case", ABORT_CASES)
def test_ticket_post_step_for_a_run_that_aborted_before_its_case_was_opened(case, tmp_path,
                                                                             monkeypatch):
    """If the run aborted before the case-open step ran, or that step failed, the post-step
    posts, records and exits exactly as the pre-move writer did.

    The REAL `run.main` under `--update-ticket` with its production writer: refused at
    preflight (nothing ran), the open step failing at the store (curl could not connect), the
    open step skipped for want of an alert, and — the control — an opened case; the last three
    end `aborted`. The exit, the seam order, every store argv and the receipt against the base
    golden. The production writer is the write-back home's module."""
    assert _run_main_default_writer() is _writer(), "run.main's post-step is not the moved writer"
    assert _observe_abort(case, tmp_path, monkeypatch) == _golden("s216")[case]


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
    write-back home's module, and the snapshot it is handed is the tenants home's `CaseMapping`."""
    assert _run_main_default_writer() is _writer(), "run.main's post-step is not the moved writer"
    root, _folder = _tenant()
    assert isinstance(_record(root).ticket_mapping, S.moved("CaseMapping"))
    assert _observe_edit(case, tmp_path, monkeypatch) == _golden("s217")[case]


# ======================================================================================
# The workspace map: through orient, and from a checkout copy
# ======================================================================================

SYSTEMS = ("cmdb", "elastic")


def _map_module() -> Any:
    return S.moved_module("workspace_map")


def _fixture_run_dir(tmp: Path) -> Path:
    """A run dir as message zero is built over it: the alert, a lead's folder, a report."""
    run_dir = tmp / "runs" / "r1080"
    run_dir.mkdir(parents=True)
    (run_dir / "alert.json").write_text(json.dumps(ALERT), encoding="utf-8")
    (run_dir / "leads").mkdir()
    (run_dir / "report.md").write_text(report_text(), encoding="utf-8")
    return run_dir


def _message_zero(run_dir: Path, defender_dir: Path = S.DEFENDER,
                  systems: Sequence[str] = SYSTEMS) -> str:
    """`runtime/orient.orientation` (unmoved) over the run dir, its lessons shims answering
    nothing (the `shim` seam)."""
    from defender.runtime import orient

    return orient.orientation(run_dir, defender_dir, run_dir / "alert.json",
                              systems=tuple(systems), shim=lambda _argv, _env: None)


def _observe_orient(tmp: Path, mp: Any) -> dict[str, Any]:
    run_dir = _fixture_run_dir(tmp)
    return _norm({"workspace": _workspace_section(_message_zero(run_dir))}, tmp)


def test_1080_orient_renders_the_workspace_section_through_the_moved_map(tmp_path):
    """`runtime/orient.py`'s workspace section, built through the moved
    `workspace_map(run_dir, systems=…)`, is identical to the base text for a fixture run dir.

    Orient's section is the moved function's text under the heading (so orient reached the
    moved map, not a fallback), and that text is the base golden's, the checkout and the tmp
    root normalized."""
    run_dir = _fixture_run_dir(tmp_path)
    section = _workspace_section(_message_zero(run_dir))
    assert "_(unavailable" not in section, f"orient fell back: {section[:300]}"
    assert section == "## Workspace\n" + _map_module().workspace_map(
        run_dir, systems=SYSTEMS).strip()
    assert _observe_orient(tmp_path / "again", None) == _golden("s_orient_workspace_map")


def _checkout_farm(dst: Path) -> Path:
    """A stand-in checkout rooted at `dst`: `dst/defender/` re-created with REAL directories,
    every `.py` file COPIED (so any module anchoring on its own `__file__` — resolved or not —
    anchors here, wherever the move put it), every file under `skills/` copied too (the map
    lists them, and the template reader refuses a linked file), and every other file and every
    link pointing at this checkout's. Tool caches and `tests/` are left out. Returns `dst`."""
    src = S.DEFENDER
    for dirpath, dirnames, filenames in os.walk(src):
        here = Path(dirpath)
        rel = here.relative_to(src)
        copy_all = rel.parts[:1] == ("skills",)
        out = dst / "defender" / rel
        out.mkdir(parents=True, exist_ok=True)
        keep = []
        for name in dirnames:
            if name in S.JUNK_DIRS or (here == src and name == "tests"):
                continue
            if (here / name).is_symlink():
                (out / name).symlink_to(os.readlink(here / name))
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            if (copy_all or name.endswith(".py")) and not (here / name).is_symlink():
                shutil.copyfile(here / name, out / name)
            else:
                (out / name).symlink_to(here / name)
    return dst


_FARM_CHILD = r"""
import importlib, json, sys
from pathlib import Path
mod = importlib.import_module(sys.argv[1])
run_dir, defender_dir = Path(sys.argv[2]), Path(sys.argv[3])
systems = tuple(json.loads(sys.argv[4]))
from defender.runtime import orient
zero = orient.orientation(run_dir, defender_dir, run_dir / "alert.json", systems=systems,
                          shim=lambda _a, _e: None)
start = zero.index("## Workspace\n")
end = zero.find("\n\n## invlang catalog", start)
print(json.dumps({"module_file": mod.__file__, "defender_dir": str(mod.DEFENDER_DIR),
                  "repo_root": str(mod.REPO_ROOT),
                  "map": mod.workspace_map(run_dir, systems=systems),
                  "workspace": zero[start:end]}))
"""


def _map_in(checkout: Path, run_dir: Path, *, import_root: Path | None = None,
            systems: Sequence[str] = SYSTEMS) -> dict[str, Any]:
    """The moved map module, imported FROM `checkout` (PYTHONPATH `import_root`, default the
    checkout itself) in a fresh child, run over `run_dir`; plus orient's section there."""
    home = S.dotted(S.home_of("workspace_map"))
    env = S.child_env(pythonpath=False, PYTHONPATH=str(import_root or checkout),
                      PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    child = S.run([sys.executable, "-c", _FARM_CHILD, home, str(run_dir),
                   str((import_root or checkout) / "defender"), json.dumps(list(systems))],
                  cwd=checkout, env=env)
    assert child.returncode == 0, (
        f"the map could not be built from {checkout}: {child.stderr.decode(errors='replace')}")
    return json.loads(child.stdout)


def _observe_s022(tmp: Path, mp: Any) -> dict[str, Any]:
    run_dir = _fixture_run_dir(tmp)
    here = _workspace_section(_message_zero(run_dir))
    copy = _map_in(_checkout_farm(tmp / "box" / "checkout"), run_dir)
    return _norm({"this_checkout": here, "another_checkout": copy["workspace"]}, tmp)


def test_workspace_section_the_model_reads_after_the_map_moved(tmp_path):
    """Message zero's workspace section is the real map, not the fallback: it prints the
    defender and repo roots of the running checkout (main checkout, linked worktree, or the box
    mount), lists the skills, the query templates of the run's systems and an adapters line
    headed by `defender/scripts/adapters/` (unchanged while adapters stay), identical in content
    to the pre- move section for the same tree. A test distinguishes it from the fallback
    `_(unavailable: …)_` and pins the roots and skills list, which today are unpinned.

    Two checkouts: this one (a linked worktree here, the main checkout in CI) in-process, and a
    copy of this tree at another root (`_checkout_farm`) in a fresh child. Each section names
    its own checkout's roots (literally), carries the adapters heading, is not the fallback, and
    equals the base golden once the roots are normalized."""
    mod = _map_module()
    assert Path(mod.DEFENDER_DIR) == S.DEFENDER, f"the moved map anchors at {mod.DEFENDER_DIR}"
    got = _observe_s022(tmp_path, None)
    for which, section in got.items():
        assert "_(unavailable" not in section, f"{which}: the fallback, not the map"
        assert "## Adapters — `defender/scripts/adapters/`" in section, which
    raw_here = _workspace_section(_message_zero(_fixture_run_dir(tmp_path / "again")))
    assert f"- DEFENDER_DIR: `{S.DEFENDER}`" in raw_here
    assert f"- REPO_ROOT: `{S.REPO_ROOT}`" in raw_here
    assert "- DEFENDER_DIR: `<TMP>/box/checkout/defender`" in got["another_checkout"]
    assert got == _golden("s022")


#: How a folder the map lists can be missing: (repo-relative folder, state).
LISTED_FOLDERS: dict[str, tuple[str, str]] = {
    f"{label}_{state}": (rel, state)
    for label, rel in (("skills", "defender/skills"),
                       ("adapters", "defender/scripts/adapters"),
                       ("query_templates", "defender/skills/gather/queries"))
    for state in ("absent", "empty", "link")
}


def _observe_listed_folder(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    rel, state = LISTED_FOLDERS[case]
    checkout = _checkout_farm(tmp / "checkout")
    target = checkout / rel
    if target.is_symlink():
        target.unlink()
    else:
        shutil.rmtree(target)
    if state == "empty":
        target.mkdir()
    elif state == "link":
        target.symlink_to(S.REPO_ROOT / rel)
    run_dir = _fixture_run_dir(tmp)
    got = _map_in(checkout, run_dir)
    return _norm({"map": got["map"], "workspace": got["workspace"]}, tmp)


@pytest.mark.parametrize("case", list(LISTED_FOLDERS))
def test_workspace_map_module_loads_but_a_directory_it_lists_is_absent(case, tmp_path):
    """The workspace map module loads and builds the real map even when the skills folder, the
    adapters folder or the query-template folder it lists is absent, empty or a link: the
    corresponding listing is empty or omitted exactly as today, the headings and roots are still
    printed, and the result is the map, not the orient fallback.

    Each state is real, in a copy of this checkout (`_checkout_farm`): the folder deleted,
    replaced by an empty one, or replaced by a link to this checkout's. The moved module is
    imported from the copy in a fresh child; its map and orient's section there against the
    base golden."""
    got = _observe_listed_folder(case, tmp_path, None)
    assert "_(unavailable" not in got["workspace"], got["workspace"][:300]
    assert got == _golden("s047")[case]


#: Run-dir entry names (str, or bytes for a name that is not UTF-8), each created for real.
HOSTILE_NAMES: dict[str, str | bytes] = {
    "plain": "plain.txt",
    "newline": "a\nb## Forged heading",
    "carriage_return": "x\ry",
    "escape_sequence": "esc\x1b[31mred",
    "bell_and_tab": "bell\x07tab\there",
    "rtl_override": "‮RTL",
    "backtick": "back`tick",
    "heading_lookalike": "## heading-looking",
    "space": "sp ace",
    "leading_dot": ".hidden",
    "name_at_255_bytes": "n" * 255,
    "multibyte_at_255_bytes": "é" * 127 + "x",
    "invalid_utf8": b"bad-\xff\xfe-utf8",
    "dunder_pycache": "__pycache__",
}


def _observe_hostile_names(tmp: Path, mp: Any) -> dict[str, Any]:
    run_dir = tmp / "runs" / "r1080"
    run_dir.mkdir(parents=True)
    for name in HOSTILE_NAMES.values():
        raw = os.path.join(os.fsencode(run_dir), name if isinstance(name, bytes)
                           else os.fsencode(name))
        with open(raw, "wb") as fh:
            fh.write(b"x")
    os.mkdir(os.path.join(os.fsencode(run_dir), b"sub\ndir"))
    text = _outcome_of(_map_module().workspace_map, run_dir, systems=SYSTEMS)
    section = _section(text["returns"], "## Run dir") if "returns" in text else text
    return _norm({"run_dir_section": section}, tmp)


def test_run_dir_entries_with_hostile_names(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Run-directory entries with newlines, control characters,
    escape sequences, a leading dot, a name over 255 bytes or invalid UTF-8 are listed or hidden
    by the workspace map exactly as today and never raise into message zero.

    Every name is created for real in one run dir (the 255-byte names are the longest the
    filesystem admits); the moved map's `## Run dir` section against the base golden, with
    `plain.txt` listed as the positive control."""
    got = _observe_hostile_names(tmp_path, None)
    assert "- plain.txt" in got["run_dir_section"], got
    assert got == _golden("s180")


#: The entries the map hides, each in four states besides absent.
SUPPRESSED_STATES = ("present", "absent", "empty", "symlinked", "dangling_link")


def _suppressed_names() -> tuple[str, ...]:
    from defender._run_paths import RUN_LAYOUT

    return (RUN_LAYOUT.gather_raw.name, RUN_LAYOUT.wire_log_dir.name, RUN_LAYOUT.budget.name,
            RUN_LAYOUT.provenance.name)


def _observe_suppressed(state: str, tmp: Path, mp: Any) -> dict[str, Any]:
    run_dir = _fixture_run_dir(tmp)
    outside = tmp / "outside"
    outside.mkdir()
    gather_raw, wire_logs, budget, provenance = _suppressed_names()
    for name, is_dir in ((gather_raw, True), (wire_logs, True), (budget, False),
                         (provenance, False)):
        path = run_dir / name
        if state == "present":
            if is_dir:
                path.mkdir()
                (path / "1.json").write_text("{}", encoding="utf-8")
            else:
                path.write_text('{"spent": 1}\n', encoding="utf-8")
        elif state == "empty":
            if is_dir:
                path.mkdir()
            else:
                path.write_bytes(b"")
        elif state == "symlinked":
            target = outside / name
            if is_dir:
                target.mkdir()
            else:
                target.write_text("{}", encoding="utf-8")
            path.symlink_to(target)
        elif state == "dangling_link":
            path.symlink_to(outside / f"missing-{name}")
    text = _map_module().workspace_map(run_dir, systems=SYSTEMS)
    return _norm({"run_dir_section": _section(text, "## Run dir")}, tmp)


@pytest.mark.parametrize("state", SUPPRESSED_STATES)
def test_suppressed_entries_present_absent_or_links(state, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). The entries the map hides (raw payloads, wire logs, budget
    file, provenance stamp) are hidden in every state (present, absent, empty, symlinked)
    exactly as today.

    The four names come from `RUN_LAYOUT` (unmoved), each put in the state for real beside the
    run's own files; the moved map's `## Run dir` section against the base golden, with
    `alert.json` listed as the positive control."""
    got = _observe_suppressed(state, tmp_path, None)
    assert "- alert.json" in got["run_dir_section"], got
    assert got == _golden("s181")[state]


#: The run's systems list, in unusual shapes.
SYSTEMS_SHAPES: dict[str, tuple[str, ...]] = {
    "empty": (),
    "duplicate": ("cmdb", "cmdb", "elastic"),
    "no_query_templates": ("ticket",),
    "hyphen_and_underscore": ("change-mgmt", "change_mgmt"),
    "path_separator": ("a/b", "../escape"),
    "non_ascii": ("système", "検知"),
    "unsorted": ("identity", "cmdb", "change-mgmt"),
}


def _observe_systems(shape: str, tmp: Path, mp: Any) -> dict[str, Any]:
    run_dir = _fixture_run_dir(tmp)
    text = _outcome_of(_map_module().workspace_map, run_dir, systems=SYSTEMS_SHAPES[shape])
    if "returns" not in text:
        return _norm(text, tmp)
    out = text["returns"]
    return _norm({"adapters": _section(out, "## Adapters"),
                  "query_templates": _section(out, "## Gather query templates")}, tmp)


@pytest.mark.parametrize("shape", list(SYSTEMS_SHAPES))
def test_systems_list_of_unusual_shape(shape, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). An empty systems list, a duplicate, a system with no query
    templates, a hyphen-versus-underscore variant, a name with a path separator and a non-ASCII
    name are listed as today.

    The moved map's `## Adapters` and `## Gather query templates` sections for each list,
    against the base golden."""
    assert _observe_systems(shape, tmp_path, None) == _golden("s182")[shape]


#: A run dir that is not a readable directory. An unreadable (mode-000) one is not here: root
#: reads it, and at the base a non-root reader's map RAISES `PermissionError` into orient's
#: swallow (observed as uid 65534), which the seed's own clause contradicts — left to the author.
RUN_DIR_STATES = ("does_not_exist", "is_a_file", "link_to_nowhere", "link_to_a_dir")


def _observe_run_dir_state(state: str, tmp: Path, mp: Any) -> dict[str, Any]:
    runs = tmp / "runs"
    runs.mkdir()
    run_dir = runs / "r1080"
    if state == "is_a_file":
        run_dir.write_text("not a dir\n", encoding="utf-8")
    elif state == "link_to_nowhere":
        run_dir.symlink_to(tmp / "nowhere")
    elif state == "link_to_a_dir":
        real = _fixture_run_dir(tmp / "real")
        run_dir.symlink_to(real)
    text = _outcome_of(_map_module().workspace_map, run_dir, systems=SYSTEMS)
    section = _section(text["returns"], "## Run dir") if "returns" in text else text
    workspace = _workspace_section(_message_zero(run_dir))
    return _norm({"run_dir_section": section,
                  "message_zero_workspace_head": workspace.splitlines()[:2]}, tmp)


@pytest.mark.parametrize("state", RUN_DIR_STATES)
def test_run_dir_missing_a_file_or_unreadable(state, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A run directory that does not exist, is a file, is a link
    to nowhere or is unreadable still yields a section in message zero (the caller must produce
    one) exactly as today, the map not raising into orient's swallow.

    Each state is real; the moved map's `## Run dir` section and the head of orient's
    `## Workspace` section in message zero (the map, not the `_(unavailable: …)_` fallback)
    against the base golden. The unreadable state is not pinned (see `RUN_DIR_STATES`)."""
    got = _observe_run_dir_state(state, tmp_path, None)
    assert got["message_zero_workspace_head"] == ["## Workspace", "# Workspace map"], got
    assert got == _golden("s183")[state]


#: Checkout locations whose path is awkward: (the import root, relative to the case's tmp; the
#: real directory it names, when the import root runs through a link).
AWKWARD_CHECKOUTS: dict[str, tuple[str, str | None]] = {
    "space": ("with space/checkout", None),
    "non_ascii": ("ünïcødé-検/checkout", None),
    "symlinked_parent": ("link/checkout", "real"),
}


def _observe_awkward(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    rel, real = AWKWARD_CHECKOUTS[case]
    import_root = tmp / rel
    if real is not None:
        (tmp / real).mkdir()
        (tmp / rel.split("/")[0]).symlink_to(tmp / real)
    checkout = _checkout_farm(import_root)
    run_dir = _fixture_run_dir(tmp)
    got = _map_in(checkout, run_dir, import_root=import_root)
    return _norm({"defender_dir": got["defender_dir"],
                  "roots": _section(got["workspace"], "## Absolute roots"),
                  "headings": [ln for ln in got["workspace"].splitlines()
                               if ln.startswith("## ")]}, tmp)


@pytest.mark.parametrize("case", list(AWKWARD_CHECKOUTS))
def test_map_built_from_a_checkout_path_with_awkward_characters(case, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A checkout path with a space, non-ASCII letters or under a
    symlinked parent is printed to the model as today for the same path.

    A copy of this checkout (`_checkout_farm`) at each path, the moved module imported from it
    in a fresh child; the module's two roots and orient's `## Absolute roots` section against
    the base golden (the tmp root normalized)."""
    assert _observe_awkward(case, tmp_path, None) == _golden("s184")[case]


# ======================================================================================
# The payload view
# ======================================================================================


def _view() -> Any:
    return S.moved_module("passthrough_max_bytes")


#: `DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES` spellings; `None` is unset.
CEILING_ENV: dict[str, str | None] = {
    "unset": None,
    "empty": "",
    "zero": "0",
    "negative": "-1",
    "padded": "  4096\t\n",
    "plus_sign": "+64",
    "underscored": "1_024",
    "float": "1.5",
    "exponent": "1e3",
    "hex": "0x10",
    "non_numeric": "eight kilobytes",
    "non_ascii_digits": "٤٠٩٦",
    "oversized": "9" * 40,
    "past_the_digit_limit": "9" * 4301,
}


def _observe_ceiling(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    view = _view()
    value = CEILING_ENV[case]
    if value is None:
        mp.delenv(PASSTHROUGH_ENV, raising=False)
    else:
        mp.setenv(PASSTHROUGH_ENV, value)
    payload = json.dumps({"rows": [{"i": i, "v": "x" * 20} for i in range(40)]})
    rendered = _outcome_of(view.render, payload, None, tmp, view=_text_digest)
    return _norm({"ceiling": S.outcome(view.passthrough_max_bytes), "render": rendered}, tmp)


@pytest.mark.parametrize("case", list(CEILING_ENV))
def test_passthrough_ceiling_env_in_unusual_forms(case, tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES unset, empty, 0,
    negative, padded, float, hex, non-numeric or oversized resolves to the same ceiling as today
    through the same parser (probe PO1).

    The variable really set (or removed) in this process; the moved `passthrough_max_bytes`
    outcome and the view it governs (`render` with no explicit ceiling, over a 2 KB payload)
    against the base golden."""
    assert _observe_ceiling(case, tmp_path, monkeypatch) == _golden("s172")[case]


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
        "nested_past_the_parser": ("[" * 100000 + "]" * 100000, 64),
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


# PRE-CUT 2026-10-04 (scope cut): only its docstring or comments changed in the live suite (kept demand s174); no cell was cut.
@pytest.mark.parametrize("case", list(_shape_cases()))
def test_payload_shapes_the_view_must_not_choke_on(case, tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Empty, plain-text, deeply nested JSON, boundary-length
    string leaves, invalid UTF-8, scalar-top-level and ten-thousand-item payloads are viewed as
    today without a new failure.

    `render` takes text (`query_tool` hands it `json.dumps(payload)`), so invalid UTF-8 reaches
    it as the surrogate-escaped characters a lossless decode leaves; each shape through the
    moved `render` against the base golden (a long view by its length, hash and ends)."""
    assert _observe_shape(case, tmp_path, monkeypatch) == _golden("s174")[case]


# ======================================================================================
# s204 / s205 — fresh-process imports and module-level state
# ======================================================================================

# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1105, #1165, #1172 and the case_ticket follow-up; #1165 or #1172 (the flat-tier exit-code vocabulary).
#: One symbol per moved module (and the home pinned by the design or the demand text, if any).
#: The seed's list: world-view naming, case mapping, pricing, query rules, row writers,
#: integrations faults, reports renderer, lessons engine, tenants home, flat-tier modules —
#: plus the write-back, the views, the Elastic grammar, the sql engine and system naming.
FIRST_IMPORTS: tuple[tuple[str, str, str | None], ...] = (
    ("world-view naming", "world_view", None),
    ("case mapping (tenants home)", "load_case_mapping", None),
    ("write-back", "record_case_ticket", None),
    ("pricing", "usage_cost", S.PROVIDERS),
    ("query rules", "resolve_query_id", None),
    ("row writers", "append_query_row", None),
    ("integrations faults", "AdapterFault", S.INTEGRATIONS),
    ("integrations HTTP check", "confine_read_endpoint", S.INTEGRATIONS),
    ("elastic grammar", "split_commands", None),
    ("reports renderer", "render_page", S.REPORTS),
    ("episode renderer", "render_episode", S.REPORTS),
    ("page failure", "VisualizeFailed", None),
    ("lessons engine", "cmd_tags", None),
    ("exit codes", "error_class_for_exit", S.EXIT_CODES),
    ("venv helper", "reexec_into_venv", None),
    ("workspace map", "workspace_map", None),
    ("payload view", "passthrough_max_bytes", None),
    ("sql engine", "EXIT_NO_RUNTIME", None),
    ("system naming", "derive_system", S.VERBS),
)


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s204); the cut cells are owned by #1105, #1165, #1172 and the case_ticket follow-up.
def test_each_moved_module_imported_first_in_a_fresh_process():
    """Each moved module comes up as the first project import in a fresh interpreter, whichever
    module is chosen: no module depends on another having been imported first, and no import
    cycle among the new homes (the world-view naming, the case-mapping module, pricing, the
    query rules, the writers) makes the first-import order matter.

    The modules are found by symbol in the parent; each module — and each package a home sits
    in below `defender/` — is then the FIRST import of its own fresh child."""
    targets: dict[str, str] = {}
    for label, symbol, home in FIRST_IMPORTS:
        dotted = S.dotted(S.home_of(symbol, home=home))
        targets.setdefault(dotted, label)
        parts = dotted.split(".")
        for i in range(2, len(parts)):
            targets.setdefault(".".join(parts[:i]), f"package of {label}")
    names = sorted(targets)
    results = _children([["-c", "import importlib, sys; importlib.import_module(sys.argv[1])",
                          name] for name in names])
    failed = [(targets[n], n, r.stderr.decode(errors="replace")[-500:])
              for n, r in zip(names, results, strict=True) if r.returncode != 0]
    assert not failed, f"imported first, these fail: {failed}"


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1165 (record_query writers), #1172 (confinement, _stub_transport, verbs), the case_ticket follow-up and #1165 or #1172 (the flat-tier exit-code vocabulary).
def _observe_state(tmp: Path, mp: Any) -> dict[str, Any]:
    from defender.runtime.verbs import VerbContext
    from defender.scripts.adapters import _stub_transport

    view = _view()
    payload = json.dumps({"rows": [{"i": i, "v": "x" * 30} for i in range(300)]})  # ~14 KB
    renders = []
    for setting in ("48", "100000", None):
        if setting is None:
            mp.delenv(PASSTHROUGH_ENV, raising=False)
        else:
            mp.setenv(PASSTHROUGH_ENV, setting)
        renders.append(_text_digest(view.render(payload, None, tmp)))

    capture_cls = S.moved("TransportCapture")
    root, _folder = _tenant()
    record = _record(root)
    captured = []
    for run, host in (("r-one", "h-1"), ("r-two", "h-2")):
        shim = T7.DockerShim(tmp / f"shim-{run}", [T7.answer(json.dumps({"host": host}), "200")])
        capture = capture_cls()
        ctx = VerbContext(defender_dir=S.DEFENDER, run_dir=tmp / run, env=_shim_env(shim),
                          tenant=record, capture=capture)
        config = _stub_transport.load_config(ctx, "cmdb", "CMDB")
        _stub_transport.http_get(ctx, config, f"/hosts/{host}", system="cmdb")
        captured.append([[r.system, r.url, r.method] for r in capture.requests])

    append, note = S.moved("append_query_row"), S.moved("repeat_note")
    digest, sha = S.moved("payload_digest"), S.moved("payload_sha256")
    rows = []
    for run, repeats in (("q-one", 2), ("q-two", 1)):
        run_dir = tmp / run
        run_dir.mkdir()
        for _ in range(repeats):
            text = json.dumps({"host": "h-1"})
            row = append(run_dir, lead_id="l-001", system="cmdb", verb="get-host",
                         query_id="cmdb.get-host", params={"host": "h-1"},
                         raw_command="", payload_text=text, exit_code=0, payload_status="ok",
                         payload_digest=digest(text, "", 0), system_key="")
            rows.append([run, S.canon(row),
                         note(run_dir, "l-001", seq=row["seq"], system="cmdb", verb="get-host",
                              params={"host": "h-1"}, payload_digest=row["payload_digest"],
                              payload_sha256=sha(text), exit_code=0)])
    return _norm({"renders": renders, "captures": captured, "rows": rows}, tmp)


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s205); the cut cells are owned by #1165, #1172 and the case_ticket follow-up (the record_query, confinement and capture cells).
def test_module_level_state_in_a_moved_module_across_two_runs_in_one_process(tmp_path,
                                                                             monkeypatch):
    """Module-level state in a moved module (a cache, a compiled table, an installed capture)
    serves each run as it did before: a second consecutive run in the same process sees nothing
    a first run left that it did not see pre-move. The move does not turn per-run state into
    process-wide state.

    Three in one process, in order: the payload view rendered under three ceilings (the
    variable set, changed, removed — no ceiling remembered); two runs each with its own moved
    `TransportCapture` on its context, each making one call through the unmoved stub transport
    (the docker shim behind it) — each capture holds only its own run's request; two run dirs
    taking query rows through the moved row writer, the repeat note read after each — the
    second run's sequence and notes start fresh. All against the base golden."""
    got = _observe_state(tmp_path, monkeypatch)
    assert [len(c) for c in got["captures"]] == [1, 1], got["captures"]
    assert got == _golden("s205")


# ======================================================================================
# Shared by the capture script (the `_observe_*` functions above ARE the capture)
# ======================================================================================

# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by none here: the 18 removed entries belong to tests parked whole, and live in ../parked_writeback_tenants_and_views.py.
#: demand -> (observer, its case names or None). The capture runs each at the base under
#: `SPEC1080_AT_BASE=1`, each case in a fresh data root and tmp dir: `observer(case, tmp, mp)`,
#: or `observer(tmp, mp)` for a demand with one case.
OBSERVERS: dict[str, tuple[Callable[..., Any], Sequence[str] | None]] = {
    "s_case_mapping_read_at_run_start": (_observe_mapping_at_run_start, None),
    "s_ticket_post_step": (_observe_post_step, None),
    "s187": (_observe_mapping_file, list(FILE_STATES)),
    "s188": (_observe_yaml_shape, list(YAML_SHAPES)),
    "s189": (_observe_comment_input, list(COMMENT_INPUTS)),
    "s190": (_observe_receipt, list(RUN_IDS)),
    "s214": (_observe_rerun, list(RERUN_STATES)),
    "s215": (_observe_interrupted, list(INTERRUPTIONS)),
    "s216": (_observe_abort, list(ABORT_CASES)),
    "s217": (_observe_edit, list(EDITS)),
    "s_orient_workspace_map": (_observe_orient, None),
    "s022": (_observe_s022, None),
    "s047": (_observe_listed_folder, list(LISTED_FOLDERS)),
    "s180": (_observe_hostile_names, None),
    "s181": (_observe_suppressed, list(SUPPRESSED_STATES)),
    "s182": (_observe_systems, list(SYSTEMS_SHAPES)),
    "s183": (_observe_run_dir_state, list(RUN_DIR_STATES)),
    "s184": (_observe_awkward, list(AWKWARD_CHECKOUTS)),
    "s172": (_observe_ceiling, list(CEILING_ENV)),
    "s173": (_observe_at_ceiling, list(_ceiling_cases())),
    "s174": (_observe_shape, list(_shape_cases())),
    "s205": (_observe_state, None),
}
