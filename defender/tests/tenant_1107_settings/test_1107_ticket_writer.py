"""#1107 — the ticket writer takes the run's record, and a failed write is visible and harmless (O6,
D5, F6, MF-9, MF-12, NF-23, NF-24, PG-12, PG-13).

THE ENTRY POINT IS `run.py main`, driven through its own injection seams (`_spec1107.RunRecorder`:
preflight, materialize, lifecycle, enqueue — each recording, none deciding) with the REAL ticket
writer as its `ticket_writer=` default, so "the record step" is whatever `run.main` reaches under
`--update-ticket` with the exit record `lifecycle` hands back (`truncated_by`,
`closed_before_cut`). The run page, where a test reads it, is the REAL renderer run.py reaches
(`run_common.visualize`, the default `visualize` seam); where it does not, the recorder's
`visualize` stands in and records.

The case-history store is reached for real, through the writer's own transport, which forks
`docker`: a `DockerShim` first on the PATH of the environment the writer's child is handed (CX8,
executed: `subprocess.run(..., env=E)` resolves `docker` on E's PATH, so the shim receives the
transport's argv and the child's whole environment — no seam, no monkeypatch; F5). Since F6
(human) the child environment is the run env run.py hands the writer, and run.py builds that from
this process's environment — so the shim goes onto PATH with `monkeypatch.setenv` before
`run.main` runs.

Every other fault is a REAL input through the real primitive: the deleted `config.env`, the
missing key, the non-integer timeout, a mapping whose `open.status` equals its `released.status`
(the loader's own lifecycle refusal), a forged receipt and a symlink planted at the receipt's name
inside the run dir, a directory squatting that name, an exported `CASE_HISTORY_URL_BASE`.

Coined here (the design does not spell them; `_spec1107` holds the rest): none beyond
`_spec1107`'s — the writer's `tenant=`/`defender_dir=`/`env=` keywords are `S.RECORD_FIELD` and
`S.record_step`/`S.open_step`.
"""
from __future__ import annotations

import ast
import dataclasses
import html
import inspect
import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender import run_common
from defender.run_repository import Run
from defender.run_repository import RunPaths
from defender.runtime import run_end, run_tenant
from defender.scripts.case_history import ticket_writer
from defender.tests._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.tenant_1107_settings import _spec1107 as S

TW_LOGGER = ticket_writer.__name__
MARKER = "tw1107"


# ======================================================================================
# Fixture plumbing — returns, never asserts.
# ======================================================================================

def _world(tmp_path: Path, *, marker: str = MARKER, released_status: str = "closed",
           name: str = "tenants") -> tuple[Path, Path, Path]:
    """The data-root row (#1078), a complete #1107 tenant set up under this test's data root
    (#1120: `run.py` reads its tenants from `DEFENDER_DATA_ROOT` alone; a second call replaces the
    first's knowledge whole), and an alert. Returns (data root, tenant knowledge folder, alert)."""
    ensure_d9_tenant()
    root = current_data_root()
    folder = S.plant(root, marker=marker, released_status=released_status)
    alert = S.plant_alert(tmp_path / f"alert-{name}")
    return root, folder, alert


def _shim(tmp_path: Path, monkeypatch, *answers: dict[str, Any], name: str = "docker"
          ) -> S.DockerShim:
    """The docker shim, first on THIS process's PATH — which run.py's run env is built from."""
    shim = S.DockerShim(tmp_path / name, list(answers) or None)
    monkeypatch.setenv("PATH", shim.path_value())
    return shim


def _run(tmp_path: Path, root: Path, alert: Path, *, run_id: str = "r1107",
         summary: dict[str, Any] | None = None, page: bool = False, before: Any = None,
         update_ticket: bool = True) -> tuple[int | None, Any, Path, S.RunRecorder]:
    """`run.main` over one alert with the REAL ticket writer. `page=True` leaves the REAL renderer
    in place; otherwise the recorder's `visualize` stands in. Returns (rc, refusal, run dir,
    recorder)."""
    rec = S.RunRecorder(tmp_path / "runs" / run_id, summary=summary, before_lifecycle=before)
    seams = {} if page else {"visualize": rec.visualize}
    rc, refused = S.drive_run(
        S.run_argv(alert, root, update_ticket=update_ticket), rec, **seams)
    return rc, refused, rec.run_dir_at, rec


def _summary(truncated_by: str | None = None, closed_before_cut: bool = False) -> dict[str, Any]:
    return {"output": "spec1107", "requests": 0, "truncated_by": truncated_by,
            "closed_before_cut": closed_before_cut}


def _host_paths(folder: Path, root: Path) -> set[str]:
    """The tenant's host settings path and the data root, as given and resolved."""
    settings = S.settings_of(folder)
    return {str(settings), str(settings.resolve()), str(root), str(root.resolve())}


def _warnings(caplog, logger: str = TW_LOGGER) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and r.name == logger]


def _in_page(page: str, text: str) -> bool:
    return html.escape(text) in page or text in page


def _ticket_line_near(page: str, reason: str, *others: str, window: int = 1500) -> bool:
    """Does the page carry `reason` with every one of `others` within `window` chars of it —
    one ticket line, whatever its markup."""
    for needle in {html.escape(reason), reason}:
        at = page.find(needle)
        while at >= 0:
            around = page[max(0, at - window): at + len(needle) + window]
            if all(html.escape(o) in around or o in around for o in others):
                return True
            at = page.find(needle, at + 1)
    return False


def _post_calls(shim: S.DockerShim) -> list[list[str]]:
    return [c["argv"] for c in shim.calls() if "POST" in c["argv"]]


def _records_carried(value: Any, *, _depth: int = 0, _seen: set[int] | None = None) -> list[Any]:
    """Every `RunTenant` reachable from `value` (mappings, sequences, attributes)."""
    seen = _seen if _seen is not None else set()
    if _depth > 6 or id(value) in seen:
        return []
    seen.add(id(value))
    if isinstance(value, run_tenant.RunTenant):
        return [value]
    if isinstance(value, (str, bytes, int, float, bool, Path)) or value is None:
        return []
    out: list[Any] = []
    if isinstance(value, dict):
        items: list[Any] = [*value.keys(), *value.values()]
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    else:
        attrs = getattr(value, "__dict__", None)
        items = list(attrs.values()) if isinstance(attrs, dict) and not isinstance(value, type) else []
    for item in items:
        out += _records_carried(item, _depth=_depth + 1, _seen=seen)
    return out


def _calls_in(module_path: Path, names: set[str], *, env_reads: bool = False) -> list[str]:
    """`file:line call` for every call in `module_path` whose callee's last name is in `names`,
    plus (`env_reads`) every `os.environ` / `os.getenv` reference — a census of what the module
    finds for itself."""
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            last = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            if last in names:
                hits.append(f"{module_path.name}:{node.lineno} {last}()")
        if (env_reads and isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv"}
                and isinstance(node.value, ast.Name) and node.value.id == "os"):
            hits.append(f"{module_path.name}:{node.lineno} os.{node.attr}")
    return hits


class _WriterSeam:
    """`run.main`'s `ticket_writer` seam as a module-shaped recorder: what each leg was handed."""

    def __init__(self) -> None:
        self.opened: list[tuple[tuple, dict]] = []
        self.recorded: list[tuple[tuple, dict]] = []

    def open_case_ticket(self, *args: Any, **kwargs: Any) -> None:
        self.opened.append((args, kwargs))

    def record_case_ticket(self, *args: Any, **kwargs: Any) -> None:
        self.recorded.append((args, kwargs))


# ======================================================================================
# The seam (D-writer, F6).
# ======================================================================================

def test_d_writer_takes_record(tmp_path, monkeypatch):
    """open_case_ticket and record_case_ticket take the run's record from run.py and have no
    settings_dir parameter. TicketWriterDeps has a request field and no load_config field."""
    root, folder, alert = _world(tmp_path)
    _shim(tmp_path, monkeypatch)
    seam = _WriterSeam()
    rec = S.RunRecorder(tmp_path / "runs" / "r-seam")
    rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec,
                              ticket_writer=seam, visualize=rec.visualize)
    assert refused is None, f"the run did not complete: rc={rc} refused={refused}"
    assert rc == 0, f"the run did not complete: rc={rc} refused={refused}"
    assert seam.opened, f"run.py reached neither ticket leg under --update-ticket: {seam.opened} {seam.recorded}"
    assert seam.recorded, f"run.py reached neither ticket leg under --update-ticket: {seam.opened} {seam.recorded}"
    for leg, calls in (("open_case_ticket", seam.opened), ("record_case_ticket", seam.recorded)):
        _args, kwargs = calls[0]
        assert "settings_dir" not in kwargs, (
            f"run.py still hands {leg} the settings folder, not the record: {kwargs}")
        handed = _records_carried(calls[0])
        assert handed, f"run.py handed {leg} no RunTenant record: {calls[0]}"
        assert handed[0].settings == S.settings_of(folder).resolve(), (
            f"{leg} was handed another tenant's record: {handed[0].settings}")

    # The real functions' own signatures — the record, never the folder.
    for fn in (ticket_writer.open_case_ticket, ticket_writer.record_case_ticket):
        params = inspect.signature(fn).parameters
        assert "settings_dir" not in params, (
            f"{fn.__name__} still takes settings_dir: {list(params)}")
        assert S.RECORD_FIELD in params, (
            f"{fn.__name__} takes no record parameter ({S.RECORD_FIELD!r}): {list(params)}")
    fields = {f.name for f in dataclasses.fields(ticket_writer.TicketWriterDeps)} if (
        dataclasses.is_dataclass(ticket_writer.TicketWriterDeps)) else set(
        getattr(ticket_writer.TicketWriterDeps, "model_fields", {}) or
        inspect.signature(ticket_writer.TicketWriterDeps).parameters)
    assert "request" in fields, f"TicketWriterDeps lost its request seam: {fields}"
    assert "load_config" not in fields, (
        f"TicketWriterDeps still carries the load_config seam: {fields}")


def test_d_writer_context_from_run(tmp_path, monkeypatch):
    """The ticket writer's transport context uses the defender dir and the run dir that run.py
    passes. With DEFENDER_DIR exported to another tree and the process cwd elsewhere, the request's
    verb context still names run.py's values. _verb_context calls neither process_defender_dir() nor
    Path.cwd(). Its child environment is the run env run.py passes (F6 resolved, human round 4: the
    provisional reading)."""
    root, folder, alert = _world(tmp_path)
    run_id = "r-ctx"
    shim = _shim(tmp_path, monkeypatch, *S.store_answers_ok(run_id))
    other_tree = tmp_path / "another-defender-tree"
    other_tree.mkdir()
    elsewhere = tmp_path / "some-other-cwd"
    elsewhere.mkdir()
    monkeypatch.setenv("DEFENDER_DIR", str(other_tree))
    monkeypatch.chdir(elsewhere)

    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=run_id)
    assert refused is None, f"the run did not complete: rc={rc} refused={refused}"
    assert rc == 0, f"the run did not complete: rc={rc} refused={refused}"
    calls = shim.calls()
    assert calls, "the record step reached no docker child at all"
    for call in calls:
        env = call["env"]
        # run_common.run_env(defender_dir, run_dir) exports both — run.py's values, whatever the
        # process's own DEFENDER_DIR and cwd say (G29).
        assert env.get("DEFENDER_DIR") == str(S.DEFENDER), (
            f"the writer's child names DEFENDER_DIR={env.get('DEFENDER_DIR')!r}, not run.py's "
            f"{S.DEFENDER}")
        assert env.get("DEFENDER_RUN_DIR") == str(run_dir), (
            f"the writer's child names DEFENDER_RUN_DIR={env.get('DEFENDER_RUN_DIR')!r}, not "
            f"the run dir run.py passed ({run_dir}) — the process cwd leaked in")
    found = _calls_in(Path(ticket_writer.__file__), {"process_defender_dir", "cwd"})
    assert not found, f"the ticket writer finds its own location: {found}"


# ======================================================================================
# O6 — every settings or transport failure on the record step writes an error receipt.
# ======================================================================================

def test_o6_missing_config_receipt(tmp_path, monkeypatch, caplog):
    """run.py main runs with --update-ticket over a tenant whose case-history config.env is deleted.
    It writes ticket_write.json with ok false, status 'error', url null and a non-empty reason that
    names the settings through SETTINGS_POINTER. It logs a warning. The run page shows the receipt's
    key, status and reason. The process exit code equals that of the same run with the config
    present."""
    # rejected: D5 reverses the issue body's 'fail loudly': a failed ticket write never changes the exit code
    # rejected: C3/CX3: at base a missing config writes no receipt
    # rejected: #1047's ticket_unconfigured_lane_stays_silent (spec_graph_1047; test_1047_ticket_lane.py:427, test_767_writer.py:861): reversed by MF-9 (A, human round 1); a tenant that has mapping.yaml but no case-history config.env gets the error receipt
    caplog.set_level(logging.INFO)
    root_ok, _folder_ok, alert_ok = _world(tmp_path, name="tenants-ok")
    _shim(tmp_path, monkeypatch, *S.store_answers_ok("r-present"))
    rc_present, refused_present, _dir, _rec = _run(tmp_path, root_ok, alert_ok,
                                                   run_id="r-present", page=True)
    assert refused_present is None, f"the control run was refused: {refused_present}"

    root, folder, alert = _world(tmp_path, name="tenants-missing")
    S.config_path(folder, "case-history").unlink()
    caplog.clear()
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-missing", page=True)
    assert refused is None, f"the run was refused over a ticket-config problem: {refused}"
    page = S.page_html(run_dir)
    assert page, "the run page did not render"
    got = S.receipt(run_dir)
    assert got is not None, "no ticket_write.json for a tenant with no case-history config.env"
    assert got.get("ok") is False, got
    assert got.get("status") == "error", got
    assert "url" in got, f"url must be null with no config: {got}"
    assert got["url"] is None, f"url must be null with no config: {got}"
    reason = got.get("reason")
    assert isinstance(reason, str), f"no reason on the receipt: {got}"
    assert reason.strip(), f"no reason on the receipt: {got}"
    assert S.settings_pointer() in reason, (
        f"the reason does not name the settings through SETTINGS_POINTER: {reason!r}")
    assert _warnings(caplog), "the missing config logged no warning"
    assert _ticket_line_near(page, reason, got["key"], "error"), (
        "the run page shows no ticket line with the receipt's key, status and reason")
    assert rc == rc_present, (
        f"a ticket-config failure changed the exit code: {rc} vs {rc_present} with the config")


def test_o6_bad_config_receipt(tmp_path, monkeypatch, caplog):
    """When the case-history config.env is missing a required key, or has a non-integer
    CASE_HISTORY_TIMEOUT_SEC, the record step writes ticket_write.json with ok false, status
    'error', url null (F8 resolved auto: url is null for every config failure and stays the store's
    url for mapping and transport faults) and a reason that names the bad key through
    SETTINGS_POINTER. It logs a warning."""
    caplog.set_level(logging.INFO)
    _shim(tmp_path, monkeypatch)
    arms = {
        "missing-key": ("CASE_HISTORY_BASTION_HOST", lambda f: S.drop_key(
            f, "case-history", "CASE_HISTORY_BASTION_HOST")),
        "non-digit-timeout": ("CASE_HISTORY_TIMEOUT_SEC", lambda f: S.set_key(
            f, "case-history", "CASE_HISTORY_TIMEOUT_SEC", "ten")),
    }
    for arm, (bad_key, spoil) in arms.items():
        root, folder, alert = _world(tmp_path, name=f"tenants-{arm}")
        spoil(folder)
        caplog.clear()
        rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=f"r-{arm}")
        assert refused is None, f"{arm}: rc={rc} refused={refused}"
        assert rc == 0, f"{arm}: rc={rc} refused={refused}"
        got = S.receipt(run_dir)
        assert got is not None, f"{arm}: no ticket_write.json for a bad case-history config"
        assert got.get("ok") is False, f"{arm}: {got}"
        assert got.get("status") == "error", f"{arm}: {got}"
        assert "url" in got, f"{arm}: url must be null: {got}"
        assert got["url"] is None, f"{arm}: url must be null: {got}"
        reason = got.get("reason") or ""
        assert bad_key in reason, f"{arm}: the reason does not name {bad_key}: {reason!r}"
        assert S.settings_pointer() in reason, (
            f"{arm}: the reason does not name the settings through SETTINGS_POINTER: {reason!r}")
        assert _warnings(caplog), f"{arm}: no warning logged"


def test_o6_mapping_fault_receipt(tmp_path, monkeypatch, caplog):
    """With a bad mapping (record.ticket_mapping a CaseTicketError), the record step makes no POST.
    It writes ticket_write.json with ok false, status 'error', the store's url, and a reason that
    names the mapping problem, and it logs a warning."""
    caplog.set_level(logging.INFO)
    run_id = "r-mapping"
    shim = _shim(tmp_path, monkeypatch, *S.store_answers_ok(run_id))
    # The loader's own lifecycle refusal: `open.status` equal to `released.status`
    # (`case_ticket._check_lifecycle`, read at base: "case-history mapping's `open.status` and
    # `released.status` are both 'open' — …") — a real bad file, not a fake error. NF-23: the
    # reason is that check's own text, so it names the mapping.
    root, _folder, alert = _world(tmp_path, released_status="open")
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=run_id)
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    assert not _post_calls(shim), f"a bad mapping still reached a POST: {_post_calls(shim)}"
    got = S.receipt(run_dir)
    assert got is not None, "no ticket_write.json for a bad mapping"
    assert got.get("ok") is False, got
    assert got.get("status") == "error", got
    assert str(got.get("url") or "").startswith(f"http://case-history-{MARKER}:8080"), (
        f"the receipt's url is not the store's: {got}")
    reason = got.get("reason") or ""
    assert "mapping" in reason.lower(), f"the reason does not name the mapping problem: {got}"
    assert _warnings(caplog), "a bad mapping logged no warning"


def test_o6_transport_fault_receipt(tmp_path, monkeypatch, caplog):
    """A transport fault on the record step (the request returns no status) writes ticket_write.json
    with ok false, status 'error', and a reason that names the transport failure, and logs a
    warning."""
    caplog.set_level(logging.INFO)
    # G23/RG3 (executed): docker answers an unknown context with rc 1 and 'context not found' on
    # stderr, before any request — the request returns no status.
    _shim(tmp_path, monkeypatch, S.context_not_found(S.context_name(MARKER, "case-history")))
    root, _folder, alert = _world(tmp_path)
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-transport")
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    got = S.receipt(run_dir)
    assert got is not None, "no ticket_write.json for a transport fault"
    assert got.get("ok") is False, got
    assert got.get("status") == "error", got
    reason = got.get("reason") or ""
    assert reason.strip(), f"no reason on the transport-fault receipt: {got}"
    # NF-23: the reason is the failing check's own text — docker's 'context not found' (G23), or
    # the transport's naming of the endpoint it could not reach (the context).
    assert ("context not found" in reason or "transport" in reason.lower()
            or S.context_name(MARKER, "case-history") in reason), (
        f"the reason does not name the transport failure: {reason!r}")
    assert _warnings(caplog), "a transport fault logged no warning"


def test_o6_reason_no_host_path(tmp_path, monkeypatch):
    """No receipt reason, across the missing-config, bad-config, bad-mapping and transport arms,
    contains the tenant's host settings path (as given or resolved) or the tenants root."""
    arms = ("missing-config", "bad-config", "bad-mapping", "transport")
    reasons: dict[str, str] = {}
    for arm in arms:
        run_id = f"r-{arm}"
        answers = ([S.context_not_found(S.context_name(MARKER, "case-history"))]
                   if arm == "transport" else S.store_answers_ok(run_id))
        _shim(tmp_path, monkeypatch, *answers, name=f"docker-{arm}")
        root, folder, alert = _world(
            tmp_path, name=f"tenants-{arm}",
            released_status="open" if arm == "bad-mapping" else "closed")
        if arm == "missing-config":
            S.config_path(folder, "case-history").unlink()
        elif arm == "bad-config":
            S.drop_key(folder, "case-history", "CASE_HISTORY_URL_BASE")
        rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=run_id)
        got = S.receipt(run_dir)
        # The channel: each arm DID write a receipt with a reason (the positive precondition).
        assert got is not None, f"{arm}: no receipt reason to judge: {got}"
        assert (got.get("reason") or "").strip(), f"{arm}: no receipt reason to judge: {got}"
        reasons[arm] = got["reason"]
        for host in _host_paths(folder, root):
            assert host not in got["reason"], (
                f"{arm}: the receipt reason carries the host path {host}: {got['reason']!r}")
    assert set(reasons) == set(arms), reasons


def test_o6_budget_cut_missing_config_no_receipt(tmp_path, monkeypatch):
    """A run cut by budget, or by store, with no verdict (closed_before_cut false) writes no
    ticket_write.json, even when the tenant's case-history config.env is missing: the #1047 check
    runs ahead of the config load."""
    _shim(tmp_path, monkeypatch)
    root, folder, alert = _world(tmp_path)
    S.config_path(folder, "case-history").unlink()
    # The control, same tenant, same missing config: an aborted run DOES write the error receipt,
    # so the channel below can see a receipt when one is written.
    _rc, _ref, aborted_dir, _rec = _run(
        tmp_path, root, alert, run_id="r-aborted",
        summary=_summary(run_end.TRUNCATED_BY_ABORTED))
    assert S.receipt(aborted_dir) is not None, (
        "the control failed: an aborted run with the config missing wrote no receipt")
    for cut in (run_end.TRUNCATED_BY_BUDGET, run_end.TRUNCATED_BY_STORE):
        rc, refused, run_dir, _rec = _run(
            tmp_path, root, alert, run_id=f"r-{cut}", summary=_summary(cut))
        assert refused is None, f"{cut}: rc={rc} refused={refused}"
        assert rc == 0, f"{cut}: rc={rc} refused={refused}"
        path = S.receipt_path(run_dir)
        assert not path.exists(), f"a run cut by {cut} with no verdict wrote {path.name}: {path.read_text()!r}"
        assert not path.is_symlink(), f"a run cut by {cut} with no verdict wrote {path.name}: {path.read_text()!r}"


def test_o6_aborted_missing_config_receipt(tmp_path, monkeypatch):
    """An aborted run (no verdict, but not budget or store) with the case-history config.env
    missing writes the error receipt with url null and a reason. The missing-config arm is reached
    once the budget/store check has passed."""
    _shim(tmp_path, monkeypatch)
    root, folder, alert = _world(tmp_path)
    S.config_path(folder, "case-history").unlink()
    rc, refused, run_dir, _rec = _run(
        tmp_path, root, alert, run_id="r-aborted",
        summary=_summary(run_end.TRUNCATED_BY_ABORTED))
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    got = S.receipt(run_dir)
    assert got is not None, "an aborted run with the config missing wrote no receipt"
    assert got.get("ok") is False, got
    assert got.get("status") == "error", got
    assert "url" in got, f"url must be null with no config: {got}"
    assert got["url"] is None, f"url must be null with no config: {got}"
    assert (got.get("reason") or "").strip(), f"no reason: {got}"


def test_o6_open_step_no_receipt(tmp_path, monkeypatch, caplog):
    """open_case_ticket writes no ticket_write.json on any path (missing config, bad config, bad
    mapping, transport fault) and only warns. The record step is the one receipt writer."""
    caplog.set_level(logging.INFO)
    for arm in ("missing-config", "bad-config", "bad-mapping", "transport"):
        run_id = f"r-open-{arm}"
        answers = ([S.context_not_found(S.context_name(MARKER, "case-history"))]
                   if arm == "transport" else [S.answer('{"key": "x"}', "201")])
        shim = _shim(tmp_path, monkeypatch, *answers, name=f"docker-{arm}")
        root, folder, alert = _world(
            tmp_path, name=f"tenants-{arm}",
            released_status="open" if arm == "bad-mapping" else "closed")
        if arm == "missing-config":
            S.config_path(folder, "case-history").unlink()
        elif arm == "bad-config":
            S.set_key(folder, "case-history", "CASE_HISTORY_TIMEOUT_SEC", "ten")
        # run.main's own seam, with the REAL open step and a record step that does nothing — so
        # whatever lands at the receipt's name came from the open step.
        writer = SimpleNamespace(open_case_ticket=ticket_writer.open_case_ticket,
                                 record_case_ticket=lambda *a, **k: None)
        rec = S.RunRecorder(tmp_path / "runs" / run_id)
        caplog.clear()
        rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec,
                                  ticket_writer=writer, visualize=rec.visualize)
        assert refused is None, f"{arm}: rc={rc} refused={refused}"
        assert rc == 0, f"{arm}: rc={rc} refused={refused}"
        # The channel: the open step RAN and said so (a warning on every failing path; the
        # transport arm also reached the store).
        assert _warnings(caplog), f"{arm}: the open step logged no warning — did it run?"
        if arm == "transport":
            assert shim.calls(), "transport arm: the open step never reached the store"
        path = S.receipt_path(rec.run_dir_at)
        assert not path.exists(), f"{arm}: the open step wrote {path.name}: {path.read_text()!r}"
        assert not path.is_symlink(), f"{arm}: the open step wrote {path.name}: {path.read_text()!r}"


def test_store_answers_the_record_step_with_an_http_error(tmp_path, monkeypatch, caplog):
    """An HTTP 4xx or 5xx from the store on the record step is a transport fault: ticket_write.json
    with ok false and a reason, a warning log line, a page line, and the exit code unchanged."""
    caplog.set_level(logging.INFO)
    root, _folder, alert = _world(tmp_path)
    _shim(tmp_path, monkeypatch, *S.store_answers_ok("r-ok"), name="docker-ok")
    rc_ok, refused_ok, ok_dir, _rec = _run(tmp_path, root, alert, run_id="r-ok", page=True)
    assert refused_ok is None, refused_ok
    control = S.receipt(ok_dir)
    assert control is not None, f"the control failed: a 2xx record step wrote {control}"
    assert control.get("ok") is True, f"the control failed: a 2xx record step wrote {control}"
    for status in ("403", "503"):
        run_id = f"r-http-{status}"
        read_back = S.answer(json.dumps({"key": run_id, "status": "open", "comments": []}), "200")
        _shim(tmp_path, monkeypatch, read_back,
              S.answer(json.dumps({"detail": f"store refused {status}"}), status),
              name=f"docker-{status}")
        caplog.clear()
        rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=run_id, page=True)
        assert refused is None, f"HTTP {status}: refused {refused}"
        page = S.page_html(run_dir)
        assert page, f"HTTP {status}: the run page did not render"
        got = S.receipt(run_dir)
        assert got is not None, f"HTTP {status}: {got}"
        assert got.get("ok") is False, f"HTTP {status}: {got}"
        reason = got.get("reason") or ""
        assert reason.strip(), f"HTTP {status}: no reason on the receipt: {got}"
        assert _warnings(caplog), f"HTTP {status}: no warning logged"
        assert _ticket_line_near(page, reason, got["key"]), (
            f"HTTP {status}: the run page shows no ticket line for the failed record")
        assert rc == rc_ok, f"HTTP {status} changed the exit code: {rc} vs {rc_ok}"


def test_s7_nf23_reason_is_the_redacted_fault_text(tmp_path, monkeypatch, caplog):
    """The receipt reason is the failing check's own fault text passed through the settings-path
    redaction: the warning log line for the same failure carries the same redacted reason and no
    host settings path, and a released-by-a-person decline keeps today's receipt and gains a
    non-empty reason naming the decline. Assertions stay at a non-empty reason and no host path."""
    caplog.set_level(logging.INFO)
    _shim(tmp_path, monkeypatch)
    root, folder, alert = _world(tmp_path, name="tenants-bad")
    S.drop_key(folder, "case-history", "CASE_HISTORY_BASTION_HOST")
    caplog.clear()
    _rc, _ref, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-bad")
    got = S.receipt(run_dir)
    assert got is not None, f"no reason: {got}"
    assert (got.get("reason") or "").strip(), f"no reason: {got}"
    reason = got["reason"]
    warned = _warnings(caplog)
    assert any(reason in w for w in warned), (
        f"no warning line carries the receipt's reason {reason!r}: {warned}")
    for host in _host_paths(folder, root):
        assert host not in reason, f"the reason carries {host}: {reason!r}"
        for w in warned:
            assert host not in w, f"a warning line carries the host path {host}: {w!r}"

    # A person already released the case (the mapping's released status is `closed`): today's
    # `refused-released` receipt, now with a reason.
    root2, _folder2, alert2 = _world(tmp_path, name="tenants-released")
    run_id = "r-released"
    _shim(tmp_path, monkeypatch,
          S.answer(json.dumps({"key": run_id, "status": "closed", "comments": []}), "200"),
          name="docker-released")
    _rc2, _ref2, run_dir2, _rec2 = _run(tmp_path, root2, alert2, run_id=run_id)
    declined = S.receipt(run_dir2)
    assert declined is not None, "the released-case decline wrote no receipt"
    assert declined.get("status") == ticket_writer.RECEIPT_REFUSED_RELEASED, declined
    assert declined.get("ok") is False, declined
    assert (declined.get("reason") or "").strip(), (
        f"the released-case decline carries no reason: {declined}")


def test_s7_nf24_receipt_write_failure_is_harmless(tmp_path, monkeypatch, caplog):
    """A failure writing ticket_write.json itself (permission denied, a full disk) is caught and
    logged as a warning, and the run's exit code is unchanged; a later record step in the same run
    dir replaces an earlier receipt (the last attempt wins)."""
    caplog.set_level(logging.INFO)
    root, folder, alert = _world(tmp_path)

    # (a) A directory squatting the receipt's name: a real input the guarded replace cannot write
    # over. The record step itself succeeds against the store.
    _shim(tmp_path, monkeypatch, *S.store_answers_ok("r-squat"), name="docker-squat")

    def squat(run_dir: Path) -> None:
        S.receipt_path(run_dir).mkdir()

    caplog.clear()
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-squat", before=squat)
    assert refused is None, f"a receipt write failure changed the run: {rc} {refused}"
    assert rc == 0, f"a receipt write failure changed the run: {rc} {refused}"
    assert S.receipt_path(run_dir).is_dir(), "the squatting directory was removed or replaced"
    warned = [w for w in _warnings(caplog)
              if "receipt" in w.lower() or RunPaths(run_dir).ticket_write.name in w]
    assert warned, f"the failed receipt write was not logged as a warning: {_warnings(caplog)}"

    # (b) The last attempt wins: a successful record, then a second record step in the SAME run
    # dir after the case-history config went missing, whose error receipt (MF-9) replaces it.
    run_id = "r-twice"
    _shim(tmp_path, monkeypatch, *S.store_answers_ok(run_id), name="docker-twice")
    _run(tmp_path, root, alert, run_id=run_id)
    first = S.receipt(tmp_path / "runs" / run_id)
    assert first is not None, f"the first attempt failed: {first}"
    assert first.get("ok") is True, f"the first attempt failed: {first}"
    S.config_path(folder, "case-history").unlink()
    _run(tmp_path, root, alert, run_id=run_id)
    last = S.receipt(tmp_path / "runs" / run_id)
    assert last is not None, f"the later record step did not replace the earlier receipt: {last}"
    assert last.get("status") == "error", f"the later record step did not replace the earlier receipt: {last}"
    assert last.get("ok") is False, f"the later record step did not replace the earlier receipt: {last}"


def test_s7_mf12_no_receipt_branch_clears_stale_receipt(tmp_path, monkeypatch):
    """Every record-step branch that writes no receipt first removes any existing ticket_write.json
    (an unlink that never follows a link). A run cut by budget with no verdict, over a run dir
    already holding a planted or earlier receipt (a forged {status: commented, ok: true}, or a
    symlink at that name), leaves no ticket_write.json behind, and its page shows no ticket line."""
    _shim(tmp_path, monkeypatch)
    root, _folder, alert = _world(tmp_path)
    forged = {"key": "FORGED-KEY-1107", "status": "commented", "url": "http://forged.invalid/x",
              "ok": True, "reason": "forged-reason-1107"}
    target = tmp_path / "outside-target.json"
    target_bytes = json.dumps(forged).encode("utf-8")
    target.write_bytes(target_bytes)
    planted: list[str] = []

    def plant_file(run_dir: Path) -> None:
        S.receipt_path(run_dir).write_text(json.dumps(forged), encoding="utf-8")
        planted.append("file" if S.receipt_path(run_dir).is_file() else "")

    def plant_link(run_dir: Path) -> None:
        S.receipt_path(run_dir).symlink_to(target)
        planted.append("link" if S.receipt_path(run_dir).is_symlink() else "")

    for arm, kind, before in (("forged", "file", plant_file), ("symlink", "link", plant_link)):
        rc, refused, run_dir, _rec = _run(
            tmp_path, root, alert, run_id=f"r-{arm}", page=True, before=before,
            summary=_summary(run_end.TRUNCATED_BY_BUDGET))
        assert refused is None, f"{arm}: rc={rc} refused={refused}"
        assert rc == 0, f"{arm}: rc={rc} refused={refused}"
        page = S.page_html(run_dir)
        assert page, f"{arm}: the run page did not render"
        # The plant was in place when the run reached its ticket lane.
        assert planted, f"{arm}: the plant was not in place: {planted}"
        assert planted[-1] == kind, f"{arm}: the plant was not in place: {planted}"
        path = S.receipt_path(run_dir)
        assert not path.exists(), f"{arm}: a budget-cut run left {path.name} behind"
        assert not path.is_symlink(), f"{arm}: a budget-cut run left {path.name} behind"
        for marker in ("FORGED-KEY-1107", "forged-reason-1107", "forged.invalid"):
            assert marker not in page, f"{arm}: the page shows the planted receipt ({marker})"
    assert target.read_bytes() == target_bytes, "the unlink followed the link into its target"


def test_o1_ticket_writer_ignores_env(tmp_path, monkeypatch):
    """With CASE_HISTORY_URL_BASE exported, the record step's request URL and the receipt's url are
    the tenant file's. At base the exported value wins (C3, CX3)."""
    exported = "http://exported-case-history-1107:1"
    monkeypatch.setenv("CASE_HISTORY_URL_BASE", exported)
    run_id = "r-o1"
    shim = _shim(tmp_path, monkeypatch, *S.store_answers_ok(run_id))
    root, _folder, alert = _world(tmp_path)
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=run_id)
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    calls = shim.calls()
    assert calls, "the record step reached the store through no docker child"
    # The variable WAS exported and did reach the run env (N4: it is passed through untouched).
    assert calls[0]["env"].get("CASE_HISTORY_URL_BASE") == exported, (
        "the exported variable never reached the run env — the fixture does not discriminate")
    file_base = f"http://case-history-{MARKER}:8080"
    for call in calls:
        url = S.curl_url(call["argv"]) or ""
        assert url.startswith(file_base), (
            f"the record step addressed {url!r}, not the tenant file's {file_base}")
        assert exported not in " ".join(call["argv"]), call["argv"]
    got = S.receipt(run_dir)
    assert got is not None, f"the receipt's url is not the tenant file's: {got}"
    assert str(got.get("url") or "").startswith(file_base), f"the receipt's url is not the tenant file's: {got}"


# ======================================================================================
# The receipt's file (PG-6, PG-12).
# ======================================================================================

def test_s60_ticket_write_fs_atomic_replace(tmp_path, monkeypatch):
    """ticket_write.json is written by a guarded replace: a reader never observes a
    partially-written file, and an interrupted write leaves either the old content or the new
    content, never a torn mix."""
    root, folder, alert = _world(tmp_path)
    run_id = "r-atomic"
    _shim(tmp_path, monkeypatch, *S.store_answers_ok(run_id))
    _run(tmp_path, root, alert, run_id=run_id)
    run_dir = tmp_path / "runs" / run_id
    path = S.receipt_path(run_dir)
    assert path.is_file(), "the first record step wrote no receipt"
    old_bytes = path.read_bytes()
    old_inode = path.stat().st_ino
    # A reader holding the file open across the next write.
    with path.open("rb") as reader:
        S.config_path(folder, "case-history").unlink()
        _run(tmp_path, root, alert, run_id=run_id)
        held = reader.read()
    assert held == old_bytes, "the second write changed the bytes under an open reader (in place)"
    json.loads(held.decode("utf-8"))
    after = json.loads(path.read_bytes().decode("utf-8"))
    # The second record step (MF-9: the missing config's error receipt) did write.
    assert after.get("status") == "error", f"the second (error) receipt did not land: {after}"
    assert path.stat().st_ino != old_inode, (
        "the second receipt was not written by a replace — the same inode was rewritten")
    leftovers = sorted(p.name for p in run_dir.iterdir()
                       if p.name != path.name and "ticket_write" in p.name)
    assert not leftovers, f"a staged receipt was left beside the real one: {leftovers}"


def test_s60_ticket_write_path_stable_for_path_helpers(tmp_path, monkeypatch):
    """RunPaths(run_dir).ticket_write(runs_base) is <runs_base>/<run id>.ticket-write.json, a
    sidecar beside the run dir like the scrub verdict (moved out of the box-writable run dir at
    the third #1156 review; it was <run_dir>/ticket_write.json). the layout and the handle
    resolve this same path, and the record step's receipt lands there."""
    root, _folder, alert = _world(tmp_path)
    run_id = "r-path"
    _shim(tmp_path, monkeypatch, *S.store_answers_ok(run_id))
    _run(tmp_path, root, alert, run_id=run_id)
    run_dir = tmp_path / "runs" / run_id
    expected = run_dir.parent / f"{run_id}.ticket-write.json"
    assert RunPaths(run_dir).ticket_write(run_dir.parent) == expected, (
        RunPaths(run_dir).ticket_write(run_dir.parent))
    assert Run.under(run_dir.parent, run_id).observability.ticket_write.path \
        == expected, "the run handle resolves the receipt somewhere else"
    assert expected.is_file(), (
        f"the record step's receipt did not land at {expected}: {sorted(os.listdir(run_dir))}")


def test_s60_ticket_writer_fakes_migrated(tmp_path, monkeypatch):
    """Every test fake standing in for open_case_ticket/record_case_ticket (_spec791.SpecTail,
    test_947_triplet_sibling.Writer, test_767_run_tail.Tail, test_1106_run_start.writer) accepts the
    new record parameter from run.py, not the old settings_dir, and a call through it is observably
    affected by the record's contents (not silently ignored by a **kwargs catch-all)."""
    from defender.tests import _spec791
    from defender.tests import test_767_run_tail
    from defender.tests.e2e import test_1106_run_start

    # The 947 fake is defined inside its test function; its class is taken from that source.
    src_947 = Path(__file__).resolve().parents[1] / "test_947_triplet_sibling.py"
    tree = ast.parse(src_947.read_text(encoding="utf-8"))
    writer_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "Writer"]
    assert writer_nodes, "test_947_triplet_sibling.py no longer defines its Writer fake"
    namespace: dict[str, Any] = {"Any": Any}
    exec(compile(ast.Module(body=[writer_nodes[0]], type_ignores=[]),  # noqa: S102 — the fake's own source
                 str(src_947), "exec"), namespace)

    fakes = {
        "_spec791.SpecTail": lambda: _spec791.SpecTail(_spec791.loop_paths(tmp_path / "l791")),
        "test_947_triplet_sibling.Writer": namespace["Writer"],
        "test_767_run_tail.Tail": lambda: test_767_run_tail.Tail(
            _spec791.loop_paths(tmp_path / "l767")),
        "test_1106_run_start.writer": test_1106_run_start.TicketWriterRecorder,
    }
    _shim(tmp_path, monkeypatch)
    root, folder, alert = _world(tmp_path)
    want = S.settings_of(folder).resolve()
    for name, make in fakes.items():
        fake = make()
        rec = S.RunRecorder(tmp_path / "runs" / f"r-{name.split('.')[-1].lower()}")
        rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec,
                                  ticket_writer=fake, visualize=rec.visualize)
        assert refused is None, f"{name} does not accept what run.py hands the ticket legs: rc={rc} {refused}"
        assert rc == 0, f"{name} does not accept what run.py hands the ticket legs: rc={rc} {refused}"
        carried = _records_carried(fake)
        assert carried, (
            f"{name} kept nothing of the record run.py handed it — the call went into a "
            f"catch-all: {vars(fake) if hasattr(fake, '__dict__') else fake}")
        assert all(r.settings == want for r in carried), (
            f"{name} kept another tenant's record: {[r.settings for r in carried]}")


def test_s7_f6_run_env_handed_to_writer_and_lead_zero(tmp_path, monkeypatch):
    """run.py hands its run env (run_common.run_env's copy) to the ticket writer, and the driver
    hands the run's env to lead-zero: with a marker variable in that env, the writer's docker child
    and lead-zero item 1's shell-fetch child both receive it, and neither lane calls run_env() or
    reads os.environ itself."""
    marker_var, marker_value = "SPEC1107_RUN_ENV_MARKER", "run-env-marker-7c1"
    monkeypatch.setenv(marker_var, marker_value)

    # Lead-zero's half: item 1's shell fetch is the first backend call the lead makes; the verb
    # it reaches is the harness's recorder (`_lead_zero_808`), and what it records is the context
    # lead-zero built — its env is what the child the real verb forks is handed.
    from defender.tests.e2e import _lead_zero_808 as LZ

    res = LZ.run(tmp_path / "lz-run", run_id="lz1107-f6")
    assert res.rec.calls, "lead-zero issued no backend call — item 1's shell fetch never ran"
    shell_env = dict(res.rec.calls[0].ctx.env)
    assert shell_env.get(marker_var) == marker_value, (
        "lead-zero item 1's shell fetch was not handed the run env's marker")

    # The writer's half, through run.main.
    root, _folder, alert = _world(tmp_path)
    run_id = "r-f6"
    shim = _shim(tmp_path, monkeypatch, *S.store_answers_ok(run_id))
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=run_id)
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    calls = shim.calls()
    assert calls, "the writer reached no docker child"
    # run_common.run_env's copy, as run.py builds it for THIS run (G29): the marker and the two
    # run-scoped variables are what the writer's child must be handed.
    run_envs = run_common.run_env(S.DEFENDER, run_dir)
    wanted = {k: run_envs.get(k) for k in (marker_var, "DEFENDER_DIR", "DEFENDER_RUN_DIR")}
    assert wanted[marker_var] == marker_value, f"the run env lost the marker: {wanted}"
    for call in calls:
        got = {k: call["env"].get(k) for k in wanted}
        assert got == wanted, (
            f"the writer's docker child was not handed run.py's run env: {got} vs {wanted}")

    # Neither lane builds or reads the environment itself: run.py and the driver hand it in.
    lanes = [Path(ticket_writer.__file__),
             *sorted((S.DEFENDER / "runtime" / "lead_zero").glob("*.py"))]
    found = [hit for lane in lanes for hit in _calls_in(lane, {"run_env"}, env_reads=True)]
    assert not found, f"a lane builds or reads the environment itself: {found}"
